use crate::traits::{ControlHandler, McpHandler, UpstreamTransport};
use aegis_core::{
    expand_env, AegisError, JsonRpcError, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest,
    JsonRpcResponse, RequestId, Result, ServerConfig, ERR_INVALID_REQUEST, ERR_PARSE,
    MCP_PROTOCOL_VERSION,
};
use async_trait::async_trait;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, RwLock};
use tokio_stream::wrappers::IntervalStream;
use tracing::{debug, info};
use uuid::Uuid;

// =============================================================================
// Upstream: MCP 2025-03-26 Streamable HTTP Client
// =============================================================================

pub struct StreamableHttpUpstream {
    name: String,
    url: String,
    headers: BTreeMap<String, String>,
    client: reqwest::Client,
    session_id: RwLock<Option<String>>,
    next_id: AtomicI64,
    alive: AtomicBool,
}

impl StreamableHttpUpstream {
    pub fn new(name: impl Into<String>, cfg: &ServerConfig) -> Result<Self> {
        let name = name.into();
        let url = cfg
            .url
            .as_deref()
            .map(expand_env)
            .filter(|u| !u.is_empty())
            .ok_or_else(|| AegisError::Config(format!("http server '{name}' missing 'url'")))?;

        let headers = cfg
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), expand_env(v)))
            .collect();

        let client = reqwest::Client::builder()
            .user_agent(format!("aegis/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| AegisError::Transport(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            name,
            url,
            headers,
            client,
            session_id: RwLock::new(None),
            next_id: AtomicI64::new(1),
            alive: AtomicBool::new(true),
        })
    }

    async fn build_post(&self, timeout: Duration) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .post(&self.url)
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", MCP_PROTOCOL_VERSION);

        if let Some(sid) = self.session_id.read().await.as_deref() {
            req = req.header("Mcp-Session-Id", sid);
        }
        for (k, v) in &self.headers {
            if !v.is_empty() {
                req = req.header(k.as_str(), v.as_str());
            }
        }
        req
    }

    async fn capture_session_id(&self, headers: &reqwest::header::HeaderMap) {
        if let Some(val) = headers.get("mcp-session-id") {
            if let Ok(s) = val.to_str() {
                let mut guard = self.session_id.write().await;
                *guard = Some(s.to_string());
            }
        }
    }
}

#[async_trait]
impl UpstreamTransport for StreamableHttpUpstream {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value> {
        let id = RequestId::Number(self.next_id.fetch_add(1, Ordering::SeqCst));
        let rpc_req = JsonRpcRequest::new(id.clone(), method, params);

        let resp = self
            .build_post(timeout)
            .await
            .json(&rpc_req)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    AegisError::Timeout {
                        server: self.name.clone(),
                        timeout_secs: timeout.as_secs(),
                    }
                } else {
                    AegisError::Upstream {
                        server: self.name.clone(),
                        message: format!("HTTP POST failed: {e}"),
                    }
                }
            })?;

        self.capture_session_id(resp.headers()).await;

        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();

        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AegisError::Upstream {
                server: self.name.clone(),
                message: format!("HTTP {status}: {body}"),
            });
        }

        let rpc_resp = if content_type.contains("text/event-stream") {
            read_sse_response_for_id(resp, &id, &self.name).await?
        } else {
            let text = resp.text().await.map_err(|e| AegisError::Upstream {
                server: self.name.clone(),
                message: format!("failed to read HTTP body: {e}"),
            })?;
            parse_json_rpc_response_for_id(&text, &id, &self.name)?
        };

        if let Some(err) = rpc_resp.error {
            return Err(AegisError::Upstream {
                server: self.name.clone(),
                message: format!("[{}] {}", err.code, err.message),
            });
        }

        Ok(rpc_resp.result.unwrap_or(Value::Null))
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        let notif = JsonRpcNotification::new(method, params);
        let resp = self
            .build_post(Duration::from_secs(15))
            .await
            .json(&notif)
            .send()
            .await
            .map_err(|e| AegisError::Upstream {
                server: self.name.clone(),
                message: format!("HTTP notification failed: {e}"),
            })?;

        self.capture_session_id(resp.headers()).await;
        if !resp.status().is_success() {
            debug!(server = %self.name, status = %resp.status(), "non-2xx status on HTTP notification");
        }
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.alive.store(false, Ordering::SeqCst);
        let sid = self.session_id.write().await.take();
        if let Some(sid) = sid {
            let mut req = self.client.delete(&self.url).header("Mcp-Session-Id", sid);
            for (k, v) in &self.headers {
                if !v.is_empty() {
                    req = req.header(k.as_str(), v.as_str());
                }
            }
            let _ = req.timeout(Duration::from_secs(5)).send().await;
        }
        Ok(())
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

fn parse_json_rpc_response_for_id(
    text: &str,
    expected_id: &RequestId,
    server: &str,
) -> Result<JsonRpcResponse> {
    let val: Value = serde_json::from_str(text).map_err(|e| AegisError::Upstream {
        server: server.to_string(),
        message: format!("invalid JSON response: {e}"),
    })?;
    match val {
        Value::Array(items) => {
            for item in items {
                if let Ok(JsonRpcMessage::Response(resp)) = JsonRpcMessage::from_value(item) {
                    if resp.id.as_ref() == Some(expected_id) {
                        return Ok(resp);
                    }
                }
            }
            Err(AegisError::Upstream {
                server: server.to_string(),
                message: format!("batch response missing id {expected_id}"),
            })
        }
        other => match JsonRpcMessage::from_value(other) {
            Ok(JsonRpcMessage::Response(resp)) => Ok(resp),
            _ => Err(AegisError::Upstream {
                server: server.to_string(),
                message: "HTTP response was not a JSON-RPC response object".into(),
            }),
        },
    }
}

async fn read_sse_response_for_id(
    resp: reqwest::Response,
    expected_id: &RequestId,
    server: &str,
) -> Result<JsonRpcResponse> {
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut data_lines: Vec<String> = Vec::new();

    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| AegisError::Upstream {
            server: server.to_string(),
            message: format!("SSE stream read error: {e}"),
        })?;
        buf.push_str(&String::from_utf8_lossy(&bytes));

        while let Some(pos) = buf.find('\n') {
            let mut line = buf[..pos].to_string();
            buf.drain(..=pos);
            if line.ends_with('\r') {
                line.pop();
            }

            if line.is_empty() {
                if !data_lines.is_empty() {
                    let payload = data_lines.join("\n");
                    data_lines.clear();
                    if let Ok(resp) = parse_json_rpc_response_for_id(&payload, expected_id, server)
                    {
                        return Ok(resp);
                    }
                }
            } else if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.trim_start().to_string());
            }
        }
    }

    if !data_lines.is_empty() {
        let payload = data_lines.join("\n");
        if let Ok(resp) = parse_json_rpc_response_for_id(&payload, expected_id, server) {
            return Ok(resp);
        }
    }

    Err(AegisError::Upstream {
        server: server.to_string(),
        message: format!("SSE stream ended before response for id {expected_id} arrived"),
    })
}

// =============================================================================
// Downstream: MCP 2025-03-26 Streamable HTTP Server (Axum)
// =============================================================================

#[derive(Clone)]
struct HttpState {
    handler: Arc<dyn McpHandler>,
    control: Option<Arc<dyn ControlHandler>>,
    sessions: Arc<RwLock<HashSet<String>>>,
}

pub fn build_http_router(
    handler: Arc<dyn McpHandler>,
    control: Option<Arc<dyn ControlHandler>>,
) -> Router {
    let state = HttpState {
        handler,
        control,
        sessions: Arc::new(RwLock::new(HashSet::new())),
    };

    Router::new()
        .route(
            "/mcp",
            post(handle_mcp_post)
                .get(handle_mcp_get_sse)
                .delete(handle_mcp_delete),
        )
        .route(
            "/",
            post(handle_mcp_post)
                .get(handle_mcp_get_sse)
                .delete(handle_mcp_delete),
        )
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .with_state(state)
}

pub async fn serve_http_downstream(
    addr: SocketAddr,
    handler: Arc<dyn McpHandler>,
    control: Option<Arc<dyn ControlHandler>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let router = build_http_router(handler, control);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| AegisError::Transport(format!("failed to bind HTTP on {addr}: {e}")))?;

    info!(%addr, "Aegis Streamable HTTP MCP gateway listening (endpoint: /mcp)");

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
        .map_err(|e| AegisError::Transport(format!("HTTP server error: {e}")))?;

    Ok(())
}

async fn handle_mcp_post(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let parsed: std::result::Result<Value, _> = serde_json::from_str(&body);
    let val = match parsed {
        Ok(v) => v,
        Err(e) => {
            let err_resp = JsonRpcResponse::err(
                None,
                JsonRpcError::new(ERR_PARSE, format!("JSON parse error: {e}")),
            );
            return json_response(StatusCode::BAD_REQUEST, &err_resp, None);
        }
    };

    let existing_session = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    match val {
        Value::Array(batch) => {
            if batch.is_empty() {
                let err_resp = JsonRpcResponse::err(
                    None,
                    JsonRpcError::new(ERR_INVALID_REQUEST, "empty JSON-RPC batch"),
                );
                return json_response(StatusCode::BAD_REQUEST, &err_resp, None);
            }
            let mut responses = Vec::new();
            let mut new_session_id = existing_session.clone();
            for item in batch {
                let (resp, maybe_sid) = dispatch_http_item(&state, item).await;
                if let Some(sid) = maybe_sid {
                    new_session_id = Some(sid);
                }
                if let Some(r) = resp {
                    responses.push(r);
                }
            }
            if responses.is_empty() {
                StatusCode::ACCEPTED.into_response()
            } else {
                json_response(StatusCode::OK, &responses, new_session_id.as_deref())
            }
        }
        single => {
            let (resp, maybe_sid) = dispatch_http_item(&state, single).await;
            let sid = maybe_sid.or(existing_session);
            match resp {
                Some(r) => json_response(StatusCode::OK, &r, sid.as_deref()),
                None => StatusCode::ACCEPTED.into_response(),
            }
        }
    }
}

async fn dispatch_http_item(
    state: &HttpState,
    value: Value,
) -> (Option<JsonRpcResponse>, Option<String>) {
    match JsonRpcMessage::from_value(value) {
        Ok(JsonRpcMessage::Request(req)) => {
            let is_init = req.method == "initialize";
            let resp = state.handler.handle_request(req).await;
            let sid = if is_init && resp.error.is_none() {
                let id = Uuid::new_v4().to_string();
                state.sessions.write().await.insert(id.clone());
                Some(id)
            } else {
                None
            };
            (Some(resp), sid)
        }
        Ok(JsonRpcMessage::Notification(notif)) => {
            state.handler.handle_notification(notif).await;
            (None, None)
        }
        Ok(JsonRpcMessage::Response(_)) => (None, None),
        Err(e) => (
            Some(JsonRpcResponse::err(
                None,
                JsonRpcError::new(ERR_INVALID_REQUEST, format!("invalid JSON-RPC message: {e}")),
            )),
            None,
        ),
    }
}

async fn handle_mcp_get_sse(
    State(_state): State<HttpState>,
) -> Sse<impl futures_util::Stream<Item = std::result::Result<Event, Infallible>>> {
    let interval = tokio::time::interval(Duration::from_secs(20));
    let stream = IntervalStream::new(interval).map(|_| Ok(Event::default().comment("keep-alive")));
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn handle_mcp_delete(State(state): State<HttpState>, headers: HeaderMap) -> StatusCode {
    if let Some(sid) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        state.sessions.write().await.remove(sid);
    }
    StatusCode::NO_CONTENT
}

async fn handle_health(State(state): State<HttpState>) -> Response {
    let body = if let Some(ctrl) = &state.control {
        let stats = ctrl.stats().await;
        json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "stats": stats,
        })
    } else {
        json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
        })
    };
    json_response(StatusCode::OK, &body, None)
}

async fn handle_metrics(State(state): State<HttpState>) -> Response {
    let Some(ctrl) = &state.control else {
        return (StatusCode::OK, "# aegis metrics unavailable\n").into_response();
    };
    let s = ctrl.stats().await;
    let body = format!(
        concat!(
            "# HELP aegis_calls_total Total MCP tool calls processed\n",
            "# TYPE aegis_calls_total counter\n",
            "aegis_calls_total {}\n",
            "# HELP aegis_calls_allowed_total Total allowed MCP tool calls\n",
            "# TYPE aegis_calls_allowed_total counter\n",
            "aegis_calls_allowed_total {}\n",
            "# HELP aegis_calls_denied_total Total MCP tool calls blocked by policy\n",
            "# TYPE aegis_calls_denied_total counter\n",
            "aegis_calls_denied_total {}\n",
            "# HELP aegis_calls_error_total Total failed MCP tool calls\n",
            "# TYPE aegis_calls_error_total counter\n",
            "aegis_calls_error_total {}\n",
            "# HELP aegis_cache_hits_total Total BLAKE3 cache hits\n",
            "# TYPE aegis_cache_hits_total counter\n",
            "aegis_cache_hits_total {}\n",
            "# HELP aegis_cache_misses_total Total BLAKE3 cache misses\n",
            "# TYPE aegis_cache_misses_total counter\n",
            "aegis_cache_misses_total {}\n",
            "# HELP aegis_redactions_total Total secret/PII items masked\n",
            "# TYPE aegis_redactions_total counter\n",
            "aegis_redactions_total {}\n",
            "# HELP aegis_latency_avg_ms Average tool call latency in milliseconds\n",
            "# TYPE aegis_latency_avg_ms gauge\n",
            "aegis_latency_avg_ms {:.2}\n",
            "# HELP aegis_latency_p95_ms P95 tool call latency in milliseconds\n",
            "# TYPE aegis_latency_p95_ms gauge\n",
            "aegis_latency_p95_ms {}\n",
            "# HELP aegis_active_servers Number of ready upstream MCP servers\n",
            "# TYPE aegis_active_servers gauge\n",
            "aegis_active_servers {}\n",
            "# HELP aegis_total_tools Total aggregated tools exposed\n",
            "# TYPE aegis_total_tools gauge\n",
            "aegis_total_tools {}\n",
        ),
        s.total_calls,
        s.allowed_calls,
        s.denied_calls,
        s.error_calls,
        s.cache_hits,
        s.cache_misses,
        s.total_redactions,
        s.avg_latency_ms,
        s.p95_latency_ms,
        s.active_servers,
        s.total_tools,
    );

    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    resp
}

fn json_response<T: serde::Serialize>(
    status: StatusCode,
    payload: &T,
    session_id: Option<&str>,
) -> Response {
    let body = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp.headers_mut().insert(
        HeaderName::from_static("mcp-protocol-version"),
        HeaderValue::from_static(MCP_PROTOCOL_VERSION),
    );
    if let Some(sid) = session_id {
        if let Ok(hv) = HeaderValue::from_str(sid) {
            resp.headers_mut()
                .insert(HeaderName::from_static("mcp-session-id"), hv);
        }
    }
    resp
}
