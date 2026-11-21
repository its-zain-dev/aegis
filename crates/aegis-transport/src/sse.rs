use crate::traits::UpstreamTransport;
use aegis_core::{
    expand_env, AegisError, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    RequestId, Result, ServerConfig,
};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::debug;

type PendingMap = Arc<Mutex<HashMap<RequestId, oneshot::Sender<Result<JsonRpcResponse>>>>>;

/// Bridges legacy MCP 2024-11-05 HTTP+SSE upstream servers (`GET /sse` + `POST <endpoint>`)
/// so modern MCP 2025-03-26 clients like Antigravity CLI can consume them seamlessly.
pub struct LegacySseUpstream {
    name: String,
    post_url: String,
    headers: BTreeMap<String, String>,
    client: reqwest::Client,
    alive: Arc<AtomicBool>,
    next_id: AtomicI64,
    pending: PendingMap,
    reader_task: Mutex<Option<JoinHandle<()>>>,
}

impl LegacySseUpstream {
    pub async fn connect(
        name: impl Into<String>,
        cfg: &ServerConfig,
        connect_timeout: Duration,
    ) -> Result<Self> {
        let name = name.into();
        let sse_url = cfg
            .url
            .as_deref()
            .map(expand_env)
            .filter(|u| !u.is_empty())
            .ok_or_else(|| AegisError::Config(format!("sse server '{name}' missing 'url'")))?;

        let base_url = reqwest::Url::parse(&sse_url).map_err(|e| {
            AegisError::Config(format!("invalid SSE url '{sse_url}' for '{name}': {e}"))
        })?;

        let headers: BTreeMap<String, String> = cfg
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), expand_env(v)))
            .collect();

        let client = reqwest::Client::builder()
            .user_agent(format!("aegis/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| AegisError::Transport(format!("failed to build SSE HTTP client: {e}")))?;

        let mut req = client
            .get(&sse_url)
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache");
        for (k, v) in &headers {
            if !v.is_empty() {
                req = req.header(k.as_str(), v.as_str());
            }
        }

        let resp = tokio::time::timeout(connect_timeout, req.send())
            .await
            .map_err(|_| AegisError::Timeout {
                server: name.clone(),
                timeout_secs: connect_timeout.as_secs(),
            })?
            .map_err(|e| AegisError::Upstream {
                server: name.clone(),
                message: format!("failed to open legacy SSE stream: {e}"),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AegisError::Upstream {
                server: name.clone(),
                message: format!("legacy SSE endpoint returned HTTP {status}: {body}"),
            });
        }

        let alive = Arc::new(AtomicBool::new(true));
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let (endpoint_tx, endpoint_rx) = oneshot::channel::<Result<String>>();

        let reader_name = name.clone();
        let reader_alive = Arc::clone(&alive);
        let reader_pending = Arc::clone(&pending);
        let reader_task = tokio::spawn(async move {
            let mut endpoint_tx = Some(endpoint_tx);
            let mut stream = resp.bytes_stream();
            let mut buf = String::new();
            let mut current_event = String::new();
            let mut data_lines: Vec<String> = Vec::new();

            while let Some(chunk) = stream.next().await {
                let bytes = match chunk {
                    Ok(b) => b,
                    Err(e) => {
                        debug!(server = %reader_name, error = %e, "legacy SSE stream error");
                        break;
                    }
                };
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
                            let event_name = if current_event.is_empty() {
                                "message".to_string()
                            } else {
                                std::mem::take(&mut current_event)
                            };
                            data_lines.clear();

                            if event_name == "endpoint" {
                                if let Some(tx) = endpoint_tx.take() {
                                    let resolved = resolve_endpoint_url(&base_url, payload.trim());
                                    let _ = tx.send(resolved);
                                }
                            } else if event_name == "message" {
                                match JsonRpcMessage::from_json_str(&payload) {
                                    Ok(JsonRpcMessage::Response(rpc_resp)) => {
                                        if let Some(id) = rpc_resp.id.clone() {
                                            let tx = {
                                                let mut guard = reader_pending.lock().await;
                                                guard.remove(&id)
                                            };
                                            if let Some(tx) = tx {
                                                let _ = tx.send(Ok(rpc_resp));
                                            }
                                        }
                                    }
                                    Ok(JsonRpcMessage::Notification(notif)) => {
                                        debug!(server = %reader_name, method = %notif.method, "legacy SSE notification");
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            current_event.clear();
                        }
                    } else if let Some(rest) = line.strip_prefix("event:") {
                        current_event = rest.trim().to_string();
                    } else if let Some(rest) = line.strip_prefix("data:") {
                        data_lines.push(rest.trim_start().to_string());
                    }
                }
            }

            if let Some(tx) = endpoint_tx.take() {
                let _ = tx.send(Err(AegisError::Upstream {
                    server: reader_name.clone(),
                    message: "legacy SSE stream closed before sending endpoint event".into(),
                }));
            }

            reader_alive.store(false, Ordering::SeqCst);
            let mut guard = reader_pending.lock().await;
            for (_, tx) in guard.drain() {
                let _ = tx.send(Err(AegisError::Upstream {
                    server: reader_name.clone(),
                    message: "legacy SSE stream disconnected".into(),
                }));
            }
        });

        let post_url = match tokio::time::timeout(connect_timeout, endpoint_rx).await {
            Ok(Ok(Ok(url))) => url,
            Ok(Ok(Err(e))) => {
                reader_task.abort();
                return Err(e);
            }
            Ok(Err(_)) => {
                reader_task.abort();
                return Err(AegisError::Upstream {
                    server: name.clone(),
                    message: "SSE endpoint handshake channel closed".into(),
                });
            }
            Err(_) => {
                reader_task.abort();
                return Err(AegisError::Timeout {
                    server: name.clone(),
                    timeout_secs: connect_timeout.as_secs(),
                });
            }
        };

        debug!(server = %name, %post_url, "legacy SSE bridge connected");

        Ok(Self {
            name,
            post_url,
            headers,
            client,
            alive,
            next_id: AtomicI64::new(1),
            pending,
            reader_task: Mutex::new(Some(reader_task)),
        })
    }
}

fn resolve_endpoint_url(base: &reqwest::Url, endpoint: &str) -> Result<String> {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        return Ok(endpoint.to_string());
    }
    base.join(endpoint)
        .map(|u| u.to_string())
        .map_err(|e| AegisError::Transport(format!("failed to resolve SSE endpoint '{endpoint}': {e}")))
}

#[async_trait]
impl UpstreamTransport for LegacySseUpstream {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value> {
        if !self.is_alive() {
            return Err(AegisError::Upstream {
                server: self.name.clone(),
                message: "legacy SSE stream is disconnected".into(),
            });
        }

        let id = RequestId::Number(self.next_id.fetch_add(1, Ordering::SeqCst));
        let rpc_req = JsonRpcRequest::new(id.clone(), method, params);

        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.pending.lock().await;
            guard.insert(id.clone(), tx);
        }

        let mut req = self
            .client
            .post(&self.post_url)
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .json(&rpc_req);
        for (k, v) in &self.headers {
            if !v.is_empty() {
                req = req.header(k.as_str(), v.as_str());
            }
        }

        let http_resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                self.pending.lock().await.remove(&id);
                return Err(AegisError::Upstream {
                    server: self.name.clone(),
                    message: format!("legacy SSE POST failed: {e}"),
                });
            }
        };

        let status = http_resp.status();
        if !status.is_success() {
            self.pending.lock().await.remove(&id);
            let body = http_resp.text().await.unwrap_or_default();
            return Err(AegisError::Upstream {
                server: self.name.clone(),
                message: format!("legacy SSE POST returned HTTP {status}: {body}"),
            });
        }

        // Some legacy servers reply inline on 200 OK instead of over the SSE stream
        let content_type = http_resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if status == reqwest::StatusCode::OK && content_type.contains("application/json") {
            let text = http_resp.text().await.unwrap_or_default();
            if let Ok(JsonRpcMessage::Response(resp)) = JsonRpcMessage::from_json_str(&text) {
                self.pending.lock().await.remove(&id);
                if let Some(err) = resp.error {
                    return Err(AegisError::Upstream {
                        server: self.name.clone(),
                        message: format!("[{}] {}", err.code, err.message),
                    });
                }
                return Ok(resp.result.unwrap_or(Value::Null));
            }
        }

        let rpc_resp = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(r))) => r,
            Ok(Ok(Err(e))) => return Err(e),
            Ok(Err(_)) => {
                return Err(AegisError::Upstream {
                    server: self.name.clone(),
                    message: "legacy SSE response channel closed".into(),
                });
            }
            Err(_) => {
                self.pending.lock().await.remove(&id);
                return Err(AegisError::Timeout {
                    server: self.name.clone(),
                    timeout_secs: timeout.as_secs(),
                });
            }
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
        let mut req = self
            .client
            .post(&self.post_url)
            .timeout(Duration::from_secs(15))
            .header("Content-Type", "application/json")
            .json(&notif);
        for (k, v) in &self.headers {
            if !v.is_empty() {
                req = req.header(k.as_str(), v.as_str());
            }
        }
        let _ = req.send().await;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.alive.store(false, Ordering::SeqCst);
        if let Some(handle) = self.reader_task.lock().await.take() {
            handle.abort();
        }
        Ok(())
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}
