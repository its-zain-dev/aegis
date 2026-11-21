use crate::traits::{McpHandler, UpstreamTransport};
use aegis_core::{
    expand_env, expand_tilde, AegisError, JsonRpcError, JsonRpcMessage, JsonRpcNotification,
    JsonRpcRequest, JsonRpcResponse, RequestId, Result, ServerConfig, ERR_INVALID_REQUEST,
    ERR_PARSE,
};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, warn};

type PendingMap = Arc<Mutex<HashMap<RequestId, oneshot::Sender<Result<JsonRpcResponse>>>>>;

/// Manages a child MCP server communicating via newline-delimited JSON-RPC over stdin/stdout.
pub struct StdioUpstream {
    name: String,
    alive: Arc<AtomicBool>,
    next_id: AtomicI64,
    outbound_tx: mpsc::UnboundedSender<String>,
    pending: PendingMap,
    child: Mutex<Option<Child>>,
}

impl StdioUpstream {
    pub async fn spawn(name: impl Into<String>, cfg: &ServerConfig) -> Result<Self> {
        let name = name.into();
        let command_str = cfg.command.as_deref().ok_or_else(|| {
            AegisError::Config(format!("stdio server '{name}' missing 'command'"))
        })?;
        let expanded_cmd = expand_env(command_str);

        let mut cmd = Command::new(&expanded_cmd);
        for arg in &cfg.args {
            cmd.arg(expand_env(arg));
        }
        for (k, v) in &cfg.env {
            cmd.env(k, expand_env(v));
        }
        if let Some(cwd) = &cfg.cwd {
            cmd.current_dir(expand_tilde(cwd));
        }

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| AegisError::Upstream {
            server: name.clone(),
            message: format!("failed to spawn '{expanded_cmd}': {e}"),
        })?;

        let mut child_stdin = child.stdin.take().ok_or_else(|| AegisError::Upstream {
            server: name.clone(),
            message: "failed to capture child stdin".into(),
        })?;
        let child_stdout = child.stdout.take().ok_or_else(|| AegisError::Upstream {
            server: name.clone(),
            message: "failed to capture child stdout".into(),
        })?;
        let child_stderr = child.stderr.take();

        let alive = Arc::new(AtomicBool::new(true));
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<String>();

        // Stdin writer task
        let writer_name = name.clone();
        let writer_alive = Arc::clone(&alive);
        tokio::spawn(async move {
            while let Some(line) = outbound_rx.recv().await {
                if let Err(e) = child_stdin.write_all(line.as_bytes()).await {
                    debug!(server = %writer_name, error = %e, "stdio upstream stdin write failed");
                    writer_alive.store(false, Ordering::SeqCst);
                    break;
                }
                if let Err(e) = child_stdin.write_all(b"\n").await {
                    debug!(server = %writer_name, error = %e, "stdio upstream newline write failed");
                    writer_alive.store(false, Ordering::SeqCst);
                    break;
                }
                let _ = child_stdin.flush().await;
            }
        });

        // Stdout reader task
        let reader_name = name.clone();
        let reader_alive = Arc::clone(&alive);
        let reader_pending = Arc::clone(&pending);
        tokio::spawn(async move {
            let mut lines = BufReader::new(child_stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match JsonRpcMessage::from_json_str(trimmed) {
                    Ok(JsonRpcMessage::Response(resp)) => {
                        if let Some(id) = resp.id.clone() {
                            let tx = {
                                let mut guard = reader_pending.lock().await;
                                guard.remove(&id)
                            };
                            if let Some(tx) = tx {
                                let _ = tx.send(Ok(resp));
                            }
                        }
                    }
                    Ok(JsonRpcMessage::Notification(notif)) => {
                        debug!(server = %reader_name, method = %notif.method, "upstream notification");
                    }
                    Ok(JsonRpcMessage::Request(req)) => {
                        debug!(server = %reader_name, method = %req.method, "ignoring upstream server-initiated request");
                    }
                    Err(e) => {
                        debug!(server = %reader_name, error = %e, line = %trimmed, "ignoring non-JSON-RPC line from upstream stdout");
                    }
                }
            }

            reader_alive.store(false, Ordering::SeqCst);
            let mut guard = reader_pending.lock().await;
            for (_, tx) in guard.drain() {
                let _ = tx.send(Err(AegisError::Upstream {
                    server: reader_name.clone(),
                    message: "stdio upstream closed stdout unexpectedly".into(),
                }));
            }
        });

        // Stderr drain task (routes strictly to tracing stderr, never downstream stdout)
        if let Some(stderr) = child_stderr {
            let err_name = name.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    debug!(server = %err_name, "upstream stderr: {line}");
                }
            });
        }

        Ok(Self {
            name,
            alive,
            next_id: AtomicI64::new(1),
            outbound_tx,
            pending,
            child: Mutex::new(Some(child)),
        })
    }
}

#[async_trait]
impl UpstreamTransport for StdioUpstream {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value> {
        if !self.is_alive() {
            return Err(AegisError::Upstream {
                server: self.name.clone(),
                message: "stdio upstream process is not running".into(),
            });
        }

        let id = RequestId::Number(self.next_id.fetch_add(1, Ordering::SeqCst));
        let req = JsonRpcRequest::new(id.clone(), method, params);
        let payload = serde_json::to_string(&req)?;

        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.pending.lock().await;
            guard.insert(id.clone(), tx);
        }

        if self.outbound_tx.send(payload).is_err() {
            let mut guard = self.pending.lock().await;
            guard.remove(&id);
            self.alive.store(false, Ordering::SeqCst);
            return Err(AegisError::Upstream {
                server: self.name.clone(),
                message: "failed to enqueue message to stdio upstream".into(),
            });
        }

        let resp = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(resp))) => resp,
            Ok(Ok(Err(err))) => return Err(err),
            Ok(Err(_)) => {
                return Err(AegisError::Upstream {
                    server: self.name.clone(),
                    message: "upstream response channel closed".into(),
                });
            }
            Err(_) => {
                let mut guard = self.pending.lock().await;
                guard.remove(&id);
                return Err(AegisError::Timeout {
                    server: self.name.clone(),
                    timeout_secs: timeout.as_secs(),
                });
            }
        };

        if let Some(err) = resp.error {
            return Err(AegisError::Upstream {
                server: self.name.clone(),
                message: format!("[{}] {}", err.code, err.message),
            });
        }

        Ok(resp.result.unwrap_or(Value::Null))
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        if !self.is_alive() {
            return Err(AegisError::Upstream {
                server: self.name.clone(),
                message: "stdio upstream process is not running".into(),
            });
        }
        let notif = JsonRpcNotification::new(method, params);
        let payload = serde_json::to_string(&notif)?;
        self.outbound_tx
            .send(payload)
            .map_err(|_| AegisError::Upstream {
                server: self.name.clone(),
                message: "failed to write notification to stdio upstream".into(),
            })?;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.alive.store(false, Ordering::SeqCst);
        let mut guard = self.child.lock().await;
        if let Some(mut child) = guard.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        Ok(())
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

/// Runs the downstream MCP Stdio server loop over process stdin/stdout.
///
/// Concurrent requests are dispatched on Tokio tasks and responses are written
/// atomically line-by-line to stdout via a dedicated writer task.
pub async fn serve_stdio_downstream(handler: Arc<dyn McpHandler>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();

    let writer_handle = tokio::spawn(async move {
        while let Some(line) = out_rx.recv().await {
            if let Err(e) = stdout.write_all(line.as_bytes()).await {
                warn!(error = %e, "downstream stdout write error");
                break;
            }
            if let Err(e) = stdout.write_all(b"\n").await {
                warn!(error = %e, "downstream stdout newline error");
                break;
            }
            if let Err(e) = stdout.flush().await {
                warn!(error = %e, "downstream stdout flush error");
                break;
            }
        }
    });

    let mut lines = BufReader::new(stdin).lines();
    let mut in_flight = tokio::task::JoinSet::new();

    while let Some(line) = lines.next_line().await? {
        while in_flight.try_join_next().is_some() {}
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parsed: std::result::Result<Value, _> = serde_json::from_str(trimmed);
        let val = match parsed {
            Ok(v) => v,
            Err(e) => {
                let err_resp = JsonRpcResponse::err(
                    None,
                    JsonRpcError::new(ERR_PARSE, format!("JSON parse error: {e}")),
                );
                if let Ok(s) = serde_json::to_string(&err_resp) {
                    let _ = out_tx.send(s);
                }
                continue;
            }
        };

        let handler = Arc::clone(&handler);
        let out_tx = out_tx.clone();
        in_flight.spawn(async move {
            match val {
                Value::Array(batch) => {
                    if batch.is_empty() {
                        let err_resp = JsonRpcResponse::err(
                            None,
                            JsonRpcError::new(ERR_INVALID_REQUEST, "empty JSON-RPC batch"),
                        );
                        if let Ok(s) = serde_json::to_string(&err_resp) {
                            let _ = out_tx.send(s);
                        }
                        return;
                    }
                    let mut responses = Vec::new();
                    for item in batch {
                        if let Some(resp) = dispatch_single_value(&handler, item).await {
                            responses.push(resp);
                        }
                    }
                    if !responses.is_empty() {
                        if let Ok(s) = serde_json::to_string(&responses) {
                            let _ = out_tx.send(s);
                        }
                    }
                }
                single => {
                    if let Some(resp) = dispatch_single_value(&handler, single).await {
                        if let Ok(s) = serde_json::to_string(&resp) {
                            let _ = out_tx.send(s);
                        }
                    }
                }
            }
        });
    }

    while in_flight.join_next().await.is_some() {}
    drop(out_tx);
    let _ = writer_handle.await;
    Ok(())
}

async fn dispatch_single_value(
    handler: &Arc<dyn McpHandler>,
    value: Value,
) -> Option<JsonRpcResponse> {
    match JsonRpcMessage::from_value(value) {
        Ok(JsonRpcMessage::Request(req)) => Some(handler.handle_request(req).await),
        Ok(JsonRpcMessage::Notification(notif)) => {
            handler.handle_notification(notif).await;
            None
        }
        Ok(JsonRpcMessage::Response(_)) => None,
        Err(e) => Some(JsonRpcResponse::err(
            None,
            JsonRpcError::new(ERR_INVALID_REQUEST, format!("invalid JSON-RPC message: {e}")),
        )),
    }
}
