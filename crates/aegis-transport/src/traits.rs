use aegis_core::{
    AegisError, ClientCapabilities, GatewayStats, Implementation, InitializeParams,
    InitializeResult, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, Result, ServerHealth,
    TelemetryEvent, MCP_PROTOCOL_VERSION,
};
use async_trait::async_trait;
use serde_json::Value;
use std::time::Duration;
use tokio::sync::broadcast;

/// Downstream JSON-RPC / MCP request handler implemented by the Aegis gateway or replay mock server.
#[async_trait]
pub trait McpHandler: Send + Sync + 'static {
    async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse;
    async fn handle_notification(&self, notification: JsonRpcNotification);
}

/// Live control & observability interface exposed over local IPC and HTTP `/health` & `/metrics`.
#[async_trait]
pub trait ControlHandler: Send + Sync + 'static {
    async fn stats(&self) -> GatewayStats;
    async fn servers(&self) -> Vec<ServerHealth>;
    async fn reload(&self) -> Result<String>;
    async fn clear_cache(&self) -> Result<usize>;
    fn subscribe_events(&self) -> broadcast::Receiver<TelemetryEvent>;
}

/// Universal upstream MCP transport abstraction (Stdio, Streamable HTTP, Legacy SSE).
#[async_trait]
pub trait UpstreamTransport: Send + Sync {
    async fn request(&self, method: &str, params: Option<Value>, timeout: Duration)
        -> Result<Value>;
    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()>;
    async fn close(&self) -> Result<()>;
    fn is_alive(&self) -> bool;
}

/// Runs the standard MCP `initialize` + `notifications/initialized` handshake on an upstream transport.
pub async fn initialize_upstream(
    transport: &dyn UpstreamTransport,
    server_name: &str,
    timeout: Duration,
) -> Result<InitializeResult> {
    let params = InitializeParams {
        protocol_version: MCP_PROTOCOL_VERSION.to_string(),
        capabilities: ClientCapabilities::default(),
        client_info: Implementation {
            name: "aegis".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    };
    let params_val = serde_json::to_value(params)?;
    let result_val = transport
        .request("initialize", Some(params_val), timeout)
        .await?;

    let init: InitializeResult = serde_json::from_value(result_val).map_err(|e| {
        AegisError::Upstream {
            server: server_name.to_string(),
            message: format!("invalid initialize response: {e}"),
        }
    })?;

    // Best-effort initialized notification per MCP spec
    let _ = transport.notify("notifications/initialized", None).await;
    Ok(init)
}
