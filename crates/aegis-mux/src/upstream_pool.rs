use aegis_core::{
    ListPromptsResult, ListResourcesResult, ListToolsResult, Prompt, Resource, Result,
    ServerCapabilities, ServerConfig, ServerHealth, ServerState, Tool, TransportKind,
};
use aegis_transport::{
    initialize_upstream, LegacySseUpstream, StdioUpstream, StreamableHttpUpstream,
    UpstreamTransport,
};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Factory abstraction for constructing upstream transports (enables mock injection in tests).
#[async_trait]
pub trait UpstreamFactory: Send + Sync {
    async fn create(
        &self,
        name: &str,
        config: &ServerConfig,
        connect_timeout: Duration,
    ) -> Result<Arc<dyn UpstreamTransport>>;
}

/// Default production upstream factory supporting Stdio, Streamable HTTP, and Legacy SSE.
pub struct DefaultUpstreamFactory;

#[async_trait]
impl UpstreamFactory for DefaultUpstreamFactory {
    async fn create(
        &self,
        name: &str,
        config: &ServerConfig,
        connect_timeout: Duration,
    ) -> Result<Arc<dyn UpstreamTransport>> {
        match config.transport {
            TransportKind::Stdio => {
                let t = StdioUpstream::spawn(name, config).await?;
                Ok(Arc::new(t))
            }
            TransportKind::Http => {
                let t = StreamableHttpUpstream::new(name, config)?;
                Ok(Arc::new(t))
            }
            TransportKind::Sse => {
                let t = LegacySseUpstream::connect(name, config, connect_timeout).await?;
                Ok(Arc::new(t))
            }
        }
    }
}

struct UpstreamRuntime {
    transport: Option<Arc<dyn UpstreamTransport>>,
    state: ServerState,
    capabilities: Option<ServerCapabilities>,
    tools: Vec<Tool>,
    resources: Vec<Resource>,
    prompts: Vec<Prompt>,
    total_calls: u64,
    error_count: u64,
    restart_count: u32,
    last_error: Option<String>,
}

pub struct UpstreamSlot {
    pub name: String,
    pub prefix: String,
    pub config: ServerConfig,
    runtime: Mutex<UpstreamRuntime>,
}

impl UpstreamSlot {
    pub fn new(name: String, config: ServerConfig) -> Self {
        let prefix = config.prefix.clone().unwrap_or_else(|| name.clone());
        Self {
            name,
            prefix,
            config,
            runtime: Mutex::new(UpstreamRuntime {
                transport: None,
                state: ServerState::Idle,
                capabilities: None,
                tools: Vec::new(),
                resources: Vec::new(),
                prompts: Vec::new(),
                total_calls: 0,
                error_count: 0,
                restart_count: 0,
                last_error: None,
            }),
        }
    }

    pub fn timeout(&self, default_secs: u64) -> Duration {
        Duration::from_secs(self.config.timeout_secs.unwrap_or(default_secs))
    }

    /// Ensures the upstream is connected and initialized, reconnecting if the transport died.
    pub async fn ensure_connected(
        &self,
        factory: &dyn UpstreamFactory,
        default_timeout_secs: u64,
    ) -> Result<Arc<dyn UpstreamTransport>> {
        let timeout = self.timeout(default_timeout_secs);
        let mut rt = self.runtime.lock().await;

        if let Some(t) = &rt.transport {
            if t.is_alive() {
                return Ok(Arc::clone(t));
            }
            // Previous transport died
            let _ = t.close().await;
            rt.transport = None;
            rt.restart_count += 1;
        }

        rt.state = ServerState::Connecting;
        match factory.create(&self.name, &self.config, timeout).await {
            Ok(transport) => match initialize_upstream(transport.as_ref(), &self.name, timeout).await
            {
                Ok(init) => {
                    info!(
                        server = %self.name,
                        upstream_name = %init.server_info.name,
                        upstream_version = %init.server_info.version,
                        transport = %self.config.transport,
                        "upstream MCP server ready"
                    );
                    rt.capabilities = Some(init.capabilities);
                    rt.state = ServerState::Ready;
                    rt.last_error = None;
                    rt.transport = Some(Arc::clone(&transport));
                    Ok(transport)
                }
                Err(e) => {
                    let _ = transport.close().await;
                    rt.state = ServerState::Degraded;
                    rt.error_count += 1;
                    rt.last_error = Some(e.to_string());
                    Err(e)
                }
            },
            Err(e) => {
                rt.state = ServerState::Degraded;
                rt.error_count += 1;
                rt.last_error = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Refreshes the tool, resource, and prompt catalogs from the upstream server.
    pub async fn refresh_catalog(
        &self,
        factory: &dyn UpstreamFactory,
        default_timeout_secs: u64,
    ) -> Result<Vec<Tool>> {
        let timeout = self.timeout(default_timeout_secs);
        let transport = self.ensure_connected(factory, default_timeout_secs).await?;

        let tools_val = transport
            .request("tools/list", Some(json!({})), timeout)
            .await?;
        let tools_res: ListToolsResult = serde_json::from_value(tools_val)?;

        let caps = {
            let rt = self.runtime.lock().await;
            rt.capabilities.clone()
        };

        let mut resources = Vec::new();
        if caps.as_ref().and_then(|c| c.resources.as_ref()).is_some() {
            if let Ok(val) = transport
                .request("resources/list", Some(json!({})), timeout)
                .await
            {
                if let Ok(res) = serde_json::from_value::<ListResourcesResult>(val) {
                    resources = res.resources;
                }
            }
        }

        let mut prompts = Vec::new();
        if caps.as_ref().and_then(|c| c.prompts.as_ref()).is_some() {
            if let Ok(val) = transport
                .request("prompts/list", Some(json!({})), timeout)
                .await
            {
                if let Ok(res) = serde_json::from_value::<ListPromptsResult>(val) {
                    prompts = res.prompts;
                }
            }
        }

        let mut rt = self.runtime.lock().await;
        rt.tools = tools_res.tools.clone();
        rt.resources = resources;
        rt.prompts = prompts;
        debug!(server = %self.name, tools = rt.tools.len(), "refreshed upstream catalog");
        Ok(tools_res.tools)
    }

    /// Sends an arbitrary JSON-RPC request to this upstream with automatic crash recovery retry.
    pub async fn request_with_retry(
        &self,
        factory: &dyn UpstreamFactory,
        default_timeout_secs: u64,
        max_restarts: u32,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value> {
        let timeout = self.timeout(default_timeout_secs);
        let mut attempt = 0u32;

        loop {
            let transport = self.ensure_connected(factory, default_timeout_secs).await?;
            match transport.request(method, params.clone(), timeout).await {
                Ok(val) => {
                    let mut rt = self.runtime.lock().await;
                    rt.total_calls += 1;
                    rt.state = ServerState::Ready;
                    rt.last_error = None;
                    return Ok(val);
                }
                Err(err) => {
                    let can_retry = !transport.is_alive() && attempt < max_restarts;
                    {
                        let mut rt = self.runtime.lock().await;
                        rt.error_count += 1;
                        rt.last_error = Some(err.to_string());
                        if !transport.is_alive() {
                            rt.state = ServerState::Degraded;
                            rt.transport = None;
                        }
                    }
                    if can_retry {
                        attempt += 1;
                        warn!(
                            server = %self.name,
                            attempt,
                            error = %err,
                            "upstream transport died; restarting and retrying"
                        );
                        continue;
                    }
                    return Err(err);
                }
            }
        }
    }

    pub async fn cached_tools(&self) -> Vec<Tool> {
        self.runtime.lock().await.tools.clone()
    }

    pub async fn cached_resources(&self) -> Vec<Resource> {
        self.runtime.lock().await.resources.clone()
    }

    pub async fn cached_prompts(&self) -> Vec<Prompt> {
        self.runtime.lock().await.prompts.clone()
    }

    pub async fn health(&self) -> ServerHealth {
        let rt = self.runtime.lock().await;
        ServerHealth {
            name: self.name.clone(),
            transport: self.config.transport,
            state: rt.state,
            tool_count: rt.tools.len(),
            total_calls: rt.total_calls,
            error_count: rt.error_count,
            restart_count: rt.restart_count,
            last_error: rt.last_error.clone(),
        }
    }

    pub async fn close(&self) {
        let mut rt = self.runtime.lock().await;
        if let Some(t) = rt.transport.take() {
            let _ = t.close().await;
        }
        rt.state = ServerState::Stopped;
    }
}
