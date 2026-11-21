pub mod metrics;
pub mod upstream_pool;

pub use metrics::MetricsTracker;
pub use upstream_pool::{DefaultUpstreamFactory, UpstreamFactory, UpstreamSlot};

use aegis_core::{
    AegisConfig, AegisError, CallOutcome, CallToolParams, CallToolResult, GatewayStats,
    GetPromptParams, Implementation, InitializeParams, InitializeResult, JsonRpcError,
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, ListPromptsResult, ListResourcesResult,
    ListToolsResult, PromptsCapability, ReadResourceParams, ResourcesCapability, Result,
    ServerCapabilities, ServerHealth, ServerState, TelemetryEvent, Tool, ToolCallEvent,
    ToolsCapability, ERR_INTERNAL, ERR_INVALID_PARAMS, ERR_METHOD_NOT_FOUND, ERR_POLICY_DENIED,
    ERR_UPSTREAM_TIMEOUT, ERR_UPSTREAM_UNAVAILABLE, MCP_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
};
use aegis_policy::{PolicyDecision, PolicyEngine};
use aegis_redact::{RedactionReport, SecretRedactor};
use aegis_store::{ToolCache, TraceRecord, TraceWal};
use aegis_transport::{ControlHandler, McpHandler};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};
use uuid::Uuid;

const PREVIEW_MAX_CHARS: usize = 400;

/// Core Aegis MCP Gateway: multiplexes heterogeneous upstreams, enforces tool-level firewall
/// policies, redacts secrets/PII, serves BLAKE3 cached responses, records binary WAL traces,
/// and broadcasts live telemetry to the TUI & IPC clients.
pub struct Gateway {
    config: AegisConfig,
    policy: PolicyEngine,
    redactor: SecretRedactor,
    cache: ToolCache,
    wal: Option<TraceWal>,
    metrics: MetricsTracker,
    factory: Arc<dyn UpstreamFactory>,
    upstreams: BTreeMap<String, Arc<UpstreamSlot>>,
    prefix_to_server: HashMap<String, String>,
    resource_routes: RwLock<HashMap<String, (String, String)>>,
    events_tx: broadcast::Sender<TelemetryEvent>,
}

impl Gateway {
    pub fn new(
        config: AegisConfig,
        profile: Option<&str>,
        mode: impl Into<String>,
    ) -> Result<Self> {
        Self::with_factory(config, profile, mode, Arc::new(DefaultUpstreamFactory))
    }

    pub fn with_factory(
        config: AegisConfig,
        profile: Option<&str>,
        mode: impl Into<String>,
        factory: Arc<dyn UpstreamFactory>,
    ) -> Result<Self> {
        config.validate()?;
        let policy = PolicyEngine::from_config(&config, profile)?;
        let redactor = SecretRedactor::from_config(&config.redaction)?;
        let cache = ToolCache::from_config(&config.cache)?;
        let wal = if config.trace.enabled {
            Some(TraceWal::open(
                config.trace.resolved_path(),
                config.trace.compress,
            )?)
        } else {
            None
        };

        let mut upstreams = BTreeMap::new();
        let mut prefix_to_server = HashMap::new();
        for (name, server_cfg) in &config.servers {
            if !server_cfg.enabled {
                continue;
            }
            let slot = Arc::new(UpstreamSlot::new(name.clone(), server_cfg.clone()));
            prefix_to_server.insert(slot.prefix.clone(), name.clone());
            upstreams.insert(name.clone(), slot);
        }

        let (events_tx, _) = broadcast::channel(512);

        Ok(Self {
            config,
            policy,
            redactor,
            cache,
            wal,
            metrics: MetricsTracker::new(mode),
            factory,
            upstreams,
            prefix_to_server,
            resource_routes: RwLock::new(HashMap::new()),
            events_tx,
        })
    }

    /// Connects all eager (`lazy = false`) upstreams concurrently at gateway startup.
    pub async fn startup(&self) {
        let mut tasks = Vec::new();
        for slot in self.upstreams.values() {
            if !slot.config.lazy {
                let slot = Arc::clone(slot);
                let factory = Arc::clone(&self.factory);
                let timeout = self.config.gateway.request_timeout_secs;
                let tx = self.events_tx.clone();
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = slot.refresh_catalog(factory.as_ref(), timeout).await {
                        warn!(server = %slot.name, error = %e, "eager upstream startup failed");
                    }
                    let _ = tx.send(TelemetryEvent::ServerStatus(slot.health().await));
                }));
            }
        }
        for task in tasks {
            let _ = task.await;
        }
    }

    /// Gracefully shuts down all active upstream connections / child processes.
    pub async fn shutdown(&self) {
        for slot in self.upstreams.values() {
            slot.close().await;
        }
    }

    pub fn config(&self) -> &AegisConfig {
        &self.config
    }

    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    fn namespace_tool(&self, prefix: &str, raw_tool: &str) -> String {
        format!("{prefix}{}{raw_tool}", self.config.gateway.namespace_separator)
    }

    fn parse_namespaced(&self, namespaced: &str) -> Option<(&Arc<UpstreamSlot>, String)> {
        let sep = &self.config.gateway.namespace_separator;
        let (prefix, raw_name) = namespaced.split_once(sep)?;
        if raw_name.is_empty() {
            return None;
        }
        let server_name = self.prefix_to_server.get(prefix)?;
        let slot = self.upstreams.get(server_name)?;
        Some((slot, raw_name.to_string()))
    }

    async fn handle_initialize(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let negotiated = req
            .params
            .as_ref()
            .and_then(|p| serde_json::from_value::<InitializeParams>(p.clone()).ok())
            .map(|params| {
                if SUPPORTED_PROTOCOL_VERSIONS.contains(&params.protocol_version.as_str()) {
                    params.protocol_version
                } else {
                    MCP_PROTOCOL_VERSION.to_string()
                }
            })
            .unwrap_or_else(|| MCP_PROTOCOL_VERSION.to_string());

        let result = InitializeResult {
            protocol_version: negotiated,
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(true),
                }),
                resources: Some(ResourcesCapability {
                    subscribe: Some(false),
                    list_changed: Some(false),
                }),
                prompts: Some(PromptsCapability {
                    list_changed: Some(false),
                }),
                extra: serde_json::Map::new(),
            },
            server_info: Implementation {
                name: self.config.gateway.name.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(format!(
                "Aegis MCP Gateway & Firewall v{}: tools are namespaced as '<server>{}<tool>'.",
                env!("CARGO_PKG_VERSION"),
                self.config.gateway.namespace_separator
            )),
        };

        match serde_json::to_value(result) {
            Ok(v) => JsonRpcResponse::ok(req.id, v),
            Err(e) => JsonRpcResponse::err(
                Some(req.id),
                JsonRpcError::new(ERR_INTERNAL, format!("failed to serialize initialize: {e}")),
            ),
        }
    }

    async fn handle_tools_list(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let mut tasks = Vec::new();
        for slot in self.upstreams.values() {
            let slot = Arc::clone(slot);
            let factory = Arc::clone(&self.factory);
            let timeout = self.config.gateway.request_timeout_secs;
            let tx = self.events_tx.clone();
            tasks.push(tokio::spawn(async move {
                let existing = slot.cached_tools().await;
                let tools = if !existing.is_empty() && slot.health().await.state == ServerState::Ready
                {
                    existing
                } else {
                    match slot.refresh_catalog(factory.as_ref(), timeout).await {
                        Ok(t) => t,
                        Err(e) => {
                            warn!(server = %slot.name, error = %e, "upstream unavailable during tools/list");
                            Vec::new()
                        }
                    }
                };
                let _ = tx.send(TelemetryEvent::ServerStatus(slot.health().await));
                (slot.name.clone(), slot.prefix.clone(), tools)
            }));
        }

        let mut aggregated: Vec<Tool> = Vec::new();
        for task in tasks {
            if let Ok((server_name, prefix, tools)) = task.await {
                for mut tool in tools {
                    let raw_name = tool.name.clone();
                    let namespaced = self.namespace_tool(&prefix, &raw_name);
                    if self.config.gateway.hide_denied_tools
                        && !self.policy.is_allowed(&server_name, &raw_name, &namespaced)
                    {
                        debug!(tool = %namespaced, "hiding policy-denied tool from tools/list");
                        continue;
                    }
                    tool.name = namespaced;
                    aggregated.push(tool);
                }
            }
        }

        aggregated.sort_by(|a, b| a.name.cmp(&b.name));
        let res = ListToolsResult {
            tools: aggregated,
            next_cursor: None,
        };
        match serde_json::to_value(res) {
            Ok(v) => JsonRpcResponse::ok(req.id, v),
            Err(e) => JsonRpcResponse::err(
                Some(req.id),
                JsonRpcError::new(ERR_INTERNAL, format!("failed to serialize tools/list: {e}")),
            ),
        }
    }

    async fn handle_tools_call(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let started = Instant::now();
        let call_id = Uuid::new_v4().to_string();

        let params: CallToolParams = match req
            .params
            .clone()
            .ok_or_else(|| "missing params".to_string())
            .and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string()))
        {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::err(
                    Some(req.id),
                    JsonRpcError::new(ERR_INVALID_PARAMS, format!("invalid tools/call params: {e}")),
                );
            }
        };

        let namespaced_tool = params.name.clone();
        let Some((slot, raw_tool)) = self.parse_namespaced(&namespaced_tool) else {
            return JsonRpcResponse::err(
                Some(req.id),
                JsonRpcError::new(
                    ERR_INVALID_PARAMS,
                    format!(
                        "unknown tool or invalid namespace '{}' (expected '<server>{}<tool>')",
                        namespaced_tool, self.config.gateway.namespace_separator
                    ),
                ),
            );
        };
        let server_name = slot.name.clone();

        // 1. Policy Firewall Evaluation
        let decision = self
            .policy
            .evaluate(&server_name, &raw_tool, &namespaced_tool);
        let matched_rule = match &decision {
            PolicyDecision::Allow { matched_rule } => matched_rule.clone(),
            PolicyDecision::Deny {
                matched_rule,
                reason,
            } => {
                let duration_ms = started.elapsed().as_millis() as u64;
                let msg = format!("Tool '{namespaced_tool}' denied by Aegis policy: {reason}");
                self.record_and_emit(
                    call_id,
                    server_name.clone(),
                    raw_tool,
                    namespaced_tool.clone(),
                    params.arguments,
                    CallOutcome::Denied,
                    None,
                    Some(msg.clone()),
                    duration_ms,
                    false,
                    false,
                    RedactionReport::default(),
                    Some(matched_rule.clone()),
                )
                .await;

                return JsonRpcResponse::err(
                    Some(req.id),
                    JsonRpcError::with_data(
                        ERR_POLICY_DENIED,
                        msg,
                        json!({
                            "server": server_name,
                            "tool": namespaced_tool,
                            "rule": matched_rule,
                            "reason": reason,
                        }),
                    ),
                );
            }
        };

        // 2. Optional Input Redaction
        let mut effective_args = params.arguments.clone();
        let mut redaction_report = RedactionReport::default();
        if self.redactor.redact_inputs_enabled() {
            if let Some(ref mut args_val) = effective_args {
                redaction_report.merge(self.redactor.redact_value(args_val));
            }
        }

        // 3. BLAKE3 Content-Addressed Cache Lookup
        let cacheable = self
            .cache
            .is_cacheable(&server_name, &raw_tool, &namespaced_tool);
        if cacheable {
            if let Some(cached_result) = self.cache.get(
                &server_name,
                &raw_tool,
                &namespaced_tool,
                effective_args.as_ref(),
            ) {
                let duration_ms = started.elapsed().as_millis() as u64;
                let resp_val = serde_json::to_value(&cached_result).unwrap_or(Value::Null);
                self.record_and_emit(
                    call_id,
                    server_name,
                    raw_tool,
                    namespaced_tool,
                    effective_args,
                    CallOutcome::Cached,
                    Some(cached_result),
                    None,
                    duration_ms,
                    true,
                    true,
                    redaction_report,
                    Some(matched_rule),
                )
                .await;
                return JsonRpcResponse::ok(req.id, resp_val);
            }
        }

        // 4. Upstream Dispatch (with automatic crash recovery)
        let upstream_params = json!({
            "name": raw_tool,
            "arguments": effective_args.clone().unwrap_or_else(|| json!({})),
        });

        let upstream_res = slot
            .request_with_retry(
                self.factory.as_ref(),
                self.config.gateway.request_timeout_secs,
                self.config.gateway.max_upstream_restarts,
                "tools/call",
                Some(upstream_params),
            )
            .await;

        let _ = self
            .events_tx
            .send(TelemetryEvent::ServerStatus(slot.health().await));

        let mut raw_result_val = match upstream_res {
            Ok(v) => v,
            Err(err) => {
                let duration_ms = started.elapsed().as_millis() as u64;
                let code = match &err {
                    AegisError::Timeout { .. } => ERR_UPSTREAM_TIMEOUT,
                    _ => ERR_UPSTREAM_UNAVAILABLE,
                };
                let msg = err.to_string();
                self.record_and_emit(
                    call_id,
                    server_name,
                    raw_tool,
                    namespaced_tool,
                    effective_args,
                    CallOutcome::Error,
                    None,
                    Some(msg.clone()),
                    duration_ms,
                    cacheable,
                    false,
                    redaction_report,
                    Some(matched_rule),
                )
                .await;
                return JsonRpcResponse::err(Some(req.id), JsonRpcError::new(code, msg));
            }
        };

        // 5. Output Secret & PII Redaction
        if self.redactor.redact_outputs_enabled() {
            let out_report = self.redactor.redact_value(&mut raw_result_val);
            redaction_report.merge(out_report);
        }

        let parsed_result: CallToolResult = serde_json::from_value(raw_result_val.clone())
            .unwrap_or_else(|_| CallToolResult::text(raw_result_val.to_string()));

        // 6. Store Redacted Result in BLAKE3 Cache
        if cacheable {
            if let Err(e) = self.cache.put(
                &server_name,
                &raw_tool,
                &namespaced_tool,
                effective_args.as_ref(),
                &parsed_result,
            ) {
                warn!(error = %e, "failed to store response in BLAKE3 cache");
            }
        }

        let duration_ms = started.elapsed().as_millis() as u64;
        self.record_and_emit(
            call_id,
            server_name,
            raw_tool,
            namespaced_tool,
            effective_args,
            CallOutcome::Allowed,
            Some(parsed_result),
            None,
            duration_ms,
            cacheable,
            false,
            redaction_report,
            Some(matched_rule),
        )
        .await;

        JsonRpcResponse::ok(req.id, raw_result_val)
    }

    async fn handle_resources_list(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let mut all_resources = Vec::new();
        let mut route_map = self.resource_routes.write().await;

        for slot in self.upstreams.values() {
            if slot.health().await.state != ServerState::Ready {
                let _ = slot
                    .refresh_catalog(
                        self.factory.as_ref(),
                        self.config.gateway.request_timeout_secs,
                    )
                    .await;
            }
            for mut res in slot.cached_resources().await {
                let original_uri = res.uri.clone();
                let exposed_uri = if route_map
                    .get(&original_uri)
                    .is_some_and(|(existing_srv, _)| existing_srv != &slot.name)
                {
                    format!("aegis://{}/{}", slot.prefix, original_uri)
                } else {
                    original_uri.clone()
                };
                route_map.insert(exposed_uri.clone(), (slot.name.clone(), original_uri));
                res.uri = exposed_uri;
                all_resources.push(res);
            }
        }

        let out = ListResourcesResult {
            resources: all_resources,
            next_cursor: None,
        };
        match serde_json::to_value(out) {
            Ok(v) => JsonRpcResponse::ok(req.id, v),
            Err(e) => JsonRpcResponse::err(
                Some(req.id),
                JsonRpcError::new(ERR_INTERNAL, e.to_string()),
            ),
        }
    }

    async fn handle_resources_read(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let params: ReadResourceParams = match req
            .params
            .clone()
            .and_then(|v| serde_json::from_value(v).ok())
        {
            Some(p) => p,
            None => {
                return JsonRpcResponse::err(
                    Some(req.id),
                    JsonRpcError::new(ERR_INVALID_PARAMS, "missing or invalid 'uri' parameter"),
                );
            }
        };

        let route = self.resource_routes.read().await.get(&params.uri).cloned();
        let Some((server_name, original_uri)) = route else {
            return JsonRpcResponse::err(
                Some(req.id),
                JsonRpcError::new(
                    ERR_INVALID_PARAMS,
                    format!("unknown resource URI '{}'", params.uri),
                ),
            );
        };

        let Some(slot) = self.upstreams.get(&server_name) else {
            return JsonRpcResponse::err(
                Some(req.id),
                JsonRpcError::new(ERR_UPSTREAM_UNAVAILABLE, "resource upstream not found"),
            );
        };

        match slot
            .request_with_retry(
                self.factory.as_ref(),
                self.config.gateway.request_timeout_secs,
                self.config.gateway.max_upstream_restarts,
                "resources/read",
                Some(json!({ "uri": original_uri })),
            )
            .await
        {
            Ok(mut val) => {
                if self.redactor.redact_outputs_enabled() {
                    let _ = self.redactor.redact_value(&mut val);
                }
                JsonRpcResponse::ok(req.id, val)
            }
            Err(e) => JsonRpcResponse::err(
                Some(req.id),
                JsonRpcError::new(ERR_UPSTREAM_UNAVAILABLE, e.to_string()),
            ),
        }
    }

    async fn handle_prompts_list(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let mut all_prompts = Vec::new();
        for slot in self.upstreams.values() {
            if slot.health().await.state != ServerState::Ready {
                let _ = slot
                    .refresh_catalog(
                        self.factory.as_ref(),
                        self.config.gateway.request_timeout_secs,
                    )
                    .await;
            }
            for mut prompt in slot.cached_prompts().await {
                prompt.name = self.namespace_tool(&slot.prefix, &prompt.name);
                all_prompts.push(prompt);
            }
        }
        let out = ListPromptsResult {
            prompts: all_prompts,
            next_cursor: None,
        };
        match serde_json::to_value(out) {
            Ok(v) => JsonRpcResponse::ok(req.id, v),
            Err(e) => JsonRpcResponse::err(
                Some(req.id),
                JsonRpcError::new(ERR_INTERNAL, e.to_string()),
            ),
        }
    }

    async fn handle_prompts_get(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let params: GetPromptParams = match req
            .params
            .clone()
            .and_then(|v| serde_json::from_value(v).ok())
        {
            Some(p) => p,
            None => {
                return JsonRpcResponse::err(
                    Some(req.id),
                    JsonRpcError::new(ERR_INVALID_PARAMS, "missing or invalid prompt params"),
                );
            }
        };

        let Some((slot, raw_name)) = self.parse_namespaced(&params.name) else {
            return JsonRpcResponse::err(
                Some(req.id),
                JsonRpcError::new(ERR_INVALID_PARAMS, format!("unknown prompt '{}'", params.name)),
            );
        };

        let mut forwarded = json!({ "name": raw_name });
        if let Some(args) = params.arguments {
            forwarded["arguments"] = Value::Object(args);
        }

        match slot
            .request_with_retry(
                self.factory.as_ref(),
                self.config.gateway.request_timeout_secs,
                self.config.gateway.max_upstream_restarts,
                "prompts/get",
                Some(forwarded),
            )
            .await
        {
            Ok(mut val) => {
                if self.redactor.redact_outputs_enabled() {
                    let _ = self.redactor.redact_value(&mut val);
                }
                JsonRpcResponse::ok(req.id, val)
            }
            Err(e) => JsonRpcResponse::err(
                Some(req.id),
                JsonRpcError::new(ERR_UPSTREAM_UNAVAILABLE, e.to_string()),
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_and_emit(
        &self,
        id: String,
        server: String,
        tool: String,
        namespaced_tool: String,
        arguments: Option<Value>,
        outcome: CallOutcome,
        result: Option<CallToolResult>,
        error_message: Option<String>,
        duration_ms: u64,
        cache_checked: bool,
        cache_hit: bool,
        redaction: RedactionReport,
        policy_rule: Option<String>,
    ) {
        let timestamp = Utc::now();
        self.metrics
            .record_call(outcome, duration_ms, cache_checked, cache_hit, &redaction);

        let args_preview = arguments
            .as_ref()
            .map(|v| truncate_preview(&v.to_string(), PREVIEW_MAX_CHARS));
        let result_preview = result.as_ref().map(|r| {
            let s = serde_json::to_string(&r.content).unwrap_or_default();
            truncate_preview(&s, PREVIEW_MAX_CHARS)
        });

        if let Some(wal) = &self.wal {
            let record = TraceRecord {
                id: id.clone(),
                timestamp,
                server: server.clone(),
                tool: tool.clone(),
                namespaced_tool: namespaced_tool.clone(),
                arguments: if self.config.trace.capture_payloads {
                    arguments
                } else {
                    None
                },
                outcome,
                result: if self.config.trace.capture_payloads {
                    result
                } else {
                    None
                },
                error_message: error_message.clone(),
                duration_ms,
                cache_hit,
                redaction_count: redaction.total_redactions,
                redaction_categories: redaction.by_category.clone(),
                policy_rule,
            };
            if let Err(e) = wal.append(&record) {
                warn!(error = %e, "failed to append WAL trace record");
            }
        }

        let event = ToolCallEvent {
            id,
            timestamp,
            server,
            tool,
            namespaced_tool,
            outcome,
            duration_ms,
            cache_hit,
            redaction_count: redaction.total_redactions,
            redaction_categories: redaction.by_category,
            error_message,
            args_preview,
            result_preview,
        };
        let _ = self.events_tx.send(TelemetryEvent::ToolCall(event));
        let stats = self.stats().await;
        let _ = self.events_tx.send(TelemetryEvent::Stats(stats));
    }
}

#[async_trait]
impl McpHandler for Gateway {
    async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        debug!(method = %request.method, id = %request.id, "handling MCP request");
        match request.method.as_str() {
            "initialize" => self.handle_initialize(request).await,
            "ping" => JsonRpcResponse::ok(request.id, json!({})),
            "tools/list" => self.handle_tools_list(request).await,
            "tools/call" => self.handle_tools_call(request).await,
            "resources/list" => self.handle_resources_list(request).await,
            "resources/read" => self.handle_resources_read(request).await,
            "prompts/list" => self.handle_prompts_list(request).await,
            "prompts/get" => self.handle_prompts_get(request).await,
            other => JsonRpcResponse::err(
                Some(request.id),
                JsonRpcError::new(
                    ERR_METHOD_NOT_FOUND,
                    format!("method '{other}' is not supported by Aegis"),
                ),
            ),
        }
    }

    async fn handle_notification(&self, notification: JsonRpcNotification) {
        debug!(method = %notification.method, "received MCP notification");
    }
}

#[async_trait]
impl ControlHandler for Gateway {
    async fn stats(&self) -> GatewayStats {
        let mut active_servers = 0usize;
        let mut total_tools = 0usize;
        for slot in self.upstreams.values() {
            let h = slot.health().await;
            if h.state == ServerState::Ready {
                active_servers += 1;
            }
            total_tools += h.tool_count;
        }
        self.metrics.snapshot(active_servers, total_tools)
    }

    async fn servers(&self) -> Vec<ServerHealth> {
        let mut out = Vec::with_capacity(self.upstreams.len());
        for slot in self.upstreams.values() {
            out.push(slot.health().await);
        }
        out
    }

    async fn reload(&self) -> Result<String> {
        let mut ok_count = 0usize;
        let mut err_count = 0usize;
        for slot in self.upstreams.values() {
            match slot
                .refresh_catalog(
                    self.factory.as_ref(),
                    self.config.gateway.request_timeout_secs,
                )
                .await
            {
                Ok(_) => ok_count += 1,
                Err(e) => {
                    warn!(server = %slot.name, error = %e, "upstream reload failed");
                    err_count += 1;
                }
            }
            let _ = self
                .events_tx
                .send(TelemetryEvent::ServerStatus(slot.health().await));
        }
        let msg = format!("reloaded upstreams: {ok_count} ready, {err_count} degraded");
        info!("{msg}");
        let _ = self.events_tx.send(TelemetryEvent::Notice {
            level: "info".into(),
            message: msg.clone(),
        });
        Ok(msg)
    }

    async fn clear_cache(&self) -> Result<usize> {
        let removed = self.cache.clear()?;
        let _ = self.events_tx.send(TelemetryEvent::Notice {
            level: "info".into(),
            message: format!("cleared {removed} BLAKE3 cache entries"),
        });
        Ok(removed)
    }

    fn subscribe_events(&self) -> broadcast::Receiver<TelemetryEvent> {
        self.events_tx.subscribe()
    }
}

fn truncate_preview(input: &str, max_chars: usize) -> String {
    let mut chars = input.chars();
    let prefix: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::ServerConfig;
    use aegis_store::ReplayEngine;
    use aegis_transport::UpstreamTransport;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tempfile::tempdir;

    struct MockUpstream {
        calls: Arc<AtomicU64>,
    }

    #[async_trait]
    impl UpstreamTransport for MockUpstream {
        async fn request(
            &self,
            method: &str,
            params: Option<Value>,
            _timeout: Duration,
        ) -> Result<Value> {
            match method {
                "initialize" => Ok(json!({
                    "protocolVersion": "2025-03-26",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "mock-gh", "version": "1.0.0" }
                })),
                "tools/list" => Ok(json!({
                    "tools": [
                        { "name": "list_issues", "description": "List issues", "inputSchema": {"type": "object"} },
                        { "name": "delete_repo", "description": "Delete repo", "inputSchema": {"type": "object"} }
                    ]
                })),
                "tools/call" => {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    let tool = params
                        .as_ref()
                        .and_then(|p| p.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    Ok(json!({
                        "content": [{
                            "type": "text",
                            "text": format!("result for {tool} token=ghp_abcdefghijklmnopqrstuvwxyz012345")
                        }],
                        "isError": false
                    }))
                }
                _ => Ok(json!({})),
            }
        }

        async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
            Ok(())
        }

        async fn close(&self) -> Result<()> {
            Ok(())
        }

        fn is_alive(&self) -> bool {
            true
        }
    }

    struct MockFactory {
        calls: Arc<AtomicU64>,
    }

    #[async_trait]
    impl UpstreamFactory for MockFactory {
        async fn create(
            &self,
            _name: &str,
            _config: &ServerConfig,
            _connect_timeout: Duration,
        ) -> Result<Arc<dyn UpstreamTransport>> {
            Ok(Arc::new(MockUpstream {
                calls: Arc::clone(&self.calls),
            }))
        }
    }

    #[tokio::test]
    async fn full_gateway_pipeline_policy_redaction_cache_wal() {
        let dir = tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");
        let cache_dir = dir.path().join("cache");

        let toml = format!(
            r#"
[gateway]
hide_denied_tools = true

[policy]
default = "allow"
deny = ["*__delete_*"]

[cache]
enabled = true
dir = '{}'
allow = ["*__list_*"]

[trace]
enabled = true
path = '{}'

[servers.github]
transport = "stdio"
command = "mock"
"#,
            cache_dir.display(),
            wal_path.display()
        );

        let cfg = AegisConfig::from_toml_str(&toml).unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let gw = Gateway::with_factory(
            cfg,
            None,
            "test",
            Arc::new(MockFactory {
                calls: Arc::clone(&calls),
            }),
        )
        .unwrap();

        // 1. tools/list hides delete_repo
        let list_resp = gw
            .handle_request(JsonRpcRequest::new(1i64, "tools/list", Some(json!({}))))
            .await;
        let listed: ListToolsResult = serde_json::from_value(list_resp.result.unwrap()).unwrap();
        assert_eq!(listed.tools.len(), 1);
        assert_eq!(listed.tools[0].name, "github__list_issues");

        // 2. Denied call returns -32001
        let denied = gw
            .handle_request(JsonRpcRequest::new(
                2i64,
                "tools/call",
                Some(json!({ "name": "github__delete_repo", "arguments": {} })),
            ))
            .await;
        assert_eq!(denied.error.unwrap().code, ERR_POLICY_DENIED);

        // 3. Allowed call redacts GitHub token and caches result
        let ok1 = gw
            .handle_request(JsonRpcRequest::new(
                3i64,
                "tools/call",
                Some(json!({ "name": "github__list_issues", "arguments": {"repo": "aegis"} })),
            ))
            .await;
        let text1 = ok1.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(text1.contains("[REDACTED:github_token]"));
        assert!(!text1.contains("ghp_"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // 4. Second identical call hits BLAKE3 cache without hitting upstream
        let ok2 = gw
            .handle_request(JsonRpcRequest::new(
                4i64,
                "tools/call",
                Some(json!({ "name": "github__list_issues", "arguments": {"repo": "aegis"} })),
            ))
            .await;
        assert!(ok2.error.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // 5. Verify stats & WAL replay
        let stats = gw.stats().await;
        assert_eq!(stats.total_calls, 3);
        assert_eq!(stats.denied_calls, 1);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.total_redactions, 1);

        let (replay, wal_stats) = ReplayEngine::from_wal(&wal_path).unwrap();
        assert_eq!(wal_stats.records_read, 3);
        assert!(replay
            .lookup_mock("github__list_issues", Some(&json!({"repo": "aegis"})))
            .is_some());
    }

    #[tokio::test]
    async fn multiplexes_real_streamable_http_and_legacy_sse_upstreams() {
        use axum::extract::State;
        use axum::response::sse::{Event, Sse};
        use axum::routing::{get, post};
        use axum::{Json, Router};
        use futures_util::StreamExt;
        use std::convert::Infallible;
        use tokio::sync::broadcast;
        use tokio_stream::wrappers::BroadcastStream;

        // Spawn Mock Streamable HTTP MCP Server
        let http_router = Router::new().route(
            "/mcp",
            post(|Json(body): Json<Value>| async move {
                let id = body.get("id").cloned().unwrap_or(json!(1));
                let method = body.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let result = match method {
                    "initialize" => json!({
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "http-mock", "version": "1.0"}
                    }),
                    "tools/list" => json!({
                        "tools": [{"name": "ping_http", "inputSchema": {"type": "object"}}]
                    }),
                    "tools/call" => json!({
                        "content": [{"type": "text", "text": "hello-from-http"}],
                        "isError": false
                    }),
                    _ => json!({}),
                };
                Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
            }),
        );
        let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(http_listener, http_router).await;
        });

        // Spawn Mock Legacy SSE (2024-11-05) MCP Server
        let (sse_tx, _) = broadcast::channel::<(String, String)>(32);
        let sse_router = Router::new()
            .route(
                "/sse",
                get(|State(tx): State<broadcast::Sender<(String, String)>>| async move {
                    let rx = tx.subscribe();
                    let initial = futures_util::stream::once(async {
                        Ok::<Event, Infallible>(
                            Event::default().event("endpoint").data("/messages"),
                        )
                    });
                    let live = BroadcastStream::new(rx).filter_map(|item| async move {
                        match item {
                            Ok((ev, data)) => {
                                Some(Ok::<Event, Infallible>(Event::default().event(ev).data(data)))
                            }
                            Err(_) => None,
                        }
                    });
                    Sse::new(initial.chain(live))
                }),
            )
            .route(
                "/messages",
                post(
                    |State(tx): State<broadcast::Sender<(String, String)>>,
                     Json(body): Json<Value>| async move {
                        if let Some(id) = body.get("id").cloned() {
                            let method =
                                body.get("method").and_then(|v| v.as_str()).unwrap_or("");
                            let result = match method {
                                "initialize" => json!({
                                    "protocolVersion": "2024-11-05",
                                    "capabilities": {"tools": {}},
                                    "serverInfo": {"name": "sse-mock", "version": "1.0"}
                                }),
                                "tools/list" => json!({
                                    "tools": [{"name": "ping_sse", "inputSchema": {"type": "object"}}]
                                }),
                                "tools/call" => json!({
                                    "content": [{"type": "text", "text": "hello-from-legacy-sse"}],
                                    "isError": false
                                }),
                                _ => json!({}),
                            };
                            let resp = json!({"jsonrpc": "2.0", "id": id, "result": result});
                            let _ = tx.send(("message".to_string(), resp.to_string()));
                        }
                        axum::http::StatusCode::ACCEPTED
                    },
                ),
            )
            .with_state(sse_tx);
        let sse_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sse_addr = sse_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(sse_listener, sse_router).await;
        });

        let dir = tempdir().unwrap();
        let toml = format!(
            r#"
[cache]
enabled = false

[trace]
enabled = true
path = '{}'

[servers.modern]
transport = "http"
url = "http://{http_addr}/mcp"

[servers.legacy]
transport = "sse"
url = "http://{sse_addr}/sse"
"#,
            dir.path().join("mux.wal").display()
        );

        let cfg = AegisConfig::from_toml_str(&toml).unwrap();
        let gw = Gateway::new(cfg, None, "test").unwrap();

        let list_resp = gw
            .handle_request(JsonRpcRequest::new(1i64, "tools/list", Some(json!({}))))
            .await;
        let listed: ListToolsResult = serde_json::from_value(list_resp.result.unwrap()).unwrap();
        let names: Vec<&str> = listed.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["legacy__ping_sse", "modern__ping_http"]);

        let r1 = gw
            .handle_request(JsonRpcRequest::new(
                2i64,
                "tools/call",
                Some(json!({"name": "modern__ping_http", "arguments": {}})),
            ))
            .await;
        assert_eq!(
            r1.result.unwrap()["content"][0]["text"].as_str(),
            Some("hello-from-http")
        );

        let r2 = gw
            .handle_request(JsonRpcRequest::new(
                3i64,
                "tools/call",
                Some(json!({"name": "legacy__ping_sse", "arguments": {}})),
            ))
            .await;
        assert_eq!(
            r2.result.unwrap()["content"][0]["text"].as_str(),
            Some("hello-from-legacy-sse")
        );

        gw.shutdown().await;
    }
}
