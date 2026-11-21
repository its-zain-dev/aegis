use aegis_core::{
    CallToolParams, Implementation, InitializeResult, JsonRpcError, JsonRpcNotification,
    JsonRpcRequest, JsonRpcResponse, ListToolsResult, ServerCapabilities, ToolsCapability,
    ERR_INVALID_PARAMS, ERR_METHOD_NOT_FOUND, ERR_POLICY_DENIED, MCP_PROTOCOL_VERSION,
};
use aegis_policy::{PolicyDecision, PolicyEngine};
use aegis_redact::SecretRedactor;
use aegis_store::ReplayEngine;
use aegis_transport::McpHandler;
use async_trait::async_trait;
use serde_json::json;

/// Deterministic offline MCP server backed by a recorded WAL trace.
/// Used by `aegis replay <wal> --mode serve-stdio` for zero-cost agent evaluation & CI tests.
pub struct ReplayMcpServer {
    engine: ReplayEngine,
    policy: PolicyEngine,
    redactor: SecretRedactor,
    separator: String,
}

impl ReplayMcpServer {
    pub fn new(
        engine: ReplayEngine,
        policy: PolicyEngine,
        redactor: SecretRedactor,
        separator: String,
    ) -> Self {
        Self {
            engine,
            policy,
            redactor,
            separator,
        }
    }
}

#[async_trait]
impl McpHandler for ReplayMcpServer {
    async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        match request.method.as_str() {
            "initialize" => {
                let res = InitializeResult {
                    protocol_version: MCP_PROTOCOL_VERSION.to_string(),
                    capabilities: ServerCapabilities {
                        tools: Some(ToolsCapability {
                            list_changed: Some(false),
                        }),
                        resources: None,
                        prompts: None,
                        extra: serde_json::Map::new(),
                    },
                    server_info: Implementation {
                        name: "aegis-replay".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                    },
                    instructions: Some(
                        "Aegis deterministic offline WAL replay mock server.".to_string(),
                    ),
                };
                JsonRpcResponse::ok(request.id, serde_json::to_value(res).unwrap_or(json!({})))
            }
            "ping" => JsonRpcResponse::ok(request.id, json!({})),
            "tools/list" => {
                let tools = self.engine.synthetic_tools();
                let res = ListToolsResult {
                    tools,
                    next_cursor: None,
                };
                JsonRpcResponse::ok(request.id, serde_json::to_value(res).unwrap_or(json!({})))
            }
            "tools/call" => {
                let Some(params) = request
                    .params
                    .and_then(|v| serde_json::from_value::<CallToolParams>(v).ok())
                else {
                    return JsonRpcResponse::err(
                        Some(request.id),
                        JsonRpcError::new(ERR_INVALID_PARAMS, "invalid tools/call params"),
                    );
                };

                let (server, raw_tool) = params
                    .name
                    .split_once(&self.separator)
                    .unwrap_or(("replay", params.name.as_str()));

                if let PolicyDecision::Deny {
                    matched_rule,
                    reason,
                } = self.policy.evaluate(server, raw_tool, &params.name)
                {
                    return JsonRpcResponse::err(
                        Some(request.id),
                        JsonRpcError::with_data(
                            ERR_POLICY_DENIED,
                            format!("Tool '{}' denied in replay mode: {reason}", params.name),
                            json!({ "rule": matched_rule, "reason": reason }),
                        ),
                    );
                }

                match self
                    .engine
                    .lookup_mock(&params.name, params.arguments.as_ref())
                {
                    Some(result) => {
                        let mut val = serde_json::to_value(result).unwrap_or(json!({}));
                        if self.redactor.redact_outputs_enabled() {
                            let _ = self.redactor.redact_value(&mut val);
                        }
                        JsonRpcResponse::ok(request.id, val)
                    }
                    None => JsonRpcResponse::err(
                        Some(request.id),
                        JsonRpcError::new(
                            ERR_INVALID_PARAMS,
                            format!("no recorded trace response found for tool '{}'", params.name),
                        ),
                    ),
                }
            }
            other => JsonRpcResponse::err(
                Some(request.id),
                JsonRpcError::new(
                    ERR_METHOD_NOT_FOUND,
                    format!("method '{other}' is not supported in replay mode"),
                ),
            ),
        }
    }

    async fn handle_notification(&self, _notification: JsonRpcNotification) {}
}
