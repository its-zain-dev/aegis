pub mod config;
pub mod error;
pub mod events;
pub mod protocol;

pub use config::{
    expand_env, expand_tilde, AegisConfig, CacheConfig, GatewayConfig, IpcConfig, PolicyConfig,
    PolicyStance, RedactionConfig, ServerConfig, ServerPolicyConfig, TraceConfig, TransportKind,
};
pub use error::{AegisError, Result};
pub use events::{
    CallOutcome, GatewayStats, IpcRequest, IpcResponse, ServerHealth, ServerState, TelemetryEvent,
    ToolCallEvent,
};
pub use protocol::{
    CallToolParams, CallToolResult, ClientCapabilities, GetPromptParams, GetPromptResult,
    Implementation, InitializeParams, InitializeResult, JsonRpcError, JsonRpcMessage,
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, ListPromptsResult, ListResourcesResult,
    ListToolsResult, Prompt, PromptsCapability, ReadResourceParams, ReadResourceResult, RequestId,
    Resource, ResourcesCapability, ServerCapabilities, Tool, ToolsCapability, ERR_INTERNAL,
    ERR_INVALID_PARAMS, ERR_INVALID_REQUEST, ERR_METHOD_NOT_FOUND, ERR_PARSE, ERR_POLICY_DENIED,
    ERR_UPSTREAM_TIMEOUT, ERR_UPSTREAM_UNAVAILABLE, MCP_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
};
