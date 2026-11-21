use crate::TransportKind;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallOutcome {
    Allowed,
    Cached,
    Denied,
    Error,
}

impl std::fmt::Display for CallOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallOutcome::Allowed => write!(f, "OK"),
            CallOutcome::Cached => write!(f, "CACHED"),
            CallOutcome::Denied => write!(f, "BLOCKED"),
            CallOutcome::Error => write!(f, "ERR"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub server: String,
    pub tool: String,
    pub namespaced_tool: String,
    pub outcome: CallOutcome,
    pub duration_ms: u64,
    pub cache_hit: bool,
    pub redaction_count: u64,
    #[serde(default)]
    pub redaction_categories: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_preview: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerState {
    Idle,
    Connecting,
    Ready,
    Degraded,
    Stopped,
}

impl std::fmt::Display for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerState::Idle => write!(f, "IDLE"),
            ServerState::Connecting => write!(f, "CONNECTING"),
            ServerState::Ready => write!(f, "READY"),
            ServerState::Degraded => write!(f, "DEGRADED"),
            ServerState::Stopped => write!(f, "STOPPED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHealth {
    pub name: String,
    pub transport: TransportKind,
    pub state: ServerState,
    pub tool_count: usize,
    pub total_calls: u64,
    pub error_count: u64,
    pub restart_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayStats {
    pub started_at: DateTime<Utc>,
    pub mode: String,
    pub uptime_secs: u64,
    pub total_calls: u64,
    pub allowed_calls: u64,
    pub denied_calls: u64,
    pub error_calls: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub total_redactions: u64,
    #[serde(default)]
    pub redactions_by_category: BTreeMap<String, u64>,
    pub avg_latency_ms: f64,
    pub p95_latency_ms: u64,
    pub active_servers: usize,
    pub total_tools: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TelemetryEvent {
    ToolCall(ToolCallEvent),
    ServerStatus(ServerHealth),
    Stats(GatewayStats),
    Notice { level: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IpcRequest {
    Ping,
    Subscribe,
    GetStats,
    GetServers,
    Reload,
    ClearCache,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcResponse {
    Pong,
    Ack { message: String },
    Stats(GatewayStats),
    Servers(Vec<ServerHealth>),
    Event(TelemetryEvent),
    Error { message: String },
}
