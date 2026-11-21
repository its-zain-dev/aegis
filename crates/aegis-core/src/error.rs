use thiserror::Error;

pub type Result<T> = std::result::Result<T, AegisError>;

#[derive(Debug, Error)]
pub enum AegisError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("upstream '{server}' error: {message}")]
    Upstream { server: String, message: String },

    #[error("upstream '{server}' timed out after {timeout_secs}s")]
    Timeout { server: String, timeout_secs: u64 },

    #[error("tool '{tool}' denied by policy: {reason}")]
    PolicyDenied { tool: String, reason: String },

    #[error("storage error: {0}")]
    Storage(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
}
