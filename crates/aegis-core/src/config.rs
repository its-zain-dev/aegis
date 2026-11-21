use crate::{AegisError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AegisConfig {
    #[serde(default)]
    pub gateway: GatewayConfig,
    #[serde(default)]
    pub ipc: IpcConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub profiles: BTreeMap<String, PolicyConfig>,
    #[serde(default)]
    pub redaction: RedactionConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub trace: TraceConfig,
    #[serde(default)]
    pub servers: BTreeMap<String, ServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default = "default_gateway_name")]
    pub name: String,
    #[serde(default = "default_namespace_separator")]
    pub namespace_separator: String,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_true")]
    pub hide_denied_tools: bool,
    #[serde(default = "default_max_restarts")]
    pub max_upstream_restarts: u32,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            name: default_gateway_name(),
            namespace_separator: default_namespace_separator(),
            request_timeout_secs: default_request_timeout_secs(),
            hide_denied_tools: true,
            max_upstream_restarts: default_max_restarts(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub tcp_addr: Option<String>,
}

impl Default for IpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            tcp_addr: None,
        }
    }
}

impl IpcConfig {
    /// Returns the resolved IPC Unix socket path (Unix/Android/macOS) or None if TCP is configured.
    pub fn resolved_unix_path(&self) -> PathBuf {
        if let Some(p) = &self.path {
            return expand_tilde(p);
        }
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            if !runtime_dir.is_empty() {
                return PathBuf::from(runtime_dir).join("aegis.sock");
            }
        }
        if let Ok(prefix) = std::env::var("PREFIX") {
            // Termux-friendly runtime path
            let tmp = PathBuf::from(prefix).join("tmp");
            if tmp.exists() {
                return tmp.join("aegis.sock");
            }
        }
        std::env::temp_dir().join("aegis.sock")
    }

    /// Returns the resolved TCP fallback address (used on Windows or when explicitly configured).
    pub fn resolved_tcp_addr(&self) -> String {
        self.tcp_addr
            .clone()
            .unwrap_or_else(|| "127.0.0.1:17420".to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PolicyStance {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub default: PolicyStance,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default: PolicyStance::Allow,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerPolicyConfig {
    #[serde(default)]
    pub default: Option<PolicyStance>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub redact_inputs: bool,
    #[serde(default = "default_true")]
    pub redact_outputs: bool,
    #[serde(default = "default_true")]
    pub enable_builtin_patterns: bool,
    #[serde(default = "default_true")]
    pub enable_entropy: bool,
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    #[serde(default = "default_entropy_min_length")]
    pub entropy_min_length: usize,
    #[serde(default)]
    pub enable_pii: bool,
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub custom_patterns: BTreeMap<String, String>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            redact_inputs: false,
            redact_outputs: true,
            enable_builtin_patterns: true,
            enable_entropy: true,
            entropy_threshold: default_entropy_threshold(),
            entropy_min_length: default_entropy_min_length(),
            enable_pii: false,
            allowlist: Vec::new(),
            custom_patterns: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub dir: Option<PathBuf>,
    #[serde(default = "default_cache_ttl_secs")]
    pub default_ttl_secs: u64,
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_cache_allow")]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: None,
            default_ttl_secs: default_cache_ttl_secs(),
            max_entries: default_cache_max_entries(),
            allow: default_cache_allow(),
            deny: Vec::new(),
        }
    }
}

impl CacheConfig {
    pub fn resolved_dir(&self) -> PathBuf {
        if let Some(d) = &self.dir {
            return expand_tilde(d);
        }
        default_data_dir().join("cache")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub capture_payloads: bool,
    #[serde(default = "default_true")]
    pub compress: bool,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            capture_payloads: true,
            compress: true,
        }
    }
}

impl TraceConfig {
    pub fn resolved_path(&self) -> PathBuf {
        if let Some(p) = &self.path {
            return expand_tilde(p);
        }
        default_data_dir().join("traces").join("aegis.wal")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Stdio,
    Http,
    Sse,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportKind::Stdio => write!(f, "stdio"),
            TransportKind::Http => write!(f, "http"),
            TransportKind::Sse => write!(f, "sse"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub transport: TransportKind,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "default_true")]
    pub lazy: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub policy: Option<ServerPolicyConfig>,
}

impl AegisConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            AegisError::Config(format!(
                "failed to read config '{}': {e}",
                path.as_ref().display()
            ))
        })?;
        let cfg: Self = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_toml_str(raw: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.gateway.namespace_separator.is_empty() {
            return Err(AegisError::Config(
                "gateway.namespace_separator cannot be empty".into(),
            ));
        }
        if self.gateway.request_timeout_secs == 0 {
            return Err(AegisError::Config(
                "gateway.request_timeout_secs must be greater than 0".into(),
            ));
        }
        for (name, server) in &self.servers {
            if !server.enabled {
                continue;
            }
            if name.contains(&self.gateway.namespace_separator) {
                return Err(AegisError::Config(format!(
                    "server name '{name}' cannot contain namespace_separator '{}'",
                    self.gateway.namespace_separator
                )));
            }
            match server.transport {
                TransportKind::Stdio => {
                    if server
                        .command
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or("")
                        .is_empty()
                    {
                        return Err(AegisError::Config(format!(
                            "stdio server '{name}' requires a non-empty 'command'"
                        )));
                    }
                }
                TransportKind::Http | TransportKind::Sse => {
                    let url = server.url.as_deref().map(str::trim).unwrap_or("");
                    if !(url.starts_with("http://") || url.starts_with("https://")) {
                        return Err(AegisError::Config(format!(
                            "{} server '{name}' requires a valid http(s) 'url'",
                            server.transport
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn effective_policy(&self, profile: Option<&str>) -> Result<PolicyConfig> {
        match profile {
            None => Ok(self.policy.clone()),
            Some(name) => self.profiles.get(name).cloned().ok_or_else(|| {
                AegisError::Config(format!(
                    "profile '{name}' not found (available: {:?})",
                    self.profiles.keys().collect::<Vec<_>>()
                ))
            }),
        }
    }
}

pub fn default_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from(".aegis"))
        .join("aegis")
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    if let Some(s) = path.to_str() {
        if let Some(rest) = s.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(rest);
            }
        }
    }
    path.to_path_buf()
}

/// Expands `${VAR}` placeholders using environment variables. Unset variables expand to empty string.
pub fn expand_env(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(rel_end) = input[i + 2..].find('}') {
                let var_name = &input[i + 2..i + 2 + rel_end];
                if let Ok(val) = std::env::var(var_name) {
                    out.push_str(&val);
                }
                i = i + 2 + rel_end + 1;
                continue;
            }
        }
        // Copy UTF-8 character safely
        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn default_gateway_name() -> String {
    "aegis".to_string()
}

fn default_namespace_separator() -> String {
    "__".to_string()
}

fn default_request_timeout_secs() -> u64 {
    60
}

fn default_max_restarts() -> u32 {
    3
}

fn default_true() -> bool {
    true
}

fn default_entropy_threshold() -> f64 {
    4.5
}

fn default_entropy_min_length() -> usize {
    20
}

fn default_cache_ttl_secs() -> u64 {
    300
}

fn default_cache_max_entries() -> usize {
    4096
}

fn default_cache_allow() -> Vec<String> {
    vec![
        "*__get_*".to_string(),
        "*__list_*".to_string(),
        "*__read_*".to_string(),
        "*__search_*".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_env_vars() {
        std::env::set_var("AEGIS_TEST_VAR", "secret123");
        assert_eq!(
            expand_env("Bearer ${AEGIS_TEST_VAR}!"),
            "Bearer secret123!"
        );
        assert_eq!(expand_env("plain text"), "plain text");
        assert_eq!(expand_env("missing=${AEGIS_NO_SUCH_VAR_XYZ}"), "missing=");
    }

    #[test]
    fn validates_config() {
        let toml = r#"
[servers.demo]
transport = "stdio"
command = "echo"
"#;
        let cfg = AegisConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.servers.len(), 1);

        let bad = r#"
[servers.broken]
transport = "http"
url = "not-a-url"
"#;
        assert!(AegisConfig::from_toml_str(bad).is_err());
    }
}
