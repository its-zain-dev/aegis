pub mod glob;

pub use glob::{compile_globs, matches_any, GlobPattern};

use aegis_core::{AegisConfig, PolicyConfig, PolicyStance, Result, ServerPolicyConfig};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow { matched_rule: String },
    Deny { matched_rule: String, reason: String },
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow { .. })
    }
}

#[derive(Debug, Clone)]
struct CompiledServerPolicy {
    default: Option<PolicyStance>,
    allow: Vec<GlobPattern>,
    deny: Vec<GlobPattern>,
}

/// Lightweight, zero-overhead tool-level allowlist/denylist firewall.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    profile_name: Option<String>,
    global_default: PolicyStance,
    global_allow: Vec<GlobPattern>,
    global_deny: Vec<GlobPattern>,
    server_policies: HashMap<String, CompiledServerPolicy>,
}

impl PolicyEngine {
    pub fn from_config(config: &AegisConfig, profile: Option<&str>) -> Result<Self> {
        let global = config.effective_policy(profile)?;
        let mut server_policies = HashMap::new();

        for (server_name, server_cfg) in &config.servers {
            if let Some(sp) = &server_cfg.policy {
                server_policies.insert(server_name.clone(), compile_server_policy(sp));
            }
        }

        Ok(Self {
            profile_name: profile.map(str::to_string),
            global_default: global.default,
            global_allow: compile_globs(&global.allow),
            global_deny: compile_globs(&global.deny),
            server_policies,
        })
    }

    pub fn from_policy(policy: &PolicyConfig) -> Self {
        Self {
            profile_name: None,
            global_default: policy.default,
            global_allow: compile_globs(&policy.allow),
            global_deny: compile_globs(&policy.deny),
            server_policies: HashMap::new(),
        }
    }

    pub fn profile_name(&self) -> Option<&str> {
        self.profile_name.as_deref()
    }

    /// Evaluates whether a tool call is permitted.
    ///
    /// Precedence (explicit deny always wins):
    /// 1. Server-level `deny` (matches either raw tool name or namespaced name)
    /// 2. Global/profile `deny` (matches namespaced name or raw tool name)
    /// 3. Server-level `allow`
    /// 4. Global/profile `allow`
    /// 5. Server-level `default` stance (if set)
    /// 6. Global/profile `default` stance
    pub fn evaluate(
        &self,
        server: &str,
        raw_tool: &str,
        namespaced_tool: &str,
    ) -> PolicyDecision {
        // 1. Server explicit deny
        if let Some(sp) = self.server_policies.get(server) {
            if let Some(rule) =
                matches_any(&sp.deny, raw_tool).or_else(|| matches_any(&sp.deny, namespaced_tool))
            {
                return PolicyDecision::Deny {
                    matched_rule: format!("servers.{server}.policy.deny:{rule}"),
                    reason: format!("denied by server '{server}' rule '{rule}'"),
                };
            }
        }

        // 2. Global/profile explicit deny
        if let Some(rule) = matches_any(&self.global_deny, namespaced_tool)
            .or_else(|| matches_any(&self.global_deny, raw_tool))
        {
            return PolicyDecision::Deny {
                matched_rule: format!("policy.deny:{rule}"),
                reason: format!("denied by global rule '{rule}'"),
            };
        }

        // 3. Server explicit allow
        if let Some(sp) = self.server_policies.get(server) {
            if let Some(rule) =
                matches_any(&sp.allow, raw_tool).or_else(|| matches_any(&sp.allow, namespaced_tool))
            {
                return PolicyDecision::Allow {
                    matched_rule: format!("servers.{server}.policy.allow:{rule}"),
                };
            }
        }

        // 4. Global/profile explicit allow
        if let Some(rule) = matches_any(&self.global_allow, namespaced_tool)
            .or_else(|| matches_any(&self.global_allow, raw_tool))
        {
            return PolicyDecision::Allow {
                matched_rule: format!("policy.allow:{rule}"),
            };
        }

        // 5. Server default stance
        if let Some(sp) = self.server_policies.get(server) {
            if let Some(stance) = sp.default {
                return match stance {
                    PolicyStance::Allow => PolicyDecision::Allow {
                        matched_rule: format!("servers.{server}.policy.default:allow"),
                    },
                    PolicyStance::Deny => PolicyDecision::Deny {
                        matched_rule: format!("servers.{server}.policy.default:deny"),
                        reason: format!("denied by server '{server}' default-deny stance"),
                    },
                };
            }
        }

        // 6. Global default stance
        match self.global_default {
            PolicyStance::Allow => PolicyDecision::Allow {
                matched_rule: "policy.default:allow".to_string(),
            },
            PolicyStance::Deny => PolicyDecision::Deny {
                matched_rule: "policy.default:deny".to_string(),
                reason: "denied by global default-deny stance".to_string(),
            },
        }
    }

    pub fn is_allowed(&self, server: &str, raw_tool: &str, namespaced_tool: &str) -> bool {
        self.evaluate(server, raw_tool, namespaced_tool)
            .is_allowed()
    }
}

fn compile_server_policy(sp: &ServerPolicyConfig) -> CompiledServerPolicy {
    CompiledServerPolicy {
        default: sp.default,
        allow: compile_globs(&sp.allow),
        deny: compile_globs(&sp.deny),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_always_overrides_allow() {
        let toml = r#"
[policy]
default = "allow"
allow = ["github__*"]
deny = ["*__delete_*"]

[servers.github]
transport = "stdio"
command = "true"
[servers.github.policy]
deny = ["merge_pull_request"]
"#;
        let cfg = AegisConfig::from_toml_str(toml).unwrap();
        let engine = PolicyEngine::from_config(&cfg, None).unwrap();

        assert!(engine.is_allowed("github", "list_issues", "github__list_issues"));
        assert!(!engine.is_allowed("github", "delete_repo", "github__delete_repo"));
        assert!(!engine.is_allowed("github", "merge_pull_request", "github__merge_pull_request"));
    }

    #[test]
    fn readonly_profile_enforces_default_deny() {
        let toml = r#"
[profiles.readonly]
default = "deny"
allow = ["*__get_*", "*__list_*"]
deny = []
"#;
        let cfg = AegisConfig::from_toml_str(toml).unwrap();
        let engine = PolicyEngine::from_config(&cfg, Some("readonly")).unwrap();

        assert!(engine.is_allowed("github", "list_repos", "github__list_repos"));
        assert!(!engine.is_allowed("github", "create_issue", "github__create_issue"));
    }
}
