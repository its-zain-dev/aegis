use aegis_core::{AegisError, RedactionConfig, Result};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::Regex;

/// How a matched regex span is rewritten during redaction.
#[derive(Debug, Clone, Copy)]
pub enum ReplaceMode {
    /// Replace the entire regex match with `[REDACTED:<category>]`.
    FullMatch,
    /// Preserve capture group 1 as prefix, replace capture group 2 with `[REDACTED:<category>]`,
    /// and preserve capture group 3 (if present) as suffix.
    CaptureGroup2,
    /// Validate Luhn checksum on digits before replacing the entire match.
    CreditCardLuhn,
}

#[derive(Debug, Clone)]
pub struct PatternRule {
    pub category: String,
    pub regex: Regex,
    pub mode: ReplaceMode,
}

#[derive(Debug)]
pub struct PatternMatcher {
    /// Aho-Corasick automaton over fast trigger literals for pre-filtered rules.
    prefilter: Option<AhoCorasick>,
    /// Maps each Aho-Corasick pattern index to its index in `prefixed_rules`.
    trigger_to_rule: Vec<usize>,
    pub prefixed_rules: Vec<PatternRule>,
    /// Rules that always run (PII patterns and user-defined custom regexes).
    pub always_rules: Vec<PatternRule>,
}

impl PatternMatcher {
    pub fn from_config(config: &RedactionConfig) -> Result<Self> {
        let mut triggers: Vec<String> = Vec::new();
        let mut trigger_to_rule: Vec<usize> = Vec::new();
        let mut prefixed_rules: Vec<PatternRule> = Vec::new();
        let mut always_rules: Vec<PatternRule> = Vec::new();

        if config.enable_builtin_patterns {
            let mut add_prefixed =
                |category: &str, lits: &[&str], pattern: &str, mode: ReplaceMode| -> Result<()> {
                    let rule_idx = prefixed_rules.len();
                    let regex = Regex::new(pattern).map_err(|e| {
                        AegisError::Config(format!(
                            "invalid builtin regex for '{category}': {e}"
                        ))
                    })?;
                    prefixed_rules.push(PatternRule {
                        category: category.to_string(),
                        regex,
                        mode,
                    });
                    for lit in lits {
                        triggers.push((*lit).to_string());
                        trigger_to_rule.push(rule_idx);
                    }
                    Ok(())
                };

            // PEM private keys (multi-line)
            add_prefixed(
                "private_key",
                &["-----BEGIN "],
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                ReplaceMode::FullMatch,
            )?;

            // GitHub classic & fine-grained PATs / OAuth / App tokens
            add_prefixed(
                "github_token",
                &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
                r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b",
                ReplaceMode::FullMatch,
            )?;

            // Anthropic API keys (must come before OpenAI `sk-` rule)
            add_prefixed(
                "anthropic_key",
                &["sk-ant-"],
                r"\bsk-ant-[A-Za-z0-9_-]{20,200}\b",
                ReplaceMode::FullMatch,
            )?;

            // OpenAI API keys
            add_prefixed(
                "openai_key",
                &["sk-proj-", "sk-svcacct-", "sk-"],
                r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,200}\b",
                ReplaceMode::FullMatch,
            )?;

            // AWS Access Key IDs
            add_prefixed(
                "aws_access_key",
                &["AKIA", "ASIA"],
                r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
                ReplaceMode::FullMatch,
            )?;

            // Google Cloud / Gemini API keys
            add_prefixed(
                "google_api_key",
                &["AIza"],
                r"\bAIza[0-9A-Za-z_-]{35}\b",
                ReplaceMode::FullMatch,
            )?;

            // Slack tokens
            add_prefixed(
                "slack_token",
                &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"],
                r"\bxox[baprs]-[0-9A-Za-z-]{10,200}\b",
                ReplaceMode::FullMatch,
            )?;

            // Stripe live/restricted keys
            add_prefixed(
                "stripe_key",
                &["sk_live_", "rk_live_"],
                r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,100}\b",
                ReplaceMode::FullMatch,
            )?;

            // GitLab personal access tokens
            add_prefixed(
                "gitlab_token",
                &["glpat-"],
                r"\bglpat-[0-9A-Za-z_-]{20,100}\b",
                ReplaceMode::FullMatch,
            )?;

            // npm tokens
            add_prefixed(
                "npm_token",
                &["npm_"],
                r"\bnpm_[A-Za-z0-9]{30,80}\b",
                ReplaceMode::FullMatch,
            )?;

            // HuggingFace tokens
            add_prefixed(
                "huggingface_token",
                &["hf_"],
                r"\bhf_[A-Za-z0-9]{25,80}\b",
                ReplaceMode::FullMatch,
            )?;

            // JSON Web Tokens (3 base64url segments starting with eyJ)
            add_prefixed(
                "jwt",
                &["eyJ"],
                r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
                ReplaceMode::FullMatch,
            )?;

            // HTTP Bearer authorization tokens
            add_prefixed(
                "bearer_token",
                &["Bearer "],
                r"(?i)(\bBearer\s+)([A-Za-z0-9._~+/=-]{20,})()",
                ReplaceMode::CaptureGroup2,
            )?;

            // Database / broker URLs with embedded credentials
            add_prefixed(
                "database_url",
                &[
                    "postgres://",
                    "postgresql://",
                    "mysql://",
                    "mongodb://",
                    "mongodb+srv://",
                    "redis://",
                    "rediss://",
                    "amqp://",
                    "amqps://",
                ],
                r"(?i)((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://)([^/\s:@]+:[^/\s@]+)(@)",
                ReplaceMode::CaptureGroup2,
            )?;

            // Generic key/value secret assignments (JSON, TOML, env, YAML)
            add_prefixed(
                "generic_secret",
                &[
                    "api_key",
                    "apikey",
                    "api-key",
                    "secret_key",
                    "client_secret",
                    "access_token",
                    "auth_token",
                    "refresh_token",
                    "password",
                    "passwd",
                    "aws_secret_access_key",
                ],
                r#"(?i)((?:api[_-]?key|secret_key|client_secret|access_token|auth_token|refresh_token|aws_secret_access_key|password|passwd)["']?\s*[:=]\s*["']?)([^"'\s,;}{]{8,})(["']?)"#,
                ReplaceMode::CaptureGroup2,
            )?;
        }

        if config.enable_pii {
            always_rules.push(PatternRule {
                category: "pii_email".to_string(),
                regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
                    .map_err(|e| AegisError::Config(format!("invalid email regex: {e}")))?,
                mode: ReplaceMode::FullMatch,
            });
            always_rules.push(PatternRule {
                category: "pii_credit_card".to_string(),
                regex: Regex::new(r"\b(?:\d[ -]*?){13,19}\b")
                    .map_err(|e| AegisError::Config(format!("invalid credit card regex: {e}")))?,
                mode: ReplaceMode::CreditCardLuhn,
            });
        }

        for (name, pattern) in &config.custom_patterns {
            let regex = Regex::new(pattern).map_err(|e| {
                AegisError::Config(format!(
                    "invalid custom redaction regex '{name}': {e}"
                ))
            })?;
            always_rules.push(PatternRule {
                category: name.clone(),
                regex,
                mode: ReplaceMode::FullMatch,
            });
        }

        let prefilter = if triggers.is_empty() {
            None
        } else {
            let ac = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(&triggers)
                .map_err(|e| AegisError::Config(format!("failed to build Aho-Corasick: {e}")))?;
            Some(ac)
        };

        Ok(Self {
            prefilter,
            trigger_to_rule,
            prefixed_rules,
            always_rules,
        })
    }

    /// Returns indices into `prefixed_rules` whose trigger literal appeared in `input`.
    pub fn candidate_rule_indices(&self, input: &str) -> Vec<usize> {
        let Some(ac) = &self.prefilter else {
            return Vec::new();
        };
        let mut seen = vec![false; self.prefixed_rules.len()];
        for mat in ac.find_iter(input) {
            let rule_idx = self.trigger_to_rule[mat.pattern().as_usize()];
            seen[rule_idx] = true;
        }
        seen.into_iter()
            .enumerate()
            .filter_map(|(idx, hit)| hit.then_some(idx))
            .collect()
    }
}

/// Standard Luhn checksum validation for credit card numbers.
pub fn is_valid_luhn(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| (b - b'0') as u32)
        .collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    // Reject all-same digits like 0000000000000000
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = d;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum % 10 == 0
}
