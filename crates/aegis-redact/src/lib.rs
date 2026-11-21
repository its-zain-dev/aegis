pub mod entropy;
pub mod patterns;

use aegis_core::{RedactionConfig, Result};
use patterns::{is_valid_luhn, PatternMatcher, PatternRule, ReplaceMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionReport {
    pub total_redactions: u64,
    pub by_category: BTreeMap<String, u64>,
}

impl RedactionReport {
    pub fn record(&mut self, category: &str, count: u64) {
        if count == 0 {
            return;
        }
        self.total_redactions += count;
        *self.by_category.entry(category.to_string()).or_insert(0) += count;
    }

    pub fn merge(&mut self, other: RedactionReport) {
        self.total_redactions += other.total_redactions;
        for (cat, count) in other.by_category {
            *self.by_category.entry(cat).or_insert(0) += count;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.total_redactions == 0
    }
}

/// High-speed one-way secret and PII redactor.
///
/// Uses a two-stage pipeline:
/// 1. Aho-Corasick multi-pattern prefilter -> high-precision regex rules (plus optional PII / custom rules)
/// 2. Optional Shannon-entropy token scanner for unlabeled random keys.
#[derive(Debug)]
pub struct SecretRedactor {
    config: RedactionConfig,
    matcher: PatternMatcher,
}

impl SecretRedactor {
    pub fn from_config(config: &RedactionConfig) -> Result<Self> {
        let matcher = PatternMatcher::from_config(config)?;
        Ok(Self {
            config: config.clone(),
            matcher,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn redact_inputs_enabled(&self) -> bool {
        self.config.enabled && self.config.redact_inputs
    }

    pub fn redact_outputs_enabled(&self) -> bool {
        self.config.enabled && self.config.redact_outputs
    }

    /// Scans `input` and returns `(redacted_text, report)`.
    pub fn redact_str(&self, input: &str) -> (String, RedactionReport) {
        let mut report = RedactionReport::default();
        if !self.config.enabled || input.is_empty() {
            return (input.to_string(), report);
        }

        let mut current: Cow<'_, str> = Cow::Borrowed(input);

        // Stage 1a: Prefiltered builtin patterns
        let candidates = self.matcher.candidate_rule_indices(&current);
        for rule_idx in candidates {
            let rule = &self.matcher.prefixed_rules[rule_idx];
            let (next, count) = apply_rule(&current, rule, &self.config.allowlist);
            if count > 0 {
                current = Cow::Owned(next);
                report.record(&rule.category, count);
            }
        }

        // Stage 1b: Always-on patterns (PII if enabled + custom user patterns)
        for rule in &self.matcher.always_rules {
            let (next, count) = apply_rule(&current, rule, &self.config.allowlist);
            if count > 0 {
                current = Cow::Owned(next);
                report.record(&rule.category, count);
            }
        }

        // Stage 2: Shannon-entropy scanner
        if self.config.enable_entropy {
            let (next, count) = entropy::redact_high_entropy(
                &current,
                self.config.entropy_threshold,
                self.config.entropy_min_length,
                &self.config.allowlist,
            );
            if count > 0 {
                current = Cow::Owned(next);
                report.record("high_entropy", count);
            }
        }

        (current.into_owned(), report)
    }

    /// Recursively redacts all string leaves in a `serde_json::Value` in place.
    pub fn redact_value(&self, value: &mut Value) -> RedactionReport {
        let mut report = RedactionReport::default();
        if !self.config.enabled {
            return report;
        }
        self.redact_value_inner(value, &mut report);
        report
    }

    fn redact_value_inner(&self, value: &mut Value, report: &mut RedactionReport) {
        match value {
            Value::String(s) => {
                let (redacted, r) = self.redact_str(s);
                if !r.is_empty() {
                    *s = redacted;
                    report.merge(r);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.redact_value_inner(item, report);
                }
            }
            Value::Object(map) => {
                for val in map.values_mut() {
                    self.redact_value_inner(val, report);
                }
            }
            _ => {}
        }
    }
}

fn is_allowlisted(matched: &str, allowlist: &[String]) -> bool {
    if matched.contains("[REDACTED:") {
        return true;
    }
    allowlist
        .iter()
        .any(|allowed| !allowed.is_empty() && matched.contains(allowed.as_str()))
}

fn apply_rule(input: &str, rule: &PatternRule, allowlist: &[String]) -> (String, u64) {
    let mut count = 0u64;
    let marker = format!("[REDACTED:{}]", rule.category);

    let replaced = match rule.mode {
        ReplaceMode::FullMatch => rule.regex.replace_all(input, |caps: &regex::Captures<'_>| {
            let m = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            if is_allowlisted(m, allowlist) {
                m.to_string()
            } else {
                count += 1;
                marker.clone()
            }
        }),
        ReplaceMode::CaptureGroup2 => {
            rule.regex.replace_all(input, |caps: &regex::Captures<'_>| {
                let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let secret = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let suffix = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                if secret.is_empty() || is_allowlisted(secret, allowlist) {
                    whole.to_string()
                } else {
                    count += 1;
                    format!("{prefix}{marker}{suffix}")
                }
            })
        }
        ReplaceMode::CreditCardLuhn => {
            rule.regex.replace_all(input, |caps: &regex::Captures<'_>| {
                let m = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                if is_allowlisted(m, allowlist) || !is_valid_luhn(m) {
                    m.to_string()
                } else {
                    count += 1;
                    marker.clone()
                }
            })
        }
    };

    (replaced.into_owned(), count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_builtin_secret_types() {
        let redactor = SecretRedactor::from_config(&RedactionConfig::default()).unwrap();
        let sample = concat!(
            "gh=ghp_abcdefghijklmnopqrstuvwxyz0123456789 ",
            "aws=AKIAIOSFODNN7EXAMPLE ",
            "anthropic=sk-ant-api03-abcdefghijklmnopqrstuvwx123456 ",
            "db=postgres://admin:supersecretpass@db.internal:5432/prod ",
            "auth=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"
        );

        let (out, report) = redactor.redact_str(sample);
        assert!(out.contains("[REDACTED:github_token]"));
        assert!(out.contains("[REDACTED:aws_access_key]"));
        assert!(out.contains("[REDACTED:anthropic_key]"));
        assert!(out.contains("postgres://[REDACTED:database_url]@db.internal:5432/prod"));
        assert!(!out.contains("supersecretpass"));
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(report.total_redactions >= 5);
    }

    #[test]
    fn redacts_high_entropy_and_respects_allowlist() {
        let cfg = RedactionConfig {
            allowlist: vec!["SAFE_TOKEN_ALLOWLIST_123456".to_string()],
            ..Default::default()
        };
        let redactor = SecretRedactor::from_config(&cfg).unwrap();

        let text = "tok1=Zx9qL2mN8pR4vT7wY3kB6cF5hJ0dS1aG tok2=SAFE_TOKEN_ALLOWLIST_123456 path=/data/data/com.termux/files/home/aegis/Cargo.toml";
        let (out, report) = redactor.redact_str(text);
        assert!(out.contains("tok1=[REDACTED:high_entropy]"));
        assert!(out.contains("SAFE_TOKEN_ALLOWLIST_123456"));
        assert!(out.contains("/data/data/com.termux/files/home/aegis/Cargo.toml"));
        assert_eq!(report.by_category.get("high_entropy"), Some(&1));
    }

    #[test]
    fn redacts_nested_json_values_and_custom_patterns() {
        let mut cfg = RedactionConfig {
            enable_pii: true,
            ..Default::default()
        };
        cfg.custom_patterns
            .insert("acme_key".to_string(), r"ACME-[0-9]{8}".to_string());
        let redactor = SecretRedactor::from_config(&cfg).unwrap();

        let mut payload = json!({
            "content": [
                {"type": "text", "text": "contact alice@example.com with ACME-12345678"}
            ]
        });
        let report = redactor.redact_value(&mut payload);
        let text = payload["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text,
            "contact [REDACTED:pii_email] with [REDACTED:acme_key]"
        );
        assert_eq!(report.total_redactions, 2);
    }
}
