use crate::canonical::cache_key;
use crate::wal::{TraceRecord, TraceWal, WalReadStats};
use aegis_core::{CallOutcome, CallToolResult, Result, Tool};
use aegis_policy::{PolicyDecision, PolicyEngine};
use aegis_redact::SecretRedactor;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayDiffEntry {
    pub record_id: String,
    pub namespaced_tool: String,
    pub previous_outcome: CallOutcome,
    pub new_policy_allowed: bool,
    pub matched_rule: String,
    pub new_redactions: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplayDiffReport {
    pub total_records: usize,
    pub now_denied: usize,
    pub now_allowed: usize,
    pub unchanged: usize,
    pub additional_redactions: u64,
    pub diffs: Vec<ReplayDiffEntry>,
}

/// Deterministic offline replay engine backed by a recorded Aegis WAL trace.
pub struct ReplayEngine {
    records: Vec<TraceRecord>,
    /// Exact lookup: BLAKE3(server, tool, canonical_args) -> recorded result
    exact_lookup: HashMap<String, CallToolResult>,
    /// Fallback lookup: namespaced_tool -> latest recorded result
    fallback_lookup: HashMap<String, CallToolResult>,
}

impl ReplayEngine {
    pub fn from_wal(path: impl AsRef<Path>) -> Result<(Self, WalReadStats)> {
        let (records, stats) = TraceWal::read_all(path)?;
        Ok((Self::from_records(records), stats))
    }

    pub fn from_records(records: Vec<TraceRecord>) -> Self {
        let mut exact_lookup = HashMap::new();
        let mut fallback_lookup = HashMap::new();

        for rec in &records {
            if let Some(result) = &rec.result {
                let key = cache_key(&rec.namespaced_tool, "", rec.arguments.as_ref());
                exact_lookup.insert(key, result.clone());
                fallback_lookup.insert(rec.namespaced_tool.clone(), result.clone());
            }
        }

        Self {
            records,
            exact_lookup,
            fallback_lookup,
        }
    }

    pub fn records(&self) -> &[TraceRecord] {
        &self.records
    }

    /// Re-evaluates all recorded tool calls against a new policy and secret redactor.
    pub fn diff(&self, policy: &PolicyEngine, redactor: &SecretRedactor) -> ReplayDiffReport {
        let mut report = ReplayDiffReport {
            total_records: self.records.len(),
            ..Default::default()
        };

        for rec in &self.records {
            let decision = policy.evaluate(&rec.server, &rec.tool, &rec.namespaced_tool);
            let (new_allowed, matched_rule) = match &decision {
                PolicyDecision::Allow { matched_rule } => (true, matched_rule.clone()),
                PolicyDecision::Deny { matched_rule, .. } => (false, matched_rule.clone()),
            };

            let was_denied = rec.outcome == CallOutcome::Denied;
            let mut new_redactions = 0u64;
            if redactor.redact_outputs_enabled() {
                if let Some(res) = &rec.result {
                    if let Ok(mut val) = serde_json::to_value(res) {
                        let r = redactor.redact_value(&mut val);
                        new_redactions = r.total_redactions;
                    }
                }
            }
            report.additional_redactions += new_redactions;

            let policy_changed = (was_denied && new_allowed) || (!was_denied && !new_allowed);
            if !was_denied && !new_allowed {
                report.now_denied += 1;
            } else if was_denied && new_allowed {
                report.now_allowed += 1;
            } else {
                report.unchanged += 1;
            }

            if policy_changed || new_redactions > 0 {
                report.diffs.push(ReplayDiffEntry {
                    record_id: rec.id.clone(),
                    namespaced_tool: rec.namespaced_tool.clone(),
                    previous_outcome: rec.outcome,
                    new_policy_allowed: new_allowed,
                    matched_rule,
                    new_redactions,
                });
            }
        }

        report
    }

    /// Synthesizes an MCP tool catalog from recorded calls for offline mock serving.
    pub fn synthetic_tools(&self) -> Vec<Tool> {
        let mut unique: BTreeMap<String, Tool> = BTreeMap::new();
        for rec in &self.records {
            unique
                .entry(rec.namespaced_tool.clone())
                .or_insert_with(|| Tool {
                    name: rec.namespaced_tool.clone(),
                    description: Some(format!(
                        "[Aegis Replay Mock] Recorded tool from upstream '{}'",
                        rec.server
                    )),
                    input_schema: json!({
                        "type": "object",
                        "additionalProperties": true
                    }),
                    extra: Map::new(),
                });
        }
        unique.into_values().collect()
    }

    /// Looks up a deterministic mock response for a tool call.
    pub fn lookup_mock(
        &self,
        namespaced_tool: &str,
        arguments: Option<&Value>,
    ) -> Option<CallToolResult> {
        let exact_key = cache_key(namespaced_tool, "", arguments);
        self.exact_lookup
            .get(&exact_key)
            .or_else(|| self.fallback_lookup.get(namespaced_tool))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{PolicyConfig, PolicyStance, RedactionConfig};
    use chrono::Utc;

    #[test]
    fn diffs_policy_and_serves_mock_results() {
        let rec = TraceRecord {
            id: "1".into(),
            timestamp: Utc::now(),
            server: "github".into(),
            tool: "delete_repo".into(),
            namespaced_tool: "github__delete_repo".into(),
            arguments: Some(json!({"repo": "demo"})),
            outcome: CallOutcome::Allowed,
            result: Some(CallToolResult::text("deleted with ghp_abcdefghijklmnopqrstuvwxyz012345")),
            error_message: None,
            duration_ms: 15,
            cache_hit: false,
            redaction_count: 0,
            redaction_categories: BTreeMap::new(),
            policy_rule: None,
        };

        let engine = ReplayEngine::from_records(vec![rec]);
        let policy = PolicyEngine::from_policy(&PolicyConfig {
            default: PolicyStance::Allow,
            allow: vec![],
            deny: vec!["*__delete_*".into()],
        });
        let redactor = SecretRedactor::from_config(&RedactionConfig::default()).unwrap();

        let report = engine.diff(&policy, &redactor);
        assert_eq!(report.total_records, 1);
        assert_eq!(report.now_denied, 1);
        assert_eq!(report.additional_redactions, 1);

        let mock = engine
            .lookup_mock("github__delete_repo", Some(&json!({"repo": "demo"})))
            .unwrap();
        assert!(!mock.content.is_empty());
    }
}
