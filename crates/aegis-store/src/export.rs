use crate::wal::TraceRecord;
use aegis_core::{CallOutcome, Result};
use serde_json::{json, Value};
use std::io::Write;

/// Exports WAL trace records as newline-delimited JSON (JSONL).
pub fn export_jsonl(records: &[TraceRecord], writer: &mut impl Write) -> Result<usize> {
    for record in records {
        serde_json::to_writer(&mut *writer, record)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(records.len())
}

/// Exports WAL trace records as an OpenTelemetry OTLP JSON payload.
pub fn export_otel(
    records: &[TraceRecord],
    service_name: &str,
    writer: &mut impl Write,
) -> Result<usize> {
    let spans: Vec<Value> = records.iter().map(record_to_otel_span).collect();

    let payload = json!({
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": { "stringValue": service_name }
                        },
                        {
                            "key": "service.version",
                            "value": { "stringValue": env!("CARGO_PKG_VERSION") }
                        }
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {
                            "name": "aegis.mcp.gateway",
                            "version": env!("CARGO_PKG_VERSION")
                        },
                        "spans": spans
                    }
                ]
            }
        ]
    });

    serde_json::to_writer_pretty(&mut *writer, &payload)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(records.len())
}

fn record_to_otel_span(rec: &TraceRecord) -> Value {
    let hash = blake3::hash(rec.id.as_bytes());
    let hex = hash.to_hex();
    let trace_id = &hex.as_str()[0..32];
    let span_id = &hex.as_str()[32..48];

    let start_ns = rec
        .timestamp
        .timestamp_nanos_opt()
        .unwrap_or(0)
        .max(0) as u64;
    let end_ns = start_ns.saturating_add(rec.duration_ms.saturating_mul(1_000_000));

    let (status_code, status_msg) = match rec.outcome {
        CallOutcome::Allowed | CallOutcome::Cached => (1, ""),
        CallOutcome::Denied => (
            2,
            rec.error_message
                .as_deref()
                .unwrap_or("denied by policy"),
        ),
        CallOutcome::Error => (2, rec.error_message.as_deref().unwrap_or("upstream error")),
    };

    let mut attributes = vec![
        attr_str("mcp.server", &rec.server),
        attr_str("mcp.tool", &rec.tool),
        attr_str("mcp.tool.namespaced", &rec.namespaced_tool),
        attr_str("aegis.outcome", &rec.outcome.to_string()),
        attr_bool("aegis.cache_hit", rec.cache_hit),
        attr_int("aegis.redaction_count", rec.redaction_count as i64),
    ];

    if let Some(rule) = &rec.policy_rule {
        attributes.push(attr_str("aegis.policy_rule", rule));
    }

    json!({
        "traceId": trace_id,
        "spanId": span_id,
        "name": format!("mcp.tools/call {}", rec.namespaced_tool),
        "kind": 3, // SPAN_KIND_CLIENT
        "startTimeUnixNano": start_ns.to_string(),
        "endTimeUnixNano": end_ns.to_string(),
        "attributes": attributes,
        "status": {
            "code": status_code,
            "message": status_msg
        }
    })
}

fn attr_str(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

fn attr_bool(key: &str, value: bool) -> Value {
    json!({ "key": key, "value": { "boolValue": value } })
}

fn attr_int(key: &str, value: i64) -> Value {
    json!({ "key": key, "value": { "intValue": value.to_string() } })
}
