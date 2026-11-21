use serde_json::Value;

/// Produces deterministic, whitespace-free canonical JSON bytes with sorted object keys.
pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => {
            if let Ok(encoded) = serde_json::to_vec(s) {
                out.extend_from_slice(&encoded);
            }
        }
        Value::Array(items) => {
            out.push(b'[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (idx, key) in keys.into_iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                if let Ok(encoded_key) = serde_json::to_vec(key) {
                    out.extend_from_slice(&encoded_key);
                }
                out.push(b':');
                write_canonical(&map[key], out);
            }
            out.push(b'}');
        }
    }
}

/// Computes a deterministic 64-character hex BLAKE3 key for a tool call.
pub fn cache_key(server: &str, tool: &str, arguments: Option<&Value>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(server.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(tool.as_bytes());
    hasher.update(&[0u8]);
    match arguments {
        Some(v) => hasher.update(&canonical_json_bytes(v)),
        None => hasher.update(b"null"),
    };
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_is_canonical() {
        let a = json!({"b": 1, "a": {"z": true, "m": [1, 2]}});
        let b = json!({"a": {"m": [1, 2], "z": true}, "b": 1});
        assert_eq!(canonical_json_bytes(&a), canonical_json_bytes(&b));
        assert_eq!(
            cache_key("github", "list_issues", Some(&a)),
            cache_key("github", "list_issues", Some(&b))
        );
    }
}
