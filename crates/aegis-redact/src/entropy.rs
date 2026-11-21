/// Computes the Shannon entropy (bits per byte) of an ASCII/UTF-8 token.
pub fn shannon_entropy(input: &str) -> f64 {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Scans `input` for high-entropy secret-like tokens and masks them with `[REDACTED:high_entropy]`.
/// Returns `(output, redacted_count)`.
pub fn redact_high_entropy(
    input: &str,
    threshold: f64,
    min_length: usize,
    allowlist: &[String],
) -> (String, u64) {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut count = 0u64;
    let mut i = 0;

    while i < bytes.len() {
        if !is_token_byte(bytes[i]) {
            if let Some(ch) = input[i..].chars().next() {
                out.push(ch);
                i += ch.len_utf8();
            } else {
                break;
            }
            continue;
        }

        let start = i;
        while i < bytes.len() && is_token_byte(bytes[i]) {
            i += 1;
        }
        let token = &input[start..i];

        if should_redact_entropy_token(token, threshold, min_length, allowlist) {
            out.push_str("[REDACTED:high_entropy]");
            count += 1;
        } else {
            out.push_str(token);
        }
    }

    (out, count)
}

#[inline]
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'/' | b'.')
}

fn should_redact_entropy_token(
    token: &str,
    threshold: f64,
    min_length: usize,
    allowlist: &[String],
) -> bool {
    if token.len() < min_length {
        return false;
    }

    // Never touch existing redaction markers or allowlisted substrings
    if token.contains("REDACTED") {
        return false;
    }
    if allowlist
        .iter()
        .any(|allowed| !allowed.is_empty() && token.contains(allowed.as_str()))
    {
        return false;
    }

    // Skip obvious file paths, domain-like dotted identifiers, and UUIDs
    if looks_like_path_or_url(token) || looks_like_uuid(token) {
        return false;
    }

    // Require character class diversity (at least 3 of: lower, upper, digit, symbol)
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_sym = false;
    for b in token.bytes() {
        if b.is_ascii_lowercase() {
            has_lower = true;
        } else if b.is_ascii_uppercase() {
            has_upper = true;
        } else if b.is_ascii_digit() {
            has_digit = true;
        } else {
            has_sym = true;
        }
    }
    let classes = (has_lower as u8) + (has_upper as u8) + (has_digit as u8) + (has_sym as u8);
    if classes < 3 {
        return false;
    }

    shannon_entropy(token) >= threshold
}

fn looks_like_path_or_url(token: &str) -> bool {
    if token.starts_with('/') || token.starts_with("./") || token.starts_with("../") {
        return true;
    }
    // Multiple path segments with lowercase ASCII words (e.g. `crates/aegis-core/src/lib.rs`)
    if token.matches('/').count() >= 2 {
        let lower_alpha = token.bytes().filter(|b| b.is_ascii_lowercase()).count();
        if lower_alpha * 2 > token.len() {
            return true;
        }
    }
    // Dotted package/module names like `com.example.SomeLongClassName`
    if token.matches('.').count() >= 2 && !token.contains('+') && !token.contains('=') {
        let digit_count = token.bytes().filter(|b| b.is_ascii_digit()).count();
        if digit_count <= 2 {
            return true;
        }
    }
    false
}

fn looks_like_uuid(token: &str) -> bool {
    let b = token.as_bytes();
    if b.len() != 36 {
        return false;
    }
    if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return false;
    }
    b.iter()
        .enumerate()
        .all(|(idx, ch)| matches!(idx, 8 | 13 | 18 | 23) || ch.is_ascii_hexdigit())
}
