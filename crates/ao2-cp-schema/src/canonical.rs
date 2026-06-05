use serde_json::Value;
use sha2::{Digest, Sha256};

/// Serialize a JSON value to AO2 canonical JSON v1 (`ao2-canonical-v1`).
///
/// This is the existing AO2 content-addressing contract: sorted object keys,
/// no whitespace, serde_json number formatting, and JSON-minimal string
/// escaping. It is intentionally pinned by golden vectors and must not be
/// "corrected" toward RFC 8785/JCS without an explicit content-address
/// migration.
pub fn canonical_json(value: &Value) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    write_value(&mut out, value);
    Ok(out)
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_string(out, s),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, &map[*k]);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Compute SHA-256 of the AO2 canonical JSON v1 representation, hex-encoded.
pub fn sha256_of_canonical(value: &Value) -> Result<String, serde_json::Error> {
    let canon = canonical_json(value)?;
    let mut hasher = Sha256::new();
    hasher.update(canon.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}
