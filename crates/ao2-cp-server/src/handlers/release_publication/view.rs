pub(super) fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

pub(super) fn json_str_obj<'a>(
    value: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

pub(super) fn json_scalar(value: &serde_json::Value) -> String {
    if let Some(s) = value.as_str() {
        s.to_string()
    } else if let Some(b) = value.as_bool() {
        b.to_string()
    } else if let Some(n) = value.as_i64() {
        n.to_string()
    } else {
        value.to_string()
    }
}

pub(super) fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_scalar_formats_simple_values_for_html_tables() {
        assert_eq!(json_scalar(&serde_json::json!("ready")), "ready");
        assert_eq!(json_scalar(&serde_json::json!(false)), "false");
        assert_eq!(json_scalar(&serde_json::json!(42)), "42");
        assert_eq!(
            json_scalar(&serde_json::json!({"status": "ready"})),
            "{\"status\":\"ready\"}"
        );
    }

    #[test]
    fn escape_html_escapes_text_inserted_into_dashboard_markup() {
        assert_eq!(
            escape_html("<tag attr=\"one\">Tom & 'AO2'</tag>"),
            "&lt;tag attr=&quot;one&quot;&gt;Tom &amp; &#39;AO2&#39;&lt;/tag&gt;"
        );
    }

    #[test]
    fn json_str_helpers_return_only_string_fields() {
        let value = serde_json::json!({
            "status": "passed",
            "count": 3,
        });
        assert_eq!(json_str(&value, "status"), Some("passed"));
        assert_eq!(json_str(&value, "count"), None);

        let object = value.as_object().expect("test value is object");
        assert_eq!(json_str_obj(object, "status"), Some("passed"));
        assert_eq!(json_str_obj(object, "count"), None);
    }
}
