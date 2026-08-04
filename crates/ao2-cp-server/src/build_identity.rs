#[used]
static AO2_CP_RUST_BUILD_PROVENANCE_MARKER: &str = concat!(
    "AO_RUST_BUILD_PROVENANCE_V1\0",
    "{\"build_profile\":\"",
    env!("AO2_CP_BUILD_PROFILE"),
    "\",\"cargo_lock_sha256\":\"",
    env!("AO2_CP_CARGO_LOCK_SHA256"),
    "\",\"repository\":\"ao2-control-plane\",\"source_sha\":\"",
    env!("AO2_CP_GIT_COMMIT"),
    "\",\"source_modified\":",
    env!("AO2_CP_SOURCE_MODIFIED"),
    ",\"target\":\"",
    env!("AO2_CP_BUILD_TARGET"),
    "\",\"version\":\"",
    env!("CARGO_PKG_VERSION"),
    "\"}\0"
);

pub fn rust_build_provenance_marker() -> &'static str {
    AO2_CP_RUST_BUILD_PROVENANCE_MARKER
}

#[cfg(test)]
mod tests {
    use super::rust_build_provenance_marker;

    #[test]
    fn embedded_rust_provenance_is_strictly_bound() {
        let marker = rust_build_provenance_marker();
        let payload = marker
            .strip_prefix("AO_RUST_BUILD_PROVENANCE_V1\0")
            .and_then(|value| value.strip_suffix('\0'))
            .expect("bounded marker");
        let value: serde_json::Value = serde_json::from_str(payload).expect("marker JSON");
        assert_eq!(value["repository"], "ao2-control-plane");
        assert_eq!(value["source_sha"].as_str().map(str::len), Some(40));
        assert_eq!(value["cargo_lock_sha256"].as_str().map(str::len), Some(64));
        assert!(value["source_modified"].is_boolean());
        assert!(!value["target"].as_str().unwrap_or_default().is_empty());
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    }
}
