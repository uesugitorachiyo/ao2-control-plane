use ao2_cp_schema::acceptance::{parse_acceptance, AcceptanceProvider};

const CODEX_FIXTURE: &str = include_str!("../../../tests/fixtures/codex-acceptance-v0.4.66.json");
const CLAUDE_FIXTURE: &str = include_str!("../../../tests/fixtures/claude-acceptance-v0.4.66.json");
const TAMPERED_FIXTURE: &str = include_str!("../../../tests/fixtures/tampered-acceptance.json");

#[test]
fn parses_codex_fixture() {
    let bundle = parse_acceptance(CODEX_FIXTURE).expect("must parse");
    assert_eq!(bundle.provider, AcceptanceProvider::Codex);
    assert_eq!(
        bundle.schema_version,
        "ao2.codex-provider-pilot-acceptance.v1"
    );
    assert_eq!(bundle.status, "passed");
}

#[test]
fn parses_claude_fixture() {
    let bundle = parse_acceptance(CLAUDE_FIXTURE).expect("must parse");
    assert_eq!(bundle.provider, AcceptanceProvider::Claude);
    assert_eq!(
        bundle.schema_version,
        "ao2.claude-provider-pilot-acceptance.v1"
    );
    assert_eq!(bundle.status, "passed");
}

#[test]
fn rejects_provider_schema_mismatch() {
    let err = parse_acceptance(TAMPERED_FIXTURE).expect_err("must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("provider"),
        "error should mention provider, got: {msg}"
    );
}

#[test]
fn rejects_unknown_schema_version() {
    let bad = r#"{"schema_version":"ao2.unknown.v1","status":"passed","provider":"codex","run_id":"r","root":"/","target":"/","provider_prompt_file":"/","evidence_pack":"/","cockpit":"/","artifacts":{"doctor":"/","smoke":"/","pilot_plan":"/","run_stdout":"/","run_stderr":"/","replay":"/","score":"/","pytest":"/"},"smoke":{"history_entry_count":0,"history_path":"/","live_providers":[],"minimum_score":0,"providers":[]}}"#;
    let err = parse_acceptance(bad).expect_err("must fail");
    assert!(err.to_string().contains("schema_version"));
}

#[test]
fn parses_antigravity_raw_string() {
    let raw = r#"{"schema_version":"ao2.antigravity-provider-pilot-acceptance.v1","status":"passed","provider":"antigravity","run_id":"r","root":"/","target":"/","provider_prompt_file":"/","evidence_pack":"/","cockpit":"/","artifacts":{},"smoke":{}}"#;
    let bundle = parse_acceptance(raw).expect("must parse");
    assert_eq!(bundle.provider, AcceptanceProvider::Antigravity);
    assert_eq!(
        bundle.schema_version,
        "ao2.antigravity-provider-pilot-acceptance.v1"
    );
    assert_eq!(bundle.status, "passed");
}
