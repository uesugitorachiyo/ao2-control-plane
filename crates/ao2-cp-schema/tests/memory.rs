use ao2_cp_schema::memory::{is_memory_export_schema, parse_memory_export};

const FIXTURE: &str = include_str!("../../../tests/fixtures/memory-export-sample.json");

#[test]
fn parses_fixture() {
    let export = parse_memory_export(FIXTURE).unwrap();

    assert_eq!(export.schema_version, "ao2.memory-export.v1");
    assert_eq!(export.record_count, 1);
    assert_eq!(export.link_count, 1);
    assert_eq!(export.records.len(), 1);
    assert_eq!(export.links.len(), 1);
}

#[test]
fn schema_check_recognizes_v1() {
    assert!(is_memory_export_schema("ao2.memory-export.v1"));
    assert!(!is_memory_export_schema(
        "ao2.control-plane-fleet-bundle.v1"
    ));
}

#[test]
fn rejects_unknown_schema_version() {
    let err = parse_memory_export(r#"{"schema_version":"ao2.memory-export.v0"}"#).unwrap_err();

    assert!(err.to_string().contains("expected schema_version"));
}

#[test]
fn rejects_count_mismatch() {
    let err = parse_memory_export(
        r#"{"schema_version":"ao2.memory-export.v1","record_count":2,"records":[]}"#,
    )
    .unwrap_err();

    assert!(err.to_string().contains("record_count"));
}
