use ao2_cp_schema::control_plane::{is_control_plane_bundle_schema, parse_control_plane_bundle};

const FIXTURE: &str = include_str!("../../../tests/fixtures/control-plane-bundle-sample.json");

#[test]
fn parses_fixture() {
    let bundle = parse_control_plane_bundle(FIXTURE).expect("must parse");
    assert_eq!(bundle.schema_version, "ao2.control-plane-fleet-bundle.v1");
}

#[test]
fn schema_check_recognizes_v1() {
    assert!(is_control_plane_bundle_schema(
        "ao2.control-plane-fleet-bundle.v1"
    ));
    assert!(!is_control_plane_bundle_schema(
        "ao2.codex-provider-pilot-acceptance.v1"
    ));
    assert!(!is_control_plane_bundle_schema("ao2.unknown.v1"));
}

#[test]
fn rejects_unknown_schema_version() {
    let bad = r#"{"schema_version":"ao2.other.v1"}"#;
    let err = parse_control_plane_bundle(bad).expect_err("must fail");
    assert!(
        err.to_string().contains("schema_version")
            || err
                .to_string()
                .contains("ao2.control-plane-fleet-bundle.v1")
    );
}
