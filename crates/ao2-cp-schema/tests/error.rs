use ao2_cp_schema::error::{ControlPlaneError, ErrorCode};

#[test]
fn serializes_error_with_schema_version() {
    let err = ControlPlaneError::new(ErrorCode::Unauthorized, "missing token");
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["schema_version"], "ao2.control-plane-error.v1");
    assert_eq!(json["code"], "unauthorized");
    assert_eq!(json["message"], "missing token");
    assert!(json["request_id"].is_string());
}

#[test]
fn deserializes_error_back() {
    let raw = r#"{
        "schema_version": "ao2.control-plane-error.v1",
        "code": "schema_invalid",
        "message": "missing field provider",
        "request_id": "abc-123",
        "details": {"field": "provider"}
    }"#;
    let err: ControlPlaneError = serde_json::from_str(raw).unwrap();
    assert_eq!(err.code, ErrorCode::SchemaInvalid);
    assert_eq!(err.request_id, "abc-123");
}
