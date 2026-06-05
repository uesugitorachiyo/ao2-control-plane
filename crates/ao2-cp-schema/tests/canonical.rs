use ao2_cp_schema::canonical::{canonical_json, sha256_of_canonical};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
struct CanonicalVectorSet {
    algorithm: String,
    vectors: Vec<CanonicalVector>,
}

#[derive(Debug, Deserialize)]
struct CanonicalVector {
    name: String,
    input: serde_json::Value,
    canonical: String,
    sha256: String,
}

#[test]
fn ao2_canonical_v1_matches_shared_golden_vectors() {
    let vectors: CanonicalVectorSet = serde_json::from_str(include_str!(
        "../../../tests/fixtures/canonical-json-vectors.json"
    ))
    .expect("canonical vector fixture parses");
    assert_eq!(vectors.algorithm, "ao2-canonical-v1");
    assert!(!vectors.vectors.is_empty());

    for vector in vectors.vectors {
        let canonical = canonical_json(&vector.input).unwrap();
        assert_eq!(canonical, vector.canonical, "{}", vector.name);
        assert_eq!(
            sha256_of_canonical(&vector.input).unwrap(),
            vector.sha256,
            "{}",
            vector.name
        );
    }
}

#[test]
fn sorts_object_keys() {
    let v = json!({"b": 1, "a": 2});
    assert_eq!(canonical_json(&v).unwrap(), r#"{"a":2,"b":1}"#);
}

#[test]
fn no_whitespace() {
    let v = json!({"a": [1, 2, 3], "b": {"c": "d"}});
    let canon = canonical_json(&v).unwrap();
    assert!(!canon.contains(' '));
    assert!(!canon.contains('\n'));
}

#[test]
fn sha256_is_deterministic() {
    let a = json!({"x": 1, "y": 2});
    let b = json!({"y": 2, "x": 1});
    assert_eq!(
        sha256_of_canonical(&a).unwrap(),
        sha256_of_canonical(&b).unwrap()
    );
}

#[test]
fn sha256_is_64_hex_chars() {
    let v = json!({"hello": "world"});
    let h = sha256_of_canonical(&v).unwrap();
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn handles_nested_arrays_and_objects() {
    let v = json!({
        "outer": {
            "inner": [3, 1, 2],
            "another": {"z": 9, "a": 1}
        }
    });
    let canon = canonical_json(&v).unwrap();
    assert_eq!(
        canon,
        r#"{"outer":{"another":{"a":1,"z":9},"inner":[3,1,2]}}"#
    );
}
