//! Property tests for the AO2 canonical JSON v1 core.
//!
//! `canonical_json` / `sha256_of_canonical` are the bedrock of two
//! security-critical mechanisms: content-addressed storage (the SHA-256 of the
//! canonical form is the artifact's identity) and signature verification (the
//! bytes that get signed/verified are the canonical form). The existing tests
//! pin a handful of hand-written examples; these pin the *invariants* over
//! arbitrarily-shaped JSON:
//!
//! - **Semantic fidelity** — the canonical string is always valid JSON that
//!   parses back to a value equal to the input. This is what catches string
//!   escaping bugs (control chars, quotes, backslashes) that a fixed example
//!   set would miss.
//! - **Fixed point** — canonicalizing an already-canonical value is a no-op.
//!   Equal-by-value inputs therefore always produce identical bytes, which is
//!   what makes the SHA a stable identity.
//! - **Digest stability and sensitivity** — the digest is deterministic, is
//!   64 lowercase hex chars, is invariant under object-key reordering, and
//!   changes when content is added. A digest that ignored a field would let
//!   two distinct artifacts collide on one content address.

use ao2_cp_schema::canonical::{canonical_json, sha256_of_canonical};
use proptest::prelude::*;
use serde_json::{Map, Value};

/// Strategy for arbitrarily-shaped JSON values. Numbers are restricted to
/// i64 so equality is exact (float formatting round-trips are a separate
/// concern, not what these invariants are about); strings are unrestricted
/// `String`s, so control characters, quotes, and backslashes are exercised.
fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| Value::Number(n.into())),
        any::<String>().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::hash_map(any::<String>(), inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    /// The canonical form is always valid JSON that means the same thing as
    /// the input. Exercises every escaping branch in `write_string`.
    #[test]
    fn canonical_is_valid_json_and_semantically_equal(v in arb_json()) {
        let canon = canonical_json(&v).unwrap();
        let reparsed: Value = serde_json::from_str(&canon)
            .expect("canonical output must be parseable JSON");
        prop_assert_eq!(reparsed, v);
    }

    /// Canonicalizing an already-canonical value yields the identical string.
    /// This is the property that makes the digest a stable identity: any two
    /// value-equal inputs collapse to the same bytes.
    #[test]
    fn canonical_is_a_fixed_point(v in arb_json()) {
        let once = canonical_json(&v).unwrap();
        let reparsed: Value = serde_json::from_str(&once).unwrap();
        let twice = canonical_json(&reparsed).unwrap();
        prop_assert_eq!(once, twice);
    }

    /// The digest is deterministic and well-formed (64 lowercase hex chars).
    #[test]
    fn digest_is_deterministic_and_well_formed(v in arb_json()) {
        let a = sha256_of_canonical(&v).unwrap();
        let b = sha256_of_canonical(&v).unwrap();
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(a.len(), 64);
        prop_assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// Object-key insertion order never affects the canonical form or the
    /// digest: the canonicalizer sorts keys itself. (Generated from a map so
    /// keys are unique — with duplicate keys, last-write-wins would make order
    /// matter, which is correct JSON-object semantics, not a canonicalizer
    /// property.)
    #[test]
    fn key_insertion_order_does_not_change_canonical(
        entries in prop::collection::hash_map(any::<String>(), any::<i64>(), 0..8)
    ) {
        let pairs: Vec<(String, i64)> = entries.into_iter().collect();
        let mut forward = Map::new();
        for (k, n) in &pairs {
            forward.insert(k.clone(), Value::Number((*n).into()));
        }
        let mut reverse = Map::new();
        for (k, n) in pairs.iter().rev() {
            reverse.insert(k.clone(), Value::Number((*n).into()));
        }
        let a = Value::Object(forward);
        let b = Value::Object(reverse);
        prop_assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
        prop_assert_eq!(
            sha256_of_canonical(&a).unwrap(),
            sha256_of_canonical(&b).unwrap()
        );
    }

    /// Adding a field changes both the canonical form and the digest. A digest
    /// that ignored content would let distinct artifacts share a content
    /// address — the core invariant of content-addressed storage.
    #[test]
    fn adding_a_field_changes_the_digest(
        base in prop::collection::hash_map(any::<String>(), any::<i64>(), 0..6),
        new_key in any::<String>(),
    ) {
        prop_assume!(!base.contains_key(&new_key));

        let mut obj = Map::new();
        for (k, n) in &base {
            obj.insert(k.clone(), Value::Number((*n).into()));
        }
        let original = Value::Object(obj.clone());

        obj.insert(new_key, Value::Number(0.into()));
        let extended = Value::Object(obj);

        prop_assert_ne!(
            canonical_json(&original).unwrap(),
            canonical_json(&extended).unwrap()
        );
        prop_assert_ne!(
            sha256_of_canonical(&original).unwrap(),
            sha256_of_canonical(&extended).unwrap()
        );
    }
}

/// Targeted check that the escaping table in `write_string` round-trips every
/// special character it handles. Complements the property test with an
/// explicit, readable enumeration of the cases that matter most.
#[test]
fn control_and_special_characters_round_trip() {
    let nasty = "quote:\" backslash:\\ newline:\n tab:\t cr:\r bs:\u{08} ff:\u{0c} nul:\u{00} unit:\u{1f} emoji:😀";
    let value = serde_json::json!({ "k": nasty });
    let canon = canonical_json(&value).unwrap();
    let reparsed: Value = serde_json::from_str(&canon).unwrap();
    assert_eq!(reparsed["k"], nasty);
}
