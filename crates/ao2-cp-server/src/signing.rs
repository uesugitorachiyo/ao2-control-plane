//! Centralized SHA-256 hashing and RSA-SHA256 signature verification for the
//! control plane's signed-artifact ingest paths.
//!
//! Every handler that ingests a signed provider/evaluator artifact
//! (provider readiness, provider registry, phase-1 promotion, evidence pack,
//! memory export, release-evaluator decision) verifies the signature and hashes
//! the signing material. That logic used to be copy-pasted into each handler,
//! which meant the security-critical verification path had to be audited in six
//! places and could silently drift. It now lives here, audited once.
//!
//! Both entry points are total: every failure mode is returned as an
//! `AppError`, never a panic. A read-only observer must never be able to crash
//! on a crafted artifact.

use crate::error::AppError;
use rsa::pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use signature::Verifier;

/// Minimum accepted RSA modulus size (bits). Keys below this are rejected
/// during verification regardless of signature validity.
const MIN_RSA_KEY_BITS: usize = 2048;

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Verify an RSA PKCS#1 v1.5 SHA-256 signature over `message` with the given
/// PEM-encoded public key.
///
/// Returns `Ok(())` only when the signature is cryptographically valid. Every
/// failure — an unparseable PEM key, a malformed signature, or a signature that
/// does not match — is mapped to `AppError::SchemaInvalid` with a diagnostic
/// message. Callers layer trust-anchor / key-pinning policy on top of this; this
/// function answers only "is the signature itself valid?".
pub fn verify_rsa_sha256_signature(
    message: &[u8],
    signature_bytes: &[u8],
    public_key_pem: &str,
) -> Result<(), AppError> {
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| AppError::SchemaInvalid(format!("public_key_pem is invalid: {e}")))?;
    // Enforce a modern modulus floor before trusting the signature. A short
    // (e.g. 512/1024-bit) key still produces a "valid" signature, so without
    // this floor a self-signer could present a brute-forceable key as verified.
    // `size()` is the modulus length in bytes; ×8 is the bit length.
    let key_bits = public_key.size() * 8;
    if key_bits < MIN_RSA_KEY_BITS {
        return Err(AppError::SchemaInvalid(format!(
            "RSA public key is {key_bits} bits; the minimum accepted is {MIN_RSA_KEY_BITS}"
        )));
    }
    let signature = RsaPkcs1v15Signature::try_from(signature_bytes).map_err(|e| {
        AppError::SchemaInvalid(format!("signature_hex is not a valid RSA signature: {e}"))
    })?;
    VerifyingKey::<Sha256>::new(public_key)
        .verify(message, &signature)
        .map_err(|e| AppError::SchemaInvalid(format!("signature verification failed: {e}")))
}

/// Annotate a cryptographically-verified signature object with trust-anchor
/// classification, in place.
///
/// `signature_verified: true` means only "the RSA signature is cryptographically
/// valid" — it says nothing about *who* signed. Authority comes from key pinning:
/// `release_authoritative` is true only when the signing key's SHA-256 appears in
/// the operator-configured `trusted_key_sha256s` allowlist. A self-asserted
/// (unpinned) key verifies but is recorded as `cryptographic-only` /
/// `release_authoritative: false`, so a token holder cannot drive a
/// release-authoritative display by self-signing with an arbitrary key.
///
/// The public key PEM is read from the signature object's own `public_key_pem`
/// field (the same value that was just verified). This mirrors the established
/// provider-readiness / release-publication trust-anchor classification so every
/// signed-ingest surface reports the same shape.
pub fn annotate_trust_policy(signature: &mut serde_json::Value, trusted_key_sha256s: &[String]) {
    let public_key_sha256 = signature
        .get("public_key_pem")
        .and_then(serde_json::Value::as_str)
        .map(|pem| sha256_hex(pem.as_bytes()))
        .unwrap_or_default();
    let trusted_key_match = !public_key_sha256.is_empty()
        && trusted_key_sha256s
            .iter()
            .any(|trusted| trusted.eq_ignore_ascii_case(&public_key_sha256));
    let (verification_scope, trust_anchor, policy, matched_public_key_sha256) = if trusted_key_match
    {
        (
            "cryptographic-and-pinned-key",
            "configured-signed-artifact-public-key-sha256",
            "pinned-public-key-sha256",
            public_key_sha256.as_str(),
        )
    } else {
        (
            "cryptographic-only",
            "upload-public-key-not-authority",
            "observer-only-upload-key",
            "",
        )
    };

    signature["signature_verified"] = serde_json::json!(true);
    signature["public_key_sha256"] = serde_json::json!(public_key_sha256);
    signature["verification_scope"] = serde_json::json!(verification_scope);
    signature["trust_anchor"] = serde_json::json!(trust_anchor);
    signature["trust_policy"] = serde_json::json!({
        "policy": policy,
        "trusted_key_match": trusted_key_match,
        "release_authoritative": trusted_key_match,
        "matched_public_key_sha256": matched_public_key_sha256
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::RsaPrivateKey;
    use signature::{SignatureEncoding, Signer};

    #[test]
    fn sha256_hex_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let digest = sha256_hex(b"control-plane");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    fn keypair() -> (String, rsa::pkcs1v15::SigningKey<Sha256>) {
        let mut rng = rsa::rand_core::OsRng;
        let signing_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key");
        let public_key_pem = signing_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode test public key");
        (
            public_key_pem,
            rsa::pkcs1v15::SigningKey::<Sha256>::new(signing_key),
        )
    }

    #[test]
    fn verify_round_trips_for_a_valid_signature() {
        let (pem, signer) = keypair();
        let message = b"a signed artifact body";
        let signature = signer.sign(message).to_vec();
        assert!(verify_rsa_sha256_signature(message, &signature, &pem).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message_and_garbage_signatures() {
        let (pem, signer) = keypair();
        let signature = signer.sign(b"original").to_vec();

        assert!(verify_rsa_sha256_signature(b"tampered", &signature, &pem).is_err());
        assert!(verify_rsa_sha256_signature(b"original", &[0u8; 7], &pem).is_err());
        assert!(verify_rsa_sha256_signature(b"original", &[], &pem).is_err());
    }

    #[test]
    fn verify_rejects_invalid_public_key_pem() {
        assert!(verify_rsa_sha256_signature(b"m", &[0u8; 256], "not a pem").is_err());
        assert!(verify_rsa_sha256_signature(b"m", &[0u8; 256], "").is_err());
        let bogus = "-----BEGIN PUBLIC KEY-----\nnotbase64!!!\n-----END PUBLIC KEY-----\n";
        assert!(verify_rsa_sha256_signature(b"m", &[0u8; 256], bogus).is_err());
    }

    #[test]
    fn verify_rejects_keys_below_the_2048_bit_floor() {
        // A 1024-bit key produces a cryptographically valid signature, but is
        // below the modern strength floor. Accepting it would let a self-signer
        // (see the trust-anchor handlers) present a brute-forceable key as a
        // "verified" signature. Verification must reject it before checking the
        // signature itself.
        let mut rng = rsa::rand_core::OsRng;
        let weak = RsaPrivateKey::new(&mut rng, 1024).expect("generate weak test RSA key");
        let pem = weak
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode weak public key");
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(weak);
        let message = b"a body signed with a 1024-bit key";
        let signature = signer.sign(message).to_vec();
        assert!(
            verify_rsa_sha256_signature(message, &signature, &pem).is_err(),
            "a 1024-bit RSA key must be rejected even though its signature is otherwise valid"
        );
    }

    fn signature_object(public_key_pem: &str) -> serde_json::Value {
        serde_json::json!({
            "signer_id": "release-lead",
            "public_key_pem": public_key_pem,
        })
    }

    #[test]
    fn annotate_marks_unpinned_key_as_observer_only() {
        let (pem, _signer) = keypair();
        let mut signature = signature_object(&pem);
        // No trust anchor configured.
        annotate_trust_policy(&mut signature, &[]);

        // The signature is still recorded as cryptographically verified — we
        // do not lie about the crypto check.
        assert_eq!(signature["signature_verified"], true);
        assert_eq!(signature["public_key_sha256"], sha256_hex(pem.as_bytes()));
        // ...but it carries no release authority.
        assert_eq!(signature["verification_scope"], "cryptographic-only");
        assert_eq!(signature["trust_anchor"], "upload-public-key-not-authority");
        assert_eq!(signature["trust_policy"]["trusted_key_match"], false);
        assert_eq!(signature["trust_policy"]["release_authoritative"], false);
        assert_eq!(signature["trust_policy"]["matched_public_key_sha256"], "");
    }

    #[test]
    fn annotate_marks_pinned_key_as_release_authoritative() {
        let (pem, _signer) = keypair();
        let pinned = sha256_hex(pem.as_bytes());
        let mut signature = signature_object(&pem);
        annotate_trust_policy(&mut signature, std::slice::from_ref(&pinned));

        assert_eq!(signature["signature_verified"], true);
        assert_eq!(
            signature["verification_scope"],
            "cryptographic-and-pinned-key"
        );
        assert_eq!(
            signature["trust_anchor"],
            "configured-signed-artifact-public-key-sha256"
        );
        assert_eq!(signature["trust_policy"]["trusted_key_match"], true);
        assert_eq!(signature["trust_policy"]["release_authoritative"], true);
        assert_eq!(
            signature["trust_policy"]["matched_public_key_sha256"],
            pinned
        );
    }

    #[test]
    fn annotate_pin_match_is_case_insensitive() {
        let (pem, _signer) = keypair();
        let pinned_upper = sha256_hex(pem.as_bytes()).to_ascii_uppercase();
        let mut signature = signature_object(&pem);
        annotate_trust_policy(&mut signature, &[pinned_upper]);
        assert_eq!(signature["trust_policy"]["release_authoritative"], true);
    }

    #[test]
    fn annotate_without_public_key_pem_is_never_authoritative() {
        // A signature object missing public_key_pem yields an empty digest.
        // The empty digest must NEVER match — not even against an allowlist
        // that (incorrectly) contained an empty string — and must never be
        // release-authoritative.
        let mut signature = serde_json::json!({ "signer_id": "release-lead" });
        annotate_trust_policy(&mut signature, &[String::new(), "deadbeef".to_string()]);
        assert_eq!(signature["public_key_sha256"], "");
        assert_eq!(signature["verification_scope"], "cryptographic-only");
        assert_eq!(signature["trust_policy"]["trusted_key_match"], false);
        assert_eq!(signature["trust_policy"]["release_authoritative"], false);
    }
}
