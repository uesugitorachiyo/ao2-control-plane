//! Shared HTTP caching helpers for content-addressed observer endpoints.
//!
//! Every GET that resolves to a SHA-256-content-addressed payload can emit a
//! strong ETag (the quoted sha256) plus `Cache-Control: public, max-age=60,
//! must-revalidate`, and answer `If-None-Match` with `304 Not Modified` —
//! which short-circuits before the disk read. The same helpers back the
//! corresponding `HEAD` handlers.
//!
//! Originally extracted from `handlers::provider_registry` so the
//! evidence-pack, acceptance, memory-export, release-publication,
//! release-evaluator-decision, provider-readiness, phase1-promotion-decision,
//! phase1-promotion-checklist, phase1-three-os-smoke and signature
//! endpoints can share one tested implementation.

use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::error::AppError;

/// Conservative, registry-parity caching directive. Pollers learn within
/// 60 s that a newer artifact exists, and `must-revalidate` keeps
/// downstream caches from serving the old body once it has expired.
pub const CACHE_CONTROL_REVALIDATE: &str = "public, max-age=60, must-revalidate";

/// Rejects anything that is not a 64-char lower/upper-case hex sha256.
/// Matches the validation rule each handler used inline previously.
pub fn validate_sha(sha: &str) -> Result<(), AppError> {
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid sha256".into()));
    }
    Ok(())
}

/// Strong RFC-7232 ETag = quoted hex sha256.
pub fn format_etag(sha: &str) -> String {
    format!("\"{sha}\"")
}

/// True if the request's `If-None-Match` lists this etag (or `*`).
/// Comma-separated lists are tolerated per spec.
pub fn etag_matches(headers: &HeaderMap, etag: &str) -> bool {
    let Some(v) = headers.get(header::IF_NONE_MATCH) else {
        return false;
    };
    let Ok(value) = v.to_str() else {
        return false;
    };
    value
        .split(',')
        .map(str::trim)
        .any(|c| c == etag || c == "*")
}

/// 304 No Content with the ETag and Cache-Control echoed so downstream
/// caches can extend their lease without re-checking immediately.
pub fn not_modified_response(etag: &str) -> Response {
    (
        StatusCode::NOT_MODIFIED,
        [
            (header::ETAG, etag),
            (header::CACHE_CONTROL, CACHE_CONTROL_REVALIDATE),
        ],
        (),
    )
        .into_response()
}

/// 200 OK with ETag + Cache-Control + JSON body — the default
/// content-addressed-GET shape.
pub fn cacheable_json_response(etag: &str, bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::ETAG, etag),
            (header::CACHE_CONTROL, CACHE_CONTROL_REVALIDATE),
        ],
        bytes,
    )
        .into_response()
}

/// 200 OK with ETag + Cache-Control but no body — the HEAD shape.
pub fn cacheable_head_response(etag: &str) -> Response {
    (
        StatusCode::OK,
        [
            (header::ETAG, etag),
            (header::CACHE_CONTROL, CACHE_CONTROL_REVALIDATE),
        ],
        (),
    )
        .into_response()
}

/// Combined `validate_sha` + `If-None-Match` short-circuit. Returns
/// `Some(304_response)` if the client already has the body cached. The
/// caller continues to its disk-read path only on `None`.
pub fn check_if_none_match(sha: &str, headers: &HeaderMap) -> Result<Option<Response>, AppError> {
    validate_sha(sha)?;
    let etag = format_etag(sha);
    if etag_matches(headers, &etag) {
        return Ok(Some(not_modified_response(&etag)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn etag_format_is_quoted_hex() {
        let sha = "a".repeat(64);
        assert_eq!(format_etag(&sha), format!("\"{sha}\""));
    }

    #[test]
    fn validate_sha_rejects_short_or_non_hex() {
        assert!(validate_sha("short").is_err());
        assert!(validate_sha(&"z".repeat(64)).is_err());
        assert!(validate_sha(&"f".repeat(64)).is_ok());
        assert!(validate_sha(&"F".repeat(64)).is_ok()); // tolerate uppercase
    }

    #[test]
    fn etag_matches_exact_list_and_wildcard() {
        let sha = "a".repeat(64);
        let etag = format_etag(&sha);
        let mut h = HeaderMap::new();

        // exact
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());
        assert!(etag_matches(&h, &etag));

        // wildcard
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(etag_matches(&h, &etag));

        // comma list with the right one in it
        let listed = format!("\"{}\", {etag}, \"{}\"", "b".repeat(64), "c".repeat(64));
        h.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_str(&listed).unwrap(),
        );
        assert!(etag_matches(&h, &etag));

        // no header
        let h_empty = HeaderMap::new();
        assert!(!etag_matches(&h_empty, &etag));

        // wrong etag
        h.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_str(&format_etag(&"d".repeat(64))).unwrap(),
        );
        assert!(!etag_matches(&h, &etag));
    }
}
