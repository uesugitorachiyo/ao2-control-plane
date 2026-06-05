//! Unit coverage for the content-addressed caching response constructors.
//!
//! `caching.rs` already unit-tests the pure predicates (`format_etag`,
//! `validate_sha`, `etag_matches`). What was only exercised indirectly through
//! endpoint tests is the *response shape* — and those shapes are an HTTP
//! correctness contract:
//!
//!   - a `304` must carry the ETag + Cache-Control (so a downstream cache can
//!     extend its lease) and MUST NOT carry a body;
//!   - the HEAD response must be header-identical to a GET but bodyless;
//!   - `check_if_none_match` is the branch that decides whether the expensive
//!     disk read is skipped: invalid sha → 400, client already current → 304,
//!     otherwise fall through (`None`).
//!
//! A regression here (a 304 with a body, a HEAD that leaks a body, a missing
//! Cache-Control, or a mis-wired short-circuit) would be silent at compile time
//! and invisible to the existing happy-path endpoint tests.

use ao2_cp_server::error::AppError;
use ao2_cp_server::handlers::caching::{
    cacheable_head_response, cacheable_json_response, check_if_none_match, format_etag,
    not_modified_response, CACHE_CONTROL_REVALIDATE,
};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::Response;

fn etag() -> String {
    format_etag(&"a".repeat(64))
}

async fn body_bytes(resp: Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body must be readable")
        .to_vec()
}

#[tokio::test]
async fn not_modified_response_is_304_with_cache_headers_and_no_body() {
    let etag = etag();
    let resp = not_modified_response(&etag);

    assert_eq!(resp.status(), 304);
    assert_eq!(resp.headers().get(header::ETAG).unwrap(), etag.as_str());
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        CACHE_CONTROL_REVALIDATE
    );
    assert!(
        body_bytes(resp).await.is_empty(),
        "304 must not carry a body"
    );
}

#[tokio::test]
async fn cacheable_json_response_sets_content_type_etag_cache_control_and_body() {
    let etag = etag();
    let payload = br#"{"ok":true}"#.to_vec();
    let resp = cacheable_json_response(&etag, payload.clone());

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(resp.headers().get(header::ETAG).unwrap(), etag.as_str());
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        CACHE_CONTROL_REVALIDATE
    );
    assert_eq!(
        body_bytes(resp).await,
        payload,
        "body must be echoed verbatim"
    );
}

#[tokio::test]
async fn cacheable_head_response_matches_get_headers_but_has_no_body() {
    let etag = etag();
    let resp = cacheable_head_response(&etag);

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get(header::ETAG).unwrap(), etag.as_str());
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        CACHE_CONTROL_REVALIDATE
    );
    assert!(
        body_bytes(resp).await.is_empty(),
        "HEAD response must not carry a body"
    );
}

#[test]
fn check_if_none_match_rejects_an_invalid_sha() {
    // Guards the disk-read path: a malformed sha never reaches storage; it is
    // turned into a 400 before any lookup.
    let err = check_if_none_match("not-a-sha", &HeaderMap::new())
        .expect_err("invalid sha must be rejected");
    assert!(matches!(err, AppError::BadRequest(_)));
}

#[tokio::test]
async fn check_if_none_match_short_circuits_to_304_when_client_is_current() {
    let sha = "a".repeat(64);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::IF_NONE_MATCH,
        HeaderValue::from_str(&format_etag(&sha)).unwrap(),
    );

    let result = check_if_none_match(&sha, &headers).expect("valid sha must not error");
    let resp = result.expect("a matching If-None-Match must short-circuit to Some(304)");
    assert_eq!(resp.status(), 304);
}

#[test]
fn check_if_none_match_falls_through_when_no_etag_matches() {
    let sha = "a".repeat(64);

    // No If-None-Match header at all → fall through to the read path.
    assert!(check_if_none_match(&sha, &HeaderMap::new())
        .unwrap()
        .is_none());

    // A present-but-different etag → still fall through.
    let mut headers = HeaderMap::new();
    headers.insert(
        header::IF_NONE_MATCH,
        HeaderValue::from_str(&format_etag(&"b".repeat(64))).unwrap(),
    );
    assert!(check_if_none_match(&sha, &headers).unwrap().is_none());
}
