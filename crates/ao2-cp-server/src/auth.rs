use axum::{
    extract::{Query, Request, State},
    http::header,
    middleware::Next,
    response::Response,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::error::AppError;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub(crate) struct TokenQuery {
    token: Option<String>,
}

pub(crate) async fn require_token(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TokenQuery>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let header_token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    // The `?token=` query-param fallback exists ONLY for browser SSE:
    // an `EventSource` cannot set an `Authorization` header, so the
    // `/audit-log/stream` endpoint accepts the bearer in the query
    // string. Every other route must authenticate via the header.
    // Restricting the query path keeps the bearer out of query strings —
    // and therefore out of browser history, `Referer` headers, and
    // upstream proxy access logs — across the entire JSON API surface.
    // (`ends_with("/stream")` is robust to the `/api/v1` nest prefix
    // being stripped before this middleware sees the path.)
    let is_sse_stream = req.uri().path().ends_with("/stream");
    let query_token = if is_sse_stream { q.token } else { None };

    let provided = header_token.or(query_token);
    match provided {
        Some(t) if tokens_match(&t, &state.api_token) => Ok(next.run(req).await),
        _ => Err(AppError::Unauthorized),
    }
}

/// Constant-time bearer-token comparison.
///
/// A plain `provided == expected` short-circuits on the first differing byte,
/// leaking — via response timing — both the length of the secret and a
/// position-by-position oracle that enables byte-at-a-time token recovery under
/// the reverse-proxy / remote exposure SECURITY.md contemplates. We instead
/// SHA-256 both sides (collapsing them to a fixed 32 bytes, so length is not
/// leaked) and compare the digests with `subtle`'s constant-time equality. A
/// digest match implies a token match (a mismatch could only collide via a
/// SHA-256 preimage, which is infeasible).
fn tokens_match(provided: &str, expected: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    let provided_digest = Sha256::digest(provided.as_bytes());
    let expected_digest = Sha256::digest(expected.as_bytes());
    provided_digest.ct_eq(&expected_digest).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_match_accepts_identical_and_rejects_everything_else() {
        let token = "test-api-token-0123456789-abcdefgh";
        assert!(tokens_match(token, token), "identical tokens must match");
        assert!(
            !tokens_match(token, "a-completely-different-token-value!"),
            "different tokens must not match"
        );
        // Off-by-one (prefix) must not match — and the length-collapsing digest
        // means the comparison cannot early-out on the length difference.
        assert!(
            !tokens_match(token, "test-api-token-0123456789-abcdefg"),
            "a prefix of the token must not match"
        );
        assert!(!tokens_match("", token), "empty provided must not match");
        assert!(!tokens_match(token, ""), "empty expected must not match");
    }
}
