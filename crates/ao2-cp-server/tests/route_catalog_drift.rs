//! Drift guard between the machine-readable route catalog and the live router.
//!
//! `route_catalog::ROUTES` is what `/api/v1/control-plane/routes.json` serves to
//! operators and tooling: the authoritative, auth-required surface of the
//! observer. `build_router` is what actually answers requests. Nothing tied the
//! two together, so the catalog could silently drift — a handler wired into the
//! router but never advertised (an undocumented surface), or an advertised route
//! that no longer exists (a 404 for anyone who trusts the index). Either way the
//! published contract lies.
//!
//! This pins them to each other. It parses the `/api/v1` sub-router builders out
//! of `server.rs` at compile time (`include_str!`) and asserts the set of
//! `(method, path)` pairs they register is exactly the set the catalog
//! advertises — no router route unadvertised, no advertised route missing from
//! the router.
//!
//! Scope is deliberate: only the `let`-bound `/api/v1` (authenticated) builders
//! are compared — both the main `api_v1` chain and the `api_v1_stream` sub-router
//! that carries the audit-log SSE stream (split out so the long-lived response
//! escapes the timeout/concurrency layers). The two unauthenticated top-level
//! routes (`/healthz`, `/readyz`) live on the unbound outer `Router::new()` and
//! are not part of the advertised observer surface, so the parser excludes them.
//!
//! Being source-text based, this test is intentionally coupled to the shape of
//! `build_router`. If that shape changes (e.g. routes move out of a single
//! chained builder), this guard must be updated alongside it — which is the
//! point: a structural change to the route table should force a catalog review.

use ao2_cp_server::route_catalog::ROUTES;
use std::collections::BTreeSet;

/// The router source, embedded at compile time so the test is independent of the
/// working directory.
const SERVER_SRC: &str = include_str!("../src/server.rs");

/// Prefix the `api_v1` sub-router is nested under (`.nest("/api/v1", api_v1)`).
const API_PREFIX: &str = "/api/v1";

/// axum method-router constructors. A `.route(path, ...)` handler expression
/// names one or more of these; each occurrence is one advertised method.
const METHOD_TOKENS: &[&str] = &[
    "get", "post", "put", "delete", "head", "patch", "options", "trace",
];

fn is_ident_char(c: char) -> bool {
    c == '_' || c.is_ascii_alphanumeric()
}

/// Marker ending each nested sub-router builder binding (`let <name> = Router::new()`).
/// Every `let`-bound `Router::new()` builder in `build_router` is merged into the
/// `/api/v1` nest and shares the bearer-auth `route_layer`, so together they form
/// the advertised observer surface. The unauthenticated top-level router
/// (`/healthz`, `/readyz`) is the trailing *unbound* `Router::new()` return
/// expression — it lacks the `= ` and so is excluded.
const BUILDER_MARKER: &str = "= Router::new()";

/// The route-registration section of every `let <name> = Router::new() ...`
/// sub-router builder. Each section runs from the builder's `Router::new()` up to
/// the first layer in its chain (`.layer(` or `.route_layer(`, whichever comes
/// first), which terminates its route list.
///
/// There are two such builders today: `api_v1` (the bulk of the surface, ending
/// its route list at `.layer(DefaultBodyLimit(...))`) and `api_v1_stream` (the
/// audit-log SSE stream, split out so the long-lived response escapes the
/// timeout/concurrency layers, ending at `.route_layer(...)`). Both are merged
/// under /api/v1, so both are compared against the catalog; a future sub-router
/// added the same way is picked up automatically.
fn api_v1_builder_blocks(src: &str) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut from = 0;
    while let Some(rel) = src[from..].find(BUILDER_MARKER) {
        let block_start = from + rel + BUILDER_MARKER.len();
        let rest = &src[block_start..];
        // The route list ends at the first layer in the builder chain. `.layer(`
        // is not a substring of `.route_layer(`, so the two are distinguishable;
        // take whichever appears first.
        let end = match (rest.find(".layer("), rest.find(".route_layer(")) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => panic!(
                "a `let <name> = Router::new()` builder must terminate its route \
                 list with a `.layer(...)` or `.route_layer(...)` call"
            ),
        };
        blocks.push(&rest[..end]);
        from = block_start + end;
    }
    assert!(
        !blocks.is_empty(),
        "server.rs must define at least one `let <name> = Router::new()` sub-router"
    );
    blocks
}

/// Method tokens (`get(`, `.post(`, `.head(`, ...) appearing in a handler
/// expression, upper-cased. A token only counts when the character before it is
/// not part of an identifier, so handler *values* like `get_bundle` (passed to
/// `get(...)`, never called) are not mistaken for method constructors.
fn methods_in(chunk: &str) -> Vec<String> {
    let mut methods = Vec::new();
    for &token in METHOD_TOKENS {
        let needle = format!("{token}(");
        let mut from = 0;
        while let Some(rel) = chunk[from..].find(&needle) {
            let at = from + rel;
            let preceded_by_ident = chunk[..at].chars().next_back().is_some_and(is_ident_char);
            if !preceded_by_ident {
                methods.push(token.to_ascii_uppercase());
            }
            from = at + token.len();
        }
    }
    methods
}

/// The first double-quoted string literal in a chunk — the route path argument.
fn first_string_literal(chunk: &str) -> Option<&str> {
    let open = chunk.find('"')?;
    let after = &chunk[open + 1..];
    let close = after.find('"')?;
    Some(&after[..close])
}

/// Every `(METHOD, full_path)` pair registered across all `/api/v1` sub-router
/// builders.
fn router_routes() -> BTreeSet<(String, String)> {
    let mut routes = BTreeSet::new();
    for block in api_v1_builder_blocks(SERVER_SRC) {
        // Skip the head of each chain before its first `.route(`.
        for chunk in block.split(".route(").skip(1) {
            let path = first_string_literal(chunk)
                .expect("each .route(...) must start with a string-literal path");
            let full_path = format!("{API_PREFIX}{path}");
            let methods = methods_in(chunk);
            assert!(
                !methods.is_empty(),
                "route {full_path} declared no HTTP method handler"
            );
            for method in methods {
                assert!(
                    routes.insert((method.clone(), full_path.clone())),
                    "router registers {method} {full_path} more than once"
                );
            }
        }
    }
    routes
}

/// Every `(METHOD, path)` pair the catalog advertises.
fn catalog_routes() -> BTreeSet<(String, String)> {
    ROUTES
        .iter()
        .map(|r| (r.method.to_string(), r.path.to_string()))
        .collect()
}

#[test]
fn catalog_matches_router_exactly() {
    let router = router_routes();
    let catalog = catalog_routes();

    // Guard against a parser that silently matches nothing (which would make the
    // set-equality assertion trivially pass).
    assert!(
        router.len() >= 100,
        "parsed only {} routes from build_router — the parser is likely broken",
        router.len()
    );

    let advertised_but_missing: Vec<_> = catalog.difference(&router).collect();
    let live_but_unadvertised: Vec<_> = router.difference(&catalog).collect();

    assert!(
        advertised_but_missing.is_empty(),
        "catalog advertises routes that build_router does not register \
         (clients would get 404s): {advertised_but_missing:#?}"
    );
    assert!(
        live_but_unadvertised.is_empty(),
        "build_router registers routes the catalog does not advertise \
         (undocumented surface): {live_but_unadvertised:#?}"
    );
    // Redundant once the two differences are empty, but states the contract.
    assert_eq!(
        router, catalog,
        "route catalog and router must match exactly"
    );
}

#[test]
fn router_routes_includes_the_audit_log_stream_subrouter() {
    // The audit-log SSE stream is registered in a separate `api_v1_stream`
    // builder (split out so the long-lived response escapes the request-timeout
    // and concurrency layers) and merged into the /api/v1 nest. It is a real,
    // bearer-authenticated part of the advertised observer surface, so the drift
    // parser must include it — not just the main `api_v1` builder. This pins the
    // multi-builder parse so the parser cannot silently regress to seeing only
    // the first sub-router.
    let router = router_routes();
    assert!(
        router.contains(&("GET".to_string(), "/api/v1/audit-log/stream".to_string())),
        "router_routes() must include the audit-log SSE stream from the \
         api_v1_stream sub-router; parsed {} routes: {router:#?}",
        router.len()
    );
}

#[test]
fn every_catalog_path_is_under_the_advertised_api_prefix() {
    // The catalog is the authenticated observer surface; every entry must live
    // under /api/v1. A path that escaped the prefix would be unreachable through
    // the nested router and signals a hand-edit mistake in the catalog.
    for route in ROUTES {
        assert!(
            route.path.starts_with(&format!("{API_PREFIX}/")),
            "catalog path {} is not under {API_PREFIX}/",
            route.path
        );
    }
}
