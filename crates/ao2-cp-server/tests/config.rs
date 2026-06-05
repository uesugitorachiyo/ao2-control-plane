use ao2_cp_server::config::{Config, ConfigError};

/// A valid API token for fixtures: >= the 32-char floor Config enforces (sec-2).
const TEST_API_TOKEN: &str = "test-api-token-0123456789-abcdefgh";

fn base_args() -> Vec<String> {
    vec![
        "ao2-cp-server".to_string(),
        "--api-token".to_string(),
        TEST_API_TOKEN.to_string(),
        "--data-dir".to_string(),
        "/tmp/data".to_string(),
    ]
}

#[test]
fn parses_minimal_required() {
    let cfg = Config::parse_from(base_args()).expect("must parse");
    assert_eq!(cfg.api_token, TEST_API_TOKEN);
    assert_eq!(cfg.data_dir, std::path::PathBuf::from("/tmp/data"));
    assert_eq!(cfg.bind, "127.0.0.1:8744");
}

#[test]
fn requires_api_token() {
    let args = vec![
        "ao2-cp-server".to_string(),
        "--data-dir".to_string(),
        "/tmp/data".to_string(),
    ];
    let err = Config::parse_from(args).expect_err("must fail");
    assert!(matches!(err, ConfigError::MissingApiToken));
}

#[test]
fn rejects_openai_api_key_in_env() {
    let mut args = base_args();
    args.push("--check-env".to_string());
    let env = vec![("OPENAI_API_KEY".to_string(), "sk-x".to_string())];
    let err = Config::parse_with_env(args, env).expect_err("must fail");
    assert!(matches!(err, ConfigError::ForbiddenEnv(_)));
}

#[test]
fn rejects_anthropic_api_key_in_env() {
    let mut args = base_args();
    args.push("--check-env".to_string());
    let env = vec![("ANTHROPIC_API_KEY".to_string(), "sk-y".to_string())];
    let err = Config::parse_with_env(args, env).expect_err("must fail");
    assert!(matches!(err, ConfigError::ForbiddenEnv(_)));
}

#[test]
fn flag_overrides_env_for_bind() {
    let mut args = base_args();
    args.extend(["--bind".to_string(), "0.0.0.0:9999".to_string()]);
    let cfg = Config::parse_from(args).expect("must parse");
    assert_eq!(cfg.bind, "0.0.0.0:9999");
}

#[test]
fn parses_provider_readiness_trusted_key_sha256s() {
    let mut args = base_args();
    args.extend([
        "--provider-readiness-trusted-key-sha256s".to_string(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,not-a-sha,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
    ]);
    let cfg = Config::parse_from(args).expect("must parse");
    assert_eq!(
        cfg.provider_readiness_trusted_key_sha256s,
        vec![
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ]
    );
}

#[test]
fn trusted_key_sanitizer_enforces_exact_64_hex_after_trimming() {
    // The trusted-key list gates `release_authoritative`, so its sanitizer is
    // security-relevant: entries are trimmed + lowercased, and anything that
    // isn't exactly 64 hex chars is dropped (never silently trusted as-is). The
    // existing test covers uppercase-normalize + drop-garbage; these isolate the
    // length boundary, the hex filter at full length, and whitespace trimming —
    // each of which the existing "not-a-sha" case conflates.
    let valid = "c".repeat(64);
    let too_short = "d".repeat(63);
    let too_long = "e".repeat(65);
    // 64 chars but one non-hex digit ('g') — isolates the hex check from length.
    let non_hex_at_len = format!("g{}", "f".repeat(63));
    // Valid digest wrapped in surrounding whitespace — must be trimmed and kept.
    let padded = format!("  {}  ", "1".repeat(64));

    let joined = [
        valid.as_str(),
        too_short.as_str(),
        too_long.as_str(),
        non_hex_at_len.as_str(),
        padded.as_str(),
    ]
    .join(",");

    let mut args = base_args();
    args.extend([
        "--provider-readiness-trusted-key-sha256s".to_string(),
        joined,
    ]);
    let cfg = Config::parse_from(args).expect("must parse");

    // Only the exact-64-hex entries survive, the padded one trimmed.
    assert_eq!(
        cfg.provider_readiness_trusted_key_sha256s,
        vec!["c".repeat(64), "1".repeat(64)],
        "63/65-char and non-hex entries must be dropped; valid ones trimmed"
    );
}

#[test]
fn release_evaluator_trusted_key_list_is_sanitized_too() {
    // The evaluator-decision list flows through the same sanitizer; pin it
    // independently so a future divergence in either field is caught.
    let mut args = base_args();
    args.extend([
        "--release-evaluator-decision-trusted-key-sha256s".to_string(),
        format!("{},bogus", "A".repeat(64)),
    ]);
    let cfg = Config::parse_from(args).expect("must parse");
    assert_eq!(
        cfg.release_evaluator_decision_trusted_key_sha256s,
        vec!["a".repeat(64)],
        "uppercase digest lowercased and kept; non-hex dropped"
    );
}

#[test]
fn rejects_empty_api_token() {
    // An empty token is `Some("")`, not `None`, so it slips past the
    // missing-token check. The bearer middleware would then match it against a
    // stripped `Authorization: Bearer ` header, silently unauthenticating the
    // whole /api/v1 surface (including destructive storage_prune).
    let args = vec![
        "ao2-cp-server".to_string(),
        "--api-token".to_string(),
        "".to_string(),
        "--data-dir".to_string(),
        "/tmp/data".to_string(),
    ];
    let err = Config::parse_from(args).expect_err("empty token must be rejected");
    assert!(matches!(err, ConfigError::EmptyApiToken), "got {err:?}");
}

#[test]
fn rejects_whitespace_only_api_token() {
    // A whitespace-only token is non-empty as a string but carries no
    // authentication value; treat it as empty.
    let args = vec![
        "ao2-cp-server".to_string(),
        "--api-token".to_string(),
        "    ".to_string(),
        "--data-dir".to_string(),
        "/tmp/data".to_string(),
    ];
    let err = Config::parse_from(args).expect_err("whitespace-only token must be rejected");
    assert!(matches!(err, ConfigError::EmptyApiToken), "got {err:?}");
}

#[test]
fn rejects_too_short_api_token() {
    // Below the 32-char floor: short enough to be brute-forceable under the
    // reverse-proxy/Tailscale exposure SECURITY.md contemplates. Rejected even
    // though non-empty.
    let args = vec![
        "ao2-cp-server".to_string(),
        "--api-token".to_string(),
        "too-short-token".to_string(),
        "--data-dir".to_string(),
        "/tmp/data".to_string(),
    ];
    let err = Config::parse_from(args).expect_err("sub-32-char token must be rejected");
    assert!(matches!(err, ConfigError::WeakApiToken(15)), "got {err:?}");
}

#[test]
fn accepts_api_token_at_the_32_char_floor() {
    // The floor is inclusive: exactly 32 chars is accepted.
    let token = "a".repeat(32);
    let args = vec![
        "ao2-cp-server".to_string(),
        "--api-token".to_string(),
        token.clone(),
        "--data-dir".to_string(),
        "/tmp/data".to_string(),
    ];
    let cfg = Config::parse_from(args).expect("a 32-char token must be accepted");
    assert_eq!(cfg.api_token, token);
}

#[test]
fn signed_artifact_trusted_key_list_is_sanitized_too() {
    // The signed-artifact list (phase-1 promotion decisions, provider
    // registry, evidence packs, memory exports) gates `release_authoritative`
    // for those surfaces and flows through the same sanitizer. Pin it
    // independently so a future divergence is caught.
    let mut args = base_args();
    args.extend([
        "--signed-artifact-trusted-key-sha256s".to_string(),
        format!("{},bogus", "B".repeat(64)),
    ]);
    let cfg = Config::parse_from(args).expect("must parse");
    assert_eq!(
        cfg.signed_artifact_trusted_key_sha256s,
        vec!["b".repeat(64)],
        "uppercase digest lowercased and kept; non-hex dropped"
    );
}
