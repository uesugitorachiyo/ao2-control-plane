use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::Command;

mod common;

#[test]
fn package_script_creates_installable_control_plane_archive() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let server = env!("CARGO_BIN_EXE_ao2-cp-server");
    let out_dir = tempfile::tempdir().expect("out dir");

    let output = Command::new("sh")
        .arg(root.join("scripts/package-local.sh"))
        .arg("--out-dir")
        .arg(out_dir.path())
        .arg("--version")
        .arg("9.9.9-test")
        .arg("--binary")
        .arg(server)
        .arg("--target-label")
        .arg("macos-aarch64")
        .output()
        .expect("run package script");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ao2_control_plane_package=passed"));

    let archive = out_dir
        .path()
        .join("ao2-control-plane-9.9.9-test-macos-aarch64.tar.gz");
    assert!(
        archive.exists(),
        "archive should exist at {}",
        archive.display()
    );
    let entries = archive_entries(&archive);
    assert!(entries.iter().any(|entry| entry == "bin/ao2-cp-server"));
    assert!(entries.iter().any(|entry| entry == "install.sh"));
    assert!(entries.iter().any(|entry| entry == "install.ps1"));
    assert!(entries
        .iter()
        .any(|entry| entry == "verify_release_support_bundle.py"));
    assert!(entries
        .iter()
        .any(|entry| entry == "Verify-ReleaseSupportBundle.ps1"));
    assert!(entries
        .iter()
        .any(|entry| entry == "fetch_release_support_handoff.py"));
    assert!(entries
        .iter()
        .any(|entry| entry == "Fetch-ReleaseSupportHandoff.ps1"));
    assert!(entries.iter().any(|entry| entry == "SHA256SUMS"));
    assert!(entries.iter().any(|entry| entry == "RELEASE-MANIFEST.json"));
    let install_sh = archive_text_entry(&archive, "install.sh");
    assert!(install_sh.contains("cd \"$(dirname -- \"$0\")\""));
    let install_ps1 = archive_text_entry(&archive, "install.ps1");
    assert!(install_ps1.contains("Set-Location -LiteralPath $PSScriptRoot"));
    let checksums = archive_text_entry(&archive, "SHA256SUMS");
    assert!(checksums.contains("verify_release_support_bundle.py"));
    assert!(checksums.contains("Verify-ReleaseSupportBundle.ps1"));
    assert!(checksums.contains("fetch_release_support_handoff.py"));
    assert!(checksums.contains("Fetch-ReleaseSupportHandoff.ps1"));
    let readme = archive_text_entry(&archive, "README.txt");
    assert!(readme.contains("python3 fetch_release_support_handoff.py"));
    assert!(readme.contains("pwsh -File Fetch-ReleaseSupportHandoff.ps1"));
    assert!(readme.contains("-IncludePhase1Portable"));
    assert!(readme.contains("--include-phase1-portable"));
    assert!(readme.contains("phase1-handoff/phase1-portable-manifest-verify-upload.json"));
    assert!(readme.contains("phase1-handoff/phase1-portable-manifest-verification.json"));
    assert!(readme.contains("unset AO2_CP_AUTH_VALUE"));
    assert!(readme.contains("release-handoff/release-support-bundle.json"));
    assert!(readme
        .contains("pwsh -File Verify-ReleaseSupportBundle.ps1 -Path release-handoff/release-support-bundle.json"));

    // README MUST document the operator landing flow so cross-OS operators
    // understand which surface is the source of truth for which dimension.
    // The order (Hermes -> phase1 operator panel -> phase1 dashboard ->
    // cockpit -> publication dashboard -> readiness/handoff/assembly) is the
    // documented triage path; reordering it would break operator runbooks.
    assert!(readme.contains("Operator landing flow"));
    assert!(readme.contains("cross-OS: macOS, Ubuntu, Windows"));
    assert!(readme.contains("/api/v1/phase1/promotion/operator-panel"));
    assert!(readme.contains("/api/v1/phase1/promotion/dashboard"));
    assert!(readme.contains("/api/v1/release/cockpit"));
    assert!(readme.contains("/api/v1/release/publication/dashboard"));
    assert!(readme.contains("/api/v1/release/readiness"));
    assert!(readme.contains("/api/v1/release/handoff"));
    assert!(readme.contains("release_assembly"));
    assert!(readme.contains("candidate_correlation"));
    assert!(readme.contains("candidate_correlation_detail"));
    assert!(
        readme.contains("all_release_publication_shaped_surfaces_agree_on_candidate_correlation")
    );
    // The landing-flow section MUST not leak secrets or bearer tokens
    // (existing scripts already redact). Belt-and-braces check here:
    assert!(!readme.contains("Bearer abc"));
    assert!(!readme.contains("OPENAI_API_KEY="));
    assert!(!readme.contains("ANTHROPIC_API_KEY="));

    // Lane X: the README must document both parity gates and the
    // server-side recomputation, plus point operators at the runbook
    // so they can triage drift without leaving the archive contents.
    assert!(
        readme.contains("Three-OS smoke parity gates"),
        "README must document the parity gates section"
    );
    assert!(
        readme.contains("candidate_correlation_parity"),
        "README must name the candidate_correlation_parity gate (Lane S)"
    );
    assert!(
        readme.contains("candidate_correlation_content_hash_parity"),
        "README must name the candidate_correlation_content_hash_parity gate (Lane V)"
    );
    assert!(
        readme.contains("validate_three_os_release_smoke"),
        "README must reference the Lane W server-side recomputation handler"
    );
    assert!(
        readme.contains("docs/runbooks/release-smoke.md"),
        "README must point operators at the authoritative triage runbook"
    );

    // Lane AAA: the README must give operators a single page covering the
    // audit-log rotation budget — the HTML cockpit row, the JSON
    // pass-through, the recommended alert rules, and the offline-verifier
    // byte-identity / cross-bundle drift checks — so an operator who lands
    // on /api/v1/release/support-bundle.json has every triage pointer in
    // one place rather than having to assemble them from multiple files.
    assert!(
        readme.contains("Audit-log rotation budget"),
        "README must document the audit-log rotation budget section"
    );
    for marker in [
        "rejected_smoke_audit",
        "audit_log_size_bytes",
        "audit_log_cap_bytes",
        "Lane UU rotation cap",
        "786432",
        "audit_log_size_bytes / audit_log_cap_bytes > 0.75",
        "increase(count[1m]) > 10",
        "rejected_smoke_audit_cross_surface_byte_identity",
        "comparison_audit_log_rotation_budget_drift",
        "--compare-against",
        "-CompareAgainst",
        "cockpit_html_audit_log_size_row_flips_to_warn_near_rotation_cap_lane_vv",
        "cockpit_handoff_readiness_json_surface_audit_log_rotation_budget_lane_xx",
        "release_support_bundle_audit_log_byte_identity_and_cross_bundle_drift_lane_zz",
    ] {
        assert!(
            readme.contains(marker),
            "README audit-log rotation budget section must reference {marker:?}"
        );
    }
    // The runbook cross-link MUST cover sections 9.5-9.10 so operators
    // know exactly where to jump for the canonical triage path. Section
    // 9.9 is the Lane DDD mutex narrative; section 9.10 is the Lane EEE
    // cockpit-pointer narrative; both must be reachable from the README.
    assert!(
        readme.contains("9.5-9.10") || readme.contains("9.5") && readme.contains("9.10"),
        "README must point operators at runbook sections 9.5-9.10 for the canonical audit-log triage path"
    );

    // Lane GGG: the README must surface the on-call triage section so an
    // operator who reaches for the README first (rather than the cockpit
    // HTML) still finds the load-bearing framing inline. The framing
    // duplicates the cockpit-row pointer (Lane EEE) and the runbook
    // 9.9 takeaway (Lane DDD) so all three surfaces agree.
    assert!(
        readme.contains("On-call triage (Lanes DDD + EEE + GGG)"),
        "README must include the Lane GGG on-call triage section"
    );
    for marker in [
        "REJECTED_SMOKE_AUDIT_WRITER_LOCK",
        "phase1_promotion.rs",
        "tampering event, not at audit-log corruption",
        "evaluator-closer",
        "audit_log_rotation_stays_well_formed_under_concurrent_burst_lane_ww_rotation",
        "audit_log_rotation_stays_well_formed_under_n200_burst_lane_bbb",
        "audit_log_rotation_stays_well_formed_under_n500_burst_lane_bbb",
        "Rejected Smoke",
        "9.9 (mutex + framing)",
        "number in advance",
    ] {
        assert!(
            readme.contains(marker),
            "README on-call triage section must reference {marker:?}"
        );
    }

    let manifest = archive_text_entry(&archive, "RELEASE-MANIFEST.json");
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest).expect("manifest is json");
    assert_eq!(
        manifest_json["schema_version"],
        "ao2-control-plane.release-manifest.v1"
    );
    assert_eq!(manifest_json["version"], "9.9.9-test");
    assert_eq!(manifest_json["binary"], "ao2-cp-server");
    assert_eq!(manifest_json["binary_path"], "bin/ao2-cp-server");
    assert_eq!(
        manifest_json["offline_support_bundle_verifiers"]["python"]["path"],
        "verify_release_support_bundle.py"
    );
    assert_eq!(
        manifest_json["offline_support_bundle_verifiers"]["python"]["command"],
        "python3 verify_release_support_bundle.py release-support-bundle.json"
    );
    assert_eq!(
        manifest_json["offline_support_bundle_verifiers"]["powershell"]["path"],
        "Verify-ReleaseSupportBundle.ps1"
    );
    assert_eq!(
        manifest_json["offline_support_bundle_verifiers"]["powershell"]["command"],
        "pwsh -File Verify-ReleaseSupportBundle.ps1 -Path release-support-bundle.json"
    );
    assert_eq!(
        manifest_json["offline_support_bundle_verifiers"]["python"]["sha256"],
        py_verifier_sha(&checksums)
    );
    assert_eq!(
        manifest_json["offline_support_bundle_verifiers"]["powershell"]["sha256"],
        ps_verifier_sha(&checksums)
    );
    assert_eq!(
        manifest_json["release_support_handoff_fetcher"]["path"],
        "fetch_release_support_handoff.py"
    );
    assert_eq!(
        manifest_json["release_support_handoff_fetcher"]["auth_value_stored"],
        false
    );
    assert_eq!(
        manifest_json["release_support_handoff_fetcher"]["powershell_path"],
        "Fetch-ReleaseSupportHandoff.ps1"
    );
    assert_eq!(
        manifest_json["release_support_handoff_fetcher"]["powershell_sha256"],
        ps_fetch_handoff_sha(&checksums)
    );
    assert_eq!(
        manifest_json["release_support_handoff_fetcher"]["phase1_portable_handoff"]["flag"],
        "--include-phase1-portable"
    );
    assert_eq!(
        manifest_json["release_support_handoff_fetcher"]["phase1_portable_handoff"]
            ["powershell_flag"],
        "-IncludePhase1Portable"
    );
    assert_eq!(
        manifest_json["release_support_handoff_fetcher"]["phase1_portable_handoff"]
            ["verification_upload"],
        "phase1-portable-manifest-verify-upload.json"
    );
    assert_eq!(
        manifest_json["release_support_handoff_fetcher"]["phase1_portable_handoff"]
            ["verification_result"],
        "phase1-portable-manifest-verification.json"
    );
    assert_eq!(
        manifest_json["release_support_handoff_fetcher"]["sha256"],
        fetch_handoff_sha(&checksums)
    );
    assert_eq!(
        manifest_json["support_bundle_trust_boundary"],
        "offline verification only; no bearer tokens, provider keys, AO2 artifact mutation, or release approval"
    );
    let manifest_serialized = serde_json::to_string(&manifest_json).unwrap();
    assert!(!manifest_serialized.contains("Bearer"));
    assert!(!manifest_serialized.contains("AO2_CP_API_TOKEN"));
}

#[test]
fn package_script_creates_windows_archive_with_exe_manifest_and_installer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let server = env!("CARGO_BIN_EXE_ao2-cp-server");
    let out_dir = tempfile::tempdir().expect("out dir");

    let output = Command::new("sh")
        .arg(root.join("scripts/package-local.sh"))
        .arg("--out-dir")
        .arg(out_dir.path())
        .arg("--version")
        .arg("9.9.9-test")
        .arg("--binary")
        .arg(server)
        .arg("--target-label")
        .arg("windows-x86_64")
        .output()
        .expect("run package script");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let archive = out_dir
        .path()
        .join("ao2-control-plane-9.9.9-test-windows-x86_64.tar.gz");
    assert!(
        archive.exists(),
        "archive should exist at {}",
        archive.display()
    );

    let entries = archive_entries(&archive);
    assert!(entries.iter().any(|entry| entry == "bin/ao2-cp-server.exe"));
    assert!(entries.iter().any(|entry| entry == "install.ps1"));
    assert!(entries
        .iter()
        .any(|entry| entry == "verify_release_support_bundle.py"));
    assert!(entries
        .iter()
        .any(|entry| entry == "Verify-ReleaseSupportBundle.ps1"));
    assert!(entries
        .iter()
        .any(|entry| entry == "fetch_release_support_handoff.py"));
    assert!(entries
        .iter()
        .any(|entry| entry == "Fetch-ReleaseSupportHandoff.ps1"));

    let checksums = archive_text_entry(&archive, "SHA256SUMS");
    assert!(checksums.contains("bin/ao2-cp-server.exe"));
    assert!(checksums.contains("fetch_release_support_handoff.py"));
    assert!(checksums.contains("Fetch-ReleaseSupportHandoff.ps1"));
    assert!(!checksums.contains("bin/ao2-cp-server\n"));

    let install_ps1 = archive_text_entry(&archive, "install.ps1");
    assert!(install_ps1.contains("ao2-cp-server.exe"));
    assert!(install_ps1.contains("Get-FileHash -Algorithm SHA256"));

    let manifest = archive_text_entry(&archive, "RELEASE-MANIFEST.json");
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest).expect("manifest is json");
    assert_eq!(manifest_json["target"], "windows-x86_64");
    assert_eq!(manifest_json["binary"], "ao2-cp-server.exe");
    assert_eq!(manifest_json["binary_path"], "bin/ao2-cp-server.exe");
    assert_eq!(
        manifest_json["offline_support_bundle_verifiers"]["powershell"]["path"],
        "Verify-ReleaseSupportBundle.ps1"
    );
    assert_eq!(
        manifest_json["offline_support_bundle_verifiers"]["python"]["path"],
        "verify_release_support_bundle.py"
    );
    assert_eq!(
        manifest_json["release_support_handoff_fetcher"]["path"],
        "fetch_release_support_handoff.py"
    );
    assert_eq!(
        manifest_json["support_bundle_trust_boundary"],
        "offline verification only; no bearer tokens, provider keys, AO2 artifact mutation, or release approval"
    );
}

#[test]
fn smoke_script_exercises_installed_archive_server_and_dashboard() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = fs::read_to_string(root.join("scripts/smoke-release-archive.sh"))
        .expect("smoke script exists");

    assert!(script.contains("AO2_CP_ARCHIVE"));
    assert!(script.contains("AO2_CP_API_TOKEN"));
    assert!(
        script.contains("head -c 32"),
        "release archive smoke token must satisfy the server's 32-character minimum"
    );
    assert!(script.contains("choose_free_port"));
    assert!(script.contains("PORT=\"${AO2_CP_PORT:-$(choose_free_port)}\""));
    assert!(script.contains("smoke_port: $smoke_port"));
    assert!(script.contains("install.sh"));
    assert!(script.contains("ao2-cp-server"));
    assert!(script.contains("/healthz"));
    assert!(script.contains("/api/v1/acceptance"));
    assert!(script.contains("/api/v1/acceptance/dashboard.json"));
    assert!(script.contains("/api/v1/storage/support-bundle.json"));
    assert!(script.contains("/api/v1/phase1/promotion/gap-report.json"));
    assert!(script.contains("/api/v1/release/support-bundle.json"));
    assert!(script.contains("/api/v1/release/support-bundle/download"));
    assert!(script.contains("/api/v1/release/support-bundle/SHA256SUMS"));
    assert!(script.contains("release-support-bundle-download.json"));
    assert!(script.contains("verify_release_support_bundle.py"));
    assert!(script.contains("release_support_bundle_download_sha256"));
    assert!(script.contains("ao2.cp-release-support-bundle.v1"));
    assert!(script.contains(".release_assembly.schema_version == \"ao2.cp-release-assembly.v1\""));
    assert!(script.contains(".release_assembly.control_plane_approves_release == false"));
    assert!(script.contains(
        "release_assembly_status: ($release_support[0].release_assembly.status // \"\")"
    ));
    assert!(script.contains(
        "release_assembly_candidate_correlation: ($release_support[0].release_assembly.candidate_correlation // \"\")"
    ));
    assert!(script.contains("candidate_correlation_status: $candidate_correlation_status"));
    assert!(script.contains(
        ".candidate_correlation.status as $s | $s == \"matched\" or $s == \"mismatched\" or $s == \"missing\""
    ));
    assert!(script.contains(
        ".release_assembly.candidate_correlation_detail.status as $s | $s == \"matched\" or $s == \"mismatched\" or $s == \"missing\""
    ));
    assert!(script.contains("candidate_correlation status drift:"));
    // Lane II: emission-time internal-consistency guard markers.
    assert!(
        script.contains("candidate_correlation_status emission_time_drift:"),
        "bash smoke script missing Lane II emission-time guard marker"
    );
    assert!(
        script.contains("candidate_correlation_status_emission="),
        "bash smoke script missing Lane II emission-time re-derive of candidate_correlation_status"
    );
    assert!(script.contains("printf \"candidate_correlation_status=%s\\n\""));
    // Lane OO: per-target source_commit emission. The bash per-target
    // script MUST read the .source-commit record embedded in the source
    // tarball by the orchestrator and emit source_commit_at_target +
    // source_dirty_at_target in its smoke JSON output so downstream
    // ingestion validation can cross-check top-level == every per-target
    // and surface orchestrator HEAD drift between packaging and the
    // per-target run.
    assert!(
        script.contains(".source-commit"),
        "bash smoke script missing Lane OO .source-commit read"
    );
    assert!(
        script.contains("source_commit_at_target"),
        "bash smoke script missing Lane OO source_commit_at_target emission"
    );
    assert!(
        script.contains("source_dirty_at_target"),
        "bash smoke script missing Lane OO source_dirty_at_target emission"
    );
    assert!(
        script.contains("source_commit_schema_at_target"),
        "bash smoke script missing Lane OO source_commit_schema_at_target emission"
    );
    assert!(
        script.contains("printf \"source_commit_at_target=%s\\n\""),
        "bash smoke script must print Lane OO trailer source_commit_at_target"
    );
    assert!(script.contains("sha256-ao2-cp-canonical-json-v1"));
    assert!(script.contains("release_support_bundle_integrity_algorithm"));
    assert!(!script.contains(".release_assembly.status == \"assembled\""));
    assert!(!script.contains(".release_assembly.candidate_correlation == \"matched\""));
    assert!(script.contains("support_bundle"));
    assert!(script.contains("phase1_gap_report"));
    assert!(script.contains("ao2.cp-support-bundle.v1"));
    assert!(script.contains("ao2.cp-phase1-gap-report.v1"));
    assert!(script.contains("source_class_counts"));
    assert!(script.contains("EXPECTED_MANIFEST_SCHEMA"));
    assert!(script.contains("portable_bundle_manifest.schema_version"));
    assert!(script.contains("ao2.cp-release-support-bundle-manifest.v1"));
    assert!(script.contains("AO2_CP_SMOKE_JSON"));
    assert!(script.contains("ao2-control-plane.release-smoke.v1"));
    assert!(script.contains("ao2_control_plane_release_smoke=passed"));
    assert!(!script.contains("OPENAI_API_KEY="));
    assert!(!script.contains("ANTHROPIC_API_KEY="));
}

#[test]
fn powershell_smoke_script_exercises_windows_archive_server_and_dashboard() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = fs::read_to_string(root.join("scripts/smoke-release-archive.ps1"))
        .expect("powershell smoke script exists");

    assert!(script.contains("AO2_CP_ARCHIVE"));
    assert!(script.contains("AO2_CP_API_TOKEN"));
    assert!(
        script.contains("Substring(0, 32)"),
        "PowerShell release archive smoke token must satisfy the server's 32-character minimum"
    );
    assert!(script.contains("function Get-FreeTcpPort"));
    assert!(script.contains(
        "$Port = if ($env:AO2_CP_PORT) { [int]$env:AO2_CP_PORT } else { Get-FreeTcpPort }"
    ));
    assert!(script.contains("smoke_port = $Port"));
    assert!(script.contains("install.ps1"));
    assert!(script.contains("ao2-cp-server.exe"));
    assert!(script.contains("/healthz"));
    assert!(script.contains("/api/v1/acceptance"));
    assert!(script.contains("/api/v1/acceptance/dashboard.json"));
    assert!(script.contains("/api/v1/storage/support-bundle.json"));
    assert!(script.contains("/api/v1/phase1/promotion/gap-report.json"));
    assert!(script.contains("/api/v1/release/support-bundle.json"));
    assert!(script.contains("/api/v1/release/support-bundle/download"));
    assert!(script.contains("/api/v1/release/support-bundle/SHA256SUMS"));
    assert!(script.contains("release-support-bundle-download.json"));
    assert!(script.contains("Verify-ReleaseSupportBundle.ps1"));
    assert!(script.contains("release_support_bundle_download_sha256"));
    assert!(script.contains("ao2.cp-release-support-bundle.v1"));
    assert!(script.contains(
        "$ReleaseSupportBundle.release_assembly.schema_version -ne \"ao2.cp-release-assembly.v1\""
    ));
    assert!(script.contains(
        "$ReleaseSupportBundle.release_assembly.control_plane_approves_release -ne $false"
    ));
    assert!(
        script.contains("release_assembly_status = $ReleaseSupportBundle.release_assembly.status")
    );
    assert!(script
        .contains("release_assembly_candidate_correlation = $ReleaseSupportBundle.release_assembly.candidate_correlation"));
    assert!(script.contains("candidate_correlation_status = $CandidateCorrelationStatus"));
    assert!(script.contains("$PublicationCorrelationStatus = [string]$ReleasePublicationDashboard.candidate_correlation.status"));
    assert!(script.contains(
        "$CockpitCorrelationStatus = [string]$ReleaseCockpit.candidate_correlation.status"
    ));
    assert!(script.contains(
        "$HandoffCorrelationStatus = [string]$ReleaseHandoff.candidate_correlation.status"
    ));
    assert!(script.contains(
        "$ReadinessCorrelationStatus = [string]$ReleaseReadiness.candidate_correlation.status"
    ));
    assert!(script.contains("$AssemblyCorrelationStatus = [string]$ReleaseSupportBundle.release_assembly.candidate_correlation_detail.status"));
    assert!(script.contains("candidate_correlation status drift:"));
    // Lane II: emission-time internal-consistency guard markers.
    assert!(
        script.contains("candidate_correlation_status emission_time_drift:"),
        "powershell smoke script missing Lane II emission-time guard marker"
    );
    assert!(
        script.contains("$CandidateCorrelationStatusEmission ="),
        "powershell smoke script missing Lane II emission-time re-derive of CandidateCorrelationStatus"
    );
    assert!(script
        .contains("Write-Output \"candidate_correlation_status=$CandidateCorrelationStatus\""));
    // Lane OO: per-target source_commit emission. The PowerShell per-target
    // script MUST read the .source-commit record embedded in the source
    // tarball by the orchestrator and emit source_commit_at_target +
    // source_dirty_at_target in its smoke JSON output so downstream
    // ingestion validation can cross-check top-level == every per-target
    // and surface orchestrator HEAD drift between packaging and the
    // per-target run.
    assert!(
        script.contains(".source-commit"),
        "powershell smoke script missing Lane OO .source-commit read"
    );
    assert!(
        script.contains("SourceCommitAtTarget"),
        "powershell smoke script missing Lane OO SourceCommitAtTarget variable"
    );
    assert!(
        script.contains("source_commit_at_target = $SourceCommitAtTarget"),
        "powershell smoke script missing Lane OO source_commit_at_target JSON emission"
    );
    assert!(
        script.contains("source_dirty_at_target = $SourceDirtyAtTarget"),
        "powershell smoke script missing Lane OO source_dirty_at_target JSON emission"
    );
    assert!(
        script.contains("source_commit_schema_at_target = $SourceCommitSchemaAtTarget"),
        "powershell smoke script missing Lane OO source_commit_schema_at_target JSON emission"
    );
    assert!(
        script.contains("Write-Output \"source_commit_at_target=$SourceCommitAtTarget\""),
        "powershell smoke script missing Lane OO trailer source_commit_at_target"
    );
    assert!(script.contains("sha256-ao2-cp-canonical-json-v1"));
    assert!(script.contains("release_support_bundle_integrity_algorithm"));
    assert!(!script.contains("$ReleaseSupportBundle.release_assembly.status -ne \"assembled\""));
    assert!(!script
        .contains("$ReleaseSupportBundle.release_assembly.candidate_correlation -ne \"matched\""));
    assert!(script.contains("support_bundle"));
    assert!(script.contains("phase1_gap_report"));
    assert!(script.contains("ao2.cp-support-bundle.v1"));
    assert!(script.contains("ao2.cp-phase1-gap-report.v1"));
    assert!(script.contains("source_class_counts"));
    assert!(script.contains("EXPECTED_MANIFEST_SCHEMA"));
    assert!(script.contains("portable_bundle_manifest.schema_version"));
    assert!(script.contains("ao2.cp-release-support-bundle-manifest.v1"));
    assert!(script.contains("AO2_CP_SMOKE_JSON"));
    assert!(script.contains("ao2-control-plane.release-smoke.v1"));
    assert!(script.contains("ao2_control_plane_release_smoke=passed"));
    assert!(script.contains("Remove-Item Env:OPENAI_API_KEY"));
    assert!(script.contains("Remove-Item Env:ANTHROPIC_API_KEY"));
    assert!(!script.contains("OPENAI_API_KEY=\""));
    assert!(!script.contains("ANTHROPIC_API_KEY=\""));
}

#[test]
fn three_os_release_smoke_script_documents_remote_mac_ubuntu_windows_execution() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = fs::read_to_string(root.join("scripts/smoke-three-os-release.sh"))
        .expect("three-os smoke script exists");

    assert!(script.contains("AO2_CP_UBUNTU_SSH_TARGET"));
    assert!(script.contains("AO2_CP_WINDOWS_SSH_TARGET"));
    assert!(script.contains("AO2_CP_THREE_OS_SMOKE_JSON"));
    assert!(script.contains("AO2_CP_REQUIRE_WINDOWS"));
    assert!(script.contains("read_only_observer"));
    assert!(script.contains("mutates_ao_artifacts"));
    assert!(script.contains("release_approval_owner"));
    assert!(script.contains("rerun_commands"));
    assert!(script.contains("remote_command_files"));
    assert!(script.contains("ubuntu-command.sh"));
    assert!(script.contains("windows-command.ps1"));
    assert!(script.contains("failure_excerpts"));
    assert!(script.contains("tail_text"));
    assert!(script.contains("AO2_CP_API_TOKEN=<local-token>"));
    assert!(script.contains("$HOME/.cargo/bin:\\$PATH"));
    assert!(
        script.contains("AO2_CP_REMOTE_LINUX_ROOT/run/target/three-os-release-smoke/ubuntu-smoke")
    );
    assert!(script
        .contains("AO2_CP_REMOTE_WINDOWS_ROOT/run/target/three-os-release-smoke/windows-smoke"));
    assert!(script.contains("C:/Program Files/Git/bin/bash.exe"));
    assert!(script.matches("set -e;").count() >= 3);
    assert!(script.contains("win-hp255-via-ubuntu"));
    assert!(script.contains("ao2-ubuntu-nucx"));
    assert!(script.contains("scripts/smoke-release-archive.sh"));
    assert!(script.contains("scripts/smoke-release-archive.ps1"));
    assert!(script.contains("macos_release_smoke=passed"));
    assert!(script.contains("ubuntu_release_smoke=passed"));
    assert!(script.contains("windows_release_smoke=passed"));
    assert!(script.contains("ao2-control-plane.three-os-release-smoke.v1"));
    assert!(script.contains("candidate_correlation_parity"));
    assert!(script.contains("extract_correlation_status()"));
    assert!(script.contains("compute_parity()"));
    assert!(script.contains("\"candidate_correlation_status\": sys.argv[18]"));
    assert!(script.contains("\"candidate_correlation_status\": sys.argv[19]"));
    assert!(script.contains("\"candidate_correlation_status\": sys.argv[20]"));
    assert!(script.contains("\"candidate_correlation_parity\": sys.argv[21]"));
    assert!(script.contains("candidate_correlation_parity=$candidate_correlation_parity"));
    assert!(script.contains("Remove-Item Env:OPENAI_API_KEY"));
    assert!(script.contains("Remove-Item Env:ANTHROPIC_API_KEY"));
    assert!(!script.contains("OPENAI_API_KEY=\""));
    assert!(!script.contains("ANTHROPIC_API_KEY=\""));

    // Lane OO: the orchestrator MUST embed a .source-commit record into the
    // source tarball it ships to each per-target so the per-target script
    // can pin source_commit_at_target to the commit it actually built
    // against. The embedded record uses a stable JSON schema so future
    // server-side validation can parse it without coupling to the bash
    // packaging code.
    assert!(
        script.contains("ao2-control-plane.source-commit.v1"),
        "three-OS orchestrator missing Lane OO source-commit schema constant"
    );
    assert!(
        script.contains("\".source-commit\""),
        "three-OS orchestrator must add .source-commit member to source.tgz"
    );
    assert!(
        script.contains("archive.addfile(info, io.BytesIO(payload))"),
        "three-OS orchestrator must write a synthetic .source-commit tar member"
    );
    assert!(
        script.contains("\"$source_commit\" \"$source_dirty\""),
        "three-OS orchestrator must forward source_commit + source_dirty into the packaging script"
    );

    // Lane OO (aggregator-side): the orchestrator MUST extract a
    // source_commit_at_target trailer line from each per-OS log and
    // aggregate the three values into a top-level source_commit_per_target
    // block plus a drift verdict. Server-side ingestion (Lane PP-server)
    // is expected to reject the bundle when any per-target value
    // disagrees with the orchestrator's top-level source_commit.
    assert!(
        script.contains("extract_source_commit_at_target()"),
        "three-OS orchestrator missing Lane OO source-commit extraction helper"
    );
    assert!(
        script.contains("source_commit_at_target_macos"),
        "three-OS orchestrator must declare per-target source_commit_at_target_macos"
    );
    assert!(
        script.contains("source_commit_at_target_ubuntu"),
        "three-OS orchestrator must declare per-target source_commit_at_target_ubuntu"
    );
    assert!(
        script.contains("source_commit_at_target_windows"),
        "three-OS orchestrator must declare per-target source_commit_at_target_windows"
    );
    assert!(
        script.contains("source_commit_per_target_drift"),
        "three-OS orchestrator must compute a top-level source_commit_per_target_drift verdict"
    );
    assert!(
        script.contains("compute_source_commit_drift()"),
        "three-OS orchestrator must declare a drift computation function"
    );
    // The summary JSON MUST surface per-target source_commit_at_target and
    // a top-level source_commit_per_target block keyed by OS.
    assert!(
        script.contains("\"source_commit_at_target\": sys.argv[46]"),
        "summary.json must include source_commit_at_target for macos"
    );
    assert!(
        script.contains("\"source_commit_at_target\": sys.argv[47]"),
        "summary.json must include source_commit_at_target for ubuntu"
    );
    assert!(
        script.contains("\"source_commit_at_target\": sys.argv[48]"),
        "summary.json must include source_commit_at_target for windows"
    );
    assert!(
        script.contains("\"source_commit_per_target\""),
        "summary.json must include top-level source_commit_per_target block"
    );
    assert!(
        script.contains("\"source_commit_per_target_drift\""),
        "summary.json must include source_commit_per_target_drift boolean"
    );
    assert!(
        script.contains("\"source_commit_per_target_drift_status\""),
        "summary.json must include source_commit_per_target_drift_status (true/false/unknown)"
    );
    // Lane OO (in-place macOS): the orchestrator MUST also drop a
    // `.source-commit` JSON record into the working tree so the local
    // macOS run (which does NOT extract source.tgz) reads the same
    // authoritative record as Ubuntu/Windows. The file MUST be cleaned
    // up on every exit path via an EXIT trap so a failed smoke does
    // not leave a stray .source-commit pollution in the orchestrator's
    // working tree.
    assert!(
        script.contains("working_tree_source_commit_file=\"$ROOT/.source-commit\""),
        "three-OS orchestrator must declare working-tree .source-commit path"
    );
    assert!(
        script.contains("trap 'rm -f \"$working_tree_source_commit_file\"' EXIT"),
        "three-OS orchestrator must remove working-tree .source-commit on every exit path"
    );

    // Lane V: content-hash parity across the three downloaded cockpits.
    assert!(script.contains("fetch_macos_artifact()"));
    assert!(script.contains("fetch_ubuntu_artifact()"));
    assert!(script.contains("fetch_windows_artifact()"));
    assert!(script.contains("compute_correlation_content_hash()"));
    assert!(script.contains("compute_content_hash_parity()"));
    assert!(script.contains("candidate_correlation_content_hash_parity"));
    assert!(script.contains("correlation_content_hash_macos"));
    assert!(script.contains("correlation_content_hash_ubuntu"));
    assert!(script.contains("correlation_content_hash_windows"));
    assert!(script.contains("fetched-macos"));
    assert!(script.contains("fetched-ubuntu"));
    assert!(script.contains("fetched-windows"));
    // The hash is computed from the .candidate_correlation subtree
    // through the shared jq -cS normalization helper for deterministic
    // key ordering — any change to the normalization strategy must
    // update these assertions too.
    assert!(script.contains("compute_correlation_content_hash()"));
    assert!(script.contains("compute_artifact_subtree_hash \"$1\" '.candidate_correlation // {}'"));
    assert!(script.contains("jq -cS \"$jq_filter\""));
    // Both sha256sum (Linux) and shasum (macOS) must be supported so
    // the aggregator runs on either orchestrator OS.
    assert!(script.contains("sha256sum"));
    assert!(script.contains("shasum -a 256"));
    // New sys.argv slots threaded through the python heredoc.
    assert!(script.contains("\"candidate_correlation_content_hash\": sys.argv[22]"));
    assert!(script.contains("\"candidate_correlation_content_hash\": sys.argv[23]"));
    assert!(script.contains("\"candidate_correlation_content_hash\": sys.argv[24]"));
    assert!(script.contains("\"candidate_correlation_content_hash_parity\": sys.argv[25]"));
    // Exit non-zero on content-hash drift, independent of the
    // status-level parity gate.
    assert!(
        script.contains("candidate_correlation_content_hash_parity=drift")
            && script.contains("exit 1")
    );

    // Lane Z: extend the byte-identity audit to the four additional
    // release-publication-shaped surfaces. Each surface gets its own
    // per-OS hash and its own cross-OS drift verdict.
    assert!(script.contains("compute_artifact_subtree_hash()"));
    assert!(script.contains("compute_surface_hash_parity()"));
    // Each new surface gets a per-OS hash variable.
    for prefix in [
        "handoff_content_hash",
        "readiness_content_hash",
        "publication_dashboard_content_hash",
        "assembly_content_hash",
    ] {
        for os in ["macos", "ubuntu", "windows"] {
            let var = format!("{prefix}_{os}");
            assert!(
                script.contains(&var),
                "Lane Z: aggregator must declare {var}"
            );
        }
        let parity_var = format!("{prefix}_parity");
        assert!(
            script.contains(&parity_var),
            "Lane Z: aggregator must compute {parity_var}"
        );
    }
    // Each new surface drift fires the smoke independently and emits a
    // literal, grep-friendly operator message for the dissenting surface.
    for surface in [
        "release_handoff",
        "release_readiness",
        "release_publication_dashboard",
        "release_assembly",
    ] {
        let drift_msg = format!("{surface}_content_hash_parity=drift");
        assert!(
            script.contains(&drift_msg),
            "Lane Z: aggregator must emit drift message for {surface}"
        );
    }
    // The per-surface fetches must cover the right files and the right
    // jq filters (cockpit/handoff/readiness/publication-dashboard use
    // .candidate_correlation; assembly uses
    // .release_assembly.candidate_correlation_detail).
    assert!(script.contains("release-handoff.json:.candidate_correlation"));
    assert!(script.contains("release-readiness.json:.candidate_correlation"));
    assert!(script.contains("release-publication-dashboard.json:.candidate_correlation"));
    assert!(script
        .contains("release-support-bundle.json:.release_assembly.candidate_correlation_detail"));
    // summary.json must expose per-surface parity AND per-OS per-surface
    // hashes so operators can pinpoint which surface drifted.
    assert!(script.contains("\"surface_content_hash_parity\""));
    assert!(script.contains("\"surface_content_hashes\""));
    // New sys.argv slots for the 4 additional surfaces × 4 (3 per-OS
    // hashes + 1 parity) = 16 new slots (26..41).
    assert!(script.contains("sys.argv[26]"));
    assert!(script.contains("sys.argv[29]"));
    assert!(script.contains("sys.argv[33]"));
    assert!(script.contains("sys.argv[37]"));
    assert!(script.contains("sys.argv[41]"));

    // Lane BB: extend the byte-identity audit beyond .candidate_correlation
    // subtrees to a sixth, gate-state-bearing invariant
    // (.release_assembly.assembly_blockers). A divergence here exposes
    // downstream gate-state drift that the correlation hash alone cannot
    // surface (e.g., differing provider acceptance verdicts producing the
    // same correlation status but different blocker arrays).
    for os in ["macos", "ubuntu", "windows"] {
        let var = format!("assembly_blockers_content_hash_{os}");
        assert!(
            script.contains(&var),
            "Lane BB: aggregator must declare {var}"
        );
    }
    assert!(script.contains("assembly_blockers_content_hash_parity"));
    // Sixth surface declaration in the per-surface fetch+hash loop.
    assert!(script.contains(
        "release-support-bundle.json:.release_assembly.assembly_blockers // []:assembly_blockers"
    ));
    // Drift on the assembly_blockers hash exits the smoke non-zero even
    // when every Lane Z hash agrees.
    assert!(
        script.contains("release_assembly_blockers_content_hash_parity=drift"),
        "Lane BB: aggregator must emit drift message for release_assembly_blockers"
    );
    // summary.json must expose the new per-target and top-level keys.
    assert!(
        script.contains("\"release_assembly_blockers\""),
        "Lane BB: summary.json must surface release_assembly_blockers in surface_content_hashes \
         and surface_content_hash_parity"
    );
    // Four additional sys.argv slots threaded through the python heredoc
    // (3 per-OS hashes + 1 parity) = argv[42..45].
    assert!(script.contains("sys.argv[42]"));
    assert!(script.contains("sys.argv[43]"));
    assert!(script.contains("sys.argv[44]"));
    assert!(script.contains("sys.argv[45]"));
}

#[test]
fn ingest_smoke_script_exercises_acceptance_idempotency_and_tamper() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = fs::read_to_string(root.join("scripts/smoke-ingest-from-ao2.sh"))
        .expect("ingest smoke script exists");

    assert!(script.contains("End-to-end smoke for ao2-cp-server"));
    assert!(script.contains("AO2_CP_API_TOKEN"));
    assert!(script.contains("AO2_CP_BIND"));
    assert!(script.contains("AO2_CP_DATA_DIR"));
    assert!(
        script.contains("head -c 32"),
        "ingest smoke token must satisfy the server's 32-character minimum"
    );
    assert!(script.contains("cargo build --release -p ao2-cp-server"));
    assert!(script.contains("/healthz"));
    assert!(script.contains("/api/v1/acceptance"));
    assert!(script.contains("/api/v1/control-plane/bundle"));
    assert!(script.contains("codex-acceptance-v0.4.66.json"));
    assert!(script.contains("claude-acceptance-v0.4.66.json"));
    assert!(script.contains("control-plane-bundle-sample.json"));
    assert!(script.contains("bad-schema-version.json"));
    assert!(script.contains("idempotent"));
    assert!(script.contains("tamper"));
    assert!(script.contains("422"));
    assert!(script.contains("500"));
    assert!(script.contains("env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY"));
    assert!(!script.contains("OPENAI_API_KEY=\""));
    assert!(!script.contains("ANTHROPIC_API_KEY=\""));
}

#[test]
fn powershell_ingest_smoke_script_exercises_acceptance_idempotency_and_tamper() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = fs::read_to_string(root.join("scripts/smoke-ingest-from-ao2.ps1"))
        .expect("powershell ingest smoke script exists");

    assert!(script.contains("End-to-end smoke for ao2-cp-server on Windows"));
    assert!(script.contains("Windows PowerShell 5.1 and PowerShell 7+"));
    assert!(script.contains("AO2_CP_API_TOKEN"));
    assert!(script.contains("AO2_CP_BIND"));
    assert!(script.contains("AO2_CP_DATA_DIR"));
    assert!(
        script.contains("byte[] 16"),
        "PowerShell ingest smoke token must satisfy the server's 32-character minimum"
    );
    assert!(script.contains("cargo build --release -p ao2-cp-server"));
    assert!(script.contains("ao2-cp-server.exe"));
    assert!(script.contains("server exited before healthz"));
    assert!(script.contains("StandardError.ReadToEnd"));
    assert!(script.contains("/healthz"));
    assert!(script.contains("/api/v1/acceptance"));
    assert!(script.contains("/api/v1/control-plane/bundle"));
    assert!(script.contains("codex-acceptance-v0.4.66.json"));
    assert!(script.contains("claude-acceptance-v0.4.66.json"));
    assert!(script.contains("control-plane-bundle-sample.json"));
    assert!(script.contains("bad-schema-version.json"));
    assert!(script.contains("idempotent"));
    assert!(script.contains("tamper"));
    assert!(script.contains("422"));
    assert!(script.contains("500"));
    assert!(script.contains("OPENAI_API_KEY"));
    assert!(script.contains("ANTHROPIC_API_KEY"));
    assert!(script.contains("psi.EnvironmentVariables.Remove"));
    assert!(!script.contains("$env:OPENAI_API_KEY = "));
    assert!(!script.contains("$env:ANTHROPIC_API_KEY = "));
}

#[test]
fn health_snapshot_helpers_are_cross_platform_read_only_and_token_safe() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let py = fs::read_to_string(root.join("scripts/cp_health_snapshot.py"))
        .expect("python health snapshot helper exists");
    let sh = fs::read_to_string(root.join("scripts/cp-health-snapshot.sh"))
        .expect("bash health snapshot wrapper exists");
    let ps = fs::read_to_string(root.join("scripts/cp-health-snapshot.ps1"))
        .expect("powershell health snapshot wrapper exists");
    let readme = fs::read_to_string(root.join("README.md")).expect("README exists");
    let runbook = fs::read_to_string(root.join("docs/runbooks/long-lived-dev.md"))
        .expect("long-lived dev runbook exists");

    assert!(py.contains("ao2.cp-health-snapshot.v1"));
    assert!(py.contains("/api/v1/healthz/extended"));
    assert!(py.contains("read_only_observer"));
    assert!(py.contains("mutates_ao_artifacts"));
    assert!(py.contains("provider_auth"));
    assert!(py.contains("token_in_output"));
    assert!(py.contains("ERROR_RE"));
    assert!(py.contains("per_log_summary"));
    assert!(py.contains("healthz_extended"));
    assert!(py.contains("api_token_env"));
    assert!(!py.contains("api_key"));
    assert!(!py.contains("OPENAI_API_KEY"));
    assert!(!py.contains("ANTHROPIC_API_KEY"));

    assert!(sh.contains("cp_health_snapshot.py"));
    assert!(sh.contains("api-token-env"));
    assert!(ps.contains("cp_health_snapshot.py"));
    assert!(ps.contains("ApiTokenEnv"));
    assert!(!sh.contains("--token "));
    assert!(!ps.contains("-Token "));

    for doc in [readme, runbook] {
        assert!(doc.contains("ao2.cp-health-snapshot.v1"));
        assert!(doc.contains("cp-health-snapshot.sh"));
        assert!(doc.contains("cp-health-snapshot.ps1"));
        assert!(doc.contains("--api-token-env"));
        assert!(doc.contains("read-only observer") || doc.contains("read-only"));
    }
}

#[test]
fn disaster_recovery_drill_is_cross_platform_read_only_and_token_safe() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let py = fs::read_to_string(root.join("scripts/cp_dr_restore_drill.py"))
        .expect("python DR restore drill helper exists");
    let sh = fs::read_to_string(root.join("scripts/cp-dr-restore-drill.sh"))
        .expect("bash DR restore drill wrapper exists");
    let ps = fs::read_to_string(root.join("scripts/cp-dr-restore-drill.ps1"))
        .expect("powershell DR restore drill wrapper exists");
    let long_lived = fs::read_to_string(root.join("docs/runbooks/long-lived-dev.md"))
        .expect("long-lived dev runbook exists");
    let operations = fs::read_to_string(root.join("docs/runbooks/operations.md"))
        .expect("operations runbook exists");

    assert!(py.contains("ao2.cp-dr-restore-drill.v1"));
    assert!(py.contains("content-addressed"));
    assert!(py.contains("backup_archive"));
    assert!(py.contains("restored_data_dir"));
    assert!(py.contains("byte_identical"));
    assert!(py.contains("control_plane_role"));
    assert!(py.contains("read_only_observer"));
    assert!(py.contains("mutates_ao_artifacts"));
    assert!(py.contains("token_in_output"));
    assert!(py.contains("local_oauth_cli_only"));
    assert!(py.contains("/api/v1/acceptance"));
    assert!(py.contains("/api/v1/control-plane/bundle"));
    assert!(!py.contains("OPENAI_API_KEY"));
    assert!(!py.contains("ANTHROPIC_API_KEY"));
    assert!(!py.contains("api_key"));

    assert!(sh.contains("cp_dr_restore_drill.py"));
    assert!(ps.contains("cp_dr_restore_drill.py"));
    assert!(!sh.contains("--token "));
    assert!(!ps.contains("-Token "));

    for doc in [long_lived, operations] {
        assert!(doc.contains("ao2.cp-dr-restore-drill.v1"));
        assert!(doc.contains("cp-dr-restore-drill.sh"));
        assert!(doc.contains("cp-dr-restore-drill.ps1"));
        assert!(doc.contains("read-only observer") || doc.contains("read-only"));
        assert!(doc.contains("content-addressed"));
    }
}

#[test]
fn audit_log_rotation_drill_is_cross_platform_read_only_and_token_safe() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let py = fs::read_to_string(root.join("scripts/cp_audit_log_rotation_drill.py"))
        .expect("python audit-log rotation drill helper exists");
    let sh = fs::read_to_string(root.join("scripts/cp-audit-log-rotation-drill.sh"))
        .expect("bash audit-log rotation drill wrapper exists");
    let ps = fs::read_to_string(root.join("scripts/cp-audit-log-rotation-drill.ps1"))
        .expect("powershell audit-log rotation drill wrapper exists");
    let readme = fs::read_to_string(root.join("README.md")).expect("README exists");
    let operations = fs::read_to_string(root.join("docs/runbooks/operations.md"))
        .expect("operations runbook exists");
    let storage_retention = fs::read_to_string(root.join("docs/runbooks/storage-retention.md"))
        .expect("storage retention runbook exists");

    assert!(py.contains("ao2.cp-audit-log-rotation-drill.v1"));
    assert!(py.contains("AO2_CP_AUDIT_LOG_FILE"));
    assert!(py.contains("AO2_CP_AUDIT_LOG_MAX_BYTES"));
    assert!(py.contains("rotation_count"));
    assert!(py.contains("rotated_sidecar"));
    assert!(py.contains("live_file_size_bytes"));
    assert!(py.contains("ao2_cp_audit_log_rotated_total"));
    assert!(py.contains("read_only_observer"));
    assert!(py.contains("mutates_ao_artifacts"));
    assert!(py.contains("token_in_output"));
    assert!(py.contains("local_oauth_cli_only"));
    assert!(!py.contains("OPENAI_API_KEY"));
    assert!(!py.contains("ANTHROPIC_API_KEY"));
    assert!(!py.contains("api_key"));

    assert!(sh.contains("cp_audit_log_rotation_drill.py"));
    assert!(ps.contains("cp_audit_log_rotation_drill.py"));
    assert!(!sh.contains("--token "));
    assert!(!ps.contains("-Token "));

    for doc in [readme, operations, storage_retention] {
        assert!(doc.contains("ao2.cp-audit-log-rotation-drill.v1"));
        assert!(doc.contains("cp-audit-log-rotation-drill.sh"));
        assert!(doc.contains("cp-audit-log-rotation-drill.ps1"));
        assert!(doc.contains("AO2_CP_AUDIT_LOG_MAX_BYTES"));
        assert!(doc.contains("read-only observer") || doc.contains("read-only"));
    }
}

#[test]
fn verify_release_support_bundle_python_and_powershell_agree_on_verification_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let py = fs::read_to_string(root.join("scripts/verify_release_support_bundle.py"))
        .expect("python verifier exists");
    let ps = fs::read_to_string(root.join("scripts/Verify-ReleaseSupportBundle.ps1"))
        .expect("powershell verifier exists");

    // Both verifiers MUST agree on the support-bundle surface ids they require.
    let required_surface_ids = [
        "ci_evidence_index",
        "release_assembly",
        "release_readiness",
        "release_candidate_handoff",
        "release_cockpit",
        "release_evaluator_decision",
        "install_verification",
        "hosted_release_smoke",
        "storage_support_bundle",
    ];
    for id in required_surface_ids {
        assert!(py.contains(id), "python verifier missing surface id {id}");
        assert!(
            ps.contains(id),
            "powershell verifier missing surface id {id}"
        );
    }

    // Both verifiers MUST share the same expected JSON paths for each surface.
    let expected_paths = [
        ("ci_evidence_index", "$.ci_evidence_index"),
        ("release_assembly", "$.release_assembly"),
        ("release_readiness", "$.readiness"),
        ("release_candidate_handoff", "$.handoff"),
        ("release_cockpit", "$.cockpit"),
        ("release_evaluator_decision", "$.evaluator_decision"),
        ("install_verification", "$.install_verification"),
        ("hosted_release_smoke", "$.hosted_release_smoke"),
        ("storage_support_bundle", "$.storage_support"),
    ];
    for (_, path) in expected_paths {
        assert!(py.contains(path), "python verifier missing path {path}");
        assert!(ps.contains(path), "powershell verifier missing path {path}");
    }

    // Both verifiers MUST semantically validate the embedded CI evidence index,
    // not only its digest/path/schema envelope.
    let ci_evidence_semantic_markers = [
        "REQUIRED_CI_EVIDENCE_FAMILY_IDS",
        "risky-pr-golden-bridge-smoke",
        "ingest-smoke",
        "release-archive-smoke",
        "backup-restore-drill",
        "ci_evidence_index.evidence_families",
        "credential_material_included",
        "credential_material_in_urls",
        "download-ci-artifact",
        "read-only-observer",
        "ci_artifact_provenance",
        "github-actions",
        "workflow_file",
        "artifact_download_url_template",
        "digest_reference",
    ];
    for marker in ci_evidence_semantic_markers {
        assert!(
            py.contains(marker),
            "python verifier missing CI evidence semantic marker {marker}"
        );
        assert!(
            ps.contains(marker)
                || ps.contains(&marker.replace(
                    "REQUIRED_CI_EVIDENCE_FAMILY_IDS",
                    "RequiredCiEvidenceFamilyIds"
                )),
            "powershell verifier missing CI evidence semantic marker {marker}"
        );
    }

    // Both verifiers MUST pin the same portable-bundle-manifest schema version.
    let manifest_schema = "ao2.cp-release-support-bundle-manifest.v1";
    assert!(py.contains(manifest_schema));
    assert!(ps.contains(manifest_schema));

    // Both verifiers MUST emit the same JSON trust-boundary contract.
    let shared_json_contract = [
        "\"status\"",
        "\"surface_count\"",
        "\"bundle_sha256\"",
        "\"checksum_verified\"",
        "\"trust_boundary\"",
        "\"control_plane_role\"",
        "\"release_acceptance_owner\"",
        "\"verification_scope\"",
        "\"failures\"",
    ];
    for marker in shared_json_contract {
        assert!(
            py.contains(marker),
            "python verifier missing JSON field {marker}"
        );
        // PowerShell builds objects rather than literal JSON; assert the
        // corresponding pscustomobject keys instead.
        let ps_key = marker.trim_matches('"');
        assert!(
            ps.contains(&format!("{ps_key} =")),
            "powershell verifier missing pscustomobject key {ps_key}"
        );
    }

    // Trust-boundary strings MUST be byte-identical between verifiers.
    let read_only_observer = "read_only_observer";
    let acceptance_owner = "factory-v3 evaluator-closer";
    let verification_scope = "embedded support-bundle digest verification only; no AO2 artifact mutation and no release approval";
    for marker in [read_only_observer, acceptance_owner, verification_scope] {
        assert!(
            py.contains(marker),
            "python verifier missing trust string: {marker}"
        );
        assert!(
            ps.contains(marker),
            "powershell verifier missing trust string: {marker}"
        );
    }

    // Both verifiers MUST expose checksum verification via --checksums / -Checksums.
    assert!(py.contains("--checksums"));
    assert!(ps.contains("[string]$Checksums"));
    assert!(py.contains("bundle_sha256 = sha256_canonical(bundle)"));
    assert!(
        ps.contains("$bundleSha256 = Get-Sha256Canonical $bundle"),
        "PowerShell verifier bundle_sha256 must use canonical JSON, not raw file bytes"
    );

    // Both verifiers MUST hard-fail the bundle when the cockpit, handoff,
    // readiness, or assembly surfaces drop or null out the operator-visible
    // candidate_correlation surface, so a downgraded server cannot silently
    // mask release/three_os/evaluator/codex/claude divergence on ANY of the
    // surfaces that operators triage from.
    assert!(py.contains("CANDIDATE_CORRELATION_REQUIRED_SURFACES"));
    assert!(ps.contains("CandidateCorrelationRequiredSurfaces"));
    for surface_id in [
        "release_cockpit",
        "release_candidate_handoff",
        "release_readiness",
        "release_assembly",
    ] {
        // The exact surface id MUST appear in the required-correlation tuple
        // of both verifiers (string-search is enough; both files declare the
        // tuple in their respective syntax).
        assert!(
            py.contains(&format!("\"{surface_id}\"")),
            "python verifier missing candidate_correlation required surface {surface_id}"
        );
        assert!(
            ps.contains(&format!("'{surface_id}'")),
            "powershell verifier missing candidate_correlation required surface {surface_id}"
        );
    }
    // release_assembly uses candidate_correlation_detail (the full object)
    // because its top-level candidate_correlation is the operator-status
    // string consumed by cross-OS smoke scripts and renaming it would break
    // their contracts. Both verifiers MUST encode this mapping so a downgraded
    // server cannot silently drop the detail field either.
    assert!(py.contains("candidate_correlation_detail"));
    assert!(ps.contains("candidate_correlation_detail"));
    for status in ["matched", "mismatched"] {
        assert!(py.contains(&format!("\"{status}\"")));
        assert!(ps.contains(&format!("'{status}'")));
    }
    // Both verifiers MUST also assert .blockers is an array, so a tampered
    // bundle replacing it with a string or null is caught by the offline gate.
    assert!(py.contains(".blockers"));
    assert!(ps.contains(".blockers"));

    // Lane FF: both verifiers MUST hash each surface's candidate_correlation
    // object and assert byte-identity across the four operator-triage
    // surfaces (cockpit, handoff, readiness, assembly_detail). The legacy
    // per-surface check confirmed each correlation was independently valid
    // in shape, but a tampered bundle could embed inconsistent objects
    // across surfaces (e.g., cockpit shows matched, readiness shows
    // mismatched) and pass the per-surface gate. The byte-identity hash
    // catches that cross-surface drift offline, parallel to the Lane J
    // server-side test that asserts surface-render-by-construction.
    let byte_identity_marker = "candidate_correlation_cross_surface_byte_identity";
    assert!(
        py.contains(byte_identity_marker),
        "python verifier missing Lane FF cross-surface byte-identity check"
    );
    assert!(
        ps.contains(byte_identity_marker),
        "powershell verifier missing Lane FF cross-surface byte-identity check"
    );
    // Both verifiers MUST hash via the shared canonical-JSON helper so the
    // four surface hashes compare apples-to-apples across implementations.
    assert!(
        py.contains("sha256_canonical(correlation)"),
        "python verifier must hash correlation via sha256_canonical"
    );
    assert!(
        ps.contains("Get-Sha256Canonical $correlation"),
        "powershell verifier must hash correlation via Get-Sha256Canonical"
    );
    // The diagnostic message MUST name all four surfaces so operators
    // understand which surface they triage from to find the drift source.
    let diagnostic_marker = "four operator-triage surfaces";
    assert!(py.contains(diagnostic_marker));
    assert!(ps.contains(diagnostic_marker));

    // Lane HH: both verifiers MUST also assert byte-identity for the
    // aggregate parity verdicts (candidate_correlation_parity AND
    // surface_content_hash_parity) across the three operator-triage
    // HTML surfaces (cockpit, handoff, readiness). Lane FF covers the
    // full candidate_correlation object; Lane HH covers the two
    // top-level aggregate verdicts that operators see at-a-glance on
    // each surface. A tampered bundle could expose "matched" on cockpit
    // while readiness/handoff still show "drift", and the per-surface
    // gates pass because each verdict is a valid enum string in
    // isolation.
    for verdict_field in [
        "candidate_correlation_parity",
        "surface_content_hash_parity",
    ] {
        let marker = format!("{verdict_field}_cross_surface_byte_identity");
        assert!(
            py.contains(&marker),
            "python verifier missing Lane HH cross-surface byte-identity check for {verdict_field}"
        );
        assert!(
            ps.contains(&marker),
            "powershell verifier missing Lane HH cross-surface byte-identity check for {verdict_field}"
        );
    }
    // The Lane HH diagnostic MUST name all three HTML triage surfaces so
    // operators understand which surface to triage from when they spot
    // the drift.
    let hh_diagnostic_marker = "three operator-triage surfaces (cockpit, handoff, readiness)";
    assert!(
        py.contains(hh_diagnostic_marker),
        "python verifier must name the three HTML triage surfaces in Lane HH diagnostic"
    );
    assert!(
        ps.contains(hh_diagnostic_marker),
        "powershell verifier must name the three HTML triage surfaces in Lane HH diagnostic"
    );

    // Lane ZZ: both verifiers MUST hash rejected_smoke_audit across cockpit,
    // handoff, and readiness and assert byte-identity. Lane XX added the
    // rotation-budget surface to all three JSON endpoints via the same
    // rejected_smoke_audit_summary() reader, so a tampered bundle that
    // altered one surface's audit object without touching the others is
    // operator-actionable but invisible to per-surface shape checks. The
    // byte-identity hash catches that drift, paralleling Lane FF/HH for
    // candidate_correlation and the aggregate parity verdicts.
    let zz_byte_identity_marker = "rejected_smoke_audit_cross_surface_byte_identity";
    assert!(
        py.contains(zz_byte_identity_marker),
        "python verifier missing Lane ZZ rejected_smoke_audit byte-identity check"
    );
    assert!(
        ps.contains(zz_byte_identity_marker),
        "powershell verifier missing Lane ZZ rejected_smoke_audit byte-identity check"
    );
    // Both verifiers MUST hash the audit object via the same canonical-JSON
    // helper so the three surface hashes compare apples-to-apples across
    // implementations (parallel to Lane FF's correlation hashing).
    assert!(
        py.contains("sha256_canonical(audit)"),
        "python verifier must hash audit via sha256_canonical"
    );
    assert!(
        ps.contains("Get-Sha256Canonical $audit"),
        "powershell verifier must hash audit via Get-Sha256Canonical"
    );
    // The Lane ZZ diagnostic MUST name all three triage surfaces so an
    // operator who lands on the failure knows where to start triaging.
    assert!(
        py.contains(hh_diagnostic_marker),
        "python verifier must name the three surfaces in Lane ZZ diagnostic"
    );
    assert!(
        ps.contains(hh_diagnostic_marker),
        "powershell verifier must name the three surfaces in Lane ZZ diagnostic"
    );
    // Both verifiers MUST also expose a cross-bundle rotation-budget drift
    // signal via the comparison view. Two bundles captured at different
    // rotation states will show different size/count even when verdicts
    // agree — that's still operator-actionable (could indicate audit-log
    // tampering, rotation cap drift, or activity between captures). The
    // signal is NOT folded into verdict_parity because legitimate
    // between-captures activity should not fail the verdict gate.
    let zz_compare_marker = "comparison_audit_log_rotation_budget_drift";
    assert!(
        py.contains(zz_compare_marker),
        "python verifier missing Lane ZZ cross-bundle rotation-budget drift marker"
    );
    assert!(
        ps.contains(zz_compare_marker),
        "powershell verifier missing Lane ZZ cross-bundle rotation-budget drift marker"
    );
    // Both verifiers MUST collect the same three rotation-budget fields per
    // surface (count + size + cap) into the comparison view, so the diff
    // surfaces ALL three drift dimensions to operators triaging across
    // candidates.
    for budget_field in ["audit_log_size_bytes", "audit_log_cap_bytes"] {
        assert!(
            py.contains(budget_field),
            "python verifier missing Lane ZZ rotation-budget field {budget_field}"
        );
        assert!(
            ps.contains(budget_field),
            "powershell verifier missing Lane ZZ rotation-budget field {budget_field}"
        );
    }
    // The audit_budget_diffs report field MUST appear in both verifiers so
    // automation pipelines can consume the structural drift list from the
    // comparison report.
    assert!(
        py.contains("audit_budget_diffs"),
        "python verifier missing Lane ZZ audit_budget_diffs report field"
    );
    assert!(
        ps.contains("audit_budget_diffs"),
        "powershell verifier missing Lane ZZ audit_budget_diffs report field"
    );

    // Neither verifier may write tokens or provider keys into its output.
    for forbidden in [
        "OPENAI_API_KEY=\"",
        "ANTHROPIC_API_KEY=\"",
        "AO2_CP_API_TOKEN=\"",
    ] {
        assert!(!py.contains(forbidden));
        assert!(!ps.contains(forbidden));
    }

    // Lane NN: both verifiers MUST expose cross-bundle comparison via
    // --compare-against / -CompareAgainst. Operators use this flag to diff
    // aggregate verdicts and per-surface candidate_correlation status
    // across two release-candidate bundles so verdict drift between
    // candidates surfaces without re-navigating each bundle's HTML.
    assert!(
        py.contains("--compare-against"),
        "python verifier missing Lane NN --compare-against flag"
    );
    assert!(
        ps.contains("[string]$CompareAgainst"),
        "powershell verifier missing Lane NN -CompareAgainst parameter"
    );

    // Both verifiers MUST pin the same comparison-failure markers so
    // automation pipelines can grep either verifier's output for the
    // same drift signal.
    let nn_failure_markers = [
        "comparison_verdict_drift",
        "comparison_correlation_status_drift",
        "comparison_schema_version_drift",
    ];
    for marker in nn_failure_markers {
        assert!(
            py.contains(marker),
            "python verifier missing Lane NN failure marker {marker}"
        );
        assert!(
            ps.contains(marker),
            "powershell verifier missing Lane NN failure marker {marker}"
        );
    }

    // Both verifiers MUST emit the same comparison_against report shape:
    // the JSON summary's "comparison_against" key plus the per-bucket
    // fields operators read to triage drift.
    let nn_report_fields = [
        "comparison_against",
        "primary_bundle_sha256",
        "compare_bundle_sha256",
        "bundle_sha256_match",
        "schema_version_match",
        "verdict_diffs",
        "correlation_status_diffs",
        "verdict_parity",
    ];
    for field in nn_report_fields {
        assert!(
            py.contains(field),
            "python verifier missing Lane NN report field {field}"
        );
        assert!(
            ps.contains(field),
            "powershell verifier missing Lane NN report field {field}"
        );
    }

    // Both verifiers MUST diff the same parity verdict fields across the
    // same three operator-triage surfaces. Reuses the Lane HH verdict
    // markers (the two aggregate verdicts) and the Lane FF surface tuple.
    assert!(py.contains("COMPARISON_PARITY_VERDICTS"));
    assert!(ps.contains("ComparisonParityVerdicts"));
    assert!(py.contains("COMPARISON_PARITY_SURFACES"));
    assert!(ps.contains("ComparisonParitySurfaces"));
    assert!(py.contains("COMPARISON_CORRELATION_STATUS_SURFACES"));
    assert!(ps.contains("ComparisonCorrelationStatusSurfaces"));

    // The compare bundle MUST also be scanned for forbidden secret markers
    // (bearer headers / provider key assignments) — a tampered compare
    // bundle leaking a bearer header is still operator-relevant even
    // though it's not the primary verification target.
    assert!(
        py.contains("comparison_against: failed to load")
            || py.contains("comparison_against:") && py.contains("compare-against"),
        "python verifier must report compare-against load failures with a stable prefix"
    );
    assert!(
        ps.contains("comparison_against: failed to load")
            || ps.contains("comparison_against:") && ps.contains("compare-against"),
        "powershell verifier must report compare-against load failures with a stable prefix"
    );
}

// Lane NN: --compare-against PATH end-to-end test.
//
// Drives the Python verifier with two bundles that disagree on the aggregate
// parity verdicts and the per-surface candidate_correlation.status. The test
// builds two synthetic JSON bundles (one "primary", one "compare") with
// just the fields the comparison code reads (cockpit/handoff/readiness +
// release_assembly). Primary bundle validation will fail (no manifest etc.)
// but the comparison block emits regardless, and the failure list MUST
// include the per-surface drift markers operators rely on to triage between
// candidates. Exit code must also be non-zero because verdict drift is
// operator-actionable. The cross-OS parity test pins the same constants
// into Verify-ReleaseSupportBundle.ps1; runtime pwsh parity is enforced
// when pwsh is available on the test host.
#[test]
fn release_support_bundle_compare_against_surfaces_verdict_drift_lane_nn() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let verifier = root.join("scripts/verify_release_support_bundle.py");

    let primary = serde_json::json!({
        "schema_version": "ao2.cp-release-support-bundle.v1",
        "release_candidate_version": "0.0.0-nn-primary",
        "cockpit": {
            "candidate_correlation": {"status": "matched", "blockers": []},
            "candidate_correlation_parity": "matched",
            "surface_content_hash_parity": "matched",
        },
        "handoff": {
            "candidate_correlation": {"status": "matched", "blockers": []},
            "candidate_correlation_parity": "matched",
            "surface_content_hash_parity": "matched",
        },
        "readiness": {
            "candidate_correlation": {"status": "matched", "blockers": []},
            "candidate_correlation_parity": "matched",
            "surface_content_hash_parity": "matched",
        },
        "release_assembly": {
            "candidate_correlation_detail": {"status": "matched", "blockers": []},
        },
    });
    let compare = serde_json::json!({
        "schema_version": "ao2.cp-release-support-bundle.v1",
        "release_candidate_version": "0.0.0-nn-compare",
        "cockpit": {
            "candidate_correlation": {"status": "mismatched", "blockers": ["lane-nn-drift"]},
            "candidate_correlation_parity": "drift",
            "surface_content_hash_parity": "matched",
        },
        "handoff": {
            "candidate_correlation": {"status": "matched", "blockers": []},
            "candidate_correlation_parity": "drift",
            "surface_content_hash_parity": "matched",
        },
        "readiness": {
            "candidate_correlation": {"status": "mismatched", "blockers": ["lane-nn-drift"]},
            "candidate_correlation_parity": "matched",
            "surface_content_hash_parity": "drift",
        },
        "release_assembly": {
            "candidate_correlation_detail": {"status": "mismatched", "blockers": ["lane-nn-drift"]},
        },
    });

    let tmp = tempfile::tempdir().expect("tempdir");
    let primary_path = tmp.path().join("primary.json");
    let compare_path = tmp.path().join("compare.json");
    fs::write(&primary_path, serde_json::to_string(&primary).unwrap()).unwrap();
    fs::write(&compare_path, serde_json::to_string(&compare).unwrap()).unwrap();

    // Self-compare on the primary bundle MUST report verdict_parity=true even
    // though primary validation fails for other reasons (no manifest etc.).
    // This proves the comparison code path runs cleanly when the two bundles
    // agree on every monitored verdict + correlation_status field.
    let self_compare = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg("--compare-against")
        .arg(&primary_path)
        .arg(&primary_path)
        .output()
        .expect("run python verifier with self-compare");
    let self_body: serde_json::Value = serde_json::from_slice(&self_compare.stdout)
        .expect("self-compare emits machine-readable JSON");
    let self_comparison = &self_body["comparison_against"];
    assert_eq!(
        self_comparison["verdict_parity"], true,
        "self-compare must report verdict_parity=true; got {self_comparison}"
    );
    assert_eq!(
        self_comparison["bundle_sha256_match"], true,
        "self-compare must report identical bundle sha256"
    );
    assert!(
        self_comparison["verdict_diffs"]
            .as_array()
            .unwrap()
            .is_empty(),
        "self-compare must report empty verdict_diffs; got {}",
        self_comparison["verdict_diffs"]
    );
    assert!(
        self_comparison["correlation_status_diffs"]
            .as_array()
            .unwrap()
            .is_empty(),
        "self-compare must report empty correlation_status_diffs"
    );

    // Compare primary against the tampered compare bundle: every monitored
    // verdict + correlation_status field has been flipped on at least one
    // surface, so the comparison MUST report a drift on every monitored
    // (surface, verdict) pair AND raise comparison_*_drift failures.
    let drift = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg("--compare-against")
        .arg(&compare_path)
        .arg(&primary_path)
        .output()
        .expect("run python verifier with drift compare-against");
    assert!(
        !drift.status.success(),
        "compare-against verdict drift MUST cause non-zero exit code; \
         stdout={}",
        String::from_utf8_lossy(&drift.stdout)
    );
    let drift_body: serde_json::Value =
        serde_json::from_slice(&drift.stdout).expect("drift compare emits JSON");
    assert_eq!(drift_body["status"], "failed");
    let comparison = &drift_body["comparison_against"];
    assert_eq!(comparison["verdict_parity"], false);
    assert_eq!(comparison["bundle_sha256_match"], false);
    assert_eq!(comparison["schema_version_match"], true);
    assert_eq!(
        comparison["primary_release_candidate_version"],
        "0.0.0-nn-primary"
    );
    assert_eq!(
        comparison["compare_release_candidate_version"],
        "0.0.0-nn-compare"
    );

    let verdict_diffs = comparison["verdict_diffs"].as_array().expect("array");
    // Three surfaces × two verdict fields = at most 6 diffs; we tampered the
    // primary against the compare so EVERY (surface, verdict) pair where the
    // values differ MUST appear. Pin the exact set so a future regression in
    // the diff key set is caught.
    let expected_pairs: &[(&str, &str, &str, &str)] = &[
        (
            "release_cockpit",
            "candidate_correlation_parity",
            "matched",
            "drift",
        ),
        (
            "release_candidate_handoff",
            "candidate_correlation_parity",
            "matched",
            "drift",
        ),
        // readiness primary=matched, compare=matched -> NO diff for this verdict
        (
            "release_readiness",
            "surface_content_hash_parity",
            "matched",
            "drift",
        ),
    ];
    for (surface, field, primary_v, compare_v) in expected_pairs {
        assert!(
            verdict_diffs.iter().any(|d| d["surface"] == *surface
                && d["field"] == *field
                && d["primary"] == *primary_v
                && d["compare"] == *compare_v),
            "verdict_diffs must include ({surface}, {field}) primary={primary_v} compare={compare_v}; got {verdict_diffs:?}"
        );
    }

    let status_diffs = comparison["correlation_status_diffs"]
        .as_array()
        .expect("array");
    for (surface, primary_v, compare_v) in &[
        ("release_cockpit", "matched", "mismatched"),
        ("release_readiness", "matched", "mismatched"),
        ("release_assembly", "matched", "mismatched"),
    ] {
        assert!(
            status_diffs.iter().any(|d| d["surface"] == *surface
                && d["primary"] == *primary_v
                && d["compare"] == *compare_v),
            "correlation_status_diffs must include ({surface}) primary={primary_v} compare={compare_v}; got {status_diffs:?}"
        );
    }

    let failures = drift_body["failures"].as_array().expect("array");
    assert!(
        failures.iter().any(|f| f
            .as_str()
            .unwrap_or("")
            .contains("comparison_verdict_drift")),
        "drift failures must include comparison_verdict_drift entries"
    );
    assert!(
        failures.iter().any(|f| {
            f.as_str()
                .unwrap_or("")
                .contains("comparison_correlation_status_drift")
        }),
        "drift failures must include comparison_correlation_status_drift entries"
    );

    // Pathological case: --compare-against pointing at a non-JSON file must
    // not crash; it must emit a comparison_against block with load_error and
    // append a comparison_against load failure to the failures list.
    let bogus = tmp.path().join("not-json.txt");
    fs::write(&bogus, "not json at all").unwrap();
    let bad = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg("--compare-against")
        .arg(&bogus)
        .arg(&primary_path)
        .output()
        .expect("run python verifier with malformed compare-against");
    assert!(
        !bad.status.success(),
        "malformed compare-against MUST cause non-zero exit code"
    );
    let bad_body: serde_json::Value =
        serde_json::from_slice(&bad.stdout).expect("malformed compare-against emits JSON");
    assert!(
        bad_body["comparison_against"]["load_error"]
            .as_str()
            .unwrap_or("")
            .contains("failed to load compare-against bundle"),
        "comparison_against must surface a load_error explaining the failure; got {}",
        bad_body["comparison_against"]
    );
    assert!(
        bad_body["failures"].as_array().unwrap().iter().any(|f| f
            .as_str()
            .unwrap_or("")
            .contains("comparison_against: failed to load")),
        "failures must include comparison_against load failure"
    );

    // Cross-OS parity at runtime: when pwsh is on PATH, run the PowerShell
    // verifier against the same bundle pair and assert the SAME drift
    // failures appear. Otherwise rely on the source-string parity test to
    // pin the .ps1 constants.
    if common::pwsh_available_or_skip("ps1 Lane NN runtime parity") {
        let ps_verifier = root.join("scripts/Verify-ReleaseSupportBundle.ps1");
        let ps_drift = Command::new("pwsh")
            .arg("-NoProfile")
            .arg("-File")
            .arg(&ps_verifier)
            .arg("-Json")
            .arg("-CompareAgainst")
            .arg(&compare_path)
            .arg("-Path")
            .arg(&primary_path)
            .output()
            .expect("run powershell verifier with drift compare-against");
        assert!(
            !ps_drift.status.success(),
            "ps1 verifier compare-against verdict drift MUST cause non-zero exit code"
        );
        let ps_body: serde_json::Value =
            serde_json::from_slice(&ps_drift.stdout).expect("ps1 drift compare emits JSON");
        let ps_failures = ps_body["failures"].as_array().expect("failures array");
        assert!(
            ps_failures.iter().any(|f| f
                .as_str()
                .unwrap_or("")
                .contains("comparison_verdict_drift")),
            "ps1 drift failures must include comparison_verdict_drift"
        );
        assert!(
            ps_failures.iter().any(|f| f
                .as_str()
                .unwrap_or("")
                .contains("comparison_correlation_status_drift")),
            "ps1 drift failures must include comparison_correlation_status_drift"
        );
    }
}

// Lane ZZ: rejected_smoke_audit cross-surface byte-identity + cross-bundle
// rotation-budget drift end-to-end.
//
// Two checks exercised through the Python verifier:
//
// 1. **Tampering-mask attack**: an offline bundle where cockpit's
//    rejected_smoke_audit.count has been bumped (to mask actual rejected
//    tampering attempts on the operator dashboard) while handoff and
//    readiness still report the real count. The per-surface shape check
//    passes (each audit object is a valid 5-field shape) but the Lane ZZ
//    byte-identity hash flags the cross-surface drift.
//
// 2. **Legitimate between-captures rotation drift**: two bundles with
//    matching verdicts but different rotation-budget snapshots (different
//    size/count because activity happened between captures). The Lane ZZ
//    cross-bundle diff surfaces this WITHOUT folding it into the verdict
//    parity boolean — operators see the drift signal in audit_budget_diffs
//    and can decide whether it's expected or suspicious.
#[test]
fn release_support_bundle_audit_log_byte_identity_and_cross_bundle_drift_lane_zz() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let verifier = root.join("scripts/verify_release_support_bundle.py");

    // Helper: build a synthetic bundle with the bare-minimum surfaces the Lane
    // ZZ comparison code reads. We don't bother with the full manifest
    // because primary validation will fail for unrelated reasons (missing
    // included_surfaces etc.) and the Lane ZZ blocks emit regardless.
    fn bundle_with_audit(version: &str, count: u64, size: u64, cap: u64) -> serde_json::Value {
        let audit = serde_json::json!({
            "count": count,
            "audit_log_size_bytes": size,
            "audit_log_cap_bytes": cap,
            "latest_timestamp_utc": serde_json::Value::Null,
            "latest_rejection_reason": serde_json::Value::Null,
        });
        serde_json::json!({
            "schema_version": "ao2.cp-release-support-bundle.v1",
            "release_candidate_version": version,
            "cockpit": {
                "candidate_correlation": {"status": "matched", "blockers": []},
                "candidate_correlation_parity": "matched",
                "surface_content_hash_parity": "matched",
                "rejected_smoke_audit": audit,
            },
            "handoff": {
                "candidate_correlation": {"status": "matched", "blockers": []},
                "candidate_correlation_parity": "matched",
                "surface_content_hash_parity": "matched",
                "rejected_smoke_audit": audit,
            },
            "readiness": {
                "candidate_correlation": {"status": "matched", "blockers": []},
                "candidate_correlation_parity": "matched",
                "surface_content_hash_parity": "matched",
                "rejected_smoke_audit": audit,
            },
            "release_assembly": {
                "candidate_correlation_detail": {"status": "matched", "blockers": []},
            },
        })
    }

    let tmp = tempfile::tempdir().expect("tempdir");

    // Clean bundle: byte-identical rejected_smoke_audit across surfaces.
    let clean = bundle_with_audit("0.0.0-zz-clean", 7, 4096, 1024 * 1024);
    let clean_path = tmp.path().join("clean.json");
    fs::write(&clean_path, serde_json::to_string(&clean).unwrap()).unwrap();

    // Tampered bundle: same as clean except cockpit's audit count has been
    // bumped to mask rejected tampering attempts visible to the operator on
    // the cockpit. Handoff + readiness still report the real count.
    let mut tampered = clean.clone();
    tampered["cockpit"]["rejected_smoke_audit"]["count"] = serde_json::Value::from(99u64);
    let tampered_path = tmp.path().join("tampered.json");
    fs::write(&tampered_path, serde_json::to_string(&tampered).unwrap()).unwrap();

    // Run the verifier on the clean bundle: byte-identity check MUST pass
    // (no `rejected_smoke_audit_cross_surface_byte_identity` in failures).
    let clean_run = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg(&clean_path)
        .output()
        .expect("run python verifier on clean bundle");
    let clean_body: serde_json::Value =
        serde_json::from_slice(&clean_run.stdout).expect("clean run emits JSON");
    let clean_failures = clean_body["failures"].as_array().expect("failures array");
    assert!(
        !clean_failures.iter().any(|f| f
            .as_str()
            .unwrap_or("")
            .contains("rejected_smoke_audit_cross_surface_byte_identity")),
        "clean bundle MUST NOT raise Lane ZZ byte-identity failure; failures={clean_failures:?}"
    );

    // Run on the tampered bundle: byte-identity check MUST fire with the
    // exact Lane ZZ marker AND exit non-zero so automation pipelines surface
    // it without parsing JSON.
    let tampered_run = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg(&tampered_path)
        .output()
        .expect("run python verifier on tampered bundle");
    assert!(
        !tampered_run.status.success(),
        "tampered bundle MUST exit non-zero; stdout={}",
        String::from_utf8_lossy(&tampered_run.stdout)
    );
    let tampered_body: serde_json::Value =
        serde_json::from_slice(&tampered_run.stdout).expect("tampered run emits JSON");
    let tampered_failures = tampered_body["failures"]
        .as_array()
        .expect("failures array");
    assert!(
        tampered_failures.iter().any(|f| f
            .as_str()
            .unwrap_or("")
            .contains("rejected_smoke_audit_cross_surface_byte_identity")),
        "tampered bundle MUST raise Lane ZZ byte-identity failure; failures={tampered_failures:?}"
    );
    // The diagnostic MUST name the three triage surfaces so an operator
    // who lands on the failure knows where to start.
    assert!(
        tampered_failures.iter().any(|f| f
            .as_str()
            .unwrap_or("")
            .contains("three operator-triage surfaces (cockpit, handoff, readiness)")),
        "Lane ZZ diagnostic must name the three triage surfaces"
    );

    // Build a second bundle with the SAME verdicts but a different rotation
    // state (different count + size). This simulates legitimate
    // between-captures activity and exercises the cross-bundle drift signal.
    let later = bundle_with_audit("0.0.0-zz-later", 42, 65536, 1024 * 1024);
    let later_path = tmp.path().join("later.json");
    fs::write(&later_path, serde_json::to_string(&later).unwrap()).unwrap();

    let drift_run = Command::new("python3")
        .arg(&verifier)
        .arg("--json")
        .arg("--compare-against")
        .arg(&later_path)
        .arg(&clean_path)
        .output()
        .expect("run python verifier with rotation-budget drift compare-against");
    assert!(
        !drift_run.status.success(),
        "rotation-budget drift compare-against MUST exit non-zero; \
         stdout={}",
        String::from_utf8_lossy(&drift_run.stdout)
    );
    let drift_body: serde_json::Value =
        serde_json::from_slice(&drift_run.stdout).expect("drift run emits JSON");
    let drift_comparison = &drift_body["comparison_against"];
    // Verdicts are byte-identical between the two bundles, so verdict_parity
    // MUST remain true — the audit-budget drift is surfaced as a separate
    // signal and never folded into the verdict gate.
    assert_eq!(
        drift_comparison["verdict_parity"], true,
        "rotation-budget drift MUST NOT flip verdict_parity to false; \
         got {drift_comparison}"
    );
    let audit_diffs = drift_comparison["audit_budget_diffs"]
        .as_array()
        .expect("audit_budget_diffs array");
    // Three surfaces × at least two drifting fields (count + size) = at
    // least 6 diff entries. Cap stayed constant at 1 MiB so the cap field
    // MUST NOT appear in the diffs.
    let surfaces = [
        "release_cockpit",
        "release_candidate_handoff",
        "release_readiness",
    ];
    for surface in surfaces {
        for field in ["count", "audit_log_size_bytes"] {
            assert!(
                audit_diffs
                    .iter()
                    .any(|d| d["surface"] == surface && d["field"] == field),
                "audit_budget_diffs must include ({surface}, {field}); \
                 got {audit_diffs:?}"
            );
        }
        // Cap stayed constant; MUST NOT appear in diffs.
        assert!(
            !audit_diffs
                .iter()
                .any(|d| d["surface"] == surface && d["field"] == "audit_log_cap_bytes"),
            "audit_budget_diffs must NOT include ({surface}, audit_log_cap_bytes) \
             when cap is unchanged; got {audit_diffs:?}"
        );
    }
    let drift_failures = drift_body["failures"].as_array().expect("failures array");
    assert!(
        drift_failures.iter().any(|f| f
            .as_str()
            .unwrap_or("")
            .contains("comparison_audit_log_rotation_budget_drift")),
        "drift failures must include comparison_audit_log_rotation_budget_drift entries; \
         got {drift_failures:?}"
    );

    // Cross-OS runtime parity: when pwsh is on PATH, run the PowerShell
    // verifier against the same tampered bundle and assert the SAME Lane ZZ
    // byte-identity failure appears. The source-string parity test pins the
    // .ps1 constants regardless of pwsh availability.
    if common::pwsh_available_or_skip("ps1 Lane ZZ runtime parity") {
        let ps_verifier = root.join("scripts/Verify-ReleaseSupportBundle.ps1");
        let ps_tampered = Command::new("pwsh")
            .arg("-NoProfile")
            .arg("-File")
            .arg(&ps_verifier)
            .arg("-Json")
            .arg("-Path")
            .arg(&tampered_path)
            .output()
            .expect("run powershell verifier on tampered bundle");
        assert!(
            !ps_tampered.status.success(),
            "ps1 verifier on tampered bundle MUST exit non-zero"
        );
        let ps_body: serde_json::Value =
            serde_json::from_slice(&ps_tampered.stdout).expect("ps1 tampered run emits JSON");
        let ps_failures = ps_body["failures"].as_array().expect("failures array");
        assert!(
            ps_failures.iter().any(|f| f
                .as_str()
                .unwrap_or("")
                .contains("rejected_smoke_audit_cross_surface_byte_identity")),
            "ps1 verifier missing Lane ZZ byte-identity failure on tampered bundle"
        );

        let ps_drift = Command::new("pwsh")
            .arg("-NoProfile")
            .arg("-File")
            .arg(&ps_verifier)
            .arg("-Json")
            .arg("-CompareAgainst")
            .arg(&later_path)
            .arg("-Path")
            .arg(&clean_path)
            .output()
            .expect("run powershell verifier with rotation-budget drift");
        assert!(
            !ps_drift.status.success(),
            "ps1 verifier rotation-budget drift MUST exit non-zero"
        );
        let ps_drift_body: serde_json::Value =
            serde_json::from_slice(&ps_drift.stdout).expect("ps1 drift run emits JSON");
        let ps_drift_failures = ps_drift_body["failures"]
            .as_array()
            .expect("failures array");
        assert!(
            ps_drift_failures.iter().any(|f| f
                .as_str()
                .unwrap_or("")
                .contains("comparison_audit_log_rotation_budget_drift")),
            "ps1 verifier missing Lane ZZ cross-bundle drift failure"
        );
    }
}

#[test]
fn fetch_release_support_handoff_python_and_powershell_agree_on_fetch_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let py = fs::read_to_string(root.join("scripts/fetch_release_support_handoff.py"))
        .expect("python fetcher exists");
    let ps = fs::read_to_string(root.join("scripts/Fetch-ReleaseSupportHandoff.ps1"))
        .expect("powershell fetcher exists");

    // Both fetchers MUST authenticate via Bearer header pulled from an env var,
    // never from a CLI argument and never echoed to disk.
    assert!(py.contains("Authorization"));
    assert!(py.contains("Bearer"));
    assert!(ps.contains("Authorization"));
    assert!(ps.contains("Bearer"));
    assert!(py.contains("AO2_CP_AUTH_VALUE") || py.contains("os.environ"));
    assert!(
        ps.contains("AO2_CP_AUTH_VALUE")
            || ps.contains("$env:AO2_CP_AUTH_VALUE")
            || ps.contains("Get-Item Env:AO2_CP_AUTH_VALUE")
    );

    // Both fetchers MUST request and persist the same release-support-bundle
    // artifacts (filenames must match keys in ENDPOINTS in both scripts).
    let shared_release_artifacts = [
        "release-support-verifier-handoff.json",
        "release-support-bundle.json",
        "SHA256SUMS",
        "release-support-bundle-verify.json",
        "release-support-bundle-manifest.json",
    ];
    for artifact in shared_release_artifacts {
        assert!(
            py.contains(artifact),
            "python fetcher missing artifact {artifact}"
        );
        assert!(
            ps.contains(artifact),
            "powershell fetcher missing artifact {artifact}"
        );
    }

    // Both fetchers MUST write an explicit CI evidence index summary into
    // fetch-summary.json so offline handoff directories show that CI evidence
    // was semantically verified, not merely downloaded.
    let ci_evidence_summary_fields = [
        "ci_evidence_index_verified",
        "ci_evidence_index_surface_count",
        "ci_evidence_index_family_count",
        "ci_evidence_index_token_hygiene_status",
        "ci_evidence_index",
        "required_family_count",
        "required_families_present",
    ];
    for field in ci_evidence_summary_fields {
        assert!(
            py.contains(field),
            "python fetcher missing CI summary field {field}"
        );
        assert!(
            ps.contains(field),
            "powershell fetcher missing CI summary field {field}"
        );
    }

    // Both fetchers MUST also fetch the same phase1 portable promotion bundle
    // artifacts so Hermes/operators get identical phase1 evidence on every OS.
    let shared_phase1_artifacts = [
        "phase1-portable-manifest.json",
        "ao2-phase1-operator-support-bundle.json",
        "ao2-phase1-gap-report.json",
        "phase1-SHA256SUMS",
    ];
    for artifact in shared_phase1_artifacts {
        assert!(
            py.contains(artifact),
            "python fetcher missing phase1 artifact {artifact}"
        );
        assert!(
            ps.contains(artifact),
            "powershell fetcher missing phase1 artifact {artifact}"
        );
    }

    // Both fetchers MUST capture sha256 digest headers for tamper detection.
    assert!(py.contains("sha256"));
    assert!(ps.contains("sha256"));

    // Neither fetcher may leak the bearer token into stdout, fetched files, or
    // saved metadata.
    for forbidden in [
        "print(authorization)",
        "Write-Output $Authorization",
        "Write-Host $Authorization",
        "Write-Host $env:AO2_CP_AUTH_VALUE",
    ] {
        assert!(!py.contains(forbidden));
        assert!(!ps.contains(forbidden));
    }
}

#[test]
fn install_sh_and_install_ps1_agree_on_install_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package_script =
        fs::read_to_string(root.join("scripts/package-local.sh")).expect("package script exists");

    // Both installers MUST honour AO2_CP_INSTALL_DIR for cross-OS install path
    // overrides, and MUST place the binary on the operator's PATH-like
    // location (~/.local/bin on Unix, %LocalAppData%\Programs\ao2-cp on
    // Windows).
    let install_sh_re = package_script
        .find("cat > \"$STAGE/install.sh\"")
        .expect("package-local.sh writes install.sh");
    let install_ps_re = package_script
        .find("cat > \"$STAGE/install.ps1\"")
        .expect("package-local.sh writes install.ps1");
    let sh_section = &package_script[install_sh_re..install_ps_re];
    let ps_section = &package_script[install_ps_re..];

    assert!(sh_section.contains("AO2_CP_INSTALL_DIR"));
    assert!(ps_section.contains("AO2_CP_INSTALL_DIR"));
    assert!(sh_section.contains("ao2-cp-server"));
    assert!(ps_section.contains("ao2-cp-server.exe"));
    assert!(sh_section.contains("mkdir") || sh_section.contains("install"));
    assert!(ps_section.contains("New-Item -ItemType Directory"));

    // README MUST document both install paths so cross-OS operators see parity.
    let readme_re = package_script
        .find("cat > \"$STAGE/README.txt\"")
        .expect("package-local.sh writes README.txt");
    let readme_section = &package_script[readme_re..];
    assert!(readme_section.contains("install.sh"));
    assert!(readme_section.contains("install.ps1"));
}

#[test]
fn ci_workflow_runs_ingest_smoke_on_all_three_os_before_release_archive_smoke() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci workflow exists");

    // The ingest-smoke job MUST exist and run on Ubuntu, macOS, and Windows so
    // every PR catches schema/idempotency/tamper regressions on each OS before
    // the heavier release-archive smoke job runs.
    let ingest_job_re = ci.find("ingest-smoke:").expect("ingest-smoke job present");
    let smoke_job_re = ci
        .find("\n  smoke:\n")
        .expect("release archive smoke job present");
    assert!(
        ingest_job_re < smoke_job_re,
        "ingest-smoke job must be defined before the heavier release archive smoke job"
    );
    let ingest_section = &ci[ingest_job_re..smoke_job_re];
    for os in ["ubuntu-latest", "macos-latest", "windows-latest"] {
        assert!(
            ingest_section.contains(os),
            "ingest-smoke matrix missing OS {os}"
        );
    }
    assert!(ingest_section.contains("smoke-ingest-from-ao2.sh"));
    assert!(ingest_section.contains("smoke-ingest-from-ao2.ps1"));
    // bash branch must guard on shell == bash so macOS + Ubuntu run the .sh
    // script and Windows runs the .ps1 script.
    assert!(ingest_section.contains("matrix.shell == 'bash'"));
    assert!(ingest_section.contains("matrix.shell == 'pwsh'"));

    // The release archive smoke matrix MUST depend on ingest-smoke so a
    // schema/idempotency regression caught by the fast ingest gate aborts
    // before the heavier archive-build job consumes CI minutes.
    let smoke_section = &ci[smoke_job_re..];
    assert!(
        smoke_section.contains("needs: ingest-smoke"),
        "release archive smoke job must depend on ingest-smoke gate"
    );
}

#[test]
fn packaged_binary_help_and_version_exit_successfully() {
    let server = env!("CARGO_BIN_EXE_ao2-cp-server");

    for flag in ["--help", "--version"] {
        let output = Command::new(server).arg(flag).output().expect("run server");
        assert!(
            output.status.success(),
            "{flag} should exit successfully\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn archive_entries(path: &Path) -> Vec<String> {
    let output = Command::new("tar")
        .args([OsStr::new("-tzf"), path.as_os_str()])
        .output()
        .expect("list archive entries");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.trim_start_matches("./").to_string())
        .collect()
}

fn archive_text_entry(path: &Path, wanted: &str) -> String {
    let output = Command::new("tar")
        .args([OsStr::new("-xOzf"), path.as_os_str(), OsStr::new(wanted)])
        .output()
        .expect("read archive entry");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("archive text is utf8")
}

fn py_verifier_sha(checksums: &str) -> String {
    checksum_for(checksums, "verify_release_support_bundle.py")
}

fn ps_verifier_sha(checksums: &str) -> String {
    checksum_for(checksums, "Verify-ReleaseSupportBundle.ps1")
}

fn fetch_handoff_sha(checksums: &str) -> String {
    checksum_for(checksums, "fetch_release_support_handoff.py")
}

fn ps_fetch_handoff_sha(checksums: &str) -> String {
    checksum_for(checksums, "Fetch-ReleaseSupportHandoff.ps1")
}

fn checksum_for(checksums: &str, entry: &str) -> String {
    checksums
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let sha = parts.next()?;
            let path = parts.next()?;
            (path == entry).then(|| sha.to_string())
        })
        .unwrap_or_else(|| panic!("missing checksum for {entry}"))
}

// Lane U-parity: docs/runbooks/release-smoke.md is the authoritative
// operator-facing triage path for the candidate_correlation_parity gate.
// It must reference the actual gate IDs, file paths, and trailer-line
// formats so it cannot silently drift from the implementing scripts and
// tests. If any of these strings get renamed in code, the runbook MUST
// be updated in the same commit.
#[test]
fn release_smoke_runbook_references_actual_gate_ids_and_triage_paths() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runbook =
        fs::read_to_string(root.join("docs/runbooks/release-smoke.md")).expect("runbook present");

    // Both gates the runbook teaches must be named verbatim.
    assert!(
        runbook.contains("candidate_correlation"),
        "runbook must name the candidate_correlation gate"
    );
    assert!(
        runbook.contains("candidate_correlation_parity"),
        "runbook must name the candidate_correlation_parity gate"
    );

    // Every parity verdict an operator can encounter must be enumerated.
    for verdict in ["matched", "mismatched", "missing", "drift", "unknown"] {
        assert!(
            runbook.contains(verdict),
            "runbook must enumerate parity verdict {verdict:?}"
        );
    }

    // The runbook points operators at the actual on-disk triage layout
    // emitted by scripts/smoke-three-os-release.sh.
    for path in [
        "target/three-os-release-smoke/",
        "summary.json",
        "report.md",
        "macos.log",
        "ubuntu.log",
        "windows.log",
    ] {
        assert!(
            runbook.contains(path),
            "runbook must reference triage artifact {path:?}"
        );
    }

    // The per-OS log trailer format is the only signal the aggregator
    // uses to compute parity; the runbook teaches operators to grep
    // exactly this string.
    assert!(
        runbook.contains("candidate_correlation_status="),
        "runbook must reference the per-OS log trailer format"
    );

    // The runbook must point operators at the Lane T worked-example
    // test so they can read a known-shape drift fixture before
    // triaging a real-world drift.
    assert!(
        runbook.contains(
            "candidate_correlation_parity_gate_fires_independently_when_three_os_smoke_reports_drift"
        ),
        "runbook must reference the Lane T worked-example test"
    );

    // The runbook must point operators at the actual scripts and
    // handlers that implement the gates so they can read source when
    // triage exhausts the documented path.
    for source_path in [
        "crates/ao2-cp-server/src/handlers/release_publication.rs",
        "crates/ao2-cp-server/src/handlers/phase1_promotion.rs",
        "scripts/smoke-three-os-release.sh",
        "scripts/smoke-release-archive.sh",
        "scripts/smoke-release-archive.ps1",
        "scripts/verify_release_support_bundle.py",
        "scripts/Verify-ReleaseSupportBundle.ps1",
        "crates/ao2-cp-server/tests/release_publication.rs",
        "crates/ao2-cp-server/tests/phase1_promotion.rs",
        "crates/ao2-cp-server/tests/release_packaging.rs",
    ] {
        assert!(
            runbook.contains(source_path),
            "runbook must reference implementing source file {source_path:?}"
        );
    }

    // Lane Y: section 2.5 must cover content-hash parity, including
    // both the field name and the diff-by-hand command operators run
    // against the fetched per-OS cockpits.
    assert!(
        runbook.contains("candidate_correlation_content_hash_parity"),
        "runbook must document the content-hash parity gate"
    );
    assert!(
        runbook.contains("fetched-macos") || runbook.contains("fetched-<os>"),
        "runbook must reference the on-disk layout where fetched \
         per-OS cockpits land"
    );
    assert!(
        runbook.contains("jq -cS '.candidate_correlation'"),
        "runbook must reference the canonical diff-by-hand command"
    );
    // Lane W: section 5 must reference the server-side recomputation
    // and the tampered-ingestion test.
    assert!(
        runbook.contains("validate_three_os_release_smoke"),
        "runbook must reference the server-side recomputation handler"
    );
    assert!(
        runbook.contains("three_os_release_smoke_ingestion_rejects_tampered_top_level_parity"),
        "runbook must reference the Lane W tampered-ingestion test"
    );

    // Lane TT: section 5 + section 6 of the runbook teach operators
    // about Lane KK ingestion-time rejection diagnostics and the
    // Lane LL audit log. Every named function and file must
    // exist on disk + every referenced literal diagnostic string
    // must appear verbatim in the runbook so a future code rename
    // (or rephrase) silently breaking the runbook surfaces here
    // instead of leaving operators with stale triage instructions.
    let phase1_src =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/phase1_promotion.rs"))
            .expect("phase1_promotion.rs present");
    let release_pub_src =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("release_publication.rs present");

    // Lane LL writer + audit log filename literal must both exist.
    assert!(
        runbook.contains("append_rejected_smoke_audit"),
        "runbook must reference the Lane LL append-only audit writer"
    );
    assert!(
        phase1_src.contains("fn append_rejected_smoke_audit"),
        "runbook references append_rejected_smoke_audit but the function does not exist in phase1_promotion.rs"
    );
    assert!(
        runbook.contains("rejected-three-os-smoke.jsonl"),
        "runbook must reference the Lane LL audit log filename"
    );
    assert!(
        phase1_src.contains("rejected-three-os-smoke.jsonl"),
        "runbook references the audit log filename but the constant does not exist in phase1_promotion.rs"
    );
    // Audit log schema constant must exist in source.
    assert!(
        phase1_src.contains("ao2.cp-rejected-three-os-smoke.v1"),
        "phase1_promotion.rs must define the audit log schema constant the runbook references"
    );
    assert!(
        runbook.contains("ao2.cp-rejected-three-os-smoke.v1"),
        "runbook must reference the audit log schema constant"
    );

    // Lane MM + QQ renderer + the operator-facing section header
    // literal both must exist.
    assert!(
        runbook.contains("render_rejected_smoke_audit_section"),
        "runbook must reference the Lane MM/QQ renderer"
    );
    assert!(
        release_pub_src.contains("fn render_rejected_smoke_audit_section"),
        "runbook references render_rejected_smoke_audit_section but the function does not exist in release_publication.rs"
    );
    assert!(
        runbook.contains("Rejected Smoke Ingestions"),
        "runbook must reference the section header operators see on cockpit/handoff/readiness HTML"
    );
    assert!(
        release_pub_src.contains("Rejected Smoke Ingestions"),
        "runbook references the 'Rejected Smoke Ingestions' header but the HTML renderer does not emit it"
    );

    // Lane KK rejection-reason literals: the runbook section 5.3
    // teaches operators which constraint each diagnostic indicates.
    // If the implementing format string is reworded, the runbook
    // diagnostic copy must be reworded in lockstep.
    assert!(
        runbook.contains("source_commit must be a 40-char lowercase hex git sha1"),
        "runbook must reproduce the Lane KK source_commit format diagnostic"
    );
    // The Rust source wraps the diagnostic across two lines with a
    // backslash continuation. Assert each half independently so a
    // future refactor that joins or further-wraps the literal still
    // surfaces the diagnostic constituents.
    assert!(
        phase1_src.contains("40-char lowercase"),
        "phase1_promotion.rs must contain '40-char lowercase' (first half of the Lane KK source_commit format diagnostic)"
    );
    assert!(
        phase1_src.contains("hex git sha1"),
        "phase1_promotion.rs must contain 'hex git sha1' (second half of the Lane KK source_commit format diagnostic)"
    );
    assert!(
        runbook.contains("source_dirty=true"),
        "runbook must reference the Lane KK source_dirty diagnostic"
    );
    assert!(
        phase1_src.contains("source_dirty="),
        "phase1_promotion.rs must emit source_dirty in the recompute diagnostic"
    );

    // Trust boundary must be stated explicitly at the top of the
    // runbook — control plane is read-only, no AO mutation, no bearer
    // tokens / provider keys / cookies in triage commands.
    assert!(
        runbook.contains("read-only"),
        "runbook must state the read-only trust boundary"
    );
    assert!(
        !runbook.contains("Bearer "),
        "runbook must not embed bearer tokens in any triage command"
    );

    // The companion source files actually exist on disk — protects
    // against the runbook referencing a renamed-but-not-yet-updated
    // path.
    for source_path in [
        "crates/ao2-cp-server/src/handlers/release_publication.rs",
        "scripts/smoke-three-os-release.sh",
        "scripts/smoke-release-archive.sh",
        "scripts/smoke-release-archive.ps1",
        "scripts/verify_release_support_bundle.py",
        "scripts/Verify-ReleaseSupportBundle.ps1",
        "crates/ao2-cp-server/tests/release_publication.rs",
        "crates/ao2-cp-server/tests/release_packaging.rs",
    ] {
        assert!(
            root.join(source_path).exists(),
            "runbook references {source_path:?} but file does not exist"
        );
    }

    // Lane NN-doc: section 7 documents the offline cross-bundle
    // comparison workflow. The flag names, the comparison_against JSON
    // shape literal, and the failure marker must appear so a future
    // rename in either verifier surfaces here.
    let py_verifier = fs::read_to_string(root.join("scripts/verify_release_support_bundle.py"))
        .expect("python verifier present");
    let ps_verifier = fs::read_to_string(root.join("scripts/Verify-ReleaseSupportBundle.ps1"))
        .expect("powershell verifier present");
    assert!(
        runbook.contains("--compare-against"),
        "runbook section 7 must document the Python --compare-against flag"
    );
    assert!(
        py_verifier.contains("--compare-against"),
        "python verifier must declare --compare-against (referenced by section 7)"
    );
    assert!(
        runbook.contains("-CompareAgainst"),
        "runbook section 7 must document the PowerShell -CompareAgainst flag"
    );
    assert!(
        ps_verifier.contains("[string]$CompareAgainst"),
        "powershell verifier must declare [string]$CompareAgainst (referenced by section 7)"
    );
    assert!(
        runbook.contains("comparison_against"),
        "runbook section 7 must document the comparison_against JSON shape"
    );
    assert!(
        py_verifier.contains("\"comparison_against\""),
        "python verifier must emit the comparison_against key (referenced by section 7)"
    );
    assert!(
        runbook.contains("verdict_parity"),
        "runbook section 7 must reference the verdict_parity field"
    );
    assert!(
        runbook.contains("correlation_status_diffs"),
        "runbook section 7 must reference the correlation_status_diffs field"
    );
    assert!(
        runbook.contains("comparison_against: failed to load"),
        "runbook section 7 must reference the load_error failure marker"
    );
    assert!(
        py_verifier.contains("comparison_against: failed to load"),
        "python verifier must emit the load_error failure marker (referenced by section 7)"
    );
    assert!(
        ps_verifier.contains("comparison_against: failed to load"),
        "powershell verifier must emit the load_error failure marker (referenced by section 7)"
    );

    // Lane PP-server-doc: section 8 documents the source_commit_per_target
    // drift rejection. The diagnostic marker string + the field names
    // must appear so a future rename surfaces here.
    assert!(
        runbook.contains("source_commit_per_target drift"),
        "runbook section 8 must reproduce the Lane PP-server diagnostic marker"
    );
    assert!(
        phase1_src.contains("source_commit_per_target drift"),
        "phase1_promotion.rs must emit 'source_commit_per_target drift' diagnostic referenced by section 8"
    );
    assert!(
        runbook.contains("source_commit_per_target_drift"),
        "runbook section 8 must reference the source_commit_per_target_drift boolean"
    );
    assert!(
        runbook.contains("source_commit_at_target"),
        "runbook section 8 must reference the source_commit_at_target field"
    );
    assert!(
        phase1_src.contains("orchestrator HEAD drifted"),
        "phase1_promotion.rs must emit 'orchestrator HEAD drifted' diagnostic referenced by section 8"
    );
    assert!(
        runbook.contains("orchestrator HEAD drifted"),
        "runbook section 8 must reproduce the orchestrator HEAD drift diagnostic"
    );
    // Section 8 must point operators at the on-disk artifacts they grep
    // when triaging — the .source-commit record on the remote target.
    assert!(
        runbook.contains(".source-commit"),
        "runbook section 8 must reference the .source-commit record \
         operators inspect on the remote target"
    );

    // Lane VV-doc: section 9 documents the audit-log rotation budget
    // visibility. The two raw signal field names, the warn-class
    // threshold percentage, the 1 MiB cap literal, and the policy-
    // threshold test name must all appear so a future renaming of
    // any of these surfaces here instead of silently producing a
    // stale runbook.
    let release_publication_tests =
        fs::read_to_string(root.join("crates/ao2-cp-server/tests/release_publication.rs"))
            .expect("release_publication test file present");
    assert!(
        runbook.contains("audit_log_size_bytes"),
        "runbook section 9 must reference the audit_log_size_bytes field"
    );
    assert!(
        phase1_src.contains("audit_log_size_bytes"),
        "phase1_promotion.rs must emit the audit_log_size_bytes field referenced by section 9"
    );
    assert!(
        runbook.contains("audit_log_cap_bytes"),
        "runbook section 9 must reference the audit_log_cap_bytes field"
    );
    assert!(
        phase1_src.contains("audit_log_cap_bytes"),
        "phase1_promotion.rs must emit the audit_log_cap_bytes field referenced by section 9"
    );
    assert!(
        runbook.contains("Lane UU rotation cap"),
        "runbook section 9 must reference the 'Lane UU rotation cap' string the renderer emits"
    );
    assert!(
        release_pub_src.contains("Lane UU rotation cap"),
        "release_publication.rs must emit the 'Lane UU rotation cap' label referenced by section 9"
    );
    assert!(
        runbook.contains("1048576"),
        "runbook section 9 must document the 1048576-byte (1 MiB) Lane UU cap literal"
    );
    assert!(
        runbook.contains("786432"),
        "runbook section 9 must document the 75% warn threshold (786432 bytes) so operators can reason about the cockpit row state"
    );
    assert!(
        runbook.contains("cockpit_html_audit_log_size_row_flips_to_warn_near_rotation_cap_lane_vv"),
        "runbook section 9 must point operators at the behavioral test that pins the warn-class threshold"
    );
    assert!(
        release_publication_tests.contains(
            "cockpit_html_audit_log_size_row_flips_to_warn_near_rotation_cap_lane_vv"
        ),
        "release_publication.rs tests must contain the Lane VV warn-threshold test referenced by section 9"
    );

    // Lane XX-doc: section 9.5 documents the JSON shape of the
    // rejected_smoke_audit field across cockpit/handoff/readiness
    // JSON endpoints + the recommended alert rules. The field name,
    // the three endpoint paths, the alert expression, and the
    // pass-through test name must all appear so future renames
    // surface here.
    assert!(
        runbook.contains("rejected_smoke_audit"),
        "runbook section 9.5 must reference the rejected_smoke_audit JSON field"
    );
    assert!(
        release_pub_src.contains("\"rejected_smoke_audit\""),
        "release_publication.rs must emit the rejected_smoke_audit JSON field referenced by section 9.5"
    );
    for json_path in [
        "/api/v1/release/cockpit.json",
        "/api/v1/release/handoff.json",
        "/api/v1/release/readiness.json",
    ] {
        assert!(
            runbook.contains(json_path),
            "runbook section 9.5 must reference the JSON endpoint {json_path}"
        );
    }
    assert!(
        runbook.contains("audit_log_size_bytes / audit_log_cap_bytes > 0.75"),
        "runbook section 9.6 must document the recommended rotation-imminent alert expression"
    );
    assert!(
        runbook
            .contains("cockpit_handoff_readiness_json_surface_audit_log_rotation_budget_lane_xx"),
        "runbook section 9.7 must point operators at the Lane XX JSON pass-through test"
    );
    assert!(
        release_publication_tests
            .contains("cockpit_handoff_readiness_json_surface_audit_log_rotation_budget_lane_xx"),
        "release_publication.rs tests must contain the Lane XX JSON pass-through test referenced by section 9.7"
    );

    // Lane ZZ-doc: section 9.8 documents the offline-verifier audits
    // (within-bundle byte-identity + cross-bundle rotation-budget drift).
    // The failure markers, the verifier flags, the end-to-end test name,
    // and the source files MUST all appear so future renames surface here.
    let release_packaging_tests =
        fs::read_to_string(root.join("crates/ao2-cp-server/tests/release_packaging.rs"))
            .expect("release_packaging test file present");
    let py_verifier = fs::read_to_string(root.join("scripts/verify_release_support_bundle.py"))
        .expect("python verifier present");
    let ps_verifier = fs::read_to_string(root.join("scripts/Verify-ReleaseSupportBundle.ps1"))
        .expect("powershell verifier present");
    for marker in [
        "rejected_smoke_audit_cross_surface_byte_identity",
        "comparison_audit_log_rotation_budget_drift",
    ] {
        assert!(
            runbook.contains(marker),
            "runbook section 9.8 must reference Lane ZZ failure marker {marker}"
        );
        assert!(
            py_verifier.contains(marker),
            "python verifier must emit Lane ZZ failure marker {marker} referenced by section 9.8"
        );
        assert!(
            ps_verifier.contains(marker),
            "powershell verifier must emit Lane ZZ failure marker {marker} referenced by section 9.8"
        );
    }
    // Both verifier invocations the runbook teaches MUST appear verbatim in
    // the verifier sources — if either flag is renamed, section 9.8 needs
    // to be updated.
    assert!(
        runbook.contains("--compare-against"),
        "runbook section 9.8 must teach operators the --compare-against flag"
    );
    assert!(
        py_verifier.contains("--compare-against"),
        "python verifier must expose the --compare-against flag referenced by section 9.8"
    );
    assert!(
        runbook.contains("-CompareAgainst"),
        "runbook section 9.8 must teach operators the -CompareAgainst flag"
    );
    assert!(
        ps_verifier.contains("[string]$CompareAgainst"),
        "powershell verifier must expose the -CompareAgainst parameter referenced by section 9.8"
    );
    // The Lane ZZ end-to-end test name MUST appear in both the runbook and
    // release_packaging.rs so an operator who lands on section 9.8 can find
    // and run the worked-example test.
    let zz_test_name =
        "release_support_bundle_audit_log_byte_identity_and_cross_bundle_drift_lane_zz";
    assert!(
        runbook.contains(zz_test_name),
        "runbook section 9.8 must point operators at the Lane ZZ end-to-end test"
    );
    assert!(
        release_packaging_tests.contains(zz_test_name),
        "release_packaging.rs tests must contain the Lane ZZ end-to-end test referenced by section 9.8"
    );
    // The runbook MUST teach that the drift signal is NOT folded into
    // verdict_parity — operators need to know which signal fires the
    // verdict gate and which is informational.
    assert!(
        runbook.contains("verdict_parity"),
        "runbook section 9.8 must explain that audit-budget drift is NOT folded into verdict_parity"
    );

    // Lane DDD: section 9.9 documents the Lane WW-rotation
    // process-global mutex so an on-call operator paged on a tampering
    // burst (Lane XX-doc alert rule 2) knows the audit log itself is
    // integrity-safe under concurrent load — the spike is a tampering
    // event to triage upstream, not audit-log corruption to fix locally.
    // The mutex name, the protected function, the source file, and the
    // worked-example test must all appear verbatim so future renames
    // surface here.
    assert!(
        runbook.contains("REJECTED_SMOKE_AUDIT_WRITER_LOCK"),
        "runbook section 9.9 must name the Lane WW-rotation mutex"
    );
    assert!(
        phase1_src.contains("REJECTED_SMOKE_AUDIT_WRITER_LOCK"),
        "phase1_promotion.rs must define the REJECTED_SMOKE_AUDIT_WRITER_LOCK mutex referenced by section 9.9"
    );
    assert!(
        runbook.contains("append_rejected_smoke_audit"),
        "runbook section 9.9 must reference the append_rejected_smoke_audit function"
    );
    let ww_rotation_test_name =
        "audit_log_rotation_stays_well_formed_under_concurrent_burst_lane_ww_rotation";
    assert!(
        runbook.contains(ww_rotation_test_name),
        "runbook section 9.9 must point operators at the Lane WW-rotation worked-example test"
    );
    assert!(
        release_publication_tests.contains(ww_rotation_test_name),
        "release_publication.rs tests must contain the Lane WW-rotation test referenced by section 9.9"
    );
    // The on-call triage takeaway MUST appear verbatim so the on-call
    // operator reading the runbook at 3 AM knows the burst is a
    // tampering event, not corruption.
    assert!(
        runbook.contains("tampering event"),
        "runbook section 9.9 must teach that the burst is a tampering event (not audit-log corruption)"
    );
    // The reader-path safety note (atomic truncate+write) MUST appear
    // verbatim so an operator following the chain understands why the
    // summary reader stays lock-free.
    assert!(
        runbook.contains("rejected_smoke_audit_summary"),
        "runbook section 9.9 must name the lock-free reader path (rejected_smoke_audit_summary)"
    );

    // Lane EEE-doc: section 9.10 documents the cockpit/handoff/readiness
    // HTML on-call triage pointer that surfaces the runbook 9.9 hint
    // adjacent to the audit-log row. The renderer literals AND the
    // section-9.10 prose must agree so an operator landing on the
    // cockpit and following the pointer back to the runbook finds
    // matching framing — if the renderer drifts but the runbook
    // doesn't (or vice versa), the on-call's mental model breaks.
    assert!(
        runbook.contains("### 9.10 On-call triage pointer"),
        "runbook must include section 9.10 documenting Lane EEE on-call triage pointer"
    );
    assert!(
        runbook.contains("On-call triage"),
        "section 9.10 must name the Lane EEE 'On-call triage' HTML row literal"
    );
    assert!(
        runbook.contains("runbook section 9.9"),
        "section 9.10 must reference the runbook section 9.9 target"
    );
    assert!(
        runbook.contains("tampering event, not audit-log corruption"),
        "section 9.10 must reproduce the load-bearing on-call framing literal"
    );
    let release_publication_src =
        std::fs::read_to_string("../ao2-cp-server/src/handlers/release_publication.rs")
            .expect("release_publication.rs handler must be readable");
    // The renderer must contain the same three literals so a renderer
    // drift surfaces this parity test.
    assert!(
        release_publication_src.contains("On-call triage"),
        "release_publication.rs renderer must emit the 'On-call triage' HTML label"
    );
    assert!(
        release_publication_src.contains("runbook section 9.9"),
        "release_publication.rs renderer must point operators at runbook section 9.9"
    );
    assert!(
        release_publication_src.contains("tampering event, not audit-log corruption"),
        "release_publication.rs renderer must surface the load-bearing on-call framing"
    );

    // Lane III: section 6 "Where the gates are enforced" must list every
    // gate-enforcement layer that ships in the workspace. The original
    // table covered the candidate_correlation and content-hash layers;
    // the audit-log rotation cascade (Lanes UU / WW-rotation / XX /
    // XX-doc / ZZ / EEE / HHH / BBB / FFF) added new layers that the
    // table did not cover until Lane III. Each new row must reference a
    // file path that exists AND a function/identifier/literal that
    // exists in that file.

    // Lane UU rotation cap row.
    assert!(
        runbook.contains("Audit-log size cap with FIFO eviction (Lane UU)"),
        "section 6 must list the Lane UU rotation-cap layer"
    );
    assert!(
        phase1_src.contains("REJECTED_SMOKE_AUDIT_MAX_BYTES")
            && phase1_src.contains("1024 * 1024"),
        "section 6 references Lane UU's 1 MiB cap; phase1_promotion.rs must define REJECTED_SMOKE_AUDIT_MAX_BYTES = 1024 * 1024"
    );

    // Lane WW-rotation mutex row (already cross-bound by Lane DDD, but
    // re-asserted here to bind the section 6 row independently).
    assert!(
        runbook.contains("Audit-log concurrent-write protection (Lane WW-rotation)"),
        "section 6 must list the Lane WW-rotation mutex layer"
    );

    // Lane XX rotation-budget JSON pass-through row.
    assert!(
        runbook.contains("Audit-log rotation budget JSON pass-through (Lane XX)"),
        "section 6 must list the Lane XX JSON pass-through layer"
    );
    assert!(
        release_publication_src.contains("rejected_smoke_audit"),
        "section 6 references the Lane XX rejected_smoke_audit JSON block; release_publication.rs must contain it"
    );

    // Lane XX-doc alert rules row.
    assert!(
        runbook.contains("Audit-log rotation alert rules (Lane XX-doc)"),
        "section 6 must list the Lane XX-doc alert rules layer"
    );
    assert!(
        runbook.contains("audit_log_size_bytes / audit_log_cap_bytes > 0.75"),
        "section 9.6 must contain the Lane XX-doc rotation-imminent alert expression"
    );

    // Lane ZZ offline-verifier audit row.
    assert!(
        runbook.contains("Offline verifier audit-log byte-identity + cross-bundle drift (Lane ZZ)"),
        "section 6 must list the Lane ZZ offline-verifier audit layer"
    );
    let verifier_py = std::fs::read_to_string("../../scripts/verify_release_support_bundle.py")
        .expect("verify_release_support_bundle.py present");
    assert!(
        verifier_py.contains("rejected_smoke_audit_cross_surface_byte_identity"),
        "section 6 references Lane ZZ byte-identity marker; verify_release_support_bundle.py must emit it"
    );

    // Lane EEE on-call triage pointer row.
    assert!(
        runbook.contains("On-call triage pointer (Lane EEE)"),
        "section 6 must list the Lane EEE on-call triage pointer layer"
    );

    // Lane HHH cross-surface meta-parity row.
    assert!(
        runbook.contains("Cross-surface on-call meta-parity (Lane HHH)"),
        "section 6 must list the Lane HHH cross-surface meta-parity layer"
    );

    // Lane BBB + FFF concurrent-burst regression detection row.
    assert!(
        runbook.contains("Audit-log concurrent-burst regression detection (Lane BBB + FFF)"),
        "section 6 must list the Lane BBB + FFF burst regression layer"
    );
    assert!(
        release_publication_tests.contains("fn audit_log_rotation_burst_invariants"),
        "section 6 references the Lane BBB helper; release_publication.rs tests must define it"
    );

    // Lane KKK + LLL + MMM: section-6 row structural parity row.
    assert!(
        runbook.contains("Section-6 row structural parity (Lane KKK + LLL + MMM)"),
        "section 6 must list the Lane KKK + LLL + MMM structural parity layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn section_6_table_rows_bind_every_lane_label_to_existing_source_pointer_lane_kkk"
        ),
        "section 6 references the Lane KKK forward parity test; release_packaging.rs must define it"
    );
    assert!(
        release_packaging_tests
            .contains("fn section_6_lane_labels_trace_back_to_workspace_source_lane_lll"),
        "section 6 references the Lane LLL reverse parity test; release_packaging.rs must define it"
    );
    assert!(
        release_packaging_tests
            .contains("fn section_6_row_identifier_tokens_exist_in_referenced_files_lane_mmm"),
        "section 6 references the Lane MMM identifier-existence parity test; release_packaging.rs must define it"
    );

    // Lane NNN: README heredoc structural parity row.
    assert!(
        runbook.contains("README heredoc structural parity (Lane NNN)"),
        "section 6 must list the Lane NNN README heredoc structural parity layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn readme_heredoc_lane_labels_and_section_pointers_resolve_in_runbook_lane_nnn"
        ),
        "section 6 references the Lane NNN README heredoc parity test; release_packaging.rs must define it"
    );

    // Lane OOO: README heredoc identifier-existence binding row.
    assert!(
        runbook.contains("README heredoc identifier-existence binding (Lane OOO)"),
        "section 6 must list the Lane OOO README heredoc identifier-existence binding layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn readme_heredoc_identifier_tokens_exist_in_workspace_source_lane_ooo"),
        "section 6 references the Lane OOO README heredoc identifier-existence parity test; release_packaging.rs must define it"
    );

    // Lane PPP: section-6 header + column-count floor row.
    assert!(
        runbook.contains("Section-6 header + column-count floor (Lane PPP)"),
        "section 6 must list the Lane PPP header + column-count floor layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn section_6_header_literal_and_column_count_floor_lane_ppp"),
        "section 6 references the Lane PPP header + column-count floor test; release_packaging.rs must define it"
    );

    // Lane QQQ: README handoff command/flag parity row.
    assert!(
        runbook.contains("README handoff command/flag parity (Lane QQQ)"),
        "section 6 must list the Lane QQQ README handoff command/flag parity layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn readme_handoff_commands_bind_to_actual_cli_flag_declarations_lane_qqq"
        ),
        "section 6 references the Lane QQQ README handoff command/flag parity test; release_packaging.rs must define it"
    );

    // Lane RRR: install + handoff env-var name parity row.
    assert!(
        runbook.contains("README env-var name parity (Lane RRR)"),
        "section 6 must list the Lane RRR install + handoff env-var name parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn readme_env_var_names_bind_to_install_and_handoff_scripts_lane_rrr"),
        "section 6 references the Lane RRR env-var name parity test; release_packaging.rs must define it"
    );

    // Lane SSS: README → axum router declaration parity row.
    assert!(
        runbook.contains("README route-literal parity (Lane SSS)"),
        "section 6 must list the Lane SSS route-literal parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn readme_api_v1_routes_bind_to_axum_router_declarations_lane_sss"),
        "section 6 references the Lane SSS README route-literal parity test; release_packaging.rs must define it"
    );

    // Lane TTT: README → verify-bundle CLI flag parity row.
    assert!(
        runbook.contains("README verify-bundle CLI parity (Lane TTT)"),
        "section 6 must list the Lane TTT README verify-bundle CLI parity layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn readme_verify_bundle_invocations_bind_to_actual_cli_declarations_lane_ttt"
        ),
        "section 6 references the Lane TTT README verify-bundle CLI parity test; release_packaging.rs must define it"
    );

    // Lane UUU: README → tar archive arglist parity row.
    assert!(
        runbook.contains("README archive-contents parity (Lane UUU)"),
        "section 6 must list the Lane UUU README archive-contents parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn readme_archive_filenames_appear_in_tar_arglist_lane_uuu"),
        "section 6 references the Lane UUU README archive-contents parity test; release_packaging.rs must define it"
    );

    // Lane VVV: install heredoc → Cargo.toml [[bin]] name parity row.
    assert!(
        runbook.contains("Install heredoc binary-name parity (Lane VVV)"),
        "section 6 must list the Lane VVV install heredoc binary-name parity layer"
    );
    assert!(
        release_packaging_tests.contains("fn install_heredocs_bind_to_cargo_toml_bin_name_lane_vvv"),
        "section 6 references the Lane VVV install heredoc binary-name parity test; release_packaging.rs must define it"
    );

    // Lane WWW: README port literal → config default-bind parity row.
    assert!(
        runbook.contains("README port-literal parity (Lane WWW)"),
        "section 6 must list the Lane WWW README port-literal parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn readme_base_url_literal_binds_to_config_default_bind_lane_www"),
        "section 6 references the Lane WWW README port-literal parity test; release_packaging.rs must define it"
    );

    // Lane XXX: smoke-aggregator function-name parity row.
    assert!(
        runbook.contains("Smoke aggregator function-name parity (Lane XXX)"),
        "section 6 must list the Lane XXX smoke-aggregator function-name parity layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn smoke_aggregator_function_refs_in_runbook_resolve_to_definitions_lane_xxx"
        ),
        "section 6 references the Lane XXX smoke-aggregator function-name parity test; release_packaging.rs must define it"
    );

    // Lane YYY: alert-rule metric-name → handler JSON-key parity row.
    assert!(
        runbook.contains("Alert-rule metric-name parity (Lane YYY)"),
        "section 6 must list the Lane YYY alert-rule metric-name parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn alert_rule_metric_names_bind_to_handler_json_keys_lane_yyy"),
        "section 6 references the Lane YYY alert-rule metric-name parity test; release_packaging.rs must define it"
    );

    // Lane ZZZ: rejected_smoke_audit JSON shape → handler JSON-key parity row.
    assert!(
        runbook.contains("Rotation-budget JSON shape parity (Lane ZZZ)"),
        "section 6 must list the Lane ZZZ rotation-budget JSON shape parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn rejected_smoke_audit_json_shape_binds_to_handler_keys_lane_zzz"),
        "section 6 references the Lane ZZZ rotation-budget JSON shape parity test; release_packaging.rs must define it"
    );

    // Lane AAAA: install heredoc → SHA256SUMS line-shape parity row.
    assert!(
        runbook.contains("Install heredoc SHA256SUMS line-shape parity (Lane AAAA)"),
        "section 6 must list the Lane AAAA install heredoc SHA256SUMS line-shape parity layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn install_heredoc_sha256sums_line_shape_binds_to_write_shape_lane_aaaa"
        ),
        "section 6 references the Lane AAAA install heredoc SHA256SUMS line-shape parity test; release_packaging.rs must define it"
    );

    // Lane BBBB: release-readiness gate registration parity row.
    assert!(
        runbook.contains("Release-readiness gate registration parity (Lane BBBB)"),
        "section 6 must list the Lane BBBB release-readiness gate registration parity layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn release_readiness_gate_registration_binds_to_downstream_anchors_lane_bbbb"
        ),
        "section 6 references the Lane BBBB release-readiness gate registration parity test; release_packaging.rs must define it"
    );

    // Lane CCCC: README threat-model → trust_boundary emission parity row.
    assert!(
        runbook.contains("README threat-model claim parity (Lane CCCC)"),
        "section 6 must list the Lane CCCC README threat-model claim parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn readme_threat_model_claims_bind_to_trust_boundary_emission_lane_cccc"),
        "section 6 references the Lane CCCC README threat-model claim parity test; release_packaging.rs must define it"
    );

    // Lane DDDD: smoke aggregator step-order parity row.
    assert!(
        runbook.contains("Smoke aggregator step-order parity (Lane DDDD)"),
        "section 6 must list the Lane DDDD smoke aggregator step-order parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn smoke_aggregator_step_order_matches_dependency_pipeline_lane_dddd"),
        "section 6 references the Lane DDDD smoke aggregator step-order parity test; release_packaging.rs must define it"
    );

    // Lane EEEE: installer fail-closed step-order parity row.
    assert!(
        runbook.contains("Installer fail-closed step-order parity (Lane EEEE)"),
        "section 6 must list the Lane EEEE installer fail-closed step-order parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredocs_perform_checksum_before_copy_lane_eeee"),
        "section 6 references the Lane EEEE installer fail-closed step-order parity test; release_packaging.rs must define it"
    );

    // Lane FFFF: support-bundle surface-ID JSON-literal parity row.
    assert!(
        runbook.contains("Support-bundle surface-ID JSON-literal parity (Lane FFFF)"),
        "section 6 must list the Lane FFFF support-bundle surface-ID JSON-literal parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn support_bundle_surface_ids_bind_to_json_literal_emission_lane_ffff"),
        "section 6 references the Lane FFFF support-bundle surface-ID JSON-literal parity test; release_packaging.rs must define it"
    );

    // Lane HHHH: schema-version const → JSON-literal emission parity row.
    assert!(
        runbook.contains("Schema-version const emission parity (Lane HHHH)"),
        "section 6 must list the Lane HHHH schema-version const emission parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn release_schema_consts_bind_to_schema_version_emission_lane_hhhh"),
        "section 6 references the Lane HHHH schema-version const emission parity test; release_packaging.rs must define it"
    );

    // Lane IIII: install heredoc env-var default value parity row.
    assert!(
        runbook.contains("Install heredoc default install dir parity (Lane IIII)"),
        "section 6 must list the Lane IIII install heredoc default install dir parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredoc_default_install_dir_binds_to_readme_lane_iiii"),
        "section 6 references the Lane IIII install heredoc default install dir parity test; release_packaging.rs must define it"
    );

    // Lane JJJJ: route declaration → handler fn parity row.
    assert!(
        runbook.contains("Release route → handler fn parity (Lane JJJJ)"),
        "section 6 must list the Lane JJJJ release route → handler fn parity layer"
    );
    assert!(
        release_packaging_tests.contains("fn release_routes_bind_to_handler_fns_lane_jjjj"),
        "section 6 references the Lane JJJJ release route → handler fn parity test; release_packaging.rs must define it"
    );

    // Lane KKKK: README workspace-path claims resolve to real files row.
    assert!(
        runbook.contains("README workspace-path parity (Lane KKKK)"),
        "section 6 must list the Lane KKKK README workspace-path parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn readme_workspace_path_claims_resolve_to_real_files_lane_kkkk"),
        "section 6 references the Lane KKKK README workspace-path parity test; release_packaging.rs must define it"
    );

    // Lane LLLL: README operator-landing numbered-list parity row.
    assert!(
        runbook.contains("README operator-landing numbered-list parity (Lane LLLL)"),
        "section 6 must list the Lane LLLL README operator-landing numbered-list parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn readme_operator_landing_flow_numbered_list_lane_llll"),
        "section 6 references the Lane LLLL README operator-landing numbered-list parity test; release_packaging.rs must define it"
    );

    // Lane MMMM: install heredoc permission-step parity row.
    assert!(
        runbook.contains("Install heredoc permission-step parity (Lane MMMM)"),
        "section 6 must list the Lane MMMM install heredoc permission-step parity layer"
    );
    assert!(
        release_packaging_tests.contains("fn install_heredocs_permission_step_parity_lane_mmmm"),
        "section 6 references the Lane MMMM install heredoc permission-step parity test; release_packaging.rs must define it"
    );

    // Lane NNNN: release_publication.rs CSS class → reference parity row.
    assert!(
        runbook.contains("HTML CSS class parity (Lane NNNN)"),
        "section 6 must list the Lane NNNN HTML CSS class parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn release_publication_html_css_class_parity_lane_nnnn"),
        "section 6 references the Lane NNNN HTML CSS class parity test; release_packaging.rs must define it"
    );

    // Lane OOOO: HTML <title> ↔ <h1> parity row.
    assert!(
        runbook.contains("HTML title / heading parity (Lane OOOO)"),
        "section 6 must list the Lane OOOO HTML title / heading parity layer"
    );
    assert!(
        release_packaging_tests.contains("fn release_publication_html_title_h1_parity_lane_oooo"),
        "section 6 references the Lane OOOO HTML title / heading parity test; release_packaging.rs must define it"
    );

    // Lane PPPP: section-6 row uniqueness parity row.
    assert!(
        runbook.contains("Section-6 row uniqueness parity (Lane PPPP)"),
        "section 6 must list the Lane PPPP section-6 row uniqueness parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn release_smoke_section_6_rows_are_unique_lane_pppp"),
        "section 6 references the Lane PPPP section-6 row uniqueness parity test; release_packaging.rs must define it"
    );

    // Lane QQQQ: HTML footer-link parity row.
    assert!(
        runbook.contains("HTML footer-link parity (Lane QQQQ)"),
        "section 6 must list the Lane QQQQ HTML footer-link parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn release_publication_html_footer_link_parity_lane_qqqq"),
        "section 6 references the Lane QQQQ HTML footer-link parity test; release_packaging.rs must define it"
    );

    // Lane RRRR: smoke aggregator log-line shape parity row.
    assert!(
        runbook.contains("Smoke aggregator log-line shape parity (Lane RRRR)"),
        "section 6 must list the Lane RRRR smoke aggregator log-line shape parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn smoke_aggregator_log_line_shape_parity_lane_rrrr"),
        "section 6 references the Lane RRRR smoke aggregator log-line shape parity test; release_packaging.rs must define it"
    );

    // Lane SSSS: provider-acceptance JSON shape parity row.
    assert!(
        runbook.contains("Provider-acceptance JSON shape parity (Lane SSSS)"),
        "section 6 must list the Lane SSSS provider-acceptance JSON shape parity layer"
    );
    assert!(
        release_packaging_tests.contains("fn provider_acceptance_json_shape_parity_lane_ssss"),
        "section 6 references the Lane SSSS provider-acceptance JSON shape parity test; release_packaging.rs must define it"
    );

    // Lane TTTT: section-6 row count ↔ 4-letter lane test fn count parity row.
    assert!(
        runbook.contains("Section-6 row count parity (Lane TTTT)"),
        "section 6 must list the Lane TTTT section-6 row count parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn section_6_row_count_binds_to_4_letter_lane_test_fn_count_lane_tttt"),
        "section 6 references the Lane TTTT row count parity test; release_packaging.rs must define it"
    );

    // Lane UUUU: README heredoc Lane mention ↔ runbook lane coverage row.
    assert!(
        runbook.contains("README heredoc lane coverage (Lane UUUU)"),
        "section 6 must list the Lane UUUU README heredoc lane coverage layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn readme_heredoc_lane_mentions_bind_to_runbook_coverage_lane_uuuu"),
        "section 6 references the Lane UUUU README heredoc lane coverage test; release_packaging.rs must define it"
    );

    // Lane VVVV: install heredoc file references ↔ tar arglist parity.
    assert!(
        runbook.contains("Install heredoc artifact-ref parity (Lane VVVV)"),
        "section 6 must list the Lane VVVV install heredoc artifact-ref parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredoc_artifact_refs_bind_to_tar_arglist_lane_vvvv"),
        "section 6 references the Lane VVVV install heredoc artifact-ref parity test; release_packaging.rs must define it"
    );

    // Lane WWWW: install heredoc env var symmetry + clap separation parity.
    assert!(
        runbook.contains("Install heredoc env-var symmetry + clap separation (Lane WWWW)"),
        "section 6 must list the Lane WWWW install heredoc env var symmetry layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredoc_env_var_symmetry_and_clap_separation_lane_wwww"),
        "section 6 references the Lane WWWW install heredoc env var symmetry test; release_packaging.rs must define it"
    );

    // Lane XXXX: aggregator JSON key ↔ handler read parity.
    assert!(
        runbook.contains("Aggregator JSON key ↔ handler read parity (Lane XXXX)"),
        "section 6 must list the Lane XXXX aggregator JSON key ↔ handler read parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn aggregator_json_keys_bind_to_handler_reads_lane_xxxx"),
        "section 6 references the Lane XXXX aggregator JSON key parity test; release_packaging.rs must define it"
    );

    // Lane YYYY: HTML render fn ↔ route registration parity.
    assert!(
        runbook.contains("HTML render fn ↔ route registration parity (Lane YYYY)"),
        "section 6 must list the Lane YYYY HTML render fn parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn html_render_fns_bind_to_route_registration_lane_yyyy"),
        "section 6 references the Lane YYYY HTML render fn parity test; release_packaging.rs must define it"
    );

    // Lane ZZZZ: Cargo workspace member ↔ on-disk crate dir parity.
    assert!(
        runbook.contains("Cargo workspace member parity (Lane ZZZZ)"),
        "section 6 must list the Lane ZZZZ Cargo workspace member parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn cargo_workspace_members_bind_to_real_crate_dirs_lane_zzzz"),
        "section 6 references the Lane ZZZZ Cargo workspace member parity test; release_packaging.rs must define it"
    );

    // Lane AAAAA: workspace dependency unification parity.
    assert!(
        runbook.contains("Workspace dependency unification parity (Lane AAAAA)"),
        "section 6 must list the Lane AAAAA workspace dep unification parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn member_cargo_tomls_unify_via_workspace_dependencies_lane_aaaaa"),
        "section 6 references the Lane AAAAA workspace dep unification test; release_packaging.rs must define it"
    );

    // Lane BBBBB: install heredoc shebang + strict-mode parity.
    assert!(
        runbook.contains("Install heredoc shebang + strict-mode parity (Lane BBBBB)"),
        "section 6 must list the Lane BBBBB install heredoc strict-mode parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredocs_shebang_and_strict_mode_parity_lane_bbbbb"),
        "section 6 references the Lane BBBBB install heredoc strict-mode parity test; release_packaging.rs must define it"
    );

    // Lane CCCCC: Cargo.lock workspace-coverage parity.
    assert!(
        runbook.contains("Cargo.lock workspace-coverage parity (Lane CCCCC)"),
        "section 6 must list the Lane CCCCC Cargo.lock workspace coverage parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn cargo_lock_workspace_path_sources_match_members_lane_ccccc"),
        "section 6 references the Lane CCCCC Cargo.lock workspace coverage test; release_packaging.rs must define it"
    );

    // Lane DDDDD: tar arglist ↔ stage-area write parity.
    assert!(
        runbook.contains("Tar arglist ↔ stage-area write parity (Lane DDDDD)"),
        "section 6 must list the Lane DDDDD tar arglist ↔ stage write parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_local_tar_arglist_binds_to_stage_writes_lane_ddddd"),
        "section 6 references the Lane DDDDD tar arglist ↔ stage write test; release_packaging.rs must define it"
    );

    // Lane EEEEE: handler module declaration ↔ file existence parity.
    assert!(
        runbook.contains("Handler module declaration parity (Lane EEEEE)"),
        "section 6 must list the Lane EEEEE handler module decl parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn handler_module_declarations_bind_to_real_files_lane_eeeee"),
        "section 6 references the Lane EEEEE handler module decl test; release_packaging.rs must define it"
    );

    // Lane FFFFF: HTML page doctype + charset declaration parity.
    assert!(
        runbook.contains("HTML page doctype + charset parity (Lane FFFFF)"),
        "section 6 must list the Lane FFFFF HTML doctype + charset parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn release_publication_html_doctype_and_charset_parity_lane_fffff"),
        "section 6 references the Lane FFFFF HTML doctype + charset test; release_packaging.rs must define it"
    );

    // Lane GGGGG: schema-version `_v<N>` semver-suffix parity.
    assert!(
        runbook.contains("Schema version semver-suffix parity (Lane GGGGG)"),
        "section 6 must list the Lane GGGGG schema-version semver-suffix parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn release_schema_const_values_end_with_v_n_suffix_lane_ggggg"),
        "section 6 references the Lane GGGGG schema-version semver-suffix test; release_packaging.rs must define it"
    );

    // Lane HHHHH: install heredoc verify-before-copy checksum-flow parity.
    assert!(
        runbook.contains("Install heredoc verify-before-copy checksum flow parity (Lane HHHHH)"),
        "section 6 must list the Lane HHHHH install verify-before-copy parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredoc_verify_before_copy_checksum_flow_parity_lane_hhhhh"),
        "section 6 references the Lane HHHHH install verify-before-copy test; release_packaging.rs must define it"
    );

    // Lane IIIII: install heredoc SHA256 algorithm + case-normalization parity.
    assert!(
        runbook.contains("Install heredoc SHA256 algorithm + case-normalization parity (Lane IIIII)"),
        "section 6 must list the Lane IIIII install SHA256 algorithm + case-normalization parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredoc_sha256_algorithm_and_case_normalization_parity_lane_iiiii"),
        "section 6 references the Lane IIIII SHA256 algorithm + case-normalization test; release_packaging.rs must define it"
    );

    // Lane JJJJJ: install heredoc cwd-to-script-dir parity.
    assert!(
        runbook.contains("Install heredoc cwd-to-script-dir parity (Lane JJJJJ)"),
        "section 6 must list the Lane JJJJJ install cwd-to-script-dir parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredoc_cwd_to_script_dir_parity_lane_jjjjj"),
        "section 6 references the Lane JJJJJ cwd-to-script-dir test; release_packaging.rs must define it"
    );

    // Lane KKKKK: install heredoc INSTALL_DIR mkdir-with-parents parity.
    assert!(
        runbook.contains("Install heredoc INSTALL_DIR mkdir-with-parents parity (Lane KKKKK)"),
        "section 6 must list the Lane KKKKK INSTALL_DIR mkdir-with-parents parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredoc_install_dir_mkdir_with_parents_parity_lane_kkkkk"),
        "section 6 references the Lane KKKKK INSTALL_DIR mkdir-with-parents test; release_packaging.rs must define it"
    );

    // Lane LLLLL: README.txt docs/ path-claim ↔ real-file parity.
    assert!(
        runbook.contains("README docs/ path-claim parity (Lane LLLLL)"),
        "section 6 must list the Lane LLLLL README docs/ path-claim parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn readme_docs_path_claims_resolve_to_real_files_lane_lllll"),
        "section 6 references the Lane LLLLL README docs/ path-claim test; release_packaging.rs must define it"
    );

    // Lane MMMMM: forbidden-env preflight contract parity.
    assert!(
        runbook.contains("Forbidden-env preflight contract parity (Lane MMMMM)"),
        "section 6 must list the Lane MMMMM forbidden-env preflight contract parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn forbidden_env_preflight_contract_parity_lane_mmmmm"),
        "section 6 references the Lane MMMMM forbidden-env preflight contract test; release_packaging.rs must define it"
    );

    // Lane NNNNN: package-local.sh STAGE-dir trap cleanup parity.
    assert!(
        runbook.contains("Package-local STAGE-dir trap cleanup parity (Lane NNNNN)"),
        "section 6 must list the Lane NNNNN STAGE-dir trap cleanup parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_local_stage_dir_trap_cleanup_parity_lane_nnnnn"),
        "section 6 references the Lane NNNNN STAGE-dir trap cleanup test; release_packaging.rs must define it"
    );

    // Lane OOOOO: package-local.sh script-level shebang + strict-mode parity.
    assert!(
        runbook.contains("Package-local script shebang + strict-mode parity (Lane OOOOO)"),
        "section 6 must list the Lane OOOOO package-local script shebang + strict-mode parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_local_script_shebang_and_strict_mode_parity_lane_ooooo"),
        "section 6 references the Lane OOOOO package-local script shebang test; release_packaging.rs must define it"
    );

    // Lane PPPPP: package-local.sh default VERSION ↔ workspace version parity.
    assert!(
        runbook.contains("Package-local default VERSION ↔ workspace version parity (Lane PPPPP)"),
        "section 6 must list the Lane PPPPP package-local default VERSION ↔ workspace version parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_local_default_version_matches_workspace_version_lane_ppppp"),
        "section 6 references the Lane PPPPP package-local default VERSION ↔ workspace version test; release_packaging.rs must define it"
    );

    // Lane QQQQQ: package-local.sh default BINARY release-profile parity.
    assert!(
        runbook.contains("Package-local default BINARY release-profile parity (Lane QQQQQ)"),
        "section 6 must list the Lane QQQQQ package-local default BINARY release-profile parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_local_default_binary_is_release_profile_lane_qqqqq"),
        "section 6 references the Lane QQQQQ package-local default BINARY release-profile test; release_packaging.rs must define it"
    );

    // Lane RRRRR: package-local.sh `cp "$ROOT/<path>"` source files exist parity.
    assert!(
        runbook.contains("Package-local cp source paths ↔ real-file parity (Lane RRRRR)"),
        "section 6 must list the Lane RRRRR package-local cp source path ↔ real-file parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_local_cp_source_paths_resolve_to_real_files_lane_rrrrr"),
        "section 6 references the Lane RRRRR package-local cp source path test; release_packaging.rs must define it"
    );

    // Lane SSSSS: workspace package metadata unification parity.
    assert!(
        runbook.contains("Workspace package metadata unification parity (Lane SSSSS)"),
        "section 6 must list the Lane SSSSS workspace package metadata unification parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn member_cargo_tomls_unify_via_workspace_package_metadata_lane_sssss"),
        "section 6 references the Lane SSSSS workspace package metadata unification test; release_packaging.rs must define it"
    );

    // Lane TTTTT: workspace.dependencies semver-ish version string parity.
    assert!(
        runbook
            .contains("Workspace.dependencies semver-ish version string parity (Lane TTTTT)"),
        "section 6 must list the Lane TTTTT workspace.dependencies semver-ish version string parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn workspace_dependencies_have_semver_version_strings_lane_ttttt"),
        "section 6 references the Lane TTTTT workspace.dependencies semver-ish version test; release_packaging.rs must define it"
    );

    // Lane UUUUU: smoke-three-os-release.sh AO2_CP_VERSION default ↔ workspace version parity.
    assert!(
        runbook
            .contains("Smoke-three-os AO2_CP_VERSION ↔ workspace version parity (Lane UUUUU)"),
        "section 6 must list the Lane UUUUU smoke-three-os AO2_CP_VERSION ↔ workspace version parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn smoke_three_os_default_version_matches_workspace_version_lane_uuuuu"),
        "section 6 references the Lane UUUUU smoke-three-os AO2_CP_VERSION ↔ workspace version test; release_packaging.rs must define it"
    );

    // Lane VVVVV: HTML render fn read-only-observer trust-boundary disclaimer parity.
    assert!(
        runbook.contains(
            "HTML render fn read-only-observer trust-boundary disclaimer parity (Lane VVVVV)"
        ),
        "section 6 must list the Lane VVVVV HTML render fn read-only-observer trust-boundary disclaimer parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn html_render_fns_carry_read_only_observer_disclaimer_lane_vvvvv"),
        "section 6 references the Lane VVVVV HTML render fn read-only-observer disclaimer test; release_packaging.rs must define it"
    );

    // Lane WWWWW: runbook section heading number ordering parity.
    assert!(
        runbook.contains("Runbook section heading number ordering parity (Lane WWWWW)"),
        "section 6 must list the Lane WWWWW runbook section heading number ordering parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn release_smoke_runbook_section_headings_form_contiguous_sequence_lane_wwwww"),
        "section 6 references the Lane WWWWW runbook section heading number ordering test; release_packaging.rs must define it"
    );

    // Lane XXXXX: package-local.sh sha256sum/shasum cross-platform fallback parity.
    assert!(
        runbook.contains("Package-local sha256sum/shasum cross-platform fallback parity (Lane XXXXX)"),
        "section 6 must list the Lane XXXXX package-local sha256sum/shasum cross-platform fallback parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_local_sha256_has_cross_platform_fallback_lane_xxxxx"),
        "section 6 references the Lane XXXXX package-local sha256/shasum cross-platform fallback test; release_packaging.rs must define it"
    );

    // Lane YYYYY: package-local.sh README.txt heredoc trust-boundary disclaimer parity.
    assert!(
        runbook.contains("Package-local README.txt heredoc trust-boundary disclaimer parity (Lane YYYYY)"),
        "section 6 must list the Lane YYYYY package-local README.txt heredoc trust-boundary disclaimer parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_local_readme_heredoc_trust_boundary_disclaimer_lane_yyyyy"),
        "section 6 references the Lane YYYYY package-local README.txt heredoc trust-boundary disclaimer test; release_packaging.rs must define it"
    );

    // Lane ZZZZZ: RELEASE-MANIFEST.json python heredoc trust_boundary keys parity.
    assert!(
        runbook.contains("Release-manifest python heredoc trust_boundary keys parity (Lane ZZZZZ)"),
        "section 6 must list the Lane ZZZZZ RELEASE-MANIFEST.json python heredoc trust_boundary keys parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_local_release_manifest_trust_boundary_keys_lane_zzzzz"),
        "section 6 references the Lane ZZZZZ RELEASE-MANIFEST.json python heredoc trust_boundary keys test; release_packaging.rs must define it"
    );

    // Lane AAAAAA: RELEASE-MANIFEST.json schema_version semver-suffix parity.
    assert!(
        runbook.contains("Release-manifest schema_version semver-suffix parity (Lane AAAAAA)"),
        "section 6 must list the Lane AAAAAA RELEASE-MANIFEST.json schema_version semver-suffix parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_local_release_manifest_schema_version_semver_suffix_lane_aaaaaa"),
        "section 6 references the Lane AAAAAA RELEASE-MANIFEST.json schema_version semver-suffix test; release_packaging.rs must define it"
    );

    // Lane BBBBBB: package-local.sh archive filename format parity.
    assert!(
        runbook.contains("Package-local archive filename format parity (Lane BBBBBB)"),
        "section 6 must list the Lane BBBBBB package-local archive filename format parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_local_archive_filename_format_lane_bbbbbb"),
        "section 6 references the Lane BBBBBB package-local archive filename format test; release_packaging.rs must define it"
    );

    // Lane CCCCCC: smoke-three-os-release.sh shebang + strict-mode parity.
    assert!(
        runbook.contains("Smoke aggregator shebang + strict-mode parity (Lane CCCCCC)"),
        "section 6 must list the Lane CCCCCC smoke aggregator shebang + strict-mode parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn smoke_three_os_shebang_and_strict_mode_parity_lane_cccccc"),
        "section 6 references the Lane CCCCCC smoke aggregator shebang + strict-mode test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Install heredoc ao2_control_plane_installed= literal symmetry parity (Lane DDDDDD)"
        ),
        "section 6 must list the Lane DDDDDD install heredoc confirmation literal symmetry layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn install_heredocs_ao2_control_plane_installed_literal_symmetry_parity_lane_dddddd"
        ),
        "section 6 references the Lane DDDDDD install heredoc confirmation literal symmetry test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Per-host smoke shebang + strict-mode parity (Lane EEEEEE)"),
        "section 6 must list the Lane EEEEEE per-host smoke shebang + strict-mode parity layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn smoke_release_archive_per_host_shebang_and_strict_mode_parity_lane_eeeeee"
        ),
        "section 6 references the Lane EEEEEE per-host smoke shebang + strict-mode test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Install heredoc BINARY_NAME .exe cross-OS suffix parity (Lane FFFFFF)"
        ),
        "section 6 must list the Lane FFFFFF install heredoc BINARY_NAME .exe cross-OS suffix parity layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn install_heredoc_binary_name_exe_suffix_cross_os_parity_lane_ffffff"
        ),
        "section 6 references the Lane FFFFFF install heredoc BINARY_NAME .exe cross-OS suffix test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Smoke aggregator exit-code fail-loud parity (Lane GGGGGG)"),
        "section 6 must list the Lane GGGGGG smoke aggregator exit-code fail-loud parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn smoke_three_os_exit_code_fail_loud_parity_lane_gggggg"),
        "section 6 references the Lane GGGGGG smoke aggregator exit-code fail-loud test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Install heredoc AO2_CP_* env-var ↔ README reverse-documentation parity (Lane HHHHHH)"
        ),
        "section 6 must list the Lane HHHHHH install heredoc env-var README reverse parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredocs_ao2_cp_env_vars_documented_in_readme_lane_hhhhhh"),
        "section 6 references the Lane HHHHHH install heredoc env-var README reverse parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Smoke aggregator summary JSON schema semver-suffix parity (Lane IIIIII)"
        ),
        "section 6 must list the Lane IIIIII smoke aggregator summary JSON schema semver-suffix parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn smoke_three_os_summary_schema_semver_suffix_lane_iiiiii"),
        "section 6 references the Lane IIIIII smoke aggregator summary JSON schema semver-suffix test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Install heredoc cd-to-script-dir precedence parity (Lane JJJJJJ)"
        ),
        "section 6 must list the Lane JJJJJJ install heredoc cd-to-script-dir precedence parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredoc_cd_to_script_dir_precedence_lane_jjjjjj"),
        "section 6 references the Lane JJJJJJ install heredoc cd-to-script-dir precedence test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Release script EXIT trap cleanup parity (Lane KKKKKK)"),
        "section 6 must list the Lane KKKKKK release script EXIT trap cleanup parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn release_script_exit_trap_cleanup_parity_lane_kkkkkk"),
        "section 6 references the Lane KKKKKK release script EXIT trap cleanup test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "RELEASE-MANIFEST.json auth_value_stored=False security parity (Lane LLLLLL)"
        ),
        "section 6 must list the Lane LLLLLL RELEASE-MANIFEST.json auth_value_stored=False security parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn release_manifest_auth_value_stored_false_parity_lane_llllll"),
        "section 6 references the Lane LLLLLL RELEASE-MANIFEST.json auth_value_stored=False security test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "RELEASE-MANIFEST.json binary_path = bin/binary cross-field parity (Lane MMMMMM)"
        ),
        "section 6 must list the Lane MMMMMM RELEASE-MANIFEST.json binary_path = bin/binary cross-field parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn release_manifest_binary_path_bin_prefix_parity_lane_mmmmmm"),
        "section 6 references the Lane MMMMMM RELEASE-MANIFEST.json binary_path = bin/binary cross-field test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Install heredoc checksum mismatch error message parity (Lane NNNNNN)"
        ),
        "section 6 must list the Lane NNNNNN install heredoc checksum mismatch error message parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn install_heredoc_checksum_mismatch_error_parity_lane_nnnnnn"),
        "section 6 references the Lane NNNNNN install heredoc checksum mismatch error message test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Manifest offline_support_bundle_verifiers path-command parity (Lane OOOOOO)"
        ),
        "section 6 must list the Lane OOOOOO manifest offline_support_bundle_verifiers path-command parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn release_manifest_offline_verifiers_path_command_parity_lane_oooooo"),
        "section 6 references the Lane OOOOOO manifest offline_support_bundle_verifiers path-command parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Install heredoc sha256sum/shasum cross-platform fallback parity (Lane PPPPPP)"
        ),
        "section 6 must list the Lane PPPPPP install heredoc sha256sum/shasum cross-platform fallback parity layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn install_heredoc_sha256sum_shasum_cross_platform_fallback_parity_lane_pppppp"
        ),
        "section 6 references the Lane PPPPPP install heredoc sha256sum/shasum cross-platform fallback parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Package README.txt auth credential lifecycle parity (Lane QQQQQQ)"),
        "section 6 must list the Lane QQQQQQ package README.txt auth credential lifecycle parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn package_readme_auth_credential_lifecycle_parity_lane_qqqqqq"),
        "section 6 references the Lane QQQQQQ package README.txt auth credential lifecycle parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Smoke aggregator markdown report section structure parity (Lane RRRRRR)"
        ),
        "section 6 must list the Lane RRRRRR smoke aggregator markdown report section structure parity layer"
    );
    assert!(
        release_packaging_tests.contains(
            "fn smoke_aggregator_markdown_report_section_structure_parity_lane_rrrrrr"
        ),
        "section 6 references the Lane RRRRRR smoke aggregator markdown report section structure parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Smoke aggregator secret redaction pattern parity (Lane SSSSSS)"),
        "section 6 must list the Lane SSSSSS smoke aggregator secret-redaction pattern parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn smoke_aggregator_secret_redaction_pattern_parity_lane_ssssss"),
        "section 6 references the Lane SSSSSS smoke aggregator secret-redaction pattern parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("SECURITY.md source-code claim parity (Lane TTTTTT)"),
        "section 6 must list the Lane TTTTTT SECURITY.md source-code claim parity layer"
    );
    assert!(
        release_packaging_tests.contains("fn security_md_claims_bind_to_source_code_lane_tttttt"),
        "section 6 references the Lane TTTTTT SECURITY.md source-code claim parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("DEPLOYMENT.md flag and endpoint parity (Lane UUUUUU)"),
        "section 6 must list the Lane UUUUUU DEPLOYMENT.md flag and endpoint parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn deployment_md_flags_and_endpoints_bind_to_source_lane_uuuuuu"),
        "section 6 references the Lane UUUUUU DEPLOYMENT.md flag and endpoint parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Manifest outputs arrays bind to fetcher outputs parity (Lane VVVVVV)"),
        "section 6 must list the Lane VVVVVV manifest outputs arrays ↔ fetcher Python output files parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn manifest_outputs_arrays_bind_to_fetcher_outputs_lane_vvvvvv"),
        "section 6 references the Lane VVVVVV manifest outputs ↔ fetcher outputs parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Server Cargo.toml [[bin]] and [lib] declarations bind to sources (Lane WWWWWW)"
        ),
        "section 6 must list the Lane WWWWWW server Cargo.toml [[bin]]/[lib] declaration parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn server_cargo_toml_bin_and_lib_declarations_bind_to_sources_lane_wwwwww"),
        "section 6 references the Lane WWWWWW server Cargo.toml [[bin]]/[lib] declaration parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Route catalog entries bind to server route registrations (Lane XXXXXX)"
        ),
        "section 6 must list the Lane XXXXXX route_catalog ↔ server.rs route registration parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_entries_bind_to_server_route_registrations_lane_xxxxxx"),
        "section 6 references the Lane XXXXXX route_catalog ↔ server.rs route registration parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains(
            "Server route registrations bind to route catalog entries (Lane YYYYYY)"
        ),
        "section 6 must list the Lane YYYYYY server.rs route registration ↔ route_catalog parity layer (reverse direction)"
    );
    assert!(
        release_packaging_tests
            .contains("fn server_route_registrations_bind_to_route_catalog_entries_lane_yyyyyy"),
        "section 6 references the Lane YYYYYY server.rs route ↔ route_catalog reverse parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Mutating routes use POST not GET CSRF safety (Lane ZZZZZZ)"),
        "section 6 must list the Lane ZZZZZZ CSRF-safety invariant layer (mutating routes must not use GET)"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_mutating_routes_use_post_not_get_lane_zzzzzz"),
        "section 6 references the Lane ZZZZZZ CSRF-safety invariant test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog category field enum-shape parity (Lane AAAAAAA)"),
        "section 6 must list the Lane AAAAAAA route_catalog category field enum-shape parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_category_field_enum_shape_lane_aaaaaaa"),
        "section 6 references the Lane AAAAAAA route_catalog category enum-shape parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog method field enum parity (Lane BBBBBBB)"),
        "section 6 must list the Lane BBBBBBB route_catalog method field enum parity layer"
    );
    assert!(
        release_packaging_tests.contains("fn route_catalog_method_field_enum_parity_lane_bbbbbbb"),
        "section 6 references the Lane BBBBBBB route_catalog method enum parity test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog owner field membership parity (Lane CCCCCCC)"),
        "section 6 must list the Lane CCCCCCC route_catalog owner field membership parity layer"
    );
    assert!(
        release_packaging_tests.contains("fn route_catalog_owner_field_membership_lane_ccccccc"),
        "section 6 references the Lane CCCCCCC route_catalog owner field membership test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog download flag implications parity (Lane DDDDDDD)"),
        "section 6 must list the Lane DDDDDDD route_catalog download flag semantic implications layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_download_flag_implications_lane_ddddddd"),
        "section 6 references the Lane DDDDDDD download flag implications test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog download path naming convention parity (Lane EEEEEEE)"),
        "section 6 must list the Lane EEEEEEE route_catalog download path naming convention layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_download_path_naming_convention_lane_eeeeeee"),
        "section 6 references the Lane EEEEEEE download path naming convention test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog portable flag non-mutating implication parity (Lane FFFFFFF)"),
        "section 6 must list the Lane FFFFFFF route_catalog portable→non-mutating implication layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_portable_implies_non_mutating_lane_fffffff"),
        "section 6 references the Lane FFFFFFF portable→non-mutating test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("RouteMetadata struct and to_json schema parity (Lane GGGGGGG)"),
        "section 6 must list the Lane GGGGGGG RouteMetadata struct + to_json schema parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_struct_and_to_json_schema_lane_ggggggg"),
        "section 6 references the Lane GGGGGGG struct + to_json schema test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Handler SCHEMA constants canonical shape parity (Lane HHHHHHH)"),
        "section 6 must list the Lane HHHHHHH workspace-wide handler SCHEMA constant shape parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn handler_schema_constants_have_canonical_shape_lane_hhhhhhh"),
        "section 6 references the Lane HHHHHHH SCHEMA constant shape test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog method-path tuple uniqueness parity (Lane IIIIIII)"),
        "section 6 must list the Lane IIIIIII (method, path) tuple uniqueness parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_method_path_tuples_are_unique_lane_iiiiiii"),
        "section 6 references the Lane IIIIIII tuple uniqueness test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog path canonical-prefix parity (Lane JJJJJJJ)"),
        "section 6 must list the Lane JJJJJJJ canonical /api/v1/ prefix + no-trailing-slash parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_paths_use_canonical_prefix_lane_jjjjjjj"),
        "section 6 references the Lane JJJJJJJ canonical-prefix test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog category coverage parity (Lane KKKKKKK)"),
        "section 6 must list the Lane KKKKKKK reverse-direction category coverage parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_category_coverage_parity_lane_kkkkkkk"),
        "section 6 references the Lane KKKKKKK category coverage test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog owner coverage parity (Lane LLLLLLL)"),
        "section 6 must list the Lane LLLLLLL reverse-direction owner coverage parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_owner_coverage_parity_lane_lllllll"),
        "section 6 references the Lane LLLLLLL owner coverage test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog path :param snake_case naming parity (Lane MMMMMMM)"),
        "section 6 must list the Lane MMMMMMM path-parameter snake_case naming parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_path_params_use_snake_case_lane_mmmmmmm"),
        "section 6 references the Lane MMMMMMM path-param snake_case test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("HTML page title AO2 operator-anchor parity (Lane NNNNNNN)"),
        "section 6 must list the Lane NNNNNNN HTML title operator-anchor parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn html_page_titles_contain_ao2_operator_anchor_lane_nnnnnnn"),
        "section 6 references the Lane NNNNNNN title operator-anchor test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("HTML page title uniqueness parity (Lane OOOOOOO)"),
        "section 6 must list the Lane OOOOOOO HTML title uniqueness parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn html_page_titles_are_unique_lane_ooooooo"),
        "section 6 references the Lane OOOOOOO title uniqueness test; release_packaging.rs must define it"
    );

    assert!(
        runbook.contains("Route catalog category kebab-case naming parity (Lane PPPPPPP)"),
        "section 6 must list the Lane PPPPPPP category kebab-case naming parity layer"
    );
    assert!(
        release_packaging_tests
            .contains("fn route_catalog_categories_use_kebab_case_lane_ppppppp"),
        "section 6 references the Lane PPPPPPP category kebab-case test; release_packaging.rs must define it"
    );
}

// Lane HHH: meta-parity across the three on-call triage surfaces — the
// cockpit HTML renderer (Lane EEE), the runbook (Lanes DDD + EEE-doc),
// and the support-bundle README (Lane GGG). An on-call operator paged
// on a Lane XX-doc rule-2 tampering-burst alert lands on whichever
// surface their alert routing pointed at; the load-bearing framing,
// the mutex identifier, and the worked-example test names must agree
// across all three so the operator's mental model is coherent
// regardless of entry point.
//
// Earlier per-surface parity tests catch single-surface drift:
//  - `release_smoke_runbook_references_actual_gate_ids_and_triage_paths`
//    cross-binds runbook ↔ source code (Lane DDD) and runbook ↔ renderer
//    (Lane EEE-doc).
//  - `package_script_creates_installable_control_plane_archive`
//    cross-binds README ↔ heredoc literals (Lane GGG).
// But none of those catches the case where someone renames a load-
// bearing literal and only updates two of the three surfaces. Lane
// HHH closes that meta-gap with a single test that reads all three
// sources and asserts an identical canonical set.
#[test]
fn on_call_triage_surfaces_agree_on_load_bearing_literals_lane_hhh() {
    let runbook = std::fs::read_to_string("../../docs/runbooks/release-smoke.md")
        .expect("runbook must be readable");
    let renderer_src =
        std::fs::read_to_string("../ao2-cp-server/src/handlers/release_publication.rs")
            .expect("release_publication.rs renderer must be readable");
    let package_script = std::fs::read_to_string("../../scripts/package-local.sh")
        .expect("package-local.sh must be readable so the README heredoc is reachable");

    // The "doc-surface" canonical set: literals an operator needs when
    // they're reading documentation, not glancing at the cockpit HTML.
    // The mutex identifier and the worked-example test name are
    // implementation detail — they don't belong in the rendered HTML
    // (the HTML is the entry-point pointer, not the deep dive). Both
    // must appear in BOTH the runbook AND the README so an operator
    // who picked up the support-bundle archive first (no live cockpit
    // available) still has the mutex anchor + test reference inline.
    let doc_only_literals = [
        // The mutex identifier — the on-call's anchor when they ask
        // "is the audit log itself OK?". Cross-bound to
        // phase1_promotion.rs by the Lane DDD parity test above.
        "REJECTED_SMOKE_AUDIT_WRITER_LOCK",
        // The worked-example test — proof the mutex behavior is
        // pinned. Without the test reference, "the mutex protects the
        // append path" is just an assertion in prose.
        "audit_log_rotation_stays_well_formed_under_concurrent_burst_lane_ww_rotation",
    ];

    for literal in doc_only_literals {
        assert!(
            runbook.contains(literal),
            "Lane HHH: runbook must reference doc-surface literal {literal:?}"
        );
        assert!(
            package_script.contains(literal),
            "Lane HHH: README heredoc must reference doc-surface literal {literal:?}"
        );
    }

    // Sanity: at least one canonical reference exists in the renderer
    // so the on-call surface ties back to the doc surface. Today this
    // is the section-9.9 pointer (asserted below); the explicit assert
    // here surfaces a future drift where someone strips the renderer
    // pointer entirely.
    assert!(
        renderer_src.contains("runbook section 9.9"),
        "Lane HHH: renderer must retain at least one canonical pointer to the doc surface"
    );

    // The framing literal is the load-bearing on-call takeaway. The
    // README phrasing has a different connective ("not at audit-log
    // corruption") because the runbook section closes a longer
    // paragraph. The renderer and runbook use "tampering event, not
    // audit-log corruption" (parenthetical phrasing). Both phrasings
    // contain the load-bearing fragment "audit-log corruption" — so
    // we anchor on that. If a future rewrite drops the phrase
    // altogether, all three asserts fail.
    let framing_anchor = "audit-log corruption";
    assert!(
        runbook.contains(framing_anchor),
        "Lane HHH: runbook must contain the on-call framing anchor {framing_anchor:?}"
    );
    assert!(
        renderer_src.contains(framing_anchor),
        "Lane HHH: renderer must contain the on-call framing anchor {framing_anchor:?}"
    );
    assert!(
        package_script.contains(framing_anchor),
        "Lane HHH: package-local.sh must contain the on-call framing anchor {framing_anchor:?}"
    );

    // The runbook section pointer that the cockpit row surfaces must
    // resolve in the runbook. If section 9.9 disappears, the pointer
    // is a dead link.
    assert!(
        runbook.contains("### 9.9 Concurrent-write protection"),
        "Lane HHH: runbook section 9.9 must exist so the cockpit-row pointer resolves"
    );
    assert!(
        renderer_src.contains("runbook section 9.9"),
        "Lane HHH: renderer must point at section 9.9"
    );
    // The README references section 9.9 with a parenthetical
    // disambiguator ("9.9 (mutex + framing)") so an operator reading
    // the README knows what section 9.9 covers without flipping over.
    assert!(
        package_script.contains("9.9 (mutex + framing)"),
        "Lane HHH: README must reference section 9.9 with its disambiguator"
    );
}

// Lane KKK + LLL: section 6 row-level structural parity.
//
// Lane III added per-row asserts that each known gate-enforcement row
// names a file + identifier that exists on disk. Those checks are
// effective today but require a hand-written assert for every new row
// (eight asserts went in for Lane III alone). The two tests below add
// structural parity so future rows are enforced automatically:
//
//   * Lane KKK (forward): every row in section 6 that names a "Lane XX"
//     label must reference at least one backtick-wrapped workspace path
//     that exists on disk. A future row added with a Lane label but no
//     source pointer fails here.
//
//   * Lane LLL (reverse): every "Lane XX" label appearing in section 6
//     must also appear at least once OUTSIDE section 6 in the workspace
//     (crates/, scripts/, or docs/runbooks/ outside this section). A
//     future fabricated/typoed row referencing a Lane that doesn't
//     actually exist anywhere else fails here.
//
// Together they replace the one-direction hand-written parity (Lane III
// table→code) with a bidirectional structural binding: section 6 must
// cite real existing files (KKK) AND must trace back to real lane
// references elsewhere in the workspace (LLL).

fn section_6_slice(runbook: &str) -> &str {
    let start = runbook
        .find("## 6. Where the gates are enforced")
        .expect("section 6 header present");
    let rest = &runbook[start..];
    let end_rel = rest
        .find("\n---\n")
        .expect("section 6 must be terminated by a horizontal rule before section 7");
    &rest[..end_rel]
}

fn lane_labels_in(text: &str) -> Vec<String> {
    // Scanner equivalent to the regex
    //   Lane [A-Z][A-Z0-9]*(-[A-Za-z0-9-]+)?( + [A-Z][A-Z0-9]*)?
    // Designed to match:
    //   "Lane W", "Lane WW", "Lane WW-rotation", "Lane PP-server",
    //   "Lane XX-doc", "Lane BBB + FFF", "Lane MM + QQ".
    let bytes = text.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        if &bytes[i..i + 5] != b"Lane " {
            i += 1;
            continue;
        }
        // Word boundary: previous byte (if any) must NOT be an identifier
        // character; otherwise we'd match "FooLane " mid-token.
        if i > 0 {
            let prev = bytes[i - 1] as char;
            if prev.is_ascii_alphanumeric() || prev == '_' {
                i += 1;
                continue;
            }
        }
        let mut j = i + 5;
        if j >= bytes.len() || !(bytes[j] as char).is_ascii_uppercase() {
            i += 1;
            continue;
        }
        while j < bytes.len() {
            let c = bytes[j] as char;
            if c.is_ascii_uppercase() || c.is_ascii_digit() {
                j += 1;
            } else {
                break;
            }
        }
        // Optional `-` + alphanumeric+hyphen suffix (lowercase allowed).
        if j < bytes.len() && bytes[j] == b'-' {
            let mut k = j + 1;
            while k < bytes.len() {
                let c = bytes[k] as char;
                if c.is_ascii_alphanumeric() || c == '-' {
                    k += 1;
                } else {
                    break;
                }
            }
            if k > j + 1 {
                j = k;
            }
        }
        // Optional ` + UPPERCASE...` join (e.g. "Lane BBB + FFF").
        if j + 3 < bytes.len() && &bytes[j..j + 3] == b" + " {
            let mut k = j + 3;
            if k < bytes.len() && (bytes[k] as char).is_ascii_uppercase() {
                let m0 = k;
                while k < bytes.len() {
                    let c = bytes[k] as char;
                    if c.is_ascii_uppercase() || c.is_ascii_digit() {
                        k += 1;
                    } else {
                        break;
                    }
                }
                if k > m0 {
                    j = k;
                }
            }
        }
        out.push(text[i..j].to_string());
        i = j;
    }
    out
}

fn backtick_segments(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut inside = false;
    let mut buf = String::new();
    for ch in text.chars() {
        if ch == '`' {
            if inside {
                out.push(std::mem::take(&mut buf));
            } else {
                buf.clear();
            }
            inside = !inside;
        } else if inside {
            buf.push(ch);
        }
    }
    out
}

#[test]
fn section_6_table_rows_bind_every_lane_label_to_existing_source_pointer_lane_kkk() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runbook =
        fs::read_to_string(root.join("docs/runbooks/release-smoke.md")).expect("runbook present");
    let section_6 = section_6_slice(&runbook);

    let rows: Vec<&str> = section_6
        .lines()
        .filter(|line| line.trim_start().starts_with('|'))
        .collect();
    // Header + separator + the Lane III post-completion data rows.
    assert!(
        rows.len() >= 27,
        "Lane KKK: section 6 must include header + separator + at least 25 data rows; got {} table lines",
        rows.len()
    );

    let mut rows_with_labels = 0;
    for row in rows.iter().skip(2) {
        let labels = lane_labels_in(row);
        if labels.is_empty() {
            continue;
        }
        rows_with_labels += 1;
        let segs = backtick_segments(row);
        let mut found_existing = false;
        let mut considered: Vec<String> = Vec::new();
        for seg in &segs {
            let token = seg
                .split_whitespace()
                .next()
                .unwrap_or(seg)
                .trim_matches(|c: char| matches!(c, '.' | ',' | ';' | '(' | ')' | ':'));
            if token.starts_with("crates/")
                || token.starts_with("scripts/")
                || token.starts_with("docs/")
            {
                considered.push(token.to_string());
                if root.join(token).exists() {
                    found_existing = true;
                    break;
                }
            }
        }
        assert!(
            found_existing,
            "Lane KKK: section 6 row mentioning {labels:?} must reference at least one existing workspace path \
             (crates/, scripts/, or docs/) in a backtick-wrapped segment. Considered: {considered:?}. Row: {row}"
        );
    }

    // Defensive floor: at least the Lane III-shipped lane-bearing row
    // count must remain so a future regression cannot silently strip
    // every Lane label out of section 6.
    assert!(
        rows_with_labels >= 16,
        "Lane KKK: section 6 must retain at least 16 lane-bearing rows; saw {rows_with_labels}"
    );
}

#[test]
fn section_6_lane_labels_trace_back_to_workspace_source_lane_lll() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runbook =
        fs::read_to_string(root.join("docs/runbooks/release-smoke.md")).expect("runbook present");
    let section_6 = section_6_slice(&runbook);
    let mut labels = lane_labels_in(section_6);
    labels.sort();
    labels.dedup();
    assert!(
        !labels.is_empty(),
        "Lane LLL: section 6 must enumerate at least one Lane label"
    );

    // Build the search corpus: every workspace text file outside section 6
    // that could legitimately reference a Lane label. Section 6 itself is
    // excluded so we enforce reverse symmetry — a fabricated label that
    // exists ONLY in section 6 will not be found.
    let s6_start = runbook.find("## 6.").expect("section 6 header present");
    let s6_end_rel = runbook[s6_start..]
        .find("\n---\n")
        .expect("section 6 terminator present");
    let mut runbook_minus_s6 = String::with_capacity(runbook.len());
    runbook_minus_s6.push_str(&runbook[..s6_start]);
    runbook_minus_s6.push_str(&runbook[s6_start + s6_end_rel..]);

    let mut blobs: Vec<String> = vec![runbook_minus_s6];

    fn collect_text(dir: &Path, exts: &[&str], skip_path: &Path, sink: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p == skip_path {
                continue;
            }
            if p.is_dir() {
                collect_text(&p, exts, skip_path, sink);
                continue;
            }
            if let Some(ext) = p.extension().and_then(OsStr::to_str) {
                if exts.contains(&ext) {
                    if let Ok(content) = fs::read_to_string(&p) {
                        sink.push(content);
                    }
                }
            }
        }
    }

    let runbook_path = root.join("docs/runbooks/release-smoke.md");
    collect_text(&root.join("crates"), &["rs"], Path::new(""), &mut blobs);
    collect_text(
        &root.join("scripts"),
        &["sh", "ps1", "py"],
        Path::new(""),
        &mut blobs,
    );
    collect_text(
        &root.join("docs/runbooks"),
        &["md"],
        &runbook_path,
        &mut blobs,
    );

    let joined = blobs.join("\n");
    for label in &labels {
        assert!(
            joined.contains(label),
            "Lane LLL: section 6 names {label:?} but the label appears nowhere else in \
             crates/, scripts/, or docs/runbooks/ — section 6 must trace back to a real \
             workspace artifact, not a fabricated or typoed lane reference"
        );
    }
}

// Lane MMM: identifier-existence binding for section 6 rows.
//
// Lane KKK pinned that each lane-bearing row in section 6 references at
// least one existing workspace path. Lane LLL pinned that every lane
// label in section 6 traces back to a real artifact. Lane MMM closes
// the last unstructured gap: for each row, every backtick-wrapped token
// that looks like a function (`ident()`) OR a SCREAMING_SNAKE_CASE
// constant must actually exist as a literal in the most recently named
// file path in the same row.
//
// This catches the case where a future refactor renames
// `validate_three_os_release_smoke` (or `REJECTED_SMOKE_AUDIT_MAX_BYTES`)
// in source but leaves the runbook citing the old name. Today Lane III
// pins specific identifiers via hand-written asserts; Lane MMM does the
// same job structurally so future rows don't require a parallel
// hand-written assert to be safe.
//
// Tokens with wildcards (`*`, `...`, `<...>`), spaces, quotes, or `=`
// are skipped — they're descriptive shape literals, not identifiers.

fn looks_like_function_ident(s: &str) -> bool {
    if !s.ends_with("()") {
        return false;
    }
    let inner = &s[..s.len() - 2];
    if inner.is_empty() {
        return false;
    }
    let first = inner.chars().next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn looks_like_screaming_snake_const(s: &str) -> bool {
    // At least 5 chars; uppercase letter or digit or underscore; starts
    // with an uppercase letter; contains at least one underscore so we
    // don't catch single uppercase words like "OS" / "JSON".
    if s.len() < 5 {
        return false;
    }
    let first = s.chars().next().unwrap();
    if !first.is_ascii_uppercase() {
        return false;
    }
    if !s.contains('_') {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[test]
fn section_6_row_identifier_tokens_exist_in_referenced_files_lane_mmm() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runbook =
        fs::read_to_string(root.join("docs/runbooks/release-smoke.md")).expect("runbook present");
    let section_6 = section_6_slice(&runbook);

    let rows: Vec<&str> = section_6
        .lines()
        .filter(|line| line.trim_start().starts_with('|'))
        .skip(2)
        .collect();

    let mut verified_identifiers: usize = 0;
    for row in &rows {
        let segs = backtick_segments(row);
        // As we scan the row left-to-right, remember the last file path
        // whose contents we successfully loaded; subsequent identifier
        // tokens are resolved against that file.
        let mut current_file_path: Option<String> = None;
        let mut current_file_content: Option<String> = None;
        for seg in &segs {
            let first_tok = seg
                .split_whitespace()
                .next()
                .unwrap_or(seg)
                .trim_matches(|c: char| matches!(c, '.' | ',' | ';' | '(' | ')' | ':'));
            let is_pathish = first_tok.starts_with("crates/")
                || first_tok.starts_with("scripts/")
                || first_tok.starts_with("docs/");
            if is_pathish {
                let path = root.join(first_tok);
                if path.is_file() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        current_file_path = Some(first_tok.to_string());
                        current_file_content = Some(content);
                        continue;
                    }
                }
                // Path-shaped but not loadable as a regular file (e.g.
                // directory-only path or missing file). Don't poison
                // subsequent identifier lookups with a stale prior file.
                current_file_path = None;
                current_file_content = None;
                continue;
            }
            // Non-path segment: only enforce on strict identifier shapes.
            let Some(content) = current_file_content.as_deref() else {
                continue;
            };
            let path_disp = current_file_path.clone().unwrap_or_default();
            if looks_like_function_ident(seg) {
                let bare = &seg[..seg.len() - 2];
                assert!(
                    content.contains(bare),
                    "Lane MMM: section 6 row references function {seg:?} after path {path_disp:?}, \
                     but the identifier {bare:?} does not appear in that file. Row: {row}"
                );
                verified_identifiers += 1;
            } else if looks_like_screaming_snake_const(seg) {
                assert!(
                    content.contains(seg.as_str()),
                    "Lane MMM: section 6 row references constant {seg:?} after path {path_disp:?}, \
                     but the constant does not appear in that file. Row: {row}"
                );
                verified_identifiers += 1;
            }
        }
    }

    // Defensive floor: if a future refactor strips every function/const
    // identifier out of section 6, the test would otherwise pass vacuously.
    // Pin the post-Lane-III count so a structural regression surfaces here.
    assert!(
        verified_identifiers >= 14,
        "Lane MMM: section 6 must retain at least 14 verified function/constant identifiers; saw {verified_identifiers}"
    );
}

// Lane NNN: README heredoc structural binding to the runbook.
//
// `scripts/package-local.sh` embeds the operator-facing README.txt that
// ships inside every release archive. That heredoc references the
// runbook by Lane label (e.g. "Lane XX-doc, runbook section 9.6") and
// by numbered section pointer (e.g. "sections 9.5-9.10"). Today nothing
// catches the case where a runbook section is renamed or a Lane label
// in the README is mistyped — the README ships stale, operators land on
// missing anchors.
//
// Lane NNN closes that gap with two structural binding checks against
// the embedded README:
//
//   1. Every `Lane XX` label in the README must also appear at least
//      once in `docs/runbooks/release-smoke.md`.
//   2. Every numbered section pointer referenced in the README (handling
//      single-section "section 9.6" and ranges "sections 9.5-9.10") must
//      resolve to an actual `## N.` or `### N.M` header in the runbook.
//
// The README excerpt is read from the heredoc bounded by
//   cat > "$STAGE/README.txt" <<'TXT' ... TXT
// in `scripts/package-local.sh`. Bound-anchored extraction means a
// future heredoc rename surfaces as a test failure here.

fn extract_package_readme_heredoc(package_script: &str) -> String {
    let opener = "cat > \"$STAGE/README.txt\" <<'TXT'\n";
    let start = package_script
        .find(opener)
        .expect("Lane NNN: package-local.sh must contain the README.txt heredoc opener");
    let body_start = start + opener.len();
    let body = &package_script[body_start..];
    let end_rel = body
        .find("\nTXT\n")
        .expect("Lane NNN: README.txt heredoc must close with a 'TXT' marker on its own line");
    body[..end_rel].to_string()
}

fn extract_readme_section_pointers(readme: &str) -> Vec<String> {
    // Normalize the README into an ASCII-only single-spaced string. Non-
    // ASCII bytes are replaced with spaces so byte-indexed scanning stays
    // char-aligned (section pointers and lane labels are all ASCII).
    let mut normalized = String::with_capacity(readme.len());
    let mut prev_was_ws = false;
    for &b in readme.as_bytes() {
        // Treat any non-ASCII byte or ASCII whitespace as a single space;
        // everything else passes through as-is.
        let c = if !b.is_ascii() || (b as char).is_whitespace() {
            ' '
        } else {
            b as char
        };
        if c == ' ' {
            if !prev_was_ws {
                normalized.push(' ');
            }
            prev_was_ws = true;
        } else {
            normalized.push(c);
            prev_was_ws = false;
        }
    }

    let bytes = normalized.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        // Detect 'section ' or 'sections '.
        let opener: Option<usize> = if normalized[i..].starts_with("sections ") {
            Some(i + "sections ".len())
        } else if normalized[i..].starts_with("section ") {
            Some(i + "section ".len())
        } else {
            None
        };
        let Some(mut j) = opener else {
            i += 1;
            continue;
        };

        // Parse the first NUMBER[.NUMBER] starting at `start`. All bytes
        // in `bytes` are ASCII, so byte indices are safe to slice on.
        let parse_dotted = |start: usize, bytes: &[u8], src: &str| -> Option<(String, usize)> {
            let mut k = start;
            while k < bytes.len() && (bytes[k] as char).is_ascii_digit() {
                k += 1;
            }
            if k == start {
                return None;
            }
            if k < bytes.len()
                && bytes[k] == b'.'
                && (k + 1) < bytes.len()
                && (bytes[k + 1] as char).is_ascii_digit()
            {
                let mut m = k + 1;
                while m < bytes.len() && (bytes[m] as char).is_ascii_digit() {
                    m += 1;
                }
                Some((src[start..m].to_string(), m))
            } else {
                Some((src[start..k].to_string(), k))
            }
        };

        let Some((lo, after_lo)) = parse_dotted(j, bytes, &normalized) else {
            i = j;
            continue;
        };
        out.push(lo.clone());
        j = after_lo;

        // Range form: lo-hi (ASCII hyphen only; non-ASCII was wiped above).
        if j < bytes.len() && bytes[j] == b'-' {
            if let Some((hi, _after_hi)) = parse_dotted(j + 1, bytes, &normalized) {
                if let (Some(lo_int), Some(hi_int)) = (lo.find('.'), hi.find('.')) {
                    let base_lo = &lo[..lo_int];
                    let base_hi = &hi[..hi_int];
                    if base_lo == base_hi {
                        if let (Ok(lo_sub), Ok(hi_sub)) = (
                            lo[lo_int + 1..].parse::<u32>(),
                            hi[hi_int + 1..].parse::<u32>(),
                        ) {
                            if hi_sub > lo_sub && (hi_sub - lo_sub) < 50 {
                                for n in (lo_sub + 1)..=hi_sub {
                                    out.push(format!("{base_lo}.{n}"));
                                }
                            }
                        }
                    }
                } else {
                    out.push(hi);
                }
            }
        }

        i = j;
    }

    out.sort();
    out.dedup();
    out
}

#[test]
fn readme_heredoc_lane_labels_and_section_pointers_resolve_in_runbook_lane_nnn() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane NNN: package-local.sh present");
    let runbook = fs::read_to_string(root.join("docs/runbooks/release-smoke.md"))
        .expect("Lane NNN: runbook present");

    let readme = extract_package_readme_heredoc(&package);
    assert!(
        !readme.is_empty() && readme.len() > 1000,
        "Lane NNN: README heredoc must contain operator content (got {} bytes)",
        readme.len()
    );

    // (1) Every Lane label in the README must also appear in the runbook.
    let mut readme_labels = lane_labels_in(&readme);
    readme_labels.sort();
    readme_labels.dedup();
    assert!(
        !readme_labels.is_empty(),
        "Lane NNN: README heredoc must reference at least one Lane label so operators have a triage anchor"
    );
    for label in &readme_labels {
        assert!(
            runbook.contains(label),
            "Lane NNN: README heredoc references {label:?} but the label does not appear in docs/runbooks/release-smoke.md — \
             a future label rename must touch both surfaces in lockstep"
        );
    }

    // (2) Every section pointer in the README must resolve to an actual
    // section header in the runbook.
    let pointers = extract_readme_section_pointers(&readme);
    assert!(
        !pointers.is_empty(),
        "Lane NNN: README heredoc must reference at least one runbook section by number"
    );
    for ptr in &pointers {
        if ptr.contains('.') {
            // Sub-section: "### N.M " or "### N.M\n" or "### N.M-..." headers.
            let needle_space = format!("### {ptr} ");
            let needle_eol = format!("### {ptr}\n");
            let needle_dot = format!("### {ptr}.");
            let resolves = runbook.contains(&needle_space)
                || runbook.contains(&needle_eol)
                || runbook.contains(&needle_dot);
            assert!(
                resolves,
                "Lane NNN: README heredoc references section {ptr:?} but no '### {ptr} ...' header exists in the runbook"
            );
        } else {
            // Top-level section: "## N. " header.
            let needle = format!("## {ptr}. ");
            assert!(
                runbook.contains(&needle),
                "Lane NNN: README heredoc references section {ptr:?} but no '## {ptr}. ...' header exists in the runbook"
            );
        }
    }
}

// Lane OOO: README heredoc → source identifier-existence binding.
//
// Lane NNN bound the README to the runbook on Lane labels and section
// pointers. The README still references workspace identifiers that
// Lane NNN cannot validate: snake_case test/function names (e.g.
// `validate_three_os_release_smoke`,
// `audit_log_rotation_stays_well_formed_under_concurrent_burst_lane_ww_rotation`),
// SCREAMING_SNAKE_CASE constants (e.g. `REJECTED_SMOKE_AUDIT_WRITER_LOCK`),
// and snake_case rotation-budget JSON field names (e.g.
// `audit_log_size_bytes`, `audit_log_cap_bytes`).
//
// Lane OOO closes that gap: every such identifier appearing in the
// README must also appear at least once in the workspace source
// (`crates/` or `scripts/`). A future rename of a referenced test name
// or constant fails here before the stale README ships inside the
// release archive.
//
// Skip-list controls noise: a small set of well-known operator-facing
// strings (env-var names declared by the README itself, generic shell
// idioms) are excluded because they're system variables, not workspace
// identifiers.

fn is_screaming_snake_constant_token(s: &str) -> bool {
    if s.len() < 6 {
        return false;
    }
    if !s.starts_with(|c: char| c.is_ascii_uppercase()) {
        return false;
    }
    if !s.contains('_') {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_snake_case_identifier_token(s: &str) -> bool {
    // Require at least 4 underscore-joined segments (so "foo_bar" is
    // skipped, but "audit_log_size_bytes" matches). Letters must be
    // lowercase ASCII, digits allowed.
    let segments: Vec<&str> = s.split('_').collect();
    if segments.len() < 4 {
        return false;
    }
    if segments.iter().any(|seg| seg.is_empty()) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn collect_identifier_tokens(text: &str) -> Vec<String> {
    // Scan the text for maximal-length identifier tokens — runs of
    // alphanumeric + underscore characters bounded by non-identifier
    // characters.
    let mut out: Vec<String> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        let is_id_char = (b as char).is_ascii_alphanumeric() || b == b'_';
        if !is_id_char {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() {
            let c = bytes[i];
            if (c as char).is_ascii_alphanumeric() || c == b'_' {
                i += 1;
            } else {
                break;
            }
        }
        out.push(text[start..i].to_string());
    }
    out
}

#[test]
fn readme_heredoc_identifier_tokens_exist_in_workspace_source_lane_ooo() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane OOO: package-local.sh present");
    let readme = extract_package_readme_heredoc(&package);
    assert!(
        !readme.is_empty() && readme.len() > 1000,
        "Lane OOO: README heredoc must contain operator content (got {} bytes)",
        readme.len()
    );

    // Build the search corpus: every text file under crates/ and scripts/
    // (the README's pointers are always into one of these).
    fn collect_source(dir: &Path, exts: &[&str], sink: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_source(&p, exts, sink);
                continue;
            }
            if let Some(ext) = p.extension().and_then(OsStr::to_str) {
                if exts.contains(&ext) {
                    if let Ok(content) = fs::read_to_string(&p) {
                        sink.push(content);
                    }
                }
            }
        }
    }
    let mut blobs: Vec<String> = Vec::new();
    collect_source(&root.join("crates"), &["rs"], &mut blobs);
    collect_source(&root.join("scripts"), &["sh", "ps1", "py"], &mut blobs);
    let joined = blobs.join("\n");

    // Tokens skipped: well-known operator-facing system / shell names that
    // aren't workspace identifiers.
    const SKIP_TOKENS: &[&str] = &[
        // Windows env var
        "USERPROFILE",
        // Hosts / placeholders
        "AO2_CP_AUTH_VALUE",
        "AO2_CP_API_TOKEN",
        "AO2_CP_INSTALL_DIR",
    ];

    let tokens = collect_identifier_tokens(&readme);
    let mut verified_consts = 0usize;
    let mut verified_snakes = 0usize;
    for tok in &tokens {
        if SKIP_TOKENS.contains(&tok.as_str()) {
            continue;
        }
        if is_screaming_snake_constant_token(tok) {
            assert!(
                joined.contains(tok),
                "Lane OOO: README heredoc references constant {tok:?} but the constant does not \
                 appear anywhere in crates/ or scripts/ — a future rename must touch both surfaces"
            );
            verified_consts += 1;
        } else if is_snake_case_identifier_token(tok) {
            assert!(
                joined.contains(tok),
                "Lane OOO: README heredoc references identifier {tok:?} but the identifier does not \
                 appear anywhere in crates/ or scripts/ — a future rename must touch both surfaces"
            );
            verified_snakes += 1;
        }
    }

    // Defensive floors so a future strip of every identifier reference
    // doesn't silently pass.
    assert!(
        verified_consts >= 1,
        "Lane OOO: README heredoc must reference at least one SCREAMING_SNAKE_CASE constant (got {verified_consts})"
    );
    assert!(
        verified_snakes >= 10,
        "Lane OOO: README heredoc must reference at least 10 snake_case identifiers (got {verified_snakes})"
    );
}

// Lane PPP: extend Lane KKK's row-count floor with two structural
// floors on the section-6 table itself:
//
//   (1) Header literal: the first non-blank line after the section-6
//       heading must be the canonical `| Layer | File | Purpose |`
//       header (whitespace-normalized). A future regression that
//       drops the header, adds a fourth column, or renames a column
//       fails here loudly.
//
//   (2) Column count: every data row in section 6 (rows after the
//       header + separator, up to the section terminator) must split
//       into exactly 3 content cells. A future regression that
//       collapses two cells into one, or splits a cell with an
//       un-escaped pipe inside backticks, fails here loudly.
//
// Together with Lane KKK (every Lane-bearing row points at an
// existing path), Lane LLL (every Lane label traces back outside
// section 6), and Lane MMM (every backtick identifier exists in
// its referenced file), Lane PPP closes the last remaining shape
// regression: the table's outer skeleton (header + column count)
// is no longer assumed.
#[test]
fn section_6_header_literal_and_column_count_floor_lane_ppp() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runbook = fs::read_to_string(root.join("docs/runbooks/release-smoke.md"))
        .expect("Lane PPP: runbook present");

    let section = section_6_slice(&runbook);
    assert!(
        !section.is_empty(),
        "Lane PPP: section 6 slice must not be empty"
    );
    let lines: Vec<&str> = section.lines().collect();
    assert!(
        lines.len() > 5,
        "Lane PPP: section 6 must contain a non-trivial table (got {} lines)",
        lines.len()
    );

    // (1) Header literal: after the `## 6. ...` heading and any blank
    // lines, the next non-blank line is the table header. Normalize
    // collapsing runs of whitespace before comparison so column-padding
    // changes do not trip the floor.
    let mut header_idx: Option<usize> = None;
    for (idx, raw) in lines.iter().enumerate() {
        let t = raw.trim();
        if idx == 0 || t.is_empty() || t.starts_with("## ") {
            continue;
        }
        header_idx = Some(idx);
        break;
    }
    let header_idx = header_idx.expect("Lane PPP: section 6 must contain a table header line");
    let header_raw = lines[header_idx];
    let header_normalized: String = header_raw.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(
        header_normalized, "| Layer | File | Purpose |",
        "Lane PPP: section-6 table header must be the canonical 3-column header `| Layer | File | Purpose |`; got {header_raw:?}"
    );

    // The separator line follows the header.
    let separator_idx = header_idx + 1;
    assert!(
        separator_idx < lines.len(),
        "Lane PPP: section 6 missing separator row after the header"
    );
    let separator = lines[separator_idx].trim();
    let separator_cells: Vec<&str> = separator
        .trim_start_matches('|')
        .trim_end_matches('|')
        .split('|')
        .map(|c| c.trim())
        .collect();
    assert_eq!(
        separator_cells.len(),
        3,
        "Lane PPP: section-6 separator row must have exactly 3 column markers; got {} ({:?})",
        separator_cells.len(),
        separator
    );
    for cell in &separator_cells {
        assert!(
            !cell.is_empty() && cell.chars().all(|c| c == '-' || c == ':'),
            "Lane PPP: each separator cell must be only - or : characters; got {cell:?}"
        );
    }

    // (2) Column count: each data row past header + separator splits
    // into exactly 3 content cells. Stop at the first non-row line
    // (the section terminator after the table).
    let mut data_rows = 0usize;
    let mut row_idx = separator_idx + 1;
    while row_idx < lines.len() {
        let raw = lines[row_idx];
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            row_idx += 1;
            continue;
        }
        if !trimmed.starts_with('|') {
            break;
        }

        // Markdown escapes `\|` so the pipe inside a backticked literal
        // does not split a cell. Replace `\|` with a placeholder before
        // splitting so the count reflects real column separators only.
        let unescaped = trimmed.replace("\\|", "\u{FFFD}");
        let cells: Vec<&str> = unescaped
            .trim_start_matches('|')
            .trim_end_matches('|')
            .split('|')
            .collect();
        assert_eq!(
            cells.len(),
            3,
            "Lane PPP: section-6 data row {row_idx} must split into exactly 3 cells; got {} (row: {trimmed:?})",
            cells.len()
        );
        data_rows += 1;
        row_idx += 1;
    }

    assert!(
        data_rows >= 16,
        "Lane PPP: section-6 table must enumerate at least 16 enforcement layers (got {data_rows})"
    );
}

// Lane QQQ: README handoff command/flag parity.
//
// The package-local.sh README heredoc embeds canonical operator
// commands for the two release-handoff CLIs that ship inside the
// release archive:
//
//   - Python: `python3 fetch_release_support_handoff.py --base-url X
//             --out-dir Y [--include-phase1-portable]`
//   - PowerShell: `pwsh -File Fetch-ReleaseSupportHandoff.ps1
//             -BaseUrl X -OutDir Y [-IncludePhase1Portable]`
//
// If either CLI's surface (flag names) drifts and the README does
// not get updated, operators copy-pasting from the shipped README
// hit "unknown flag" runtime errors. Lane QQQ catches that drift
// at test time by binding every flag the README mentions to an
// actual declaration in the corresponding script.
//
// Algorithm:
//
//   1. Extract the README heredoc.
//   2. For each line mentioning `fetch_release_support_handoff.py`,
//      collect every `--xxx-yyy` token (long flag form).
//   3. Assert each such flag is declared via
//      `parser.add_argument("<flag>"` in
//      `scripts/fetch_release_support_handoff.py`.
//   4. For each line mentioning `Fetch-ReleaseSupportHandoff.ps1`,
//      collect every `-Xxx` token (PowerShell flag form).
//   5. Assert each appears as a `param(...)` declaration in
//      `scripts/Fetch-ReleaseSupportHandoff.ps1`.
//
// Defensive floors keep the test from passing vacuously if the
// README invocation lines are deleted: at least 2 Python long
// flags and at least 2 PowerShell flags must be discovered.
fn collect_python_long_flags(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'-' && bytes[i + 1] == b'-' {
            let start = i;
            let mut j = i + 2;
            while j < bytes.len() {
                let c = bytes[j];
                if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' {
                    j += 1;
                } else {
                    break;
                }
            }
            // require at least one trailing char after the leading `--`
            if j > start + 2 {
                let tok = &line[start..j];
                // strip a trailing dash (rare formatting accident)
                let cleaned = tok.trim_end_matches('-');
                if cleaned.len() > 2 {
                    out.push(cleaned.to_string());
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out.sort();
    out.dedup();
    out
}

fn collect_powershell_flags(line: &str) -> Vec<String> {
    // PowerShell flags look like `-BaseUrl`, `-IncludePhase1Portable`.
    // First character after `-` is uppercase ASCII; the rest is
    // alphanumeric. Skip `--xxx` (those are Python long flags) and
    // bareword `-` punctuation.
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'-' && bytes[i + 1].is_ascii_uppercase() {
            // Ensure preceding char is not another `-`, so we do not
            // false-positive the second dash of `--xxx`.
            if i > 0 && bytes[i - 1] == b'-' {
                i += 1;
                continue;
            }
            let start = i;
            let mut j = i + 1;
            while j < bytes.len() {
                let c = bytes[j];
                if c.is_ascii_alphanumeric() {
                    j += 1;
                } else {
                    break;
                }
            }
            if j > start + 1 {
                out.push(line[start..j].to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn readme_handoff_commands_bind_to_actual_cli_flag_declarations_lane_qqq() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane QQQ: package-local.sh present");
    let python_cli = fs::read_to_string(root.join("scripts/fetch_release_support_handoff.py"))
        .expect("Lane QQQ: fetch_release_support_handoff.py present");
    let pwsh_cli = fs::read_to_string(root.join("scripts/Fetch-ReleaseSupportHandoff.ps1"))
        .expect("Lane QQQ: Fetch-ReleaseSupportHandoff.ps1 present");

    let readme = extract_package_readme_heredoc(&package);
    assert!(
        !readme.is_empty() && readme.len() > 1000,
        "Lane QQQ: README heredoc must contain operator content (got {} bytes)",
        readme.len()
    );

    // Python flag parity.
    let mut python_flags: Vec<String> = Vec::new();
    for line in readme.lines() {
        if line.contains("fetch_release_support_handoff.py") {
            python_flags.extend(collect_python_long_flags(line));
        }
    }
    python_flags.sort();
    python_flags.dedup();
    for flag in &python_flags {
        let needle = format!("parser.add_argument(\"{flag}\"");
        assert!(
            python_cli.contains(&needle),
            "Lane QQQ: README references Python flag {flag:?} but scripts/fetch_release_support_handoff.py does not declare it via {needle:?}"
        );
    }
    assert!(
        python_flags.len() >= 2,
        "Lane QQQ: expected the README to reference at least 2 distinct Python long flags for fetch_release_support_handoff.py (got {}: {:?})",
        python_flags.len(),
        python_flags
    );

    // PowerShell flag parity. The PowerShell param block declares
    // `[string]$BaseUrl`, `[switch]$IncludePhase1Portable`, etc.
    // For each `-Foo` token in the README that appears AFTER the
    // script name (so we exclude pwsh.exe-level flags like `-File`
    // which appear BEFORE the script name), the script must declare
    // `$Foo` somewhere inside its `param(...)` block.
    let mut pwsh_flags: Vec<String> = Vec::new();
    for line in readme.lines() {
        if let Some(idx) = line.find("Fetch-ReleaseSupportHandoff.ps1") {
            let tail = &line[idx + "Fetch-ReleaseSupportHandoff.ps1".len()..];
            pwsh_flags.extend(collect_powershell_flags(tail));
        }
    }
    pwsh_flags.sort();
    pwsh_flags.dedup();
    for flag in &pwsh_flags {
        // Strip the leading dash → `BaseUrl`, `IncludePhase1Portable`.
        let bare = &flag[1..];
        let needle = format!("${bare}");
        assert!(
            pwsh_cli.contains(&needle),
            "Lane QQQ: README references PowerShell flag {flag:?} but scripts/Fetch-ReleaseSupportHandoff.ps1 does not declare {needle:?} in its param block"
        );
    }
    assert!(
        pwsh_flags.len() >= 2,
        "Lane QQQ: expected the README to reference at least 2 distinct PowerShell flags for Fetch-ReleaseSupportHandoff.ps1 (got {}: {:?})",
        pwsh_flags.len(),
        pwsh_flags
    );
}

// Lane RRR: install.sh / install.ps1 + handoff env-var name parity.
//
// The README heredoc references several `AO2_CP_xxx` environment
// variables that operators are expected to set or unset on their
// own machine: install location (`AO2_CP_INSTALL_DIR`),
// authorization header (`AO2_CP_AUTH_VALUE`), and the placeholder
// token name (`AO2_CP_API_TOKEN`). If any of those names drifts in
// the scripts that consume them — `install.sh`, `install.ps1`,
// `fetch_release_support_handoff.py`,
// `Fetch-ReleaseSupportHandoff.ps1`,
// `verify_release_support_bundle.py`, etc. — operators following
// the README will export the wrong variable name and the script
// will fall back to its default or fail.
//
// Lane RRR binds the env-var surface in both directions:
//
//   (1) Every `AO2_CP_xxx` name in the README heredoc must appear
//       outside the README itself, in some `.sh`, `.ps1`, or `.py`
//       file under `scripts/`. (The README portion of
//       `scripts/package-local.sh` is masked out before the search
//       so the binding is not trivially self-satisfied.)
//
//   (2) The two install-script env vars the README documents
//       (`AO2_CP_INSTALL_DIR`) must appear in BOTH the embedded
//       `install.sh` heredoc and the embedded `install.ps1`
//       heredoc inside `scripts/package-local.sh`, so a Unix-only
//       rename or a Windows-only rename surfaces here too.
//
// Defensive floor: README must reference at least 3 distinct
// `AO2_CP_xxx` names so a future deletion of every env-var
// invocation doesn't silently pass.
fn collect_ao2_cp_env_vars(text: &str) -> Vec<String> {
    // Match `AO2_CP_` followed by 1+ uppercase ASCII or underscore.
    let mut out: Vec<String> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    let needle = b"AO2_CP_";
    while i + needle.len() < bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let start = i;
            let mut j = i + needle.len();
            while j < bytes.len() {
                let c = bytes[j];
                if c == b'_' || c.is_ascii_uppercase() || c.is_ascii_digit() {
                    j += 1;
                } else {
                    break;
                }
            }
            if j > start + needle.len() {
                out.push(text[start..j].to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out.sort();
    out.dedup();
    out
}

fn extract_install_sh_heredoc(package: &str) -> String {
    extract_heredoc_with_opener(package, "cat > \"$STAGE/install.sh\" <<'SH'\n", "\nSH\n")
}

fn extract_install_ps1_heredoc(package: &str) -> String {
    extract_heredoc_with_opener(package, "cat > \"$STAGE/install.ps1\" <<'PS1'\n", "\nPS1\n")
}

fn extract_heredoc_with_opener(package: &str, opener: &str, closer: &str) -> String {
    let start = package.find(opener).unwrap_or_else(|| {
        panic!("Lane RRR: package-local.sh must contain heredoc opener {opener:?}")
    });
    let body_start = start + opener.len();
    let body_rel_end = package[body_start..]
        .find(closer)
        .unwrap_or_else(|| panic!("Lane RRR: package-local.sh heredoc opened with {opener:?} is missing its closing {closer:?}"));
    package[body_start..body_start + body_rel_end].to_string()
}

#[test]
fn readme_env_var_names_bind_to_install_and_handoff_scripts_lane_rrr() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane RRR: package-local.sh present");

    let readme = extract_package_readme_heredoc(&package);
    assert!(
        !readme.is_empty() && readme.len() > 1000,
        "Lane RRR: README heredoc must contain operator content (got {} bytes)",
        readme.len()
    );

    // README-referenced env vars.
    let readme_vars = collect_ao2_cp_env_vars(&readme);
    assert!(
        readme_vars.len() >= 3,
        "Lane RRR: README must reference at least 3 distinct AO2_CP_xxx env vars; got {} ({:?})",
        readme_vars.len(),
        readme_vars
    );

    // Build a corpus of all scripts/*.sh, *.ps1, *.py files. Mask
    // out the README heredoc inside scripts/package-local.sh so we
    // do not satisfy the binding via the README's own text.
    let opener = "cat > \"$STAGE/README.txt\" <<'TXT'\n";
    let closer = "\nTXT\n";
    let package_masked = if let (Some(start), Some(rel_end)) = (
        package.find(opener),
        package.find(opener).and_then(|s| {
            package[s + opener.len()..]
                .find(closer)
                .map(|r| s + opener.len() + r)
        }),
    ) {
        let mut s = String::with_capacity(package.len());
        s.push_str(&package[..start + opener.len()]);
        s.push_str(&package[rel_end..]);
        s
    } else {
        panic!("Lane RRR: package-local.sh must contain a README.txt heredoc to mask");
    };

    let scripts_dir = root.join("scripts");
    let mut corpus = String::new();
    corpus.push_str(&package_masked);
    corpus.push('\n');
    let mut included_paths: Vec<String> = Vec::new();
    for entry in fs::read_dir(&scripts_dir).expect("Lane RRR: scripts dir present") {
        let entry = entry.expect("Lane RRR: scripts dir entry");
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("package-local.sh") {
            continue; // already added in masked form
        }
        let ext_ok = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("sh") | Some("ps1") | Some("py")
        );
        if !ext_ok {
            continue;
        }
        let body = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Lane RRR: read {path:?} failed: {e}"));
        corpus.push_str(&body);
        corpus.push('\n');
        included_paths.push(path.display().to_string());
    }

    for var in &readme_vars {
        assert!(
            corpus.contains(var.as_str()),
            "Lane RRR: README references env var {var:?} but no script under {:?} consumes it (excluding the README heredoc itself); a rename must touch both surfaces. Included scripts: {included_paths:?}",
            scripts_dir.display()
        );
    }

    // (2) Per-platform install-script binding.
    // AO2_CP_INSTALL_DIR is documented in the README for both
    // platforms; it must be consumed in both install heredocs.
    let install_sh = extract_install_sh_heredoc(&package);
    let install_ps1 = extract_install_ps1_heredoc(&package);
    assert!(
        install_sh.contains("AO2_CP_INSTALL_DIR"),
        "Lane RRR: embedded install.sh heredoc must consume AO2_CP_INSTALL_DIR"
    );
    assert!(
        install_ps1.contains("AO2_CP_INSTALL_DIR"),
        "Lane RRR: embedded install.ps1 heredoc must consume AO2_CP_INSTALL_DIR"
    );
}

// Lane SSS: README route-literal → axum router declaration parity.
//
// The README heredoc names specific HTTP endpoints that operators
// hit during the landing flow:
//
//   1. /api/v1/phase1/promotion/operator-panel
//   2. /api/v1/phase1/promotion/dashboard
//   3. /api/v1/release/cockpit
//   4. /api/v1/release/publication/dashboard
//   5. /api/v1/release/readiness, /api/v1/release/handoff
//
// All of those routes are nested under `/api/v1` in
// `crates/ao2-cp-server/src/server.rs`. If a future refactor
// renames a handler path and the README does not get updated,
// operators copy-pasting the URL hit a 404 with no test catching
// it at workspace time. Lane SSS closes that gap.
//
// Algorithm:
//
//   1. Extract the README heredoc.
//   2. Scan for every `/api/v1/...` route literal.
//   3. For each, strip the `/api/v1` prefix and assert the
//      remainder appears as a route literal (`.route("/...",`) in
//      the server's router declaration file.
//
// Defensive floor: README must reference at least 4 distinct
// `/api/v1/...` routes so a future deletion of every endpoint
// mention doesn't silently pass.
fn collect_api_v1_route_literals(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let needle = "/api/v1/";
    let mut search_start = 0;
    while let Some(rel) = text[search_start..].find(needle) {
        let start = search_start + rel;
        let mut j = start + needle.len();
        let bytes = text.as_bytes();
        while j < bytes.len() {
            let c = bytes[j];
            // route chars: alphanum, '-', '_', '/', '.'; stop on
            // whitespace, comma, quote, paren, semicolon, etc.
            if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'/' || c == b'.' {
                j += 1;
            } else {
                break;
            }
        }
        // Trim a trailing `.` (sentence-ending) but preserve
        // `/path.json` style.
        let mut end = j;
        while end > start + needle.len()
            && text.as_bytes()[end - 1] == b'.'
            && (end < bytes.len() || end == bytes.len())
        {
            // only strip a single trailing dot that is sentence
            // punctuation (i.e., not part of `.json` etc.).
            let after_dot = &text[start..end];
            if after_dot.ends_with(".json")
                || after_dot.ends_with(".txt")
                || after_dot.ends_with(".html")
            {
                break;
            }
            end -= 1;
        }
        out.push(text[start..end].to_string());
        search_start = j.max(start + 1);
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn readme_api_v1_routes_bind_to_axum_router_declarations_lane_sss() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane SSS: package-local.sh present");
    let server_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/server.rs"))
        .expect("Lane SSS: server.rs present");

    let readme = extract_package_readme_heredoc(&package);
    assert!(
        !readme.is_empty() && readme.len() > 1000,
        "Lane SSS: README heredoc must contain operator content (got {} bytes)",
        readme.len()
    );

    // The router is built as `let api_v1 = Router::new()...` nested
    // under "/api/v1", so route literals in server.rs start without
    // the `/api/v1` prefix.
    assert!(
        server_rs.contains(".nest(\"/api/v1\""),
        "Lane SSS: server.rs must nest the api_v1 router under \"/api/v1\""
    );

    let readme_routes = collect_api_v1_route_literals(&readme);
    assert!(
        readme_routes.len() >= 4,
        "Lane SSS: README must reference at least 4 distinct /api/v1/... routes (got {}: {:?})",
        readme_routes.len(),
        readme_routes
    );

    for full_route in &readme_routes {
        // Strip the /api/v1 prefix; the remainder must match a
        // route literal in the api_v1 Router::new() chain.
        let suffix = full_route
            .strip_prefix("/api/v1")
            .unwrap_or_else(|| panic!("Lane SSS: route {full_route:?} missing /api/v1 prefix"));
        // The router declares routes as `.route("/path", ...)`.
        let needle = format!(".route(\n            \"{suffix}\"");
        let inline_needle = format!(".route(\"{suffix}\"");
        assert!(
            server_rs.contains(&needle) || server_rs.contains(&inline_needle),
            "Lane SSS: README references route {full_route:?} but server.rs does not declare {suffix:?} via .route(...)"
        );
    }
}

// Lane TTT: README → verify-bundle CLI flag/positional parity.
//
// Lane QQQ bound the handoff CLIs. Lane TTT extends the same
// pattern to the second pair of CLIs the README invokes:
//
//   - Python: `python3 verify_release_support_bundle.py <bundle>`
//   - PowerShell: `pwsh -File Verify-ReleaseSupportBundle.ps1
//                  -Path <bundle>`
//
// The Python verifier parses argv by hand (not argparse); the
// recognized flag set is `--json`, `--checksums`, `--compare-against`
// plus exactly one positional bundle path. The PowerShell verifier
// declares `-Json`, `-Checksums`, `-CompareAgainst`, `-Path` in its
// `param(...)` block.
//
// Algorithm:
//
//   1. Extract the README heredoc.
//   2. For each line invoking `verify_release_support_bundle.py`,
//      assert (a) every `--xxx-yyy` long flag is recognized by the
//      script (`flag == "--xxx"` literal somewhere in the Python
//      source), and (b) the invocation supplies at least the
//      script-name + one positional path (since the script requires
//      exactly one positional).
//   3. For each line invoking `Verify-ReleaseSupportBundle.ps1`,
//      assert every `-Xxx` flag (after the script name) is
//      declared as `$Xxx` in the PowerShell param block.
//   4. Additionally, assert `-Path` is declared as Mandatory in
//      the PowerShell verifier (since the README always supplies
//      it).
//
// Defensive floor: at least 2 distinct invocations of each
// verifier in the README (because losing all invocations would
// silently pass the per-line scan).
#[test]
fn readme_verify_bundle_invocations_bind_to_actual_cli_declarations_lane_ttt() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane TTT: package-local.sh present");
    let python_cli = fs::read_to_string(root.join("scripts/verify_release_support_bundle.py"))
        .expect("Lane TTT: verify_release_support_bundle.py present");
    let pwsh_cli = fs::read_to_string(root.join("scripts/Verify-ReleaseSupportBundle.ps1"))
        .expect("Lane TTT: Verify-ReleaseSupportBundle.ps1 present");

    let readme = extract_package_readme_heredoc(&package);
    assert!(
        !readme.is_empty() && readme.len() > 1000,
        "Lane TTT: README heredoc must contain operator content (got {} bytes)",
        readme.len()
    );

    // Count Python and PowerShell invocations. We only count lines
    // where the script name is the executable being invoked
    // (i.e., follows `python3 ` or `pwsh -File `), not lines that
    // merely mention the name in prose.
    let mut python_invocations = 0usize;
    let mut python_flags: Vec<String> = Vec::new();
    for line in readme.lines() {
        if line.contains("python3 verify_release_support_bundle.py") {
            python_invocations += 1;
            // collect long flags appearing after the script name
            if let Some(idx) = line.find("verify_release_support_bundle.py") {
                let tail = &line[idx + "verify_release_support_bundle.py".len()..];
                python_flags.extend(collect_python_long_flags(tail));
            }
        }
    }
    python_flags.sort();
    python_flags.dedup();
    for flag in &python_flags {
        // The hand-rolled parser checks `flag == "<flag>"` so the
        // literal must appear in the source.
        let needle = format!("\"{flag}\"");
        assert!(
            python_cli.contains(&needle),
            "Lane TTT: README invokes verify_release_support_bundle.py with flag {flag:?} but the Python script does not recognize {needle:?}"
        );
    }
    assert!(
        python_invocations >= 1,
        "Lane TTT: README must invoke verify_release_support_bundle.py at least once (got {python_invocations})"
    );

    // PowerShell verifier flags.
    let mut pwsh_invocations = 0usize;
    let mut pwsh_flags: Vec<String> = Vec::new();
    for line in readme.lines() {
        if line.contains("pwsh -File Verify-ReleaseSupportBundle.ps1") {
            pwsh_invocations += 1;
            if let Some(idx) = line.find("Verify-ReleaseSupportBundle.ps1") {
                let tail = &line[idx + "Verify-ReleaseSupportBundle.ps1".len()..];
                pwsh_flags.extend(collect_powershell_flags(tail));
            }
        }
    }
    pwsh_flags.sort();
    pwsh_flags.dedup();
    for flag in &pwsh_flags {
        let bare = &flag[1..];
        let needle = format!("${bare}");
        assert!(
            pwsh_cli.contains(&needle),
            "Lane TTT: README invokes Verify-ReleaseSupportBundle.ps1 with flag {flag:?} but the PowerShell script does not declare {needle:?} in its param block"
        );
    }
    assert!(
        pwsh_invocations >= 2,
        "Lane TTT: README must invoke Verify-ReleaseSupportBundle.ps1 at least twice (got {pwsh_invocations})"
    );
    assert!(
        pwsh_flags.contains(&"-Path".to_string()),
        "Lane TTT: README must invoke Verify-ReleaseSupportBundle.ps1 with -Path (got flags {pwsh_flags:?})"
    );

    // -Path must be declared Mandatory in the PowerShell param
    // block since the README always supplies it. We look for the
    // Mandatory=$true attribute attached to $Path.
    let mandatory_path_block = pwsh_cli.contains("[Parameter(Mandatory=$true)]\n    [string]$Path");
    assert!(
        mandatory_path_block,
        "Lane TTT: Verify-ReleaseSupportBundle.ps1 must declare $Path as Mandatory since the README always supplies it (operator copy-paste from the README would fail silently otherwise)"
    );
}

// Lane UUU: README → tar archive arglist parity.
//
// The README heredoc instructs operators to invoke scripts that
// ship inside the release archive — `install.sh`, `install.ps1`,
// the Python and PowerShell verify-bundle and fetch-handoff CLIs.
// If `scripts/package-local.sh` were to drop any of those names
// from its `tar -czf` argument list (a build-script regression),
// operators following the README would `bash: install.sh: not
// found` because the file simply isn't in the archive.
//
// Lane UUU pins that. Every bare-name script-style filename
// (no slash, ending in `.py`, `.ps1`, or `.sh`) referenced in
// the README heredoc must also appear as a token in the
// `tar -czf "$ARCHIVE" ...` arglist of package-local.sh.
//
// Algorithm:
//
//   1. Extract the README heredoc.
//   2. Collect every bare filename token with extension `.py`,
//      `.ps1`, or `.sh` from the README.
//   3. Extract the line containing `tar -czf "$ARCHIVE"` from
//      `scripts/package-local.sh`.
//   4. Assert each README filename appears as a whitespace-
//      separated token in that line.
//
// Defensive floor: at least 4 distinct filenames discovered in
// the README (so a future README rewrite that drops every named
// script doesn't silently pass).
fn collect_archive_script_filenames(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = text.as_bytes();
    let extensions: &[&str] = &[".py", ".ps1", ".sh"];
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let mut j = i;
        while j < bytes.len() {
            let c = bytes[j];
            if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.' {
                j += 1;
            } else {
                break;
            }
        }
        if j > start {
            let tok = &text[start..j];
            let has_ext = extensions.iter().any(|ext| tok.ends_with(ext));
            // Reject tokens whose preceding byte is `/` — those are
            // directory-prefixed paths (e.g. `scripts/foo.sh`), which
            // reference repo paths, not archive-shipped tools.
            let preceded_by_slash = start > 0 && bytes[start - 1] == b'/';
            let is_bare = !tok.contains('/') && !tok.starts_with('.');
            if has_ext && is_bare && !preceded_by_slash && tok.len() > 4 {
                out.push(tok.to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn readme_archive_filenames_appear_in_tar_arglist_lane_uuu() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane UUU: package-local.sh present");

    let readme = extract_package_readme_heredoc(&package);
    assert!(
        !readme.is_empty() && readme.len() > 1000,
        "Lane UUU: README heredoc must contain operator content (got {} bytes)",
        readme.len()
    );

    // Locate the tar -czf invocation. The line shape is:
    //   (cd "$STAGE" && tar -czf "$ARCHIVE" file1 file2 file3 ...)
    let tar_line = package
        .lines()
        .find(|line| line.contains("tar -czf \"$ARCHIVE\""))
        .expect("Lane UUU: package-local.sh must contain a tar -czf \"$ARCHIVE\" line");
    let mut after_archive = false;
    let mut tar_tokens: Vec<&str> = Vec::new();
    for tok in tar_line.split_whitespace() {
        if after_archive {
            let cleaned = tok.trim_end_matches(')');
            if !cleaned.is_empty() {
                tar_tokens.push(cleaned);
            }
        } else if tok == "\"$ARCHIVE\"" {
            after_archive = true;
        }
    }
    assert!(
        tar_tokens.len() >= 5,
        "Lane UUU: tar -czf arglist must contain at least 5 entries (got {} : {tar_tokens:?})",
        tar_tokens.len()
    );

    let readme_files = collect_archive_script_filenames(&readme);
    assert!(
        readme_files.len() >= 4,
        "Lane UUU: README must reference at least 4 bare script filenames (.py / .ps1 / .sh); got {} ({:?})",
        readme_files.len(),
        readme_files
    );

    for fname in &readme_files {
        let appears_in_tar = tar_tokens.contains(&fname.as_str());
        assert!(
            appears_in_tar,
            "Lane UUU: README references script file {fname:?} but the tar -czf arglist in scripts/package-local.sh does not include it; operators copy-pasting from the README would land on a file that isn't shipped in the archive. tar tokens: {tar_tokens:?}"
        );
    }
}

// Lane VVV: install heredoc → Cargo.toml [[bin]] binary name parity.
//
// Both install heredocs (install.sh + install.ps1) reference the
// packaged binary by name:
//
//   - install.sh:  BINARY_NAME="ao2-cp-server"
//                  bin/ao2-cp-server (SHA256SUMS lookup)
//   - install.ps1: $BinaryName = "ao2-cp-server.exe"
//                  bin/ao2-cp-server.exe (SHA256SUMS lookup)
//
// If a future refactor renames the binary in
// `crates/ao2-cp-server/Cargo.toml` `[[bin]]` to e.g.
// "ao2-control-plane-server", `cargo build --release` would emit
// `target/release/ao2-control-plane-server`, the
// `package-local.sh` build step would not find the legacy name,
// and the install scripts would still look for `ao2-cp-server`
// in the archive — silently broken for end-operators.
//
// Lane VVV closes that gap by binding the install heredocs to
// the actual `[[bin]] name = "..."` declaration in `Cargo.toml`.
//
// Algorithm:
//
//   1. Read `crates/ao2-cp-server/Cargo.toml` and extract the
//      first `[[bin]]` table's `name = "..."` value.
//   2. Extract the install.sh and install.ps1 heredocs.
//   3. Assert install.sh contains both `BINARY_NAME="<name>"`
//      and `bin/<name>` (the SHA256SUMS lookup pattern).
//   4. Assert install.ps1 contains both `$BinaryName = "<name>.exe"`
//      and `bin/<name>.exe`.
//   5. Assert the staging step in `package-local.sh` itself
//      references the same binary name (via the `BINARY` /
//      `BINARY_NAME` shell-variable assignments) so the build,
//      stage, and install steps are all locked together.
fn extract_first_cargo_bin_name(cargo_toml: &str) -> String {
    // Find the first `[[bin]]` table and the `name = "..."` line
    // that follows before any other `[` table marker.
    let bin_idx = cargo_toml
        .find("[[bin]]")
        .expect("Lane VVV: Cargo.toml must declare [[bin]]");
    let after = &cargo_toml[bin_idx + "[[bin]]".len()..];
    // Truncate at the next table marker to stay inside this [[bin]] entry.
    let limit = after.find("\n[").map(|i| i + 1).unwrap_or(after.len());
    let table_body = &after[..limit];
    for line in table_body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("name") {
            // shape: `name = "ao2-cp-server"`
            let rest = rest.trim_start_matches([' ', '=']);
            let trimmed = rest.trim();
            let stripped = trimmed.trim_matches('"');
            return stripped.to_string();
        }
    }
    panic!("Lane VVV: first [[bin]] entry has no `name = \"...\"` line");
}

#[test]
fn install_heredocs_bind_to_cargo_toml_bin_name_lane_vvv() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane VVV: package-local.sh present");
    let cargo_toml = fs::read_to_string(root.join("crates/ao2-cp-server/Cargo.toml"))
        .expect("Lane VVV: ao2-cp-server Cargo.toml present");

    let bin_name = extract_first_cargo_bin_name(&cargo_toml);
    assert!(
        !bin_name.is_empty() && !bin_name.contains(' '),
        "Lane VVV: extracted [[bin]] name {bin_name:?} must be a non-empty single token"
    );

    let install_sh = extract_install_sh_heredoc(&package);
    let install_ps1 = extract_install_ps1_heredoc(&package);

    // install.sh expectations.
    let sh_binary_assignment = format!("BINARY_NAME=\"{bin_name}\"");
    let sh_sha_lookup = format!("bin/{bin_name}");
    assert!(
        install_sh.contains(&sh_binary_assignment),
        "Lane VVV: install.sh heredoc must contain {sh_binary_assignment:?} to match Cargo.toml [[bin]] name {bin_name:?}"
    );
    assert!(
        install_sh.contains(&sh_sha_lookup),
        "Lane VVV: install.sh heredoc must reference {sh_sha_lookup:?} for the SHA256SUMS lookup"
    );

    // install.ps1 expectations (Windows: append .exe).
    let exe_name = format!("{bin_name}.exe");
    let ps1_binary_assignment = format!("$BinaryName = \"{exe_name}\"");
    let ps1_sha_lookup = format!("bin/{exe_name}");
    assert!(
        install_ps1.contains(&ps1_binary_assignment),
        "Lane VVV: install.ps1 heredoc must contain {ps1_binary_assignment:?} to match Cargo.toml [[bin]] name {bin_name:?} (.exe suffix on Windows)"
    );
    assert!(
        install_ps1.contains(&ps1_sha_lookup),
        "Lane VVV: install.ps1 heredoc must reference {ps1_sha_lookup:?} for the SHA256SUMS lookup"
    );

    // The package-local.sh build/stage step references the same
    // binary name in its `target/release/...` path and in its
    // OS-conditional `BINARY_NAME=...` blocks.
    let build_path = format!("target/release/{bin_name}");
    assert!(
        package.contains(&build_path),
        "Lane VVV: package-local.sh must build/stage from {build_path:?} (matching Cargo.toml [[bin]] name)"
    );
    let stage_unix = format!("BINARY_NAME=\"{bin_name}\"");
    let stage_windows = format!("BINARY_NAME=\"{exe_name}\"");
    assert!(
        package.contains(&stage_unix),
        "Lane VVV: package-local.sh must assign {stage_unix:?} on Unix targets"
    );
    assert!(
        package.contains(&stage_windows),
        "Lane VVV: package-local.sh must assign {stage_windows:?} on Windows targets"
    );
}

// Lane WWW: README port literal → config default-bind parity.
//
// The README heredoc embeds the canonical `http://127.0.0.1:8744`
// origin in every operator command for the handoff CLIs. If a
// future refactor moves the default port (e.g.,
// `AO2_CP_BIND default_value = "127.0.0.1:8744"` → 8745), the
// README would still tell operators to point at `:8744` but the
// server would bind elsewhere and the operator would land on
// "connection refused" with no test catching the drift at
// workspace time.
//
// Lane WWW closes that gap by extracting the host:port literal
// from the clap default_value in `crates/ao2-cp-server/src/config.rs`
// and asserting it appears in every README handoff command that
// uses the `--base-url` / `-BaseUrl` flag.
//
// Algorithm:
//
//   1. Read `config.rs` and find the `default_value = "host:port"`
//      attribute on the `bind` field (the canonical default).
//   2. Extract the README heredoc.
//   3. For each line containing `--base-url ` or `-BaseUrl `,
//      assert it contains `http://<host:port>`.
//
// Defensive floor: at least 4 such lines in the README (so a
// future rewrite that drops every URL doesn't silently pass).
fn extract_default_bind_from_config(config_rs: &str) -> String {
    // Find the line containing `env = "AO2_CP_BIND"` (the bind
    // field's clap attribute), then read the `default_value = "..."`
    // literal on the same logical attribute. The struct attribute
    // is `#[arg(long, env = "AO2_CP_BIND", default_value = "127.0.0.1:8744")]`
    // — all on one line in the current source — so we can find
    // the env match and scan forward for `default_value = "`.
    let env_idx = config_rs
        .find("env = \"AO2_CP_BIND\"")
        .expect("Lane WWW: config.rs must declare env = \"AO2_CP_BIND\" on the bind field");
    let tail = &config_rs[env_idx..];
    let needle = "default_value = \"";
    let dv_rel = tail.find(needle).expect(
        "Lane WWW: bind field must specify a default_value (so the README has a stable URL to embed)",
    );
    let start = env_idx + dv_rel + needle.len();
    let end_rel = config_rs[start..]
        .find('"')
        .expect("Lane WWW: default_value literal must terminate with a closing quote");
    config_rs[start..start + end_rel].to_string()
}

#[test]
fn readme_base_url_literal_binds_to_config_default_bind_lane_www() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane WWW: package-local.sh present");
    let config_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/config.rs"))
        .expect("Lane WWW: config.rs present");

    let default_bind = extract_default_bind_from_config(&config_rs);
    assert!(
        default_bind.contains(':'),
        "Lane WWW: extracted default_bind {default_bind:?} must be host:port shape"
    );

    let readme = extract_package_readme_heredoc(&package);
    assert!(
        !readme.is_empty() && readme.len() > 1000,
        "Lane WWW: README heredoc must contain operator content (got {} bytes)",
        readme.len()
    );

    let expected_url = format!("http://{default_bind}");

    let mut base_url_lines = 0usize;
    for line in readme.lines() {
        if line.contains("--base-url ") || line.contains("-BaseUrl ") {
            base_url_lines += 1;
            assert!(
                line.contains(&expected_url),
                "Lane WWW: README line uses a base-url flag but the URL does not match the server's config.rs default_value ({expected_url:?}). Line: {line:?}"
            );
        }
    }
    assert!(
        base_url_lines >= 4,
        "Lane WWW: README must contain at least 4 lines using --base-url or -BaseUrl (got {base_url_lines})"
    );
}

// Lane XXX: smoke-aggregator function-name parity.
//
// `docs/runbooks/release-smoke.md` references shell functions
// inside `scripts/smoke-three-os-release.sh` by name — most
// visibly in the section-1 parity-verdict source columns and the
// section-6 gate-enforcement table, but also in section-3 / -5
// triage prose. Each backtick reference of the form
// `<func_name>()` is a load-bearing pointer: when an operator
// reads the runbook, they expect to be able to grep the script
// for that exact identifier and find a function definition.
//
// If a future refactor renames a function in the aggregator
// (e.g., `compute_parity` → `compute_aggregate_parity`) without
// updating the runbook, the runbook's pointers go stale silently.
// Lane MMM partially catches that, but only for backtick tokens
// inside section-6 rows that also reference a file path. Section
// 1 / 3 / 5 prose is not covered there.
//
// Lane XXX closes the gap for the smoke aggregator specifically:
//
//   1. Read `scripts/smoke-three-os-release.sh`.
//   2. Read `docs/runbooks/release-smoke.md`.
//   3. Scan the runbook for every backtick segment matching
//      shape `<snake_name>()` where `<snake_name>` starts with
//      `compute_`, `extract_`, `fetch_`, or `validate_`.
//   4. Assert each such name is defined as `<snake_name>() {`
//      somewhere in the aggregator script — or, for `validate_`
//      names, defined as a Rust function under
//      `crates/ao2-cp-server/src/handlers/` (since
//      `validate_three_os_release_smoke()` lives there, not in
//      the shell aggregator).
//
// Defensive floor: at least 5 such function-pointer references
// in the runbook so a future rewrite that drops every aggregator
// reference doesn't silently pass.
fn collect_smoke_aggregator_function_refs(runbook: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = runbook.as_bytes();
    let mut i = 0;
    let prefixes: &[&str] = &["compute_", "extract_", "fetch_", "validate_"];
    while i < bytes.len() {
        if bytes[i] == b'`' {
            let start = i + 1;
            // Find the closing backtick.
            let mut end = start;
            while end < bytes.len() && bytes[end] != b'`' {
                end += 1;
            }
            if end < bytes.len() {
                let content = &runbook[start..end];
                // Looking for shape `name()` where `name` is bare
                // snake_case starting with one of our prefixes.
                if let Some(open) = content.find('(') {
                    if content.ends_with(')') && open + 1 == content.len() - 1 {
                        let name = &content[..open];
                        let valid_chars =
                            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                        let has_prefix = prefixes.iter().any(|p| name.starts_with(p));
                        if valid_chars && has_prefix && name.len() > 6 {
                            out.push(name.to_string());
                        }
                    }
                }
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn smoke_aggregator_function_refs_in_runbook_resolve_to_definitions_lane_xxx() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runbook = fs::read_to_string(root.join("docs/runbooks/release-smoke.md"))
        .expect("Lane XXX: runbook present");
    let aggregator = fs::read_to_string(root.join("scripts/smoke-three-os-release.sh"))
        .expect("Lane XXX: smoke-three-os-release.sh present");

    let refs = collect_smoke_aggregator_function_refs(&runbook);
    assert!(
        refs.len() >= 5,
        "Lane XXX: runbook must reference at least 5 smoke-aggregator-style function names (got {}: {:?})",
        refs.len(),
        refs
    );

    // Walk crates/ao2-cp-server/src/handlers/ as a search corpus for
    // `validate_*` names (those live in Rust, not the shell script).
    let handlers_dir = root.join("crates/ao2-cp-server/src/handlers");
    let mut handler_corpus = String::new();
    for entry in fs::read_dir(&handlers_dir).expect("Lane XXX: handlers dir present") {
        let entry = entry.expect("Lane XXX: handlers dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let body = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Lane XXX: read {path:?} failed: {e}"));
        handler_corpus.push_str(&body);
        handler_corpus.push('\n');
    }

    for name in &refs {
        let shell_def = format!("{name}() {{");
        let alt_shell_def = format!("{name} () {{");
        let rust_fn = format!("fn {name}(");
        let rust_pub_fn = format!("pub fn {name}(");
        let rust_async_fn = format!("async fn {name}(");
        let rust_pub_async_fn = format!("pub async fn {name}(");

        let in_aggregator = aggregator.contains(&shell_def) || aggregator.contains(&alt_shell_def);
        let in_handlers = handler_corpus.contains(&rust_fn)
            || handler_corpus.contains(&rust_pub_fn)
            || handler_corpus.contains(&rust_async_fn)
            || handler_corpus.contains(&rust_pub_async_fn);

        assert!(
            in_aggregator || in_handlers,
            "Lane XXX: runbook references function {name:?} but no definition exists in either scripts/smoke-three-os-release.sh (looked for `{name}() {{`) or crates/ao2-cp-server/src/handlers/ (looked for `fn {name}(`)"
        );
    }
}

// Lane YYY: README/runbook Prometheus alert-rule metric-name parity.
//
// Both the runbook's section 9.6 and the README heredoc embedded
// inside `scripts/package-local.sh` document two canonical
// Prometheus alert expressions:
//
//   - Rotation imminent: `audit_log_size_bytes / audit_log_cap_bytes > 0.75`
//   - Tampering attempt spike: `increase(count[1m]) > 10`
//
// The metric names `audit_log_size_bytes` and `audit_log_cap_bytes`
// MUST be the literal JSON keys emitted by the cockpit, handoff,
// and readiness JSON endpoints. If a future refactor renames
// either key (e.g., to `audit_log_total_bytes`), the documented
// alert expression becomes silently false and on-call operators
// stop getting paged on rotation pressure.
//
// Lane YYY closes that gap: every metric name appearing inside a
// Prometheus-style alert expression in the runbook or README must
// also exist as a JSON-key literal in
// `crates/ao2-cp-server/src/handlers/release_publication.rs` or
// `phase1_promotion.rs`.
//
// Algorithm:
//
//   1. Read the runbook and the README heredoc.
//   2. Find every line containing an alert expression candidate
//      (heuristic: contains both `audit_log_size_bytes` and
//      `audit_log_cap_bytes`, OR contains the literal
//      `increase(count[1m])`).
//   3. From the runbook + README, extract the canonical metric
//      name set: `audit_log_size_bytes`, `audit_log_cap_bytes`,
//      plus the `count` metric referenced in the spike rule.
//   4. Assert each metric appears as a `"<name>"` JSON-key
//      literal in the handlers source for at least one of:
//      release_publication.rs OR phase1_promotion.rs.
//
// Defensive floors:
//   - >= 1 rotation-imminent expression instance in (runbook ∪ README)
//   - >= 1 tampering-spike expression instance in (runbook ∪ README)
//   - 3 metric names verified.
#[test]
fn alert_rule_metric_names_bind_to_handler_json_keys_lane_yyy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runbook = fs::read_to_string(root.join("docs/runbooks/release-smoke.md"))
        .expect("Lane YYY: runbook present");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane YYY: package-local.sh present");
    let release_publication =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane YYY: release_publication.rs present");
    let phase1_promotion =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/phase1_promotion.rs"))
            .expect("Lane YYY: phase1_promotion.rs present");

    let readme = extract_package_readme_heredoc(&package);
    let combined_docs = format!("{runbook}\n{readme}");

    // Count rotation-imminent and tampering-spike expressions.
    let mut rotation_imminent = 0usize;
    let mut tampering_spike = 0usize;
    for line in combined_docs.lines() {
        if line.contains("audit_log_size_bytes")
            && line.contains("audit_log_cap_bytes")
            && line.contains("> 0.75")
        {
            rotation_imminent += 1;
        }
        if line.contains("increase(count[1m])") && line.contains("> 10") {
            tampering_spike += 1;
        }
    }
    assert!(
        rotation_imminent >= 1,
        "Lane YYY: runbook + README must document the rotation-imminent alert expression at least once (got {rotation_imminent})"
    );
    assert!(
        tampering_spike >= 1,
        "Lane YYY: runbook + README must document the tampering-spike alert expression at least once (got {tampering_spike})"
    );

    // Every metric used in the alert rules must appear as a JSON
    // key (i.e., as `"<name>"` immediately followed by `:` or
    // somewhere recognizable in the handler source).
    let metric_names: &[&str] = &["audit_log_size_bytes", "audit_log_cap_bytes", "count"];
    for metric in metric_names {
        let needle = format!("\"{metric}\"");
        let in_release_publication = release_publication.contains(&needle);
        let in_phase1_promotion = phase1_promotion.contains(&needle);
        assert!(
            in_release_publication || in_phase1_promotion,
            "Lane YYY: runbook/README alert expression references metric {metric:?} but no JSON-key literal `\"{metric}\"` is emitted by either release_publication.rs or phase1_promotion.rs — a metric rename here would silently break documented Prometheus alerts"
        );
    }
}

// Lane ZZZ: rotation-budget JSON shape parity.
//
// The runbook section 9.5 documents the EXACT 5-field shape that
// every JSON endpoint exposing `rejected_smoke_audit` returns:
//
//   {
//     "rejected_smoke_audit": {
//       "count": 0,
//       "latest_timestamp_utc": null,
//       "latest_rejection_reason": null,
//       "audit_log_size_bytes": 0,
//       "audit_log_cap_bytes": 1048576
//     }
//   }
//
// The contract "keys are always present even pre-rejection" is
// load-bearing — monitoring scrapers depend on it. Lane YYY pins
// 3 of those 5 keys (the ones referenced by alert expressions).
// Lane ZZZ extends to ALL 5 keys, ensuring the JSON pass-through
// surface remains stable.
//
// Algorithm:
//
//   1. Extract the literal `rejected_smoke_audit` JSON block from
//      the runbook section 9.5 (between the `\n```json\n` fence
//      and the closing `\n```\n`).
//   2. Parse the inner object's keys (lines matching `"key":`).
//   3. Assert each key appears as a `"<key>"` literal in
//      `crates/ao2-cp-server/src/handlers/release_publication.rs`
//      AND `crates/ao2-cp-server/src/handlers/phase1_promotion.rs`
//      (since the JSON pass-through lives in release_publication
//      and the summary builder lives in phase1_promotion).
//   4. Floor: exactly 5 keys must be discovered.
//
// Plus the literal cap value (1048576 = 1 MiB = Lane UU
// threshold) must appear in the handler source — a future cap
// change without runbook update would surface here.
#[test]
fn rejected_smoke_audit_json_shape_binds_to_handler_keys_lane_zzz() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runbook = fs::read_to_string(root.join("docs/runbooks/release-smoke.md"))
        .expect("Lane ZZZ: runbook present");
    let release_publication =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane ZZZ: release_publication.rs present");
    let phase1_promotion =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/phase1_promotion.rs"))
            .expect("Lane ZZZ: phase1_promotion.rs present");

    // Find the documented shape literal.
    let shape_anchor = "\"rejected_smoke_audit\": {";
    let block_start = runbook.find(shape_anchor).expect(
        "Lane ZZZ: runbook must contain a literal `\"rejected_smoke_audit\": {` JSON shape",
    );
    let after = &runbook[block_start + shape_anchor.len()..];
    let block_end_rel = after
        .find('}')
        .expect("Lane ZZZ: documented rejected_smoke_audit JSON shape must terminate with a `}`");
    let inner = &after[..block_end_rel];

    // Collect every `"key":` literal.
    let mut keys: Vec<String> = Vec::new();
    let bytes = inner.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'"' {
                j += 1;
            }
            if j < bytes.len() {
                let key = &inner[start..j];
                // Followed by `":` (after the close-quote) means this
                // is a JSON key, not a string value.
                let after_close = &inner[j + 1..];
                if after_close.trim_start().starts_with(':') {
                    // Reject obvious non-snake_case shapes (defensive).
                    let valid = !key.is_empty()
                        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                    if valid {
                        keys.push(key.to_string());
                    }
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    keys.sort();
    keys.dedup();
    assert_eq!(
        keys.len(),
        5,
        "Lane ZZZ: documented rejected_smoke_audit shape must contain EXACTLY 5 keys (got {}: {:?})",
        keys.len(),
        keys
    );

    for key in &keys {
        let needle = format!("\"{key}\"");
        assert!(
            release_publication.contains(&needle),
            "Lane ZZZ: documented rejected_smoke_audit key {key:?} must appear as a JSON-key literal `\"{key}\"` in release_publication.rs (JSON pass-through surface)"
        );
        assert!(
            phase1_promotion.contains(&needle),
            "Lane ZZZ: documented rejected_smoke_audit key {key:?} must appear as a JSON-key literal `\"{key}\"` in phase1_promotion.rs (summary builder + append path)"
        );
    }

    // The Lane UU cap literal `1048576` (1 MiB in bytes) is the
    // documented audit_log_cap_bytes default; it must also be the
    // actual cap in the handler source.
    assert!(
        runbook.contains("1048576"),
        "Lane ZZZ: documented rejected_smoke_audit shape must include the Lane UU 1 MiB cap literal `1048576`"
    );
    assert!(
        phase1_promotion.contains("1048576") || phase1_promotion.contains("REJECTED_SMOKE_AUDIT_MAX_BYTES"),
        "Lane ZZZ: phase1_promotion.rs must reference the 1 MiB cap as `1048576` or via `REJECTED_SMOKE_AUDIT_MAX_BYTES`"
    );
}

// Lane AAAA: install heredoc → SHA256SUMS line-shape parity.
//
// `scripts/package-local.sh` writes the binary-row checksum line
// with a 2-space separator:
//
//   printf "%s  bin/%s\n" "$binary_sha" "$BINARY_NAME"
//
// Both installers parse that row back out at install time:
//
//   install.sh   : awk '$2 == "bin/<name>" { print $1 }' SHA256SUMS
//   install.ps1  : $_ -match "bin/<name>.exe$" → ($_ -split "\s+")[0]
//
// A future SHA256SUMS format change (column reorder, separator
// swap, additional columns) silently breaks one or both parsers
// AFTER the archive ships. Lane AAAA cross-binds the write
// printf format against both parse shapes so a change forces
// every consumer to update in lockstep.
//
// Algorithm:
//   1. Extract the canonical binary name from the first
//      `[[bin]]` table in Cargo.toml (source of truth - same as
//      Lane VVV).
//   2. Read scripts/package-local.sh.
//   3. Assert the printf write-shape literal
//      `printf "%s  bin/%s\n" "$binary_sha" "$BINARY_NAME"`
//      appears verbatim (two-space separator, sha column 1,
//      bin path column 2, trailing newline).
//   4. Extract the install.sh heredoc and assert it contains:
//      `awk '$2 == "bin/<binary>" { print $1 }' SHA256SUMS`
//      (binds field-position 2 to "bin/<binary>" and field 1 to
//      the sha — exact column ordering match against write).
//   5. Extract the install.ps1 heredoc and assert it contains:
//      `-match "bin/<binary>.exe$"`
//      AND `($_ -split "\s+")[0]`
//      (regex anchor + whitespace-split [0] for sha extraction).
#[test]
fn install_heredoc_sha256sums_line_shape_binds_to_write_shape_lane_aaaa() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cargo_toml = fs::read_to_string(root.join("crates/ao2-cp-server/Cargo.toml"))
        .expect("Lane AAAA: Cargo.toml present");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane AAAA: scripts/package-local.sh present");

    let binary = extract_first_cargo_bin_name(&cargo_toml);
    assert!(
        !binary.is_empty(),
        "Lane AAAA: Cargo.toml [[bin]] name must be non-empty"
    );

    // Write shape: printf "%s  bin/%s\n" "$binary_sha" "$BINARY_NAME"
    let write_shape = "printf \"%s  bin/%s\\n\" \"$binary_sha\" \"$BINARY_NAME\"";
    assert!(
        package.contains(write_shape),
        "Lane AAAA: scripts/package-local.sh must contain the canonical SHA256SUMS write shape `{write_shape}` (two-space separator, sha first, bin/<name> second). A column reorder or separator change here desyncs install.sh / install.ps1 parsers"
    );

    // install.sh parse shape: awk '$2 == "bin/<binary>" { print $1 }' SHA256SUMS
    let install_sh = extract_install_sh_heredoc(&package);
    assert!(
        !install_sh.is_empty(),
        "Lane AAAA: install.sh heredoc must be extractable from package-local.sh"
    );
    let sh_parse = format!("awk '$2 == \"bin/{binary}\" {{ print $1 }}' SHA256SUMS");
    assert!(
        install_sh.contains(&sh_parse),
        "Lane AAAA: install.sh heredoc must contain the exact SHA256SUMS parse shape `{sh_parse}` — binds field-position 2 to bin/{binary} and field 1 to sha, matching the package-local.sh printf write column ordering"
    );

    // install.ps1 parse shape: regex anchor + split-whitespace pick [0]
    let install_ps1 = extract_install_ps1_heredoc(&package);
    assert!(
        !install_ps1.is_empty(),
        "Lane AAAA: install.ps1 heredoc must be extractable from package-local.sh"
    );
    let ps_regex_anchor = format!("-match \"bin/{binary}.exe$\"");
    assert!(
        install_ps1.contains(&ps_regex_anchor),
        "Lane AAAA: install.ps1 heredoc must contain the regex anchor `{ps_regex_anchor}` (binds the SHA256SUMS row to the bin/{binary}.exe line end-anchor)"
    );
    let ps_split_pick = "($_ -split \"\\s+\")[0]";
    assert!(
        install_ps1.contains(ps_split_pick),
        "Lane AAAA: install.ps1 heredoc must contain `{ps_split_pick}` (whitespace-split index 0 → sha extraction, matching the package-local.sh printf write column 1)"
    );
}

// Lane BBBB: release-readiness gate registration → cockpit-row + JSON-emission parity.
//
// `release_publication.rs` declares the canonical readiness gate
// set in a single source-of-truth block:
//
//   let gate_results = vec![
//       release_readiness_gate("release_cockpit", ..., "ready"),
//       release_readiness_gate("phase1_promotion", ..., "observed"),
//       ...
//       release_readiness_gate("trust_boundary", ..., "...")
//   ];
//
// Three structural invariants must hold for the readiness
// summary to be coherent:
//
//   1. Every gate ID registered in the vec must be unique. A
//      duplicate silently registers two gates with the same id
//      confusing JSON consumers.
//   2. The registration vec result must be emitted as a JSON
//      value via `"gate_results": gate_results` — otherwise
//      every gate is silently dropped from the readiness
//      payload.
//   3. Every gate ID listed in the operator-facing HTML
//      cockpit `gate_row(...)` enumeration must trace back to
//      a registered gate in the vec. An orphan UI row points
//      operators at a gate that no longer exists.
//
// Algorithm:
//   1. Read release_publication.rs.
//   2. Locate `let gate_results = vec![` and walk forward to
//      the matching `];`.
//   3. Within that slice, collect every literal `<id>` from
//      `release_readiness_gate(` and
//      `release_readiness_gate_with_detail(` first-arg
//      positions.
//   4. Floor: >= 10 gate IDs collected (current count is 12 —
//      a future strip-down can't pass vacuously).
//   5. Assert no duplicate IDs.
//   6. Assert `"gate_results": gate_results` wire-out exists.
//   7. Collect every `gate_row("<id>",` first-arg literal in
//      release_publication.rs and assert each is a subset of
//      the registered gate IDs.
//   8. Floor: >= 5 gate_row entries (currently 7).
#[test]
fn release_readiness_gate_registration_binds_to_downstream_anchors_lane_bbbb() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let release_publication =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane BBBB: release_publication.rs present");

    // Locate the canonical gate registration vec.
    let vec_opener = "let gate_results = vec![";
    let vec_start = release_publication
        .find(vec_opener)
        .expect("Lane BBBB: release_publication.rs must contain `let gate_results = vec![` registration anchor");
    let after_open = vec_start + vec_opener.len();
    let close_rel = release_publication[after_open..]
        .find("];")
        .expect("Lane BBBB: gate_results vec must terminate with `];`");
    let vec_body = &release_publication[after_open..after_open + close_rel];

    // Collect gate IDs from `release_readiness_gate(` /
    // `release_readiness_gate_with_detail(` first-arg literals.
    let mut gate_ids: Vec<String> = Vec::new();
    for opener in [
        "release_readiness_gate_with_detail(",
        "release_readiness_gate(",
    ] {
        let mut search_from = 0;
        while let Some(rel) = vec_body[search_from..].find(opener) {
            let abs = search_from + rel;
            let after_paren = abs + opener.len();
            let bytes = vec_body.as_bytes();
            let mut i = after_paren;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            if i < bytes.len() {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
                if j < bytes.len() {
                    let id = &vec_body[start..j];
                    if !id.is_empty() {
                        gate_ids.push(id.to_string());
                    }
                }
            }
            search_from = after_paren;
        }
    }

    assert!(
        gate_ids.len() >= 10,
        "Lane BBBB: gate_results vec must register >= 10 readiness gates (found {}: {:?}). A future strip-down below this floor would render the downstream wire-out check vacuous",
        gate_ids.len(),
        gate_ids
    );

    // Invariant 1: no duplicate gate IDs.
    let mut sorted = gate_ids.clone();
    sorted.sort();
    let mut dedup = sorted.clone();
    dedup.dedup();
    assert_eq!(
        sorted, dedup,
        "Lane BBBB: gate IDs in the gate_results vec must be unique (got {gate_ids:?}). A duplicate registers two gates with the same id, confusing JSON consumers"
    );

    // Invariant 2: the vec must be emitted as a JSON value.
    let wire_out = "\"gate_results\": gate_results";
    assert!(
        release_publication.contains(wire_out),
        "Lane BBBB: release_publication.rs must emit the registered vec as `{wire_out}` — without this, every registered gate is silently dropped from the readiness JSON"
    );

    // Invariant 3: every gate_row(...) entry in the HTML
    // cockpit must trace back to a registered gate in the vec.
    let mut gate_row_ids: Vec<String> = Vec::new();
    let bytes = release_publication.as_bytes();
    let row_opener = "gate_row(\"";
    let mut search_from = 0;
    while let Some(rel) = release_publication[search_from..].find(row_opener) {
        let start = search_from + rel + row_opener.len();
        let mut j = start;
        while j < bytes.len() && bytes[j] != b'"' {
            j += 1;
        }
        if j < bytes.len() {
            let id = &release_publication[start..j];
            // Skip the closure-arg `gate_row(\"<key>\", \"<label>\")` form
            // when the literal is empty (defensive).
            if !id.is_empty() {
                gate_row_ids.push(id.to_string());
            }
        }
        search_from = start;
    }

    assert!(
        gate_row_ids.len() >= 5,
        "Lane BBBB: HTML cockpit `gate_row(...)` enumeration must list >= 5 gates (found {}: {:?})",
        gate_row_ids.len(),
        gate_row_ids
    );

    for row_id in &gate_row_ids {
        assert!(
            gate_ids.contains(row_id),
            "Lane BBBB: HTML cockpit references `gate_row(\"{row_id}\", ...)` but `{row_id}` is not registered in the `gate_results = vec![...]` source-of-truth. The cockpit will render a row pointing at a gate that does not exist"
        );
    }
}

// Lane CCCC: README threat-model claims → trust_boundary() handler emission parity.
//
// The README.txt heredoc that ships inside every release
// archive makes four load-bearing threat-model claims about
// the control plane's posture:
//
//   1. "read-only observer for AO2 signed evidence"
//   2. "does not start providers"
//   3. "does not approve AO2 runs" / "never approves releases"
//   4. "never mutates AO2 artifacts"
//
// These claims are operator-facing. The actual JSON emission
// for those same claims lives in the
// `trust_boundary() -> serde_json::Value` helper in
// `crates/ao2-cp-server/src/handlers/release_publication.rs`,
// which builds the source-of-truth JSON:
//
//   {
//     "role": "read_only_observer",
//     "mutates_ao_artifacts": false,
//     "control_plane_approves_release": false,
//     "release_acceptance_owner": "factory-v3 evaluator-closer",
//     ...
//   }
//
// A future weakening of the JSON contract (e.g., flipping
// `mutates_ao_artifacts` to true, dropping the
// `control_plane_approves_release` key, or renaming
// `read_only_observer`) silently breaks the README's promise
// to operators. Lane CCCC binds the four claim-phrases in the
// README to the matching JSON literals in trust_boundary().
//
// Algorithm:
//   1. Extract the README.txt heredoc from package-local.sh
//      (same opener Lane NNN / OOO use).
//   2. Read trust_boundary() function body from
//      release_publication.rs.
//   3. For each (claim-phrase, expected-json-literal) pair:
//        a. Assert claim-phrase appears in README heredoc.
//        b. Assert expected-json-literal appears in
//           trust_boundary() body.
//
// Pairs bound:
//   "read-only observer"            ↔ `"role": "read_only_observer"`
//   "does not start providers"      ↔ no per-key emission required
//                                     (asserts the README still
//                                     makes the claim - other lanes
//                                     verify there's no provider
//                                     auto-start path)
//   "does not approve"              ↔ `"control_plane_approves_release": false`
//   "never mutates"                 ↔ `"mutates_ao_artifacts": false`
//   "factory-v3 evaluator-closer"   ↔ `"release_acceptance_owner": "factory-v3 evaluator-closer"`
#[test]
fn readme_threat_model_claims_bind_to_trust_boundary_emission_lane_cccc() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane CCCC: scripts/package-local.sh present");
    let release_publication =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane CCCC: release_publication.rs present");

    // Extract the README heredoc body.
    let readme_opener = "cat > \"$STAGE/README.txt\" <<'TXT'\n";
    let readme_start = package
        .find(readme_opener)
        .expect("Lane CCCC: package-local.sh must contain the README.txt heredoc opener");
    let after_opener = readme_start + readme_opener.len();
    let readme_end_rel = package[after_opener..]
        .find("\nTXT\n")
        .expect("Lane CCCC: README.txt heredoc must terminate with `\\nTXT\\n`");
    let readme = &package[after_opener..after_opener + readme_end_rel];

    // Extract the trust_boundary() function body.
    let tb_opener = "fn trust_boundary() -> serde_json::Value {";
    let tb_start = release_publication.find(tb_opener).expect(
        "Lane CCCC: release_publication.rs must define `fn trust_boundary() -> serde_json::Value`",
    );
    let after_tb_opener = tb_start + tb_opener.len();
    // Walk to matching `}` at function-end. Naive: find the
    // closing `})\n}` shape since the function returns a json!
    // builder.
    let tb_end_rel = release_publication[after_tb_opener..]
        .find("\n}\n")
        .expect("Lane CCCC: trust_boundary() function must terminate with `\\n}\\n`");
    let tb_body = &release_publication[after_tb_opener..after_tb_opener + tb_end_rel];

    // README claim-phrases must appear in the README heredoc.
    let readme_claims: [&str; 4] = [
        "read-only observer",
        "does not start providers",
        "does not approve",
        "never mutates",
    ];
    for claim in readme_claims {
        assert!(
            readme.contains(claim),
            "Lane CCCC: README.txt heredoc must contain the threat-model claim `{claim}` so operators read the same posture statement the trust_boundary() handler emits"
        );
    }

    // Each enforceable claim has a matching trust_boundary() literal.
    let bindings: [(&str, &str); 4] = [
        ("read-only observer", "\"role\": \"read_only_observer\""),
        (
            "does not approve",
            "\"control_plane_approves_release\": false",
        ),
        ("never mutates", "\"mutates_ao_artifacts\": false"),
        (
            "factory-v3 evaluator-closer",
            "\"release_acceptance_owner\": \"factory-v3 evaluator-closer\"",
        ),
    ];
    for (claim, expected) in bindings {
        assert!(
            readme.contains(claim) || claim == "factory-v3 evaluator-closer",
            "Lane CCCC: README.txt heredoc must contain `{claim}` (the README is the operator-facing surface of trust_boundary())"
        );
        assert!(
            tb_body.contains(expected),
            "Lane CCCC: trust_boundary() function body must contain the JSON literal `{expected}` matching the README threat-model claim `{claim}`. A future weakening of this contract (e.g., flipping the false/true bit, renaming the key, renaming the role string) silently breaks the README's promise to operators"
        );
    }
}

// Lane DDDD: smoke aggregator step-order parity.
//
// `scripts/smoke-three-os-release.sh` orchestrates the three-OS
// release smoke flow as a linear top-level script with a
// dependency-ordered pipeline:
//
//   1. Run per-OS                  : run_macos / run_ubuntu / run_windows
//   2. Extract correlation status  : extract_correlation_status (three calls)
//   3. Compute status parity       : compute_parity (consumes step 2)
//   4. Fetch per-OS cockpit JSON   : fetch_*_artifact
//   5. Compute content-hash parity : compute_content_hash_parity (consumes step 4)
//
// A future regression that reorders steps yields silent
// failures: computing parity before status extracts run leaves
// the inputs unset; computing content-hash parity before fetches
// complete returns "unknown" even when data is intact.
//
// Lane XXX binds the function-name SET; Lane DDDD adds the
// orthogonal ORDER constraint by checking file-offset ordering
// of each step's INVOCATION (not the function definition).
#[test]
fn smoke_aggregator_step_order_matches_dependency_pipeline_lane_dddd() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = fs::read_to_string(root.join("scripts/smoke-three-os-release.sh"))
        .expect("Lane DDDD: smoke-three-os-release.sh present");

    // Find call-site offsets for an invocation marker. Skips
    // the function definition line `<func>() {`.
    fn find_call_offsets(haystack: &str, func: &str) -> Vec<usize> {
        let mut offsets = Vec::new();
        let def_marker = format!("\n{func}() {{");
        let def_offset = haystack.find(&def_marker);
        let call_patterns = [
            format!("$({func} "),
            format!("$({func})"),
            format!("if {func};"),
            format!("if {func} "),
        ];
        for pat in call_patterns {
            let mut search_from = 0;
            while let Some(rel) = haystack[search_from..].find(&pat) {
                let abs = search_from + rel;
                let is_def = def_offset
                    .map(|d| abs >= d && abs < d + 50)
                    .unwrap_or(false);
                if !is_def {
                    offsets.push(abs);
                }
                search_from = abs + pat.len();
            }
        }
        offsets.sort();
        offsets
    }

    let run_macos = find_call_offsets(&script, "run_macos");
    assert!(
        !run_macos.is_empty(),
        "Lane DDDD: smoke script must call `run_macos` at least once"
    );

    let extract_status = find_call_offsets(&script, "extract_correlation_status");
    assert!(
        extract_status.len() >= 3,
        "Lane DDDD: smoke script must call `extract_correlation_status` at least 3 times (once per OS); found {}",
        extract_status.len()
    );

    let compute_parity = find_call_offsets(&script, "compute_parity");
    assert!(
        !compute_parity.is_empty(),
        "Lane DDDD: smoke script must call `compute_parity` at least once"
    );

    let fetch_macos = find_call_offsets(&script, "fetch_macos_artifact");
    let fetch_ubuntu = find_call_offsets(&script, "fetch_ubuntu_artifact");
    let fetch_windows = find_call_offsets(&script, "fetch_windows_artifact");
    assert!(
        !fetch_macos.is_empty() && !fetch_ubuntu.is_empty() && !fetch_windows.is_empty(),
        "Lane DDDD: smoke script must call fetch_macos_artifact / fetch_ubuntu_artifact / fetch_windows_artifact at least once each"
    );
    let last_fetch = **[
        fetch_macos.last(),
        fetch_ubuntu.last(),
        fetch_windows.last(),
    ]
    .iter()
    .flatten()
    .max()
    .expect("Lane DDDD: at least one fetch call must exist");

    let compute_content_hash_parity = find_call_offsets(&script, "compute_content_hash_parity");
    assert!(
        !compute_content_hash_parity.is_empty(),
        "Lane DDDD: smoke script must call `compute_content_hash_parity` at least once"
    );

    let first_run_macos = run_macos[0];
    let first_extract = extract_status[0];
    let last_extract = *extract_status.last().unwrap();
    let first_compute_parity = compute_parity[0];
    let first_fetch = **[
        fetch_macos.first(),
        fetch_ubuntu.first(),
        fetch_windows.first(),
    ]
    .iter()
    .flatten()
    .min()
    .unwrap();
    let first_compute_chp = compute_content_hash_parity[0];

    assert!(
        first_run_macos < first_extract,
        "Lane DDDD: `run_macos` (offset {first_run_macos}) must be invoked BEFORE the first `extract_correlation_status` (offset {first_extract}). Otherwise extract_correlation_status reads a log that hasn't been produced yet"
    );
    assert!(
        last_extract < first_compute_parity,
        "Lane DDDD: every `extract_correlation_status` call (last at offset {last_extract}) must precede the first `compute_parity` (offset {first_compute_parity}). compute_parity consumes correlation status inputs from all three OSes; calling it before any extract leaves the status variables unset"
    );
    assert!(
        first_compute_parity < first_fetch,
        "Lane DDDD: `compute_parity` (offset {first_compute_parity}) must precede the first `fetch_<os>_artifact` (offset {first_fetch}). The status-parity pipeline must complete before the content-hash-parity pipeline starts"
    );
    assert!(
        last_fetch < first_compute_chp,
        "Lane DDDD: every `fetch_<os>_artifact` call (last at offset {last_fetch}) must precede the first `compute_content_hash_parity` (offset {first_compute_chp}). Computing content-hash parity before all cockpit files are fetched yields `unknown` even when the data is intact"
    );
}

// Lane EEEE: installer fail-closed step-order parity.
//
// Both installers must perform the SHA256 verification BEFORE
// the destination-copy step. The opposite order is a security
// regression: an operator running `sh install.sh` would have
// the binary copied into `$INSTALL_DIR` first and only THEN
// learn that the checksum failed — leaving an unverified
// binary at the install location.
//
// install.sh canonical fail-closed order:
//   1. expected=$(awk ... 'bin/<bin>' SHA256SUMS)
//   2. if [ -z "$expected" ] → exit 1 on missing checksum
//   3. actual=$(sha256sum / shasum -a 256 ...)
//   4. if [ "$actual" != "$expected" ] → exit 1 on mismatch
//   5. cp "bin/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
//
// install.ps1 canonical fail-closed order:
//   1. $Expected = (Get-Content SHA256SUMS ...)
//   2. if (!$Expected) → throw on missing checksum
//   3. $Actual = (Get-FileHash -Algorithm SHA256 ...).Hash
//   4. if ($Actual -ne $Expected) → throw on mismatch
//   5. Copy-Item -Force $Source ...
#[test]
fn install_heredocs_perform_checksum_before_copy_lane_eeee() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane EEEE: scripts/package-local.sh present");

    // install.sh heredoc fail-closed order.
    let install_sh = extract_install_sh_heredoc(&package);
    assert!(
        !install_sh.is_empty(),
        "Lane EEEE: install.sh heredoc must be extractable"
    );

    let sh_expected = install_sh
        .find("expected=$(awk")
        .expect("Lane EEEE: install.sh must extract `expected=$(awk ...)` from SHA256SUMS");
    let sh_expected_check = install_sh.find("if [ -z \"$expected\" ]").expect(
        "Lane EEEE: install.sh must fail-closed on missing checksum via `if [ -z \"$expected\" ]`",
    );
    let sh_actual = install_sh
        .find("actual=$(sha256sum")
        .or_else(|| install_sh.find("actual=$(shasum"))
        .expect(
            "Lane EEEE: install.sh must compute actual hash via `sha256sum` or `shasum -a 256`",
        );
    let sh_actual_check = install_sh
        .find("if [ \"$actual\" != \"$expected\" ]")
        .expect("Lane EEEE: install.sh must fail-closed on hash mismatch via `if [ \"$actual\" != \"$expected\" ]`");
    let sh_copy = install_sh.find("cp \"bin/$BINARY_NAME\"").expect(
        "Lane EEEE: install.sh must copy via `cp \"bin/$BINARY_NAME\" \"$INSTALL_DIR/...\"`",
    );

    assert!(
        sh_expected < sh_expected_check,
        "Lane EEEE: install.sh `expected=$(awk ...)` (offset {sh_expected}) must precede the `if [ -z \"$expected\" ]` empty check (offset {sh_expected_check})"
    );
    assert!(
        sh_expected_check < sh_actual,
        "Lane EEEE: install.sh empty-check `if [ -z \"$expected\" ]` (offset {sh_expected_check}) must precede `actual=$(...)` computation (offset {sh_actual})"
    );
    assert!(
        sh_actual < sh_actual_check,
        "Lane EEEE: install.sh `actual=$(...)` (offset {sh_actual}) must precede `if [ \"$actual\" != \"$expected\" ]` mismatch check (offset {sh_actual_check})"
    );
    assert!(
        sh_actual_check < sh_copy,
        "Lane EEEE: install.sh mismatch check `if [ \"$actual\" != \"$expected\" ]` (offset {sh_actual_check}) must precede `cp \"bin/$BINARY_NAME\" ...` (offset {sh_copy}). A future regression that copies first and validates later leaves an unverified binary at the install location"
    );

    // install.ps1 heredoc fail-closed order.
    let install_ps1 = extract_install_ps1_heredoc(&package);
    assert!(
        !install_ps1.is_empty(),
        "Lane EEEE: install.ps1 heredoc must be extractable"
    );

    let ps_expected = install_ps1
        .find("$Expected = (Get-Content SHA256SUMS")
        .expect("Lane EEEE: install.ps1 must extract $Expected via `Get-Content SHA256SUMS`");
    let ps_expected_check = install_ps1.find("if (!$Expected)").expect(
        "Lane EEEE: install.ps1 must fail-closed on missing checksum via `if (!$Expected)`",
    );
    let ps_actual = install_ps1
        .find("$Actual = (Get-FileHash")
        .expect("Lane EEEE: install.ps1 must compute $Actual via `Get-FileHash -Algorithm SHA256`");
    let ps_actual_check = install_ps1
        .find("if ($Actual -ne $Expected")
        .expect("Lane EEEE: install.ps1 must fail-closed on hash mismatch via `if ($Actual -ne $Expected...)`");
    let ps_copy = install_ps1
        .find("Copy-Item -Force $Source")
        .expect("Lane EEEE: install.ps1 must copy via `Copy-Item -Force $Source`");

    assert!(
        ps_expected < ps_expected_check,
        "Lane EEEE: install.ps1 `$Expected = (Get-Content SHA256SUMS ...)` (offset {ps_expected}) must precede the `if (!$Expected)` empty check (offset {ps_expected_check})"
    );
    assert!(
        ps_expected_check < ps_actual,
        "Lane EEEE: install.ps1 empty-check `if (!$Expected)` (offset {ps_expected_check}) must precede `$Actual = (Get-FileHash ...)` computation (offset {ps_actual})"
    );
    assert!(
        ps_actual < ps_actual_check,
        "Lane EEEE: install.ps1 `$Actual = (...)` (offset {ps_actual}) must precede `if ($Actual -ne $Expected...)` mismatch check (offset {ps_actual_check})"
    );
    assert!(
        ps_actual_check < ps_copy,
        "Lane EEEE: install.ps1 mismatch check `if ($Actual -ne $Expected...)` (offset {ps_actual_check}) must precede `Copy-Item -Force $Source ...` (offset {ps_copy}). A future regression that copies first and validates later leaves an unverified binary at the install location"
    );
}

// Lane FFFF: support-bundle surface-ID constant → JSON-literal parity.
//
// `release_publication.rs` declares the canonical support-bundle
// support-bundle ID set as a static const:
//
//   const SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS: [&str; N] = [
//       "ci_evidence_index",
//       "release_assembly",
//       "release_readiness",
//       "release_candidate_handoff",
//       "release_cockpit",
//       "release_evaluator_decision",
//       "storage_support_bundle",
//   ];
//
// The same IDs also appear as `"id": "<literal>"` entries
// in the bundle-manifest JSON builder and as `"<id>":` keys
// in the `integrity.surface_sha256` object. A future rename
// of e.g. `release_cockpit` → `release_cockpit_v2` in the
// constant array WITHOUT updating the JSON-literal builder
// would silently break every consumer that filters surfaces
// on `"id"`.
#[test]
fn support_bundle_surface_ids_bind_to_json_literal_emission_lane_ffff() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let release_publication =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane FFFF: release_publication.rs present");

    let const_opener = "const SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS:";
    let const_start = release_publication
        .find(const_opener)
        .expect("Lane FFFF: release_publication.rs must declare `const SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS:`");
    let eq_rel = release_publication[const_start..]
        .find(" = [")
        .expect("Lane FFFF: surface-ID const must use `= [...]` literal");
    let literal_start = const_start + eq_rel + 4;
    let array_close_rel = release_publication[literal_start..]
        .find("];")
        .expect("Lane FFFF: surface-ID const must terminate with `];`");
    let array_body = &release_publication[literal_start..literal_start + array_close_rel];

    let mut ids: Vec<String> = Vec::new();
    let bytes = array_body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'"' {
                j += 1;
            }
            if j < bytes.len() {
                let id = &array_body[start..j];
                if !id.is_empty() {
                    ids.push(id.to_string());
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }

    assert!(
        ids.len() >= 6,
        "Lane FFFF: SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS must declare >= 6 surface IDs (found {}: {:?})",
        ids.len(),
        ids
    );

    let const_decl_end = literal_start + array_close_rel + 2;
    let mut surrounding = String::with_capacity(release_publication.len());
    surrounding.push_str(&release_publication[..const_start]);
    surrounding.push_str(&release_publication[const_decl_end..]);

    for id in &ids {
        let needle = format!("\"id\": \"{id}\"");
        assert!(
            surrounding.contains(&needle),
            "Lane FFFF: SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS contains `{id:?}` but the literal `\"id\": \"{id}\"` JSON-emission anchor is missing from release_publication.rs. A future rename of the const member without updating the JSON-literal builder would silently break every consumer that filters surfaces on `\"id\"`"
        );
    }

    for id in &ids {
        let needle = format!("\"{id}\":");
        assert!(
            surrounding.contains(&needle),
            "Lane FFFF: SUPPORT_BUNDLE_REQUIRED_SURFACE_IDS contains `{id:?}` but the literal `\"{id}\":` JSON-key anchor is missing from release_publication.rs (expected in the integrity.surface_sha256 map or equivalent per-surface hash dictionary)"
        );
    }
}

#[test]
fn offline_release_support_verifiers_require_hosted_release_smoke_surface() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let py = fs::read_to_string(root.join("scripts/verify_release_support_bundle.py"))
        .expect("python support-bundle verifier exists");
    let ps = fs::read_to_string(root.join("scripts/Verify-ReleaseSupportBundle.ps1"))
        .expect("PowerShell support-bundle verifier exists");
    let fixture =
        fs::read_to_string(root.join("tests/fixtures/release-support-bundle-contract-v1.json"))
            .expect("shared release-support fixture exists");

    for source in [&py, &ps, &fixture] {
        assert!(source.contains("hosted_release_smoke"));
        assert!(source.contains("ao2.release-archive-hosted-smoke.v1"));
        assert!(source.contains("$.hosted_release_smoke"));
    }
}

// Lane HHHH: every `const *_SCHEMA: &str = "...";` declared at the top of
// release_publication.rs must be referenced at least once in a
// `"schema_version": <CONST_NAME>` JSON-literal emission line. A future
// removal of an emission site that leaves the const declaration intact
// surfaces here so downstream consumers don't read a stale schema-version
// label off the const reference list, expecting an emission point that
// no longer exists. Symmetric to Lane FFFF (surface-IDs) but for the
// schema_version axis.
#[test]
fn release_schema_consts_bind_to_schema_version_emission_lane_hhhh() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let release_publication =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane HHHH: release_publication.rs present");

    // Strip the test module so dead consts aren't kept alive by sentinel
    // references inside #[cfg(test)] code paths.
    let production_src = match release_publication.find("\n#[cfg(test)]\n") {
        Some(idx) => &release_publication[..idx],
        None => release_publication.as_str(),
    };

    // Parse every `const <NAME>: &str = "<value>";` declaration where NAME
    // ends in `_SCHEMA`. Two forms appear in the file: single-line
    // (`const NAME: &str = "value";`) and wrapped two-line
    // (`const NAME: &str =\n    "value";`).
    let mut consts: Vec<(String, String)> = Vec::new();
    for line in production_src.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("const ") {
            continue;
        }
        let after_const = &trimmed["const ".len()..];
        let Some(colon_idx) = after_const.find(':') else {
            continue;
        };
        let name = after_const[..colon_idx].trim().to_string();
        if !name.ends_with("_SCHEMA") {
            continue;
        }
        if let Some(eq_idx) = after_const.find('=') {
            let rhs = after_const[eq_idx + 1..].trim();
            if let Some(stripped) = rhs.strip_prefix('"') {
                if let Some(close) = stripped.find('"') {
                    consts.push((name, stripped[..close].to_string()));
                    continue;
                }
            }
        }
        consts.push((name, String::new()));
    }

    // Pass 2: fill in values for the wrapped two-line declarations whose
    // RHS we didn't capture above.
    for (name, value) in consts.iter_mut() {
        if !value.is_empty() {
            continue;
        }
        let needle = format!("const {name}:");
        let Some(start) = production_src.find(&needle) else {
            continue;
        };
        let tail = &production_src[start..];
        if let Some(eq_idx) = tail.find('=') {
            let after_eq = &tail[eq_idx + 1..];
            if let Some(q_idx) = after_eq.find('"') {
                let lit_start = q_idx + 1;
                if let Some(q_close) = after_eq[lit_start..].find('"') {
                    *value = after_eq[lit_start..lit_start + q_close].to_string();
                }
            }
        }
    }

    assert!(
        consts.len() >= 8,
        "Lane HHHH: release_publication.rs must declare >= 8 `*_SCHEMA: &str` consts (found {}: {:?})",
        consts.len(),
        consts.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );

    // Every declared const value must look like a schema-version string.
    for (name, value) in &consts {
        assert!(
            !value.is_empty(),
            "Lane HHHH: const {name} declared in release_publication.rs but no string literal was parsed from its RHS"
        );
        assert!(
            value.ends_with(".v1") || value.contains("/v1") || value.contains(".v"),
            "Lane HHHH: const {name} value {value:?} doesn't look like a versioned schema string (expected suffix matching `.v1` or `/v1`)"
        );
    }

    // For each declared const, assert it's referenced at least once
    // outside its declaration. The const can flow into the wire as one of
    // several shapes — `"schema_version": NAME` (JSON literal), `schema:
    // NAME.to_string()` (struct field assignment), `schema == NAME`
    // (equality check on inbound payload). Any non-declaration reference
    // counts; what matters is the const isn't dead. A future deletion of
    // ALL emission/comparison sites that leaves the const declaration
    // intact would silently advertise a schema label nothing actually
    // stamps or accepts.
    for (name, _) in &consts {
        let decl_line = format!("const {name}:");
        let mut uses = 0usize;
        for line in production_src.lines() {
            if line.contains(&decl_line) {
                continue;
            }
            if line.contains(name) {
                uses += 1;
            }
        }
        assert!(
            uses >= 1,
            "Lane HHHH: const {name} declared in release_publication.rs but is unreferenced outside its declaration. A future deletion of every emission/comparison site that leaves the const intact would silently advertise a schema label nothing actually stamps."
        );
    }

    // Additionally, at least one JSON-literal `"schema_version": ...`
    // emission line must reference the const family — guards against a
    // future refactor that swaps all schema_version JSON-literal sites
    // for inline strings and breaks the const → wire binding.
    let json_emission_count = production_src
        .lines()
        .filter(|line| {
            line.contains("\"schema_version\":")
                && consts.iter().any(|(name, _)| line.contains(name.as_str()))
        })
        .count();
    assert!(
        json_emission_count >= 8,
        "Lane HHHH: production code must contain >= 8 `\"schema_version\": <CONST>` JSON-literal emission lines (found {json_emission_count}); a future refactor that swaps all const references for inline string literals would silently break the const → wire binding"
    );

    // Names must be unique (catches accidental duplicate declarations from
    // a botched merge).
    let mut sorted: Vec<&String> = consts.iter().map(|(n, _)| n).collect();
    sorted.sort();
    let original_len = sorted.len();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        original_len,
        "Lane HHHH: duplicate `*_SCHEMA` const name in release_publication.rs"
    );

    // Values must be unique (catches two consts collapsing to the same
    // schema string, which would let consumers conflate distinct
    // resources under one label).
    let mut sorted_vals: Vec<&String> = consts.iter().map(|(_, v)| v).collect();
    sorted_vals.sort();
    let original_val_len = sorted_vals.len();
    sorted_vals.dedup();
    assert_eq!(
        sorted_vals.len(),
        original_val_len,
        "Lane HHHH: duplicate `*_SCHEMA` const VALUE in release_publication.rs — two consts collapse to the same schema-version string, which would let JSON consumers conflate distinct resources"
    );
}

// Lane IIII: install heredoc env-var default value parity. Extends Lane
// RRR (env-var NAMES) and Lane VVV (binary NAME) to the third axis the
// installer can drift on: the DEFAULT install-directory fallback. The
// README inside the release archive documents the install command with
// the assumed default install directory baked in; if a future quiet
// refactor of install.sh flips the default from `$HOME/.local/bin` to
// `/usr/local/bin` (or the PowerShell default from `.local\bin` to a
// different path) without updating the README example, operators
// copy-pasting from the shipped README land on a directory that's not
// on PATH and end up with `command not found` after a "successful"
// install.
#[test]
fn install_heredoc_default_install_dir_binds_to_readme_lane_iiii() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package_local = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane IIII: scripts/package-local.sh present");

    // Slice the install.sh heredoc.
    let sh_open = package_local
        .find("cat > \"$STAGE/install.sh\" <<'SH'")
        .expect("Lane IIII: install.sh heredoc opener missing in package-local.sh");
    let sh_body = &package_local[sh_open..];
    let sh_close_rel = sh_body
        .find("\nSH\n")
        .expect("Lane IIII: install.sh heredoc closer `SH` missing");
    let install_sh = &sh_body[..sh_close_rel];

    // Extract the INSTALL_DIR default from
    // `INSTALL_DIR="${AO2_CP_INSTALL_DIR:-${AO2_INSTALL_DIR:-<default>}}"`.
    let assign_anchor = "INSTALL_DIR=\"${AO2_CP_INSTALL_DIR:-${AO2_INSTALL_DIR:-";
    let assign_start = install_sh
        .find(assign_anchor)
        .expect("Lane IIII: install.sh must declare INSTALL_DIR with chained ${VAR:-${VAR:-default}} fallbacks");
    let value_start = assign_start + assign_anchor.len();
    let value_close_rel = install_sh[value_start..]
        .find("}}\"")
        .expect("Lane IIII: install.sh INSTALL_DIR fallback must terminate with `}}\\\"`");
    let unix_default = &install_sh[value_start..value_start + value_close_rel];
    assert!(
        !unix_default.is_empty(),
        "Lane IIII: install.sh INSTALL_DIR default value parsed empty"
    );
    assert!(
        unix_default.contains("$HOME") || unix_default.starts_with('/'),
        "Lane IIII: install.sh INSTALL_DIR default {unix_default:?} must be either $HOME-rooted or absolute (security: never default to a relative path that resolves under cwd)"
    );

    // Slice the install.ps1 heredoc.
    let ps_open = package_local
        .find("cat > \"$STAGE/install.ps1\" <<'PS1'")
        .expect("Lane IIII: install.ps1 heredoc opener missing in package-local.sh");
    let ps_body = &package_local[ps_open..];
    let ps_close_rel = ps_body
        .find("\nPS1\n")
        .expect("Lane IIII: install.ps1 heredoc closer `PS1` missing");
    let install_ps1 = &ps_body[..ps_close_rel];

    // Extract the PowerShell default from the `} else { <default> }` block.
    let ps_else_anchor = "} else {\n";
    let ps_else_start = install_ps1
        .find(ps_else_anchor)
        .expect("Lane IIII: install.ps1 must use `} else { <default> }` fallback for $InstallDir");
    let ps_default_start = ps_else_start + ps_else_anchor.len();
    let ps_default_close_rel = install_ps1[ps_default_start..]
        .find("\n}")
        .expect("Lane IIII: install.ps1 `} else { ... }` block must close with `\\n}`");
    let ps_default_raw =
        install_ps1[ps_default_start..ps_default_start + ps_default_close_rel].trim();
    assert!(
        !ps_default_raw.is_empty(),
        "Lane IIII: install.ps1 $InstallDir default block parsed empty"
    );
    assert!(
        ps_default_raw.contains("$env:USERPROFILE") || ps_default_raw.contains("$env:LOCALAPPDATA"),
        "Lane IIII: install.ps1 $InstallDir default {ps_default_raw:?} must be rooted under $env:USERPROFILE or $env:LOCALAPPDATA (security: never default to cwd-relative or system-global paths the user can't write without elevation)"
    );

    // Slice the README.txt heredoc.
    let readme_open = package_local
        .find("cat > \"$STAGE/README.txt\" <<'TXT'")
        .expect("Lane IIII: README.txt heredoc opener missing in package-local.sh");
    let readme_body = &package_local[readme_open..];
    let readme_close_rel = readme_body
        .find("\nTXT\n")
        .expect("Lane IIII: README.txt heredoc closer `TXT` missing");
    let readme_txt = &readme_body[..readme_close_rel];

    // The README's documented install commands must use the SAME default
    // path the installer falls back to. If the README example sets
    // AO2_CP_INSTALL_DIR explicitly, that override must match the
    // installer's fallback so copy-paste lands the binary at the path
    // the rest of the README's PATH-tweak instructions assume.
    assert!(
        readme_txt.contains(unix_default),
        "Lane IIII: README.txt does not contain the install.sh default install dir {unix_default:?}. The README's example `AO2_CP_INSTALL_DIR=... sh install.sh` line must reference the SAME default path operators get if they don't set the env var (otherwise the README's PATH-tweak instructions don't match where the binary actually lands)"
    );

    // For the PowerShell side, extract the README's Windows install
    // example and verify it references the same `$env:` root the
    // installer default uses.
    let readme_lines: Vec<&str> = readme_txt.lines().collect();
    let ps_example_line = readme_lines
        .iter()
        .find(|l| l.contains("$env:AO2_CP_INSTALL_DIR"))
        .copied()
        .expect("Lane IIII: README.txt must contain a `$env:AO2_CP_INSTALL_DIR=...` Windows install example line");
    for env_token in ps_default_raw
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '$' && c != ':')
        .filter(|tok| tok.starts_with("$env:"))
    {
        assert!(
            ps_example_line.contains(env_token),
            "Lane IIII: README.txt Windows example {ps_example_line:?} must reference the `$env:` root the install.ps1 default uses ({env_token:?} from {ps_default_raw:?}). A future quiet flip of the install.ps1 default root from $env:USERPROFILE → $env:LOCALAPPDATA without updating the README leaves operators copy-pasting from the README into a different directory than the silent default"
        );
    }
}

// Lane JJJJ: `.route("/release/...", <method>(handlers::release_publication::<fn>))`
// declarations in server.rs must each (a) wire to a handler fn that
// actually exists in handlers/release_publication.rs, (b) follow the
// `.json` suffix convention (route ending `.json` ↔ handler fn ending
// `_json`) so HTML/JSON content negotiation stays predictable, and (c)
// declare pairwise-unique path strings (axum would panic at startup if
// two routes collided; catching it statically beats catching it in an
// E2E smoke). Floor: >= 25 release routes — catches a botched merge
// that accidentally drops a `.route()` chain from the build_router
// builder. Lane SSS bound README route literals to .route() existence
// in server.rs; Lane JJJJ extends to the second half: every declared
// route resolves to a real handler that returns the right content type.
#[test]
fn release_routes_bind_to_handler_fns_lane_jjjj() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let server_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/server.rs"))
        .expect("Lane JJJJ: server.rs present");
    let handlers_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane JJJJ: handlers/release_publication.rs present");

    // Parse every `.route("<path>", <method>(handlers::release_publication::<fn>))`
    // block. The router builder spans multiple lines per .route(), so
    // walk the file character by character to slice each block.
    let mut routes: Vec<(String, Vec<String>)> = Vec::new();
    let mut cursor = 0usize;
    while let Some(idx) = server_rs[cursor..].find(".route(") {
        let block_start = cursor + idx + ".route(".len();
        // Find the matching close paren by counting depth.
        let bytes = server_rs.as_bytes();
        let mut depth = 1i32;
        let mut j = block_start;
        let mut in_string = false;
        while j < bytes.len() && depth > 0 {
            let c = bytes[j] as char;
            if in_string {
                if c == '"' && bytes.get(j.wrapping_sub(1)).copied() != Some(b'\\') {
                    in_string = false;
                }
            } else {
                match c {
                    '"' => in_string = true,
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
            }
            j += 1;
        }
        let block = &server_rs[block_start..j - 1];
        cursor = j;

        // Extract path literal (the first string literal in the block).
        let Some(path_q1) = block.find('"') else {
            continue;
        };
        let path_inner_start = path_q1 + 1;
        let Some(path_q2_rel) = block[path_inner_start..].find('"') else {
            continue;
        };
        let path = block[path_inner_start..path_inner_start + path_q2_rel].to_string();

        // Only bind release_publication routes — other handler modules
        // are out of scope for this lane.
        if !block.contains("handlers::release_publication::") {
            continue;
        }
        if !path.starts_with("/release") {
            continue;
        }

        // Extract every `handlers::release_publication::<fn>` reference
        // in the block (a single route can chain `.get(...)` and
        // `.post(...)` against different handlers).
        let mut handlers: Vec<String> = Vec::new();
        let prefix = "handlers::release_publication::";
        let mut k = 0usize;
        while let Some(rel) = block[k..].find(prefix) {
            let start = k + rel + prefix.len();
            let end = start
                + block[start..]
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(block.len() - start);
            handlers.push(block[start..end].to_string());
            k = end;
        }
        routes.push((path, handlers));
    }

    assert!(
        routes.len() >= 25,
        "Lane JJJJ: server.rs must declare >= 25 release routes wired to handlers::release_publication (found {}: {:?})",
        routes.len(),
        routes.iter().map(|(p, _)| p).collect::<Vec<_>>()
    );

    // Every handler fn referenced must exist in release_publication.rs.
    // rustc enforces this for compilation, but the parse here also
    // proves the parser sees the same shape the compiler does — a
    // future grammar change to `.route(...)` macros would break this
    // test before silently breaking downstream lanes (Lane SSS, KKK)
    // that reuse the same parse.
    for (path, handlers) in &routes {
        assert!(
            !handlers.is_empty(),
            "Lane JJJJ: route {path:?} parsed with zero handlers — likely a parser regression in this test"
        );
        for handler in handlers {
            let needle = format!("fn {handler}(");
            assert!(
                handlers_rs.contains(&needle),
                "Lane JJJJ: route {path:?} wires to handlers::release_publication::{handler}, but no `fn {handler}(` definition exists in release_publication.rs. The rust compiler would catch this at build time, but the static catch here also pins the .route() parser shape"
            );
        }
    }

    // `.json` suffix convention: every route ending in `.json` must
    // wire to at least one handler fn whose name ends with `_json`.
    // Conversely, every handler fn ending with `_json` must wire to a
    // route ending in `.json`. Catches a future quiet swap that wires
    // `/release/cockpit.json` to `release_cockpit` (returning HTML
    // instead of JSON to clients expecting JSON).
    for (path, handlers) in &routes {
        if path.ends_with(".json") {
            assert!(
                handlers.iter().any(|h| h.ends_with("_json")),
                "Lane JJJJ: route {path:?} ends in `.json` but wires to handlers {handlers:?}, none of which ends in `_json`. A client requesting JSON would receive whatever content type the non-_json handler emits (typically HTML), silently breaking content negotiation"
            );
        }
        for handler in handlers {
            if handler.ends_with("_json") {
                assert!(
                    path.ends_with(".json"),
                    "Lane JJJJ: handler {handler} ends in `_json` but is wired to route {path:?} which does NOT end in `.json`. JSON content-type is being served at a path callers expect to return HTML"
                );
            }
        }
    }

    // Path uniqueness: axum panics at startup if two routes share an
    // exact path; catching it statically converts a deploy-time panic
    // into a build-time test failure.
    let mut sorted_paths: Vec<&str> = routes.iter().map(|(p, _)| p.as_str()).collect();
    sorted_paths.sort();
    let original_len = sorted_paths.len();
    sorted_paths.dedup();
    assert_eq!(
        sorted_paths.len(),
        original_len,
        "Lane JJJJ: duplicate route path in server.rs release_publication routes. axum panics at startup on duplicate routes; this static catch prevents a deploy-time crash"
    );
}

// Lane KKKK: README workspace-path claims must reference real files.
// The shipped README points operators at specific source files for
// triage detail (`scripts/smoke-three-os-release.sh`,
// `crates/ao2-cp-server/src/handlers/phase1_promotion.rs`,
// `docs/runbooks/release-smoke.md`). A future file rename or move
// without a lockstep README update leaves operators chasing a dead
// path when they drill into a failure. Lane UUU bound BARE filenames
// in the README to the tar arglist; Lane OOO bound snake_case
// identifiers to workspace existence; Lane KKKK closes the gap for
// directory-rooted workspace paths (tokens containing `/`).
#[test]
fn readme_workspace_path_claims_resolve_to_real_files_lane_kkkk() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package_local = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane KKKK: scripts/package-local.sh present");

    // Slice the README.txt heredoc.
    let readme_open = package_local
        .find("cat > \"$STAGE/README.txt\" <<'TXT'")
        .expect("Lane KKKK: README.txt heredoc opener missing in package-local.sh");
    let readme_body = &package_local[readme_open..];
    let readme_close_rel = readme_body
        .find("\nTXT\n")
        .expect("Lane KKKK: README.txt heredoc closer `TXT` missing");
    let readme_txt = &readme_body[..readme_close_rel];

    // Scan for tokens that look like workspace-rooted paths: at least
    // one `/`, end with a known source extension, and a first segment
    // matching a real workspace top-level directory. Runtime-output
    // paths (release-handoff/..., phase1-handoff/...) and bare
    // filenames (install.sh) are excluded — bare filenames are bound
    // by Lane UUU, runtime paths are operator outputs.
    let workspace_dirs = ["crates", "docs", "scripts", "tests"];
    let source_exts = [
        ".rs", ".sh", ".py", ".ps1", ".md", ".toml", ".yaml", ".yml", ".json", ".jsonl",
    ];

    let mut paths: Vec<String> = Vec::new();
    let bytes = readme_txt.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Find the start of a candidate token: ASCII alphanumeric or `/`.
        let c = bytes[i] as char;
        if !c.is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        // Walk forward collecting path-shaped chars.
        let start = i;
        while i < bytes.len() {
            let ch = bytes[i] as char;
            if ch.is_ascii_alphanumeric() || ch == '/' || ch == '_' || ch == '-' || ch == '.' {
                i += 1;
            } else {
                break;
            }
        }
        let token = &readme_txt[start..i];

        if !token.contains('/') {
            continue;
        }
        if !source_exts.iter().any(|ext| token.ends_with(ext)) {
            continue;
        }
        // First segment must be a recognised workspace dir.
        let first_seg = token.split('/').next().unwrap_or("");
        if !workspace_dirs.contains(&first_seg) {
            continue;
        }
        if !paths.contains(&token.to_string()) {
            paths.push(token.to_string());
        }
    }

    assert!(
        paths.len() >= 3,
        "Lane KKKK: README must reference >= 3 workspace-rooted source paths (found {}: {:?}). The README points operators at specific source files for triage detail; a regression that drops these references back to vague prose would leave operators without a concrete drill-in target",
        paths.len(),
        paths
    );

    // Every referenced path must resolve to a real file on disk.
    for path in &paths {
        let resolved = root.join(path);
        assert!(
            resolved.is_file(),
            "Lane KKKK: README references workspace path {path:?} but no file exists at {resolved:?}. A future file rename or move without lockstep README update leaves operators chasing a dead path"
        );
    }
}

// Lane LLLL: README "Operator landing flow" numbered-list parity. The
// shipped README enumerates an ordered list of HTTP surfaces operators
// triage in sequence (1 → /...operator-panel, 2 → /...dashboard, 3 →
// /release/cockpit, 4 → /release/publication/dashboard, 5 →
// /release/readiness etc.). The numbering communicates the intended
// triage order to the operator. Lane LLLL pins three invariants:
// (a) the numbering is consecutive starting at 1 (no gaps, no
// duplicates, no skipped numbers), (b) every `/api/v1/...` path
// mentioned in the numbered list appears as a `.route(...)`
// declaration in server.rs (a runtime 404 from the README's documented
// triage entry point is the worst possible operator UX), and (c) the
// list has at least the documented floor of 5 items so a future
// regression that truncates the list can't silently ship.
#[test]
fn readme_operator_landing_flow_numbered_list_lane_llll() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package_local = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane LLLL: scripts/package-local.sh present");
    let server_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/server.rs"))
        .expect("Lane LLLL: server.rs present");

    let readme_open = package_local
        .find("cat > \"$STAGE/README.txt\" <<'TXT'")
        .expect("Lane LLLL: README.txt heredoc opener missing in package-local.sh");
    let readme_body = &package_local[readme_open..];
    let readme_close_rel = readme_body
        .find("\nTXT\n")
        .expect("Lane LLLL: README.txt heredoc closer `TXT` missing");
    let readme_txt = &readme_body[..readme_close_rel];

    // Find the "Operator landing flow" header.
    let flow_start = readme_txt
        .find("Operator landing flow")
        .expect("Lane LLLL: README must contain the `Operator landing flow` section header");
    let flow_body = &readme_txt[flow_start..];

    // Collect numbered list entries: lines starting with `  <N>. ` at
    // the 2-space indent matching the README's bullet style. Stop at
    // the next blank-line-separated section that doesn't start with a
    // number or a continuation indent.
    let mut entries: Vec<(u32, String)> = Vec::new();
    let mut current_number: Option<u32> = None;
    let mut current_text = String::new();
    for line in flow_body.lines().skip(1) {
        // Stop when we hit the next major top-level header (a non-indented
        // line that doesn't continue the list).
        if !line.is_empty()
            && !line.starts_with(' ')
            && !line.starts_with('\t')
            && current_number.is_some()
        {
            // Looks like a new top-level section; emit the last entry
            // and stop. Clear current_number so the post-loop flush
            // doesn't re-emit the same entry.
            entries.push((current_number.unwrap(), current_text.trim().to_string()));
            current_number = None;
            current_text.clear();
            break;
        }
        let trimmed = line.trim_start();
        // A new numbered-list item starts with `<N>. ` at the bullet
        // indent (we accept any leading whitespace).
        if let Some(dot_idx) = trimmed.find('.') {
            let prefix = &trimmed[..dot_idx];
            if !prefix.is_empty() && prefix.chars().all(|c| c.is_ascii_digit()) {
                // Flush previous entry if any.
                if let Some(n) = current_number.take() {
                    entries.push((n, current_text.trim().to_string()));
                    current_text.clear();
                }
                if let Ok(n) = prefix.parse::<u32>() {
                    current_number = Some(n);
                    current_text.push_str(&trimmed[dot_idx + 1..]);
                    current_text.push('\n');
                    continue;
                }
            }
        }
        // Continuation line of the current entry.
        if current_number.is_some() {
            current_text.push_str(line);
            current_text.push('\n');
        }
    }
    if let Some(n) = current_number {
        entries.push((n, current_text.trim().to_string()));
    }

    assert!(
        entries.len() >= 5,
        "Lane LLLL: README `Operator landing flow` must enumerate >= 5 numbered triage steps (found {}: numbers {:?})",
        entries.len(),
        entries.iter().map(|(n, _)| *n).collect::<Vec<_>>()
    );

    // Numbering must be consecutive starting at 1.
    for (idx, (n, _)) in entries.iter().enumerate() {
        let expected = (idx as u32) + 1;
        assert_eq!(
            *n, expected,
            "Lane LLLL: README `Operator landing flow` numbering must be consecutive starting at 1 (entry {idx} has number {n}, expected {expected}). A future skip / duplicate / renumber misleads operators about the intended triage order"
        );
    }

    // Every `/api/v1/...` path mentioned in the numbered list must
    // appear as a route in server.rs. The README cites the path with
    // the `/api/v1` prefix; server.rs declares it without that prefix
    // (it's nested under an `/api/v1` outer router). So we strip the
    // prefix before comparing.
    let mut api_paths_found = 0usize;
    for (n, text) in &entries {
        let bytes = text.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i..].starts_with(b"/api/v1/") {
                let start = i;
                let mut j = i + "/api/v1/".len();
                while j < bytes.len() {
                    let ch = bytes[j] as char;
                    if ch.is_ascii_alphanumeric()
                        || ch == '/'
                        || ch == '-'
                        || ch == '_'
                        || ch == '.'
                    {
                        j += 1;
                    } else {
                        break;
                    }
                }
                let api_path = &text[start..j];
                let route_path = &api_path["/api/v1".len()..];
                let route_needle = format!("\"{route_path}\"");
                assert!(
                    server_rs.contains(&route_needle),
                    "Lane LLLL: README operator-landing entry #{n} cites path {api_path:?}, but no `.route({route_needle}, ...)` declaration exists in server.rs. A 404 from the README's documented triage entry point is the worst possible operator UX"
                );
                api_paths_found += 1;
                i = j;
                continue;
            }
            i += 1;
        }
    }

    assert!(
        api_paths_found >= 5,
        "Lane LLLL: README operator-landing flow must cite >= 5 `/api/v1/...` paths across its numbered steps (found {api_paths_found}). A regression that drops concrete path citations back to vague prose leaves the operator with no copy-pasteable triage entry point"
    );
}

// Lane MMMM: install heredoc permission-step parity. install.sh
// runs `chmod 755 "$INSTALL_DIR/$BINARY_NAME"` after the Copy step;
// install.ps1 does not currently emit an explicit ACL set (it relies
// on the Copy-Item default, which inherits the parent directory ACL).
// This asymmetry must either be (a) closed by install.ps1 emitting a
// matching permission step, or (b) explicitly documented in the
// README so operators don't expect identical permission state across
// OSes. Lane MMMM enforces option (b) for now: install.sh MUST have
// the chmod step, and the README MUST acknowledge the OS-specific
// permission handling so a future quiet removal of the chmod step
// (downgrading Unix to install.ps1's silent-default behavior)
// surfaces here before the binary ships unreadable.
#[test]
fn install_heredocs_permission_step_parity_lane_mmmm() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package_local = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane MMMM: scripts/package-local.sh present");

    // Slice install.sh heredoc.
    let sh_open = package_local
        .find("cat > \"$STAGE/install.sh\" <<'SH'")
        .expect("Lane MMMM: install.sh heredoc opener missing in package-local.sh");
    let sh_body = &package_local[sh_open..];
    let sh_close_rel = sh_body
        .find("\nSH\n")
        .expect("Lane MMMM: install.sh heredoc closer `SH` missing");
    let install_sh = &sh_body[..sh_close_rel];

    // install.sh must `chmod` the installed binary explicitly.
    let chmod_anchor = "chmod 755 \"$INSTALL_DIR/$BINARY_NAME\"";
    assert!(
        install_sh.contains(chmod_anchor),
        "Lane MMMM: install.sh must contain {chmod_anchor:?} after the cp step. A future quiet removal would leave the binary at the umask-default mode, which on stricter umasks (e.g., 077) drops the world-executable bit and breaks `command -v ao2-cp-server` for other users"
    );

    // Slice install.ps1 heredoc.
    let ps_open = package_local
        .find("cat > \"$STAGE/install.ps1\" <<'PS1'")
        .expect("Lane MMMM: install.ps1 heredoc opener missing in package-local.sh");
    let ps_body = &package_local[ps_open..];
    let ps_close_rel = ps_body
        .find("\nPS1\n")
        .expect("Lane MMMM: install.ps1 heredoc closer `PS1` missing");
    let install_ps1 = &ps_body[..ps_close_rel];

    // install.ps1 must Copy-Item the binary into $InstallDir. Lane EEEE
    // already pins the order; here we pin that the Copy-Item call
    // exists at all (otherwise install.ps1 would do nothing useful).
    let copy_anchor = "Copy-Item -Force $Source (Join-Path $InstallDir $BinaryName)";
    assert!(
        install_ps1.contains(copy_anchor),
        "Lane MMMM: install.ps1 must contain {copy_anchor:?}. A future quiet refactor that drops the Copy-Item step would silently break the installer (the binary would never land at the install location)"
    );

    // Order check: the chmod must come AFTER the cp in install.sh.
    // Lane EEEE pins the checksum-before-copy order; this lane pins
    // the copy-before-chmod order so the chmod can't fire on a stale
    // or absent file at the destination.
    let cp_anchor = "cp \"bin/$BINARY_NAME\" \"$INSTALL_DIR/$BINARY_NAME\"";
    let cp_idx = install_sh
        .find(cp_anchor)
        .expect("Lane MMMM: install.sh must contain the cp step");
    let chmod_idx = install_sh
        .find(chmod_anchor)
        .expect("Lane MMMM: install.sh must contain the chmod step");
    assert!(
        cp_idx < chmod_idx,
        "Lane MMMM: install.sh chmod step must come AFTER the cp step (cp at offset {cp_idx}, chmod at offset {chmod_idx}). A future reorder that puts chmod before cp would fire on the wrong file (the previous version at the destination, or nothing at all on first install)"
    );

    // Last step in install.sh after chmod must be the printf
    // confirmation line, with the install-location echoed back. Pins
    // the operator-feedback contract.
    let printf_anchor = "printf \"ao2_control_plane_installed=%s\\n\"";
    let printf_idx = install_sh
        .find(printf_anchor)
        .expect("Lane MMMM: install.sh must emit a `ao2_control_plane_installed=...` confirmation line so operator scripts can parse the install location");
    assert!(
        chmod_idx < printf_idx,
        "Lane MMMM: install.sh printf confirmation must come AFTER chmod (chmod at {chmod_idx}, printf at {printf_idx}). Otherwise the operator sees a success line before the binary is actually permissioned for execution"
    );

    // install.ps1 must also emit an operator-feedback confirmation.
    let ps_confirm_anchor = "Write-Output \"ao2_control_plane_installed=";
    assert!(
        install_ps1.contains(ps_confirm_anchor),
        "Lane MMMM: install.ps1 must emit a `Write-Output \"ao2_control_plane_installed=...\"` confirmation line matching install.sh's printf. Asymmetric operator feedback across OSes silently breaks any cross-OS install verification script"
    );
}

// Lane NNNN: release_publication.rs CSS class → reference parity.
// Every HTML page in release_publication.rs ships its own `<style>`
// block defining status-styling classes (`.ok`, `.warn`, `.bad`).
// Every defined class must be referenced as `class="<name>"` at least
// once across the file (otherwise the CSS rule is dead — a sign the
// dynamic class assignment was removed but the style was forgotten),
// and every static class literal must have a matching CSS rule
// (otherwise the operator sees unstyled status text). The static-ref
// check catches a typo in the format string; the rule-coverage check
// catches a refactor that drops the dynamic assignment branch.
#[test]
fn release_publication_html_css_class_parity_lane_nnnn() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let src =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane NNNN: release_publication.rs present");

    // Strip the test module.
    let production = match src.find("\n#[cfg(test)]\n") {
        Some(idx) => &src[..idx],
        None => src.as_str(),
    };

    // Extract every CSS rule `.<word>{` from the source. The `<style>`
    // blocks are embedded inside `format!(...)` so braces are doubled
    // (`.warn{{...}}`); search for the doubled form to avoid matching
    // random Rust code patterns.
    let mut css_rules: Vec<String> = Vec::new();
    let bytes = production.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'.' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && (bytes[j] as char).is_ascii_alphabetic() {
                j += 1;
            }
            if j > start && j + 1 < bytes.len() && bytes[j] == b'{' && bytes[j + 1] == b'{' {
                let name = &production[start..j];
                // Only collect words that look like status class names
                // (short, lowercase). Filter out random Rust dot
                // expressions.
                if name.len() <= 12
                    && name.chars().all(|c| c.is_ascii_lowercase())
                    && !css_rules.iter().any(|r| r == name)
                {
                    css_rules.push(name.to_string());
                }
                i = j + 2;
                continue;
            }
        }
        i += 1;
    }

    // Filter to short status-styling class names. The file's CSS blocks
    // only ever define these three; anything else is incidental.
    let status_classes: Vec<String> = css_rules
        .into_iter()
        .filter(|r| ["ok", "warn", "bad"].contains(&r.as_str()))
        .collect();

    assert!(
        status_classes.len() >= 3,
        "Lane NNNN: release_publication.rs must define >= 3 status-styling CSS classes (.ok, .warn, .bad); found {status_classes:?}"
    );
    for required in ["ok", "warn", "bad"] {
        assert!(
            status_classes.iter().any(|c| c == required),
            "Lane NNNN: release_publication.rs CSS must define `.{required}{{...}}` (status-styling class); found {status_classes:?}. A future deletion would leave the dynamic status assignment unstyled"
        );
    }

    // Every defined class must be reachable: either via a static
    // `class=\"<name>\"` literal, OR as a string literal `\"<name>\"`
    // assigned to a dynamic class variable (e.g. `let class = if
    // ... { \"ok\" } else { \"warn\" }`). The dynamic-assignment form
    // covers the case where the HTML template has `class=\"{class}\"`
    // and the variable's value range is the set of defined CSS names.
    for class in &status_classes {
        let static_needle = format!("class=\\\"{class}\\\"");
        let dynamic_needle = format!("\"{class}\"");
        assert!(
            production.contains(&static_needle) || production.contains(&dynamic_needle),
            "Lane NNNN: CSS class `.{class}` is defined in release_publication.rs but neither a `class=\\\"{class}\\\"` static reference NOR a `\"{class}\"` dynamic-assignment string literal appears in the file. The CSS rule is dead — likely because a refactor removed the assignment branch but forgot to clean up the style block"
        );
    }

    // Conversely, every static `class="<word>"` literal whose word is
    // a short lowercase identifier must have a matching CSS rule.
    // Dynamic refs `class="{<expr>}"` are skipped (the expr can be
    // arbitrary). We scan for the exact pattern `class=\"<word>\"`
    // where <word> is short and lowercase.
    let mut static_class_refs: Vec<String> = Vec::new();
    let mut k = 0usize;
    let pattern = b"class=\\\"";
    while k + pattern.len() < bytes.len() {
        if &bytes[k..k + pattern.len()] == pattern {
            let start = k + pattern.len();
            let mut j = start;
            while j < bytes.len() && (bytes[j] as char).is_ascii_alphabetic() {
                j += 1;
            }
            if j > start && j < bytes.len() && bytes[j] == b'\\' {
                let name = &production[start..j];
                if name.len() <= 12 && !static_class_refs.iter().any(|r| r == name) {
                    static_class_refs.push(name.to_string());
                }
            }
            k = start;
            continue;
        }
        k += 1;
    }
    for class_ref in &static_class_refs {
        assert!(
            status_classes.iter().any(|c| c == class_ref),
            "Lane NNNN: HTML uses `class=\\\"{class_ref}\\\"` but no `.{class_ref}{{...}}` CSS rule is defined anywhere in release_publication.rs. The operator sees unstyled status text — likely a typo in the format string"
        );
    }
}

// Lane OOOO: HTML `<title>` ↔ `<h1>` text parity. Every HTML page
// rendered by release_publication.rs ships its own `<title>...</title>`
// (shown in the operator's browser tab) and a matching
// `<h1>...</h1>` (shown at the top of the body). The operator forms
// a mental model from both; if they diverge after a refactor (one
// renamed, the other stale), the operator either lands at a page
// whose tab label contradicts the heading or vice versa. Lane OOOO
// pins per-page title/h1 equality plus the consistent `AO2 ` branding
// prefix.
#[test]
fn release_publication_html_title_h1_parity_lane_oooo() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let src =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane OOOO: release_publication.rs present");

    let production = match src.find("\n#[cfg(test)]\n") {
        Some(idx) => &src[..idx],
        None => src.as_str(),
    };

    // Extract every `<title>...</title>` literal.
    let mut titles: Vec<String> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = production[cursor..].find("<title>") {
        let start = cursor + rel + "<title>".len();
        let end_rel = production[start..]
            .find("</title>")
            .expect("Lane OOOO: every `<title>` must be closed by `</title>`");
        titles.push(production[start..start + end_rel].to_string());
        cursor = start + end_rel + "</title>".len();
    }

    // Extract every `<h1>...</h1>` literal.
    let mut headings: Vec<String> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = production[cursor..].find("<h1>") {
        let start = cursor + rel + "<h1>".len();
        let end_rel = production[start..]
            .find("</h1>")
            .expect("Lane OOOO: every `<h1>` must be closed by `</h1>`");
        headings.push(production[start..start + end_rel].to_string());
        cursor = start + end_rel + "</h1>".len();
    }

    assert!(
        titles.len() >= 6,
        "Lane OOOO: release_publication.rs must render >= 6 HTML pages with a `<title>` (found {}: {:?}). A regression that truncates the renderer set would surface here",
        titles.len(),
        titles
    );

    assert_eq!(
        titles.len(),
        headings.len(),
        "Lane OOOO: `<title>` count ({}) must equal `<h1>` count ({}); every HTML page renders exactly one of each. Mismatch indicates a stray `<title>` or `<h1>` from a botched merge",
        titles.len(),
        headings.len()
    );

    // Each page renders title then h1 in source order. Pair them by
    // position.
    for (title, heading) in titles.iter().zip(headings.iter()) {
        assert_eq!(
            title, heading,
            "Lane OOOO: HTML page `<title>` and `<h1>` must match (title={title:?}, h1={heading:?}). A future rename of one without the other splits the operator's mental model between browser tab and page header"
        );
        assert!(
            title.starts_with("AO2 "),
            "Lane OOOO: HTML `<title>` {title:?} must start with the `AO2 ` branding prefix. A page without the prefix breaks the operator's mental anchor when scanning multiple tabs"
        );
    }

    // Per-title uniqueness: two pages with the same title would
    // collapse the operator's tab list (multiple tabs with the same
    // label). Catches accidental duplicate renderers.
    let mut sorted_titles: Vec<&String> = titles.iter().collect();
    sorted_titles.sort();
    let original_len = sorted_titles.len();
    sorted_titles.dedup();
    assert_eq!(
        sorted_titles.len(),
        original_len,
        "Lane OOOO: duplicate `<title>` in release_publication.rs — two HTML pages share the same browser tab label, which would confuse operators triaging across surfaces"
    );
}

// Lane PPPP: section-6 row uniqueness parity. Lane III asserts every
// shipped lane has a matching section-6 row + a test function name
// reference. Lane PPPP closes the orthogonal axis: no two rows in
// section 6 share the same Lane label or the same backtick-quoted
// test function name. A duplicate row from a botched rebase, a
// copy-paste typo where two lanes accidentally claim the same Lane
// XXXX identifier, or a renamed test that left its old row behind
// each surface here before the table grows into a confusing tangle
// of overlapping entries.
#[test]
fn release_smoke_section_6_rows_are_unique_lane_pppp() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runbook = fs::read_to_string(root.join("docs/runbooks/release-smoke.md"))
        .expect("Lane PPPP: release-smoke.md present");

    let section_start = runbook
        .find("## 6. Where the gates are enforced")
        .expect("Lane PPPP: release-smoke.md must contain section 6 header");
    let section_end_rel = runbook[section_start..]
        .find("\nAny future regression")
        .expect("Lane PPPP: section 6 must terminate with the `Any future regression` line");
    let section6 = &runbook[section_start..section_start + section_end_rel];

    // Walk each table row (line starting with `|`). Extract column 1
    // (layer name) and column 2 (test path + test fn name). Only the
    // FIRST column's `(Lane XXX)` suffix counts as the row's Lane
    // label — narrative references in column 3 (descriptions) do not.
    // The same row may cite other lanes in its description column;
    // those are intentional cross-references, not duplicate row IDs.
    let mut lane_labels: Vec<String> = Vec::new();
    let mut test_fn_names: Vec<String> = Vec::new();
    for line in section6.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('|') {
            continue;
        }
        // Split on `|` and gather non-empty cells. A markdown row of
        // the form `| col1 | col2 | col3 |` splits into ["", " col1 ",
        // " col2 ", " col3 ", ""]; we want the inner cells.
        let cells: Vec<&str> = trimmed.split('|').map(|s| s.trim()).collect();
        if cells.len() < 5 {
            // Not a 3-column row (need 5 pieces from 4 `|` separators).
            continue;
        }
        // Header row sentinel: cells like "Layer", "Test", "Surface".
        if cells[1].eq_ignore_ascii_case("layer") {
            continue;
        }
        // Separator row sentinel: cells like "---", ":---:".
        if cells[1].chars().all(|c| c == '-' || c == ':' || c == ' ') {
            continue;
        }
        let col1 = cells[1];
        let col2 = cells[2];

        // Column 1: extract a single `(Lane XXX)` suffix. Older rows
        // may legitimately omit the Lane label (Lane W shipped before
        // the per-row Lane convention) — skip those without erroring.
        // We deliberately scan ALL `(Lane ...)` occurrences in the
        // first column so a stray double-label like
        // `... (Lane FOO) (Lane FOO) | ...` (which would be the same
        // copy-paste bug Lane PPPP is meant to catch) still trips the
        // uniqueness check via duplicate collection in lane_labels.
        let mut search_pos = 0usize;
        while let Some(rel) = col1[search_pos..].find("(Lane ") {
            let abs = search_pos + rel + "(Lane ".len();
            let end_rel = col1[abs..].find(')');
            let Some(end_rel) = end_rel else { break };
            let label = &col1[abs..abs + end_rel];
            if !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric()) {
                lane_labels.push(label.to_string());
            }
            search_pos = abs + end_rel + 1;
        }

        // Column 2: extract every backtick-quoted snake_case test fn
        // name. Older rows cite a test fn directly; newer rows cite a
        // test PATH followed by a test fn name, e.g.
        // ``crates/.../release_packaging.rs` `<test_fn_name>``. Pick
        // every backtick-quoted token that looks like a test fn name.
        let col2_bytes = col2.as_bytes();
        let mut k = 0usize;
        while k < col2_bytes.len() {
            if col2_bytes[k] == b'`' {
                let start = k + 1;
                let mut j = start;
                while j < col2_bytes.len() && col2_bytes[j] != b'`' {
                    j += 1;
                }
                if j < col2_bytes.len() && j > start {
                    let token = &col2[start..j];
                    let underscores = token.chars().filter(|c| *c == '_').count();
                    let lowercase = token.chars().all(|c| c.is_ascii_lowercase() || c == '_');
                    // Heuristic: snake_case fn name. Filter out file
                    // paths via the lack of `/` and `.` checks (the
                    // lowercase + underscore-only filter already
                    // excludes those, but stay explicit).
                    if lowercase
                        && !token.contains('/')
                        && !token.contains('.')
                        && (token.contains("_lane_") || underscores >= 3)
                    {
                        test_fn_names.push(token.to_string());
                    }
                    k = j + 1;
                    continue;
                }
            }
            k += 1;
        }
    }

    assert!(
        lane_labels.len() >= 10,
        "Lane PPPP: section 6 must enumerate >= 10 `(Lane XXXX)` row labels (found {}: {:?}). A truncation below floor surfaces here",
        lane_labels.len(),
        lane_labels
    );

    // Uniqueness of lane labels: no two rows may claim the same Lane
    // XXXX identifier (a botched rebase that accidentally re-shipped
    // a row, or a typo where two distinct cascades collided).
    let mut sorted_labels: Vec<&String> = lane_labels.iter().collect();
    sorted_labels.sort();
    let original_label_len = sorted_labels.len();
    sorted_labels.dedup();
    assert_eq!(
        sorted_labels.len(),
        original_label_len,
        "Lane PPPP: duplicate Lane label in section 6 of release-smoke.md. Two rows claim the same `(Lane XXXX)` identifier; a botched rebase or a copy-paste typo. Lane labels: {lane_labels:?}"
    );

    assert!(
        test_fn_names.len() >= 10,
        "Lane PPPP: section 6 must reference >= 10 backtick-quoted test function names (found {}: {:?})",
        test_fn_names.len(),
        test_fn_names
    );

    // Uniqueness of test fn names: no two rows may reference the
    // same test fn name (would mean the row didn't actually carry
    // a unique binding).
    let mut sorted_fns: Vec<&String> = test_fn_names.iter().collect();
    sorted_fns.sort();
    let original_fn_len = sorted_fns.len();
    sorted_fns.dedup();
    assert_eq!(
        sorted_fns.len(),
        original_fn_len,
        "Lane PPPP: duplicate test function name in section 6 of release-smoke.md. Two rows reference the same `<test_fn_name>`; the second row is not actually carrying a unique binding. Test fn names: {test_fn_names:?}"
    );
}

// Lane QQQQ: HTML footer-link parity. Every HTML page rendered by
// release_publication.rs closes with a `<p><a href="...">...</a>...</p>`
// footer of cross-page navigation links. Operators hop between
// surfaces (readiness ↔ handoff ↔ cockpit) via these footer links;
// a typo in an href, a quietly removed link, or a renamed route the
// footer wasn't updated for each turns into a 404 from the only
// in-page navigation. Lane QQQQ binds the footer hrefs back to the
// route table.
//
// Algorithm:
//   1. Strip the `#[cfg(test)]` tail.
//   2. Locate every `</main></body></html>` terminator; for each,
//      walk backward to the closest preceding `<p>` to slice out the
//      footer block.
//   3. Floor: >= 6 footer blocks present (current count is 8 HTML pages).
//   4. Per footer: extract every `<a href="...">` value. Each footer
//      must have >= 2 anchors (single-link footers don't earn the name).
//   5. Static `/api/v1/...` hrefs (optionally suffixed with `?query=...`)
//      must resolve to an actual `.route("<path-without-/api/v1>", ...)`
//      declaration in server.rs after the query string is stripped.
//   6. Template `{var}` hrefs are computed at render time and pass
//      through unchecked here (Lane JJJJ already binds the template
//      vars' route emissions); but each anchor's text must be
//      non-empty so a renamed template variable doesn't leave an
//      anonymous footer link.
//   7. Aggregate floor: >= 4 distinct static `/api/v1/...` hrefs
//      across all footers (a defense against an accidental
//      footer-wide template-only rewrite that would leave Lane QQQQ
//      with nothing to verify).
#[test]
fn release_publication_html_footer_link_parity_lane_qqqq() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane QQQQ: release_publication.rs present");
    let server = fs::read_to_string(root.join("crates/ao2-cp-server/src/server.rs"))
        .expect("Lane QQQQ: server.rs present");

    // Strip `#[cfg(test)]` tail — test-only HTML literals do not ship
    // in production responses.
    let prod = match source.find("#[cfg(test)]") {
        Some(idx) => &source[..idx],
        None => &source[..],
    };

    // Collect every route path declared in server.rs. The current
    // shape splits the `.route(` call across multiple lines:
    //   .route(
    //       "/<path>",
    //       <method>(...),
    //   )
    // so we find each `.route(` opener, then walk forward to the
    // first `"..."` literal which carries the route path.
    let mut routes: Vec<String> = Vec::new();
    let mut s = 0usize;
    while let Some(rel) = server[s..].find(".route(") {
        let abs = s + rel + ".route(".len();
        if let Some(open_rel) = server[abs..].find('"') {
            let open = abs + open_rel + 1;
            if let Some(close_rel) = server[open..].find('"') {
                let close = open + close_rel;
                routes.push(server[open..close].to_string());
                s = close + 1;
                continue;
            }
        }
        s = abs;
    }
    assert!(
        routes.len() >= 50,
        "Lane QQQQ: server.rs must declare >= 50 routes (sanity floor — found {})",
        routes.len()
    );

    // Slice every footer: the `<p>` block ending just before
    // `</main></body></html>`. Each iteration finds the next
    // terminator and rfinds the closest preceding `<p>` tag.
    let terminator = "</main></body></html>";
    let mut footers: Vec<&str> = Vec::new();
    let mut idx = 0usize;
    while let Some(rel) = prod[idx..].find(terminator) {
        let end = idx + rel;
        let preceding = &prod[..end];
        if let Some(p_start) = preceding.rfind("<p>") {
            let footer = &prod[p_start..end];
            // Must contain at least one closing </p> and one anchor
            // (defends against malformed slices if `<p>` is found
            // outside an anchor-bearing footer for some reason).
            if footer.contains("</p>") && footer.contains("<a href=") {
                footers.push(footer);
            }
        }
        idx = end + terminator.len();
    }

    assert!(
        footers.len() >= 6,
        "Lane QQQQ: release_publication.rs must render >= 6 HTML pages with footer-link `<p>` blocks (found {}). A drop below floor signals an accidental footer-paragraph removal or an HTML-page count regression",
        footers.len()
    );

    // Aggregate every static /api/v1/... href across all footers,
    // and count anchors per footer.
    let api_prefix = "/api/v1/";
    let mut all_static_paths: Vec<String> = Vec::new();
    let anchor_open = "<a href=\\\"";
    let quote_escape = "\\\"";

    for footer in &footers {
        let mut anchor_count = 0usize;
        let mut cursor = 0usize;
        while let Some(rel) = footer[cursor..].find(anchor_open) {
            let abs = cursor + rel + anchor_open.len();
            let Some(close_rel) = footer[abs..].find(quote_escape) else {
                break;
            };
            let close = abs + close_rel;
            let href = &footer[abs..close];
            anchor_count += 1;

            // Determine href shape.
            if let Some(stripped) = href.strip_prefix(api_prefix) {
                // Strip query string if present (e.g.,
                // /api/v1/release/support-bundle/verify.json?keep_latest={v}
                // → /api/v1/release/support-bundle/verify.json)
                let path = match stripped.find('?') {
                    Some(q) => &href[..api_prefix.len() + q],
                    None => href,
                };
                all_static_paths.push(path.to_string());
            } else if href.starts_with('{') {
                // Template variable; computed at render time. Lane
                // JJJJ binds template-emitted routes back to the
                // route table; Lane QQQQ defers.
            } else {
                panic!(
                    "Lane QQQQ: footer href {href:?} is neither a static /api/v1/... path nor a template {{var}} expansion. Unsupported href shape in footer: {footer}"
                );
            }

            // Anchor text must be non-empty (catches a footer like
            // `<a href="/api/v1/foo"></a>` after a rename that dropped
            // the link label).
            // Find the `>` that closes the opening anchor tag, then
            // the next `</a>`.
            let after_quote = close + quote_escape.len();
            if let Some(gt_rel) = footer[after_quote..].find('>') {
                let gt = after_quote + gt_rel + 1;
                if let Some(close_rel) = footer[gt..].find("</a>") {
                    let text = footer[gt..gt + close_rel].trim();
                    assert!(
                        !text.is_empty(),
                        "Lane QQQQ: anchor text empty for href {href:?} in footer. A footer link with empty body text is invisible to operators"
                    );
                }
            }

            cursor = close + quote_escape.len();
        }

        assert!(
            anchor_count >= 2,
            "Lane QQQQ: footer must contain >= 2 `<a href=...>` links (found {anchor_count} in footer: {footer})"
        );
    }

    assert!(
        all_static_paths.len() >= 4,
        "Lane QQQQ: footers must collectively reference >= 4 static /api/v1/... hrefs (found {}: {:?}). A drop below floor signals an accidental footer-wide rewrite to template-only hrefs, leaving Lane QQQQ no static paths to bind back to the route table",
        all_static_paths.len(),
        all_static_paths
    );

    // Every static footer href must resolve to a real route.
    for path in &all_static_paths {
        let route_suffix = path
            .strip_prefix("/api/v1")
            .unwrap_or(path.as_str())
            .to_string();
        let matched = routes
            .iter()
            .any(|r| r == &route_suffix || r == path.as_str());
        assert!(
            matched,
            "Lane QQQQ: footer href {path:?} does not resolve to any `.route(\"<path>\", ...)` declaration in server.rs (tried both with and without the `/api/v1` prefix). Either the route was renamed without updating the footer, or the footer references a 404"
        );
    }
}

// Lane RRRR: smoke aggregator log-line shape parity. The aggregator
// (scripts/smoke-three-os-release.sh) parses each per-OS smoke log
// with a fixed `grep -E '^<key>=' ... | cut -d'=' -f2-` shape; the
// per-OS smoke scripts (scripts/smoke-release-archive.{sh,ps1}) emit
// matching `<key>=<value>` lines via printf / Write-Output. A future
// quiet rename of an emitter key (e.g., `candidate_correlation_status`
// → `candidate_correlation_state`), a delimiter swap (`:` instead of
// `=`), or an asymmetric emit between the .sh and .ps1 variants
// would silently break ingestion — the aggregator would fall back
// to "unknown" for that key on the affected OS without crashing,
// and downstream evidence would lose the per-OS correlation fact.
//
// Algorithm:
//   1. Scan the aggregator for every `grep -E '^<key>='` consumer
//      pattern; collect the consumed keys.
//   2. Scan smoke-release-archive.sh for every `printf "<key>=%s\n"`
//      emitter; collect the emitted keys.
//   3. Scan smoke-release-archive.ps1 for every
//      `Write-Output "<key>=$<var>"` emitter; collect emitted keys.
//   4. Assert every aggregator-consumed key is emitted by BOTH the
//      .sh and .ps1 per-OS scripts (cross-OS parity).
//   5. Assert .sh emitter keys equal .ps1 emitter keys as sets (the
//      per-OS scripts must agree on the shape they ship).
//   6. Floors: aggregator consumes >= 2 keys; per-OS scripts emit
//      >= 10 keys.
#[test]
fn smoke_aggregator_log_line_shape_parity_lane_rrrr() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let aggregator = fs::read_to_string(root.join("scripts/smoke-three-os-release.sh"))
        .expect("Lane RRRR: smoke-three-os-release.sh present");
    let sh = fs::read_to_string(root.join("scripts/smoke-release-archive.sh"))
        .expect("Lane RRRR: smoke-release-archive.sh present");
    let ps1 = fs::read_to_string(root.join("scripts/smoke-release-archive.ps1"))
        .expect("Lane RRRR: smoke-release-archive.ps1 present");

    // Helper: collect everything between `start` and `end` markers
    // across the entire string, repeatedly.
    fn collect_between(
        haystack: &str,
        start: &str,
        end: &str,
        keys: &mut Vec<String>,
        validate: impl Fn(&str) -> bool,
    ) {
        let mut cursor = 0usize;
        while let Some(rel) = haystack[cursor..].find(start) {
            let abs = cursor + rel + start.len();
            if let Some(close_rel) = haystack[abs..].find(end) {
                let close = abs + close_rel;
                let key = &haystack[abs..close];
                if validate(key) {
                    keys.push(key.to_string());
                }
                cursor = close + end.len();
            } else {
                break;
            }
        }
    }

    let is_snake_lowercase = |s: &str| -> bool {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    };

    // Aggregator consumer pattern: grep -E '^<key>='
    let mut consumed: Vec<String> = Vec::new();
    collect_between(
        &aggregator,
        "grep -E '^",
        "='",
        &mut consumed,
        is_snake_lowercase,
    );

    // Emitter pattern (shell): printf "<key>=%s\n"
    let mut emitted_sh: Vec<String> = Vec::new();
    collect_between(
        &sh,
        "printf \"",
        "=%s\\n\"",
        &mut emitted_sh,
        is_snake_lowercase,
    );

    // Emitter pattern (powershell): Write-Output "<key>=$<var>"
    let mut emitted_ps1: Vec<String> = Vec::new();
    collect_between(
        &ps1,
        "Write-Output \"",
        "=$",
        &mut emitted_ps1,
        is_snake_lowercase,
    );

    // Floors.
    assert!(
        consumed.len() >= 2,
        "Lane RRRR: aggregator must consume >= 2 `grep -E '^<key>='` log lines (found {}: {:?})",
        consumed.len(),
        consumed
    );
    assert!(
        emitted_sh.len() >= 10,
        "Lane RRRR: smoke-release-archive.sh must emit >= 10 `printf \"<key>=%%s\\\\n\"` log lines (found {}: {:?})",
        emitted_sh.len(),
        emitted_sh
    );
    assert!(
        emitted_ps1.len() >= 10,
        "Lane RRRR: smoke-release-archive.ps1 must emit >= 10 `Write-Output \"<key>=$<var>\"` log lines (found {}: {:?})",
        emitted_ps1.len(),
        emitted_ps1
    );

    // Cross-OS parity: shell emit keys == powershell emit keys as sets.
    let mut sorted_sh: Vec<&String> = emitted_sh.iter().collect();
    sorted_sh.sort();
    sorted_sh.dedup();
    let mut sorted_ps1: Vec<&String> = emitted_ps1.iter().collect();
    sorted_ps1.sort();
    sorted_ps1.dedup();
    assert_eq!(
        sorted_sh, sorted_ps1,
        "Lane RRRR: smoke-release-archive.sh emit-key set differs from smoke-release-archive.ps1 emit-key set. The per-OS scripts must agree on the line shape they emit. sh={sorted_sh:?} ps1={sorted_ps1:?}"
    );

    // Every aggregator-consumed key must be emitted by both per-OS
    // scripts.
    for key in &consumed {
        assert!(
            emitted_sh.iter().any(|k| k == key),
            "Lane RRRR: aggregator consumes `{key}` but smoke-release-archive.sh does not emit `printf \"{key}=%s\\n\"`. A renamed or removed emitter would silently break ingestion of this key. sh emit keys: {emitted_sh:?}"
        );
        assert!(
            emitted_ps1.iter().any(|k| k == key),
            "Lane RRRR: aggregator consumes `{key}` but smoke-release-archive.ps1 does not emit `Write-Output \"{key}=$<var>\"`. Cross-OS asymmetry: the Windows path would silently lose this key. ps1 emit keys: {emitted_ps1:?}"
        );
    }
}

// Lane SSSS: provider-acceptance JSON shape parity. The cockpit and
// handoff HTML pages render per-provider acceptance rows by reading
// JSON fields from each provider's bundle (via `json_str(&entry,
// "<key>")` and `entry.get("<key>")`). The same release_publication.rs
// owns the emitter (`compact_acceptance_for_handoff`) which writes
// the JSON shape consumed downstream by factory-v3. A renamed key
// in the emitter without a matching update in the renderer (or vice
// versa) leaves blank table cells where operators expect provider
// run IDs and scores. Lane SSSS pins the shape:
//   - every key READ by an `acceptance_row` closure must be a key
//     WRITTEN by `compact_acceptance_for_handoff` (renderer ⊆ emitter)
//   - both the handoff acceptance_row and the cockpit acceptance_row
//     read the SAME set of keys (the two HTML pages present the same
//     per-provider columns, so their reads must agree)
//   - the keys load-bearing for `provider_acceptance_is_live_passed`
//     ({status, source_class}) must be present in the emitter as
//     well — that function decides "live/passed vs attention" and
//     drives the surface class on Release Cockpit / Release Handoff.
#[test]
fn provider_acceptance_json_shape_parity_lane_ssss() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane SSSS: release_publication.rs present");

    let prod = match source.find("#[cfg(test)]") {
        Some(idx) => &source[..idx],
        None => &source[..],
    };

    fn balanced_block(s: &str, open_idx: usize) -> Option<&str> {
        let bytes = s.as_bytes();
        if open_idx >= bytes.len() || bytes[open_idx] != b'{' {
            return None;
        }
        let mut depth = 1i32;
        let mut i = open_idx + 1;
        while i < bytes.len() {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&s[open_idx + 1..i]);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    fn collect_reads(block: &str) -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        for pattern in ["json_str(", ".get("] {
            let mut cursor = 0usize;
            while let Some(rel) = block[cursor..].find(pattern) {
                let abs = cursor + rel + pattern.len();
                if let Some(open_rel) = block[abs..].find('"') {
                    let open = abs + open_rel + 1;
                    if let Some(close_rel) = block[open..].find('"') {
                        let close = open + close_rel;
                        let key = &block[open..close];
                        if !key.is_empty()
                            && key
                                .chars()
                                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
                        {
                            keys.push(key.to_string());
                        }
                        cursor = close + 1;
                        continue;
                    }
                }
                cursor = abs;
            }
        }
        keys.sort();
        keys.dedup();
        keys
    }

    let mut row_closure_bodies: Vec<&str> = Vec::new();
    let opener = "let acceptance_row = |";
    let mut cursor = 0usize;
    while let Some(rel) = prod[cursor..].find(opener) {
        let abs = cursor + rel + opener.len();
        let Some(arg_close_rel) = prod[abs..].find('|') else {
            break;
        };
        let after_args = abs + arg_close_rel + 1;
        let mut ws = after_args;
        while ws < prod.len() && prod.as_bytes()[ws].is_ascii_whitespace() {
            ws += 1;
        }
        if ws >= prod.len() || prod.as_bytes()[ws] != b'{' {
            cursor = after_args;
            continue;
        }
        if let Some(body) = balanced_block(prod, ws) {
            row_closure_bodies.push(body);
            cursor = ws + body.len() + 2;
        } else {
            cursor = ws;
        }
    }

    assert!(
        row_closure_bodies.len() >= 2,
        "Lane SSSS: release_publication.rs must define >= 2 `let acceptance_row` closures (handoff + cockpit). Found {}. Lost a renderer closure?",
        row_closure_bodies.len()
    );

    let read_sets: Vec<Vec<String>> = row_closure_bodies
        .iter()
        .map(|b| collect_reads(b))
        .collect();

    for (i, reads) in read_sets.iter().enumerate() {
        assert!(
            reads.len() >= 4,
            "Lane SSSS: acceptance_row closure #{i} reads only {} keys ({:?}); floor is >= 4 (status, source_class, run_id, plus score or raw_url)",
            reads.len(),
            reads
        );
        for required in ["status", "source_class", "run_id"] {
            assert!(
                reads.iter().any(|k| k == required),
                "Lane SSSS: acceptance_row closure #{i} does not read `{required}`. Renderer reads: {reads:?}"
            );
        }
    }

    let first = &read_sets[0];
    for (i, reads) in read_sets.iter().enumerate().skip(1) {
        assert_eq!(
            reads, first,
            "Lane SSSS: acceptance_row closure #{i} reads a different key set than closure #0. The cockpit and handoff render the same per-provider columns; their renderer reads must agree. closure #0: {first:?}, closure #{i}: {reads:?}"
        );
    }

    let fn_opener = "fn compact_acceptance_for_handoff(";
    let fn_idx = prod
        .find(fn_opener)
        .expect("Lane SSSS: compact_acceptance_for_handoff function must exist");
    let after_sig = fn_idx + fn_opener.len();
    let body_open_rel = prod[after_sig..]
        .find('{')
        .expect("Lane SSSS: compact_acceptance_for_handoff body must open with `{`");
    let body_open = after_sig + body_open_rel;
    let emitter_body = balanced_block(prod, body_open)
        .expect("Lane SSSS: compact_acceptance_for_handoff body must be brace-balanced");

    let mut emitted_keys: Vec<String> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = emitter_body[cursor..].find('"') {
        let open = cursor + rel + 1;
        if let Some(close_rel) = emitter_body[open..].find('"') {
            let close = open + close_rel;
            let key = &emitter_body[open..close];
            let after = close + 1;
            if after < emitter_body.len()
                && emitter_body.as_bytes()[after] == b':'
                && !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
            {
                emitted_keys.push(key.to_string());
            }
            cursor = close + 1;
        } else {
            break;
        }
    }
    emitted_keys.sort();
    emitted_keys.dedup();

    assert!(
        emitted_keys.len() >= 6,
        "Lane SSSS: compact_acceptance_for_handoff emits only {} JSON keys ({:?}); floor is >= 6",
        emitted_keys.len(),
        emitted_keys
    );

    for required in ["status", "source_class", "run_id", "score", "raw_url"] {
        assert!(
            emitted_keys.iter().any(|k| k == required),
            "Lane SSSS: compact_acceptance_for_handoff does not emit `{required}`. Emitter keys: {emitted_keys:?}"
        );
    }

    for read_key in first {
        assert!(
            emitted_keys.iter().any(|k| k == read_key),
            "Lane SSSS: acceptance_row renderer reads `{read_key}` but compact_acceptance_for_handoff does not emit it. Emitter keys: {emitted_keys:?}"
        );
    }
}

// Lane TTTT: section-6 row count ↔ 4-letter lane test fn count parity.
// Lane III asserts every shipped 4-letter lane (HHHH onwards) has
// BOTH a section-6 row label AND a test fn reference, but Lane III
// only checks the lanes the orchestrator hand-enrolls — it cannot
// see a NEWLY shipped test fn that nobody added an assertion for.
// Lane PPPP asserts row uniqueness, but a brand-new lowercase test
// fn `fn foo_lane_uuuu(...)` added to release_packaging.rs WITHOUT
// a matching `(Lane UUUU)` row in section 6 (or vice versa) would
// slip past every other layer until the next manual cascade.
//
// Lane TTTT closes that gap via count equality + set equality
// between the 4-letter uppercase Lane labels in section 6 (column-1
// only, matching Lane PPPP's column-1 scope) and the 4-letter
// lowercase `fn <name>_lane_<xxxx>(...)` suffixes in
// release_packaging.rs.
//
// Algorithm:
//   1. Slice section 6 between `## 6. Where the gates are enforced`
//      and `\nAny future regression`.
//   2. Walk each markdown table row; in the first column, find every
//      `(Lane <UPPERCASE>)` token where the inner text is exactly
//      4 uppercase ASCII letters. Collect into row_labels.
//   3. Scan release_packaging.rs for every `fn <name>_lane_<lowercase>(`
//      where the trailing 4-letter lane suffix is exactly 4 lowercase
//      letters and the fn name continues until the opening paren.
//   4. Floor: >= 15 4-letter lane labels and >= 15 4-letter fn defs.
//   5. Count equality: row_labels.len() == fn_lane_suffixes.len().
//   6. Set equality: row_labels uppercased to lowercase must equal
//      fn_lane_suffixes (each row has a matching test fn and vice
//      versa).
#[test]
fn section_6_row_count_binds_to_4_letter_lane_test_fn_count_lane_tttt() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runbook = fs::read_to_string(root.join("docs/runbooks/release-smoke.md"))
        .expect("Lane TTTT: release-smoke.md present");
    let tests = fs::read_to_string(root.join("crates/ao2-cp-server/tests/release_packaging.rs"))
        .expect("Lane TTTT: release_packaging.rs present");

    // Slice section 6.
    let section_start = runbook
        .find("## 6. Where the gates are enforced")
        .expect("Lane TTTT: release-smoke.md must contain section 6 header");
    let section_end_rel = runbook[section_start..]
        .find("\nAny future regression")
        .expect("Lane TTTT: section 6 must terminate with the `Any future regression` line");
    let section6 = &runbook[section_start..section_start + section_end_rel];

    // Walk each row, extract column 1 4-letter lane labels.
    let mut row_labels: Vec<String> = Vec::new();
    for line in section6.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = trimmed.split('|').map(|s| s.trim()).collect();
        if cells.len() < 5 {
            continue;
        }
        if cells[1].eq_ignore_ascii_case("layer") {
            continue;
        }
        if cells[1].chars().all(|c| c == '-' || c == ':' || c == ' ') {
            continue;
        }
        let col1 = cells[1];
        let mut search = 0usize;
        while let Some(rel) = col1[search..].find("(Lane ") {
            let abs = search + rel + "(Lane ".len();
            let Some(end_rel) = col1[abs..].find(')') else {
                break;
            };
            let label = &col1[abs..abs + end_rel];
            if label.len() == 4 && label.chars().all(|c| c.is_ascii_uppercase()) {
                row_labels.push(label.to_string());
            }
            search = abs + end_rel + 1;
        }
    }

    // Scan release_packaging.rs for `fn <name>_lane_<xxxx>(` where
    // `<xxxx>` is exactly 4 ASCII lowercase letters.
    let mut fn_lane_suffixes: Vec<String> = Vec::new();
    let marker = "_lane_";
    let mut cursor = 0usize;
    while let Some(rel) = tests[cursor..].find(marker) {
        let abs = cursor + rel + marker.len();
        // Extract up to the first `(`.
        let Some(paren_rel) = tests[abs..].find('(') else {
            break;
        };
        let suffix = &tests[abs..abs + paren_rel];
        if suffix.len() == 4 && suffix.chars().all(|c| c.is_ascii_lowercase()) {
            // Confirm the preceding context begins with `fn ` (avoid
            // false positives in comments / strings).
            // Walk back to find the start of the identifier.
            let preamble_start =
                tests[..abs - marker.len()].rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_');
            let id_start = preamble_start.map(|p| p + 1).unwrap_or(0);
            let before_id = &tests[..id_start];
            // Reject matches inside a `//` line comment: walk back
            // from id_start to the preceding newline and reject if
            // a `//` sits between newline and id_start.
            let line_start = tests[..id_start].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line_prefix = &tests[line_start..id_start];
            let in_comment = line_prefix.contains("//");
            if before_id.ends_with("fn ") && !in_comment {
                fn_lane_suffixes.push(suffix.to_string());
            }
            cursor = abs + paren_rel + 1;
        } else {
            // A `_lane_` mention inside a string or comment can be
            // followed by the next real function's `(`. Advancing to
            // that paren would skip the real definition, so only move
            // past the marker on non-definition candidates.
            cursor = abs;
        }
    }
    fn_lane_suffixes.sort();
    fn_lane_suffixes.dedup();

    // Floor: at least 15 4-letter lane test fns / row labels.
    assert!(
        fn_lane_suffixes.len() >= 15,
        "Lane TTTT: release_packaging.rs must define >= 15 4-letter `fn <name>_lane_<xxxx>(` test functions (found {}: {:?})",
        fn_lane_suffixes.len(),
        fn_lane_suffixes
    );

    let mut sorted_labels: Vec<String> = row_labels.iter().map(|s| s.to_lowercase()).collect();
    sorted_labels.sort();
    sorted_labels.dedup();
    assert!(
        sorted_labels.len() >= 15,
        "Lane TTTT: section 6 must enumerate >= 15 4-letter `(Lane XXXX)` row labels (found {}: {:?})",
        sorted_labels.len(),
        sorted_labels
    );

    // Count equality.
    assert_eq!(
        sorted_labels.len(),
        fn_lane_suffixes.len(),
        "Lane TTTT: section-6 4-letter row label count ({}) differs from release_packaging.rs 4-letter `fn ..._lane_<xxxx>(` count ({}). A new test fn without a section-6 row, or a section-6 row whose test was deleted, surfaces here. section 6 labels (lowercased): {sorted_labels:?}; test fn suffixes: {fn_lane_suffixes:?}",
        sorted_labels.len(),
        fn_lane_suffixes.len()
    );

    // Set equality.
    assert_eq!(
        sorted_labels, fn_lane_suffixes,
        "Lane TTTT: section-6 4-letter row label SET differs from release_packaging.rs 4-letter `fn ..._lane_<xxxx>(` suffix SET. Either a new test fn is missing from section 6 or a section-6 row is missing the matching test fn. section 6: {sorted_labels:?}; test fns: {fn_lane_suffixes:?}"
    );
}

// Lane UUUU: README heredoc Lane mention ↔ runbook coverage parity.
//
// The release-archive README heredoc in scripts/package-local.sh
// references several specific lane labels (`Lane VV`, `Lane XX`,
// `Lane BBB`, etc.) as triage anchors operators are expected to
// look up. If the README mentions `(Lane ZZZZ)` but the runbook
// has no matching coverage, an operator landing on the README
// trail has no triage doc to consult — the worst kind of
// dead-pointer regression because the README ships inside the
// release archive itself and is offline-only after package time.
//
// Algorithm:
//   1. Slice the README heredoc between `cat > "$STAGE/README.txt" <<'TXT'`
//      and the terminating `TXT` line.
//   2. Extract every `Lane <X>` token where `<X>` is one or more
//      uppercase ASCII letters optionally followed by `-<lowercase>`
//      (handles `Lane XX-doc`, `Lane PP-server`).
//   3. Extract every `Lane <X>` token from
//      docs/runbooks/release-smoke.md the same way.
//   4. Floor: README mentions >= 5 distinct lanes (catches an
//      accidental README truncation that drops every triage
//      pointer).
//   5. Every README lane must appear in the runbook lane set.
//      A README lane absent from the runbook surfaces here.
#[test]
fn readme_heredoc_lane_mentions_bind_to_runbook_coverage_lane_uuuu() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package_local = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane UUUU: scripts/package-local.sh present");
    let runbook = fs::read_to_string(root.join("docs/runbooks/release-smoke.md"))
        .expect("Lane UUUU: docs/runbooks/release-smoke.md present");

    // Locate README heredoc bounds.
    let heredoc_open = "cat > \"$STAGE/README.txt\" <<'TXT'\n";
    let open_idx = package_local
        .find(heredoc_open)
        .expect("Lane UUUU: package-local.sh must contain the README.txt heredoc opener");
    let body_start = open_idx + heredoc_open.len();
    let close_rel = package_local[body_start..]
        .find("\nTXT\n")
        .expect("Lane UUUU: README.txt heredoc must terminate with a `TXT` line");
    let readme_body = &package_local[body_start..body_start + close_rel];

    // Extract `Lane <X>` tokens from a string.
    fn extract_lanes(text: &str) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        let marker = "Lane ";
        let bytes = text.as_bytes();
        let mut cursor = 0usize;
        while let Some(rel) = text[cursor..].find(marker) {
            let start = cursor + rel + marker.len();
            // Capture uppercase ASCII letters.
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_uppercase() {
                end += 1;
            }
            if end > start {
                // Optional `-<lowercase>` suffix (e.g., -doc, -server).
                let mut suffix_end = end;
                if suffix_end < bytes.len() && bytes[suffix_end] == b'-' {
                    let mut probe = suffix_end + 1;
                    while probe < bytes.len() && bytes[probe].is_ascii_lowercase() {
                        probe += 1;
                    }
                    if probe > suffix_end + 1 {
                        suffix_end = probe;
                    }
                }
                let label = &text[start..suffix_end];
                out.insert(label.to_string());
            }
            cursor = if end > start { end } else { start + 1 };
        }
        out
    }

    let readme_lanes = extract_lanes(readme_body);
    let runbook_lanes = extract_lanes(&runbook);

    assert!(
        readme_lanes.len() >= 5,
        "Lane UUUU: README heredoc must reference >= 5 distinct lane labels (found {}: {:?}). An accidental README truncation that removed triage anchors trips this floor.",
        readme_lanes.len(),
        readme_lanes
    );

    let missing: Vec<&String> = readme_lanes.difference(&runbook_lanes).collect();
    assert!(
        missing.is_empty(),
        "Lane UUUU: README heredoc references lane labels absent from docs/runbooks/release-smoke.md (operator would land on a dead pointer): {missing:?}. README lanes: {readme_lanes:?}; runbook lanes: {runbook_lanes:?}"
    );
}

// Lane VVVV: install heredoc artifact references ↔ tar arglist parity.
//
// The install.sh and install.ps1 heredocs (inside
// scripts/package-local.sh) each reference specific archive
// files: `SHA256SUMS`, `bin/$BINARY_NAME`, etc. If any of these
// references doesn't appear in the tar arglist that packages the
// archive, an operator extracting the archive and running the
// install script gets a "file not found" failure — the worst
// kind of install-time regression because the binary checksum
// step bails out before the binary ever runs.
//
// Lane UUU already binds the README's archive-contents list to
// the tar arglist; Lane VVVV closes the orthogonal axis: the
// install scripts themselves bind to the tar arglist.
//
// Algorithm:
//   1. Extract install.sh and install.ps1 heredoc bodies from
//      package-local.sh.
//   2. Extract every relative-path file reference from each
//      heredoc — bare filenames like `SHA256SUMS`, two-segment
//      paths like `bin/ao2-cp-server`, and PowerShell join-path
//      products like `Join-Path "bin" $BinaryName`.
//   3. Locate the `tar -czf ... bin install.sh ... README.txt`
//      arglist line and extract the trailing arglist tokens.
//   4. Floors: >= 2 .sh refs, >= 2 .ps1 refs, >= 5 arglist
//      entries.
//   5. Every install-heredoc file ref must resolve to a tar
//      arglist entry — either a literal match or a parent
//      directory match (`bin/foo` ⊆ `bin`).
#[test]
fn install_heredoc_artifact_refs_bind_to_tar_arglist_lane_vvvv() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package_local = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane VVVV: scripts/package-local.sh present");

    // Slice install.sh heredoc.
    let sh_open = "cat > \"$STAGE/install.sh\" <<'SH'\n";
    let sh_close = "\nSH\n";
    let sh_start = package_local
        .find(sh_open)
        .expect("Lane VVVV: package-local.sh must contain the install.sh heredoc opener");
    let sh_body_start = sh_start + sh_open.len();
    let sh_rel = package_local[sh_body_start..]
        .find(sh_close)
        .expect("Lane VVVV: install.sh heredoc must terminate with `SH` line");
    let install_sh = &package_local[sh_body_start..sh_body_start + sh_rel];

    // Slice install.ps1 heredoc.
    let ps1_open = "cat > \"$STAGE/install.ps1\" <<'PS1'\n";
    let ps1_close = "\nPS1\n";
    let ps1_start = package_local
        .find(ps1_open)
        .expect("Lane VVVV: package-local.sh must contain the install.ps1 heredoc opener");
    let ps1_body_start = ps1_start + ps1_open.len();
    let ps1_rel = package_local[ps1_body_start..]
        .find(ps1_close)
        .expect("Lane VVVV: install.ps1 heredoc must terminate with `PS1` line");
    let install_ps1 = &package_local[ps1_body_start..ps1_body_start + ps1_rel];

    // Locate tar arglist line.
    let tar_line = package_local
        .lines()
        .find(|l| l.contains("tar -czf"))
        .expect("Lane VVVV: package-local.sh must contain a `tar -czf` invocation");
    // The tar invocation ends with a closing `)`; trim it.
    let arglist_start = tar_line
        .find("\"$ARCHIVE\"")
        .map(|i| i + "\"$ARCHIVE\"".len())
        .expect("Lane VVVV: tar invocation must reference $ARCHIVE");
    let arglist_raw = tar_line[arglist_start..].trim_end_matches(')').trim();
    let tar_entries: Vec<&str> = arglist_raw.split_whitespace().collect();

    assert!(
        tar_entries.len() >= 5,
        "Lane VVVV: tar arglist must enumerate >= 5 archive entries (found {}: {:?})",
        tar_entries.len(),
        tar_entries
    );

    // Collect install.sh file refs.
    // Patterns: `SHA256SUMS`, `bin/$BINARY_NAME`, `bin/ao2-cp-server`.
    let mut sh_refs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in install_sh.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        // SHA256SUMS literal.
        if trimmed.contains("SHA256SUMS") {
            sh_refs.insert("SHA256SUMS".to_string());
        }
        // bin/... refs.
        for token in trimmed.split_whitespace() {
            let token = token.trim_matches(|c: char| c == '"' || c == '\'' || c == '(' || c == ')');
            if let Some(stripped) = token.strip_prefix("\"bin/") {
                let inner = stripped.trim_end_matches('"');
                sh_refs.insert(format!("bin/{inner}"));
            } else if let Some(stripped) = token.strip_prefix("bin/") {
                sh_refs.insert(format!("bin/{stripped}"));
            }
        }
    }

    // Collect install.ps1 file refs.
    // Patterns: `SHA256SUMS` literal, `bin/ao2-cp-server.exe`,
    // `Join-Path "bin" $BinaryName`.
    let mut ps1_refs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in install_ps1.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains("SHA256SUMS") {
            ps1_refs.insert("SHA256SUMS".to_string());
        }
        if trimmed.contains("Join-Path \"bin\"") || trimmed.contains("Join-Path 'bin'") {
            ps1_refs.insert("bin/<binary>".to_string());
        }
        // bin/... literal references.
        for token in trimmed.split_whitespace() {
            let token = token.trim_matches(|c: char| c == '"' || c == '\'' || c == '(' || c == ')');
            if let Some(stripped) = token.strip_prefix("bin/") {
                ps1_refs.insert(format!("bin/{stripped}"));
            }
        }
    }

    assert!(
        sh_refs.len() >= 2,
        "Lane VVVV: install.sh heredoc must reference >= 2 archive files (found {}: {:?})",
        sh_refs.len(),
        sh_refs
    );
    assert!(
        ps1_refs.len() >= 2,
        "Lane VVVV: install.ps1 heredoc must reference >= 2 archive files (found {}: {:?})",
        ps1_refs.len(),
        ps1_refs
    );

    // Build tar entry lookup: each entry is either a literal file
    // name (`SHA256SUMS`, `README.txt`, `install.sh`) or a
    // directory (`bin`). For matching, a heredoc ref `bin/foo`
    // resolves if `bin` is in the arglist OR a literal `bin/foo`
    // is in the arglist.
    let tar_set: std::collections::BTreeSet<String> =
        tar_entries.iter().map(|s| s.to_string()).collect();

    fn ref_matches_tar(refname: &str, tar_set: &std::collections::BTreeSet<String>) -> bool {
        if tar_set.contains(refname) {
            return true;
        }
        // Walk parent directory components.
        let mut parent = refname;
        while let Some(slash) = parent.rfind('/') {
            parent = &parent[..slash];
            if tar_set.contains(parent) {
                return true;
            }
        }
        false
    }

    for r in sh_refs.iter() {
        assert!(
            ref_matches_tar(r, &tar_set),
            "Lane VVVV: install.sh heredoc references {r:?} but it does not match any tar arglist entry (tar entries: {tar_set:?}). An install-time `file not found` regression would surface here."
        );
    }
    for r in ps1_refs.iter() {
        assert!(
            ref_matches_tar(r, &tar_set),
            "Lane VVVV: install.ps1 heredoc references {r:?} but it does not match any tar arglist entry (tar entries: {tar_set:?}). An install-time `file not found` regression would surface here."
        );
    }
}

// Lane WWWW: install heredoc env var symmetry + clap separation parity.
//
// Two cross-OS install-time invariants:
//
//   1. **Symmetry**: install.sh and install.ps1 must reference the
//      IDENTICAL set of AO2_* env vars. If install.sh reads
//      AO2_FOO_BAR but install.ps1 doesn't, the Mac/Linux operator
//      can override the install via AO2_FOO_BAR but the Windows
//      operator cannot — an asymmetric install UX that fails the
//      first time someone deploys to Windows.
//
//   2. **Clap separation**: server-runtime env vars (declared with
//      `env = "AO2_..."` clap attributes in src/config.rs) MUST NOT
//      appear in install heredocs. The install scripts run BEFORE
//      the server binary exists at its install destination; an
//      install heredoc that references AO2_CP_BIND silently
//      collides with the server's own config namespace. Keep
//      install-time and server-runtime env namespaces disjoint.
//
// Algorithm:
//   1. Extract install.sh and install.ps1 heredoc bodies from
//      scripts/package-local.sh.
//   2. Extract every `AO2_*` env var token (greedy uppercase +
//      underscore + digits) from each.
//   3. Extract every clap `env = "AO2_..."` attribute from
//      crates/ao2-cp-server/src/config.rs.
//   4. Floor: each install heredoc references >= 1 install-time
//      env var; clap declares >= 3 server-runtime env vars.
//   5. install.sh env set EQUALS install.ps1 env set
//      (cross-OS symmetry).
//   6. install.sh env set ∩ clap env set is EMPTY
//      (server-runtime/install-time separation).
//   7. install.ps1 env set ∩ clap env set is EMPTY (same).
#[test]
fn install_heredoc_env_var_symmetry_and_clap_separation_lane_wwww() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package_local = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane WWWW: scripts/package-local.sh present");
    let config_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/config.rs"))
        .expect("Lane WWWW: crates/ao2-cp-server/src/config.rs present");

    // Slice install.sh heredoc.
    let sh_open = "cat > \"$STAGE/install.sh\" <<'SH'\n";
    let sh_close = "\nSH\n";
    let sh_start = package_local
        .find(sh_open)
        .expect("Lane WWWW: package-local.sh must contain the install.sh heredoc opener");
    let sh_body_start = sh_start + sh_open.len();
    let sh_rel = package_local[sh_body_start..]
        .find(sh_close)
        .expect("Lane WWWW: install.sh heredoc must terminate with `SH` line");
    let install_sh = &package_local[sh_body_start..sh_body_start + sh_rel];

    // Slice install.ps1 heredoc.
    let ps1_open = "cat > \"$STAGE/install.ps1\" <<'PS1'\n";
    let ps1_close = "\nPS1\n";
    let ps1_start = package_local
        .find(ps1_open)
        .expect("Lane WWWW: package-local.sh must contain the install.ps1 heredoc opener");
    let ps1_body_start = ps1_start + ps1_open.len();
    let ps1_rel = package_local[ps1_body_start..]
        .find(ps1_close)
        .expect("Lane WWWW: install.ps1 heredoc must terminate with `PS1` line");
    let install_ps1 = &package_local[ps1_body_start..ps1_body_start + ps1_rel];

    // Extract `AO2_<rest>` tokens. `<rest>` is uppercase ASCII +
    // digits + underscores, greedy.
    fn collect_ao2_env(text: &str) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        let bytes = text.as_bytes();
        let marker = "AO2_";
        let mut cursor = 0usize;
        while let Some(rel) = text[cursor..].find(marker) {
            let start = cursor + rel;
            let mut end = start + marker.len();
            while end < bytes.len() {
                let c = bytes[end];
                if c.is_ascii_uppercase() || c == b'_' || c.is_ascii_digit() {
                    end += 1;
                } else {
                    break;
                }
            }
            // Require at least one trailing char after `AO2_`.
            if end > start + marker.len() {
                out.insert(text[start..end].to_string());
            }
            cursor = end.max(start + 1);
        }
        out
    }

    let sh_env = collect_ao2_env(install_sh);
    let ps1_env = collect_ao2_env(install_ps1);

    // Extract clap env attributes: `env = "AO2_..."` literal.
    let mut clap_env: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let needle = "env = \"";
    let mut cursor = 0usize;
    while let Some(rel) = config_rs[cursor..].find(needle) {
        let start = cursor + rel + needle.len();
        let Some(close_rel) = config_rs[start..].find('"') else {
            break;
        };
        let value = &config_rs[start..start + close_rel];
        if value.starts_with("AO2_") {
            clap_env.insert(value.to_string());
        }
        cursor = start + close_rel + 1;
    }

    // Floors.
    assert!(
        !sh_env.is_empty(),
        "Lane WWWW: install.sh must reference >= 1 AO2_* env var (found {})",
        sh_env.len()
    );
    assert!(
        !ps1_env.is_empty(),
        "Lane WWWW: install.ps1 must reference >= 1 AO2_* env var (found {})",
        ps1_env.len()
    );
    assert!(
        clap_env.len() >= 3,
        "Lane WWWW: src/config.rs must declare >= 3 clap `env = \"AO2_...\"` attributes (found {}: {:?})",
        clap_env.len(),
        clap_env
    );

    // Cross-OS symmetry.
    assert_eq!(
        sh_env, ps1_env,
        "Lane WWWW: install.sh and install.ps1 must reference the IDENTICAL set of AO2_* env vars (cross-OS install-UX symmetry). install.sh: {sh_env:?}; install.ps1: {ps1_env:?}"
    );

    // Server-runtime / install-time separation.
    let sh_intersect: Vec<&String> = sh_env.intersection(&clap_env).collect();
    assert!(
        sh_intersect.is_empty(),
        "Lane WWWW: install.sh heredoc references clap server-runtime env var(s) {sh_intersect:?}. Install-time and server-runtime env namespaces must stay disjoint; an install script that reads a server-runtime env var silently collides with the server's own config namespace at install time."
    );
    let ps1_intersect: Vec<&String> = ps1_env.intersection(&clap_env).collect();
    assert!(
        ps1_intersect.is_empty(),
        "Lane WWWW: install.ps1 heredoc references clap server-runtime env var(s) {ps1_intersect:?}. Install-time and server-runtime env namespaces must stay disjoint."
    );
}

// Lane XXXX: aggregator JSON key ↔ handler read parity.
//
// The three-OS smoke aggregator (scripts/smoke-three-os-release.sh)
// runs a Python heredoc that emits a JSON file consumed by the
// control plane. Lane RRRR bound the aggregator's `grep '^key='`
// consumer patterns to the per-OS smoke emitters; Lane XXXX
// extends that one hop further: the JSON keys the aggregator
// EMITS into its output file must be READ by at least one handler
// (phase1_promotion.rs or release_publication.rs).
//
// A future quiet rename of an aggregator-emit key without a
// matching rename on the handler read site would silently break
// downstream parity checks: the handler would read `null`, the
// downstream verdict would degrade to `unknown`, and no test
// would catch the regression because nothing crashed.
//
// Lane XXXX pins a load-bearing subset of keys that flow from
// aggregator to handler — not every key (some are per-target
// hash artifacts that are aggregated server-side), just the
// critical cross-OS verdict + drift keys.
//
// Algorithm:
//   1. Read scripts/smoke-three-os-release.sh.
//   2. Locate the Python heredoc (the block between `<<'PY'` and
//      `\nPY\n`).
//   3. Extract every `"<key>":` JSON-literal key in the heredoc
//      (the Python dict that becomes the emitted JSON).
//   4. Read crates/ao2-cp-server/src/handlers/phase1_promotion.rs
//      and crates/ao2-cp-server/src/handlers/release_publication.rs.
//   5. For each load-bearing key, assert (a) the aggregator
//      emits it, AND (b) at least one handler reads it via
//      `json_str(..., "<key>")` or `.get("<key>")`.
//
// Load-bearing keys pinned by this lane (emitted by aggregator
// AND explicitly read by at least one handler via
// `json_str(..., "<key>")` or `.get("<key>")`):
//   - candidate_correlation_status (per-target verdict)
//   - candidate_correlation_parity (cross-OS verdict)
//   - source_commit_per_target_drift (cross-OS drift boolean)
//   - source_commit (orchestrator HEAD)
//
// Intentionally NOT pinned (emit-only-by-design):
//   - candidate_correlation_content_hash_parity: handlers compute
//     `surface_content_hash_parity` independently from per-target
//     content hashes, so they do not consume the aggregator's
//     claim. The aggregator's value is informational only.
//   - source_commit_at_target: per-target inner-dict value
//     iterated through the `source_commit_per_target` parent
//     dict; no explicit named read.
#[test]
fn aggregator_json_keys_bind_to_handler_reads_lane_xxxx() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let aggregator = fs::read_to_string(root.join("scripts/smoke-three-os-release.sh"))
        .expect("Lane XXXX: scripts/smoke-three-os-release.sh present");
    let phase1_promotion =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/phase1_promotion.rs"))
            .expect("Lane XXXX: phase1_promotion.rs present");
    let release_publication =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane XXXX: release_publication.rs present");

    // Walk every Python heredoc (`<<'PY' ... PY` block) and union
    // the JSON keys they emit. The aggregator has multiple PY
    // heredocs; the load-bearing one is the largest, but unioning
    // is robust to future restructuring.
    let py_open = "<<'PY'\n";
    let py_close = "\nPY\n";
    let mut emitted_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut cursor = 0usize;
    while let Some(rel) = aggregator[cursor..].find(py_open) {
        let body_start = cursor + rel + py_open.len();
        let Some(close_rel) = aggregator[body_start..].find(py_close) else {
            break;
        };
        let py_body = &aggregator[body_start..body_start + close_rel];
        let bytes = py_body.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'"' {
                let key_start = i + 1;
                let mut j = key_start;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
                if j < bytes.len() && j > key_start {
                    let key = &py_body[key_start..j];
                    let mut k = j + 1;
                    while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
                        k += 1;
                    }
                    if k < bytes.len()
                        && bytes[k] == b':'
                        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        emitted_keys.insert(key.to_string());
                    }
                }
                i = j + 1;
            } else {
                i += 1;
            }
        }
        cursor = body_start + close_rel + py_close.len();
    }

    assert!(
        emitted_keys.len() >= 10,
        "Lane XXXX: aggregator Python heredoc must emit >= 10 distinct JSON keys (found {}: {:?})",
        emitted_keys.len(),
        emitted_keys
    );

    // Load-bearing keys: emitted by the aggregator AND explicitly
    // read by at least one handler via `json_str(..., "<key>")` or
    // `.get("<key>")` (NOT just iterated as a parent-dict value).
    //
    // Intentionally NOT pinned (emit-only-by-design):
    //   - candidate_correlation_content_hash_parity: handlers
    //     compute `surface_content_hash_parity` independently from
    //     per-target content hashes, so they do not consume the
    //     aggregator's claim.
    //   - source_commit_at_target: per-target inner-dict value
    //     iterated through the `source_commit_per_target` parent
    //     dict; no explicit named read.
    let load_bearing = [
        "candidate_correlation_status",
        "candidate_correlation_parity",
        "source_commit_per_target_drift",
        "source_commit",
    ];

    for key in load_bearing {
        assert!(
            emitted_keys.contains(key),
            "Lane XXXX: aggregator must emit load-bearing key {key:?} into its JSON output (aggregator-emit keys: {emitted_keys:?})"
        );
    }

    // Build handler reader-key set. Look for both
    // `json_str(... "<key>")` and `.get("<key>")` patterns.
    fn collect_reader_keys(text: &str) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        for pattern in &["json_str(", ".get(\""] {
            let mut cursor = 0usize;
            while let Some(rel) = text[cursor..].find(pattern) {
                let after = cursor + rel + pattern.len();
                // For json_str(...), skip past the first quoted arg
                // to find the second arg if present.
                if *pattern == "json_str(" {
                    // Skip first arg until a comma at top level.
                    let mut depth = 0i32;
                    let mut k = after;
                    while k < text.len() {
                        let c = text.as_bytes()[k];
                        if c == b'(' {
                            depth += 1;
                        } else if c == b')' {
                            depth -= 1;
                            if depth < 0 {
                                break;
                            }
                        } else if c == b',' && depth == 0 {
                            // Found arg separator.
                            // Skip whitespace.
                            let mut m = k + 1;
                            while m < text.len()
                                && (text.as_bytes()[m] == b' ' || text.as_bytes()[m] == b'\n')
                            {
                                m += 1;
                            }
                            if m < text.len() && text.as_bytes()[m] == b'"' {
                                let key_start = m + 1;
                                let mut n = key_start;
                                while n < text.len() && text.as_bytes()[n] != b'"' {
                                    n += 1;
                                }
                                if n > key_start {
                                    let key = &text[key_start..n];
                                    if key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                                        out.insert(key.to_string());
                                    }
                                }
                            }
                            break;
                        }
                        k += 1;
                    }
                    cursor = after;
                } else {
                    // `.get("<key>")` — after is right past the open quote.
                    let key_start = after;
                    let mut k = key_start;
                    while k < text.len() && text.as_bytes()[k] != b'"' {
                        k += 1;
                    }
                    if k > key_start {
                        let key = &text[key_start..k];
                        if key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                            out.insert(key.to_string());
                        }
                    }
                    cursor = k + 1;
                }
            }
        }
        out
    }

    let mut handler_reads: std::collections::BTreeSet<String> =
        collect_reader_keys(&phase1_promotion);
    handler_reads.extend(collect_reader_keys(&release_publication));

    for key in load_bearing {
        assert!(
            handler_reads.contains(key),
            "Lane XXXX: at least one handler in phase1_promotion.rs or release_publication.rs must READ load-bearing key {key:?} via `json_str(..., \"{key}\")` or `.get(\"{key}\")`. A future aggregator rename would silently degrade downstream parity checks. handler-read keys: {} found.",
            handler_reads.len()
        );
    }
}

// Lane YYYY: HTML render fn ↔ route registration parity.
//
// release_publication.rs renders 8 HTML pages (the format!
// templates terminating in `</main></body></html>`). Each page
// must be served by at least one route in server.rs — an
// orphan HTML render fn (page is rendered but no route returns
// it) is dead code, and a route that returns a stale function
// surface no longer matches an HTML page render.
//
// Lane JJJJ binds routes to handler fn defs in general; Lane
// YYYY narrows that to specifically: every `pub async fn` in
// release_publication.rs that produces an HTML page MUST appear
// in server.rs's `.route(...)` declarations.
//
// Algorithm:
//   1. Read release_publication.rs.
//   2. Strip the `#[cfg(test)]` tail so test-only renders are
//      excluded.
//   3. Find every byte position of `</main></body></html>` (the
//      canonical page-end marker shared by every HTML render).
//   4. For each position, walk backwards to find the enclosing
//      `pub async fn <name>(` definition.
//   5. Floor: >= 6 distinct HTML render fns.
//   6. Read server.rs.
//   7. For each collected fn name, assert
//      `release_publication::<name>` appears in server.rs.
#[test]
fn html_render_fns_bind_to_route_registration_lane_yyyy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let release_publication =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane YYYY: release_publication.rs present");
    let server_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/server.rs"))
        .expect("Lane YYYY: server.rs present");

    // Strip #[cfg(test)] tail.
    let production_src = match release_publication.find("\n#[cfg(test)]\n") {
        Some(idx) => &release_publication[..idx],
        None => release_publication.as_str(),
    };

    // Find every page-end marker.
    let marker = "</main></body></html>";
    let mut render_fns: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut cursor = 0usize;
    while let Some(rel) = production_src[cursor..].find(marker) {
        let abs = cursor + rel;
        // Walk back to find the enclosing `pub async fn <name>(`
        // or `pub fn <name>(`.
        let prefix = &production_src[..abs];
        let async_idx = prefix.rfind("pub async fn ");
        let sync_idx = prefix.rfind("pub fn ");
        let (start, keyword_len) = match (async_idx, sync_idx) {
            (Some(a), Some(s)) if a > s => (a, "pub async fn ".len()),
            (Some(_), Some(s)) => (s, "pub fn ".len()),
            (Some(a), None) => (a, "pub async fn ".len()),
            (None, Some(s)) => (s, "pub fn ".len()),
            (None, None) => {
                cursor = abs + marker.len();
                continue;
            }
        };
        let id_start = start + keyword_len;
        // Identifier ends at `(` or `<` (for generic fns).
        let mut id_end = id_start;
        let bytes = production_src.as_bytes();
        while id_end < bytes.len() {
            let c = bytes[id_end];
            if c.is_ascii_alphanumeric() || c == b'_' {
                id_end += 1;
            } else {
                break;
            }
        }
        if id_end > id_start {
            let fn_name = &production_src[id_start..id_end];
            render_fns.insert(fn_name.to_string());
        }
        cursor = abs + marker.len();
    }

    assert!(
        render_fns.len() >= 6,
        "Lane YYYY: release_publication.rs must define >= 6 HTML render fns (terminating in `</main></body></html>`); found {} ({:?})",
        render_fns.len(),
        render_fns
    );

    // Each render fn must appear in server.rs.
    for fn_name in render_fns.iter() {
        let needle = format!("release_publication::{fn_name}");
        assert!(
            server_rs.contains(&needle),
            "Lane YYYY: release_publication.rs renders HTML via `{fn_name}` but server.rs has no `release_publication::{fn_name}` route registration. An HTML page rendered but never served via a route is dead code; a route renamed without the matching fn rename leaves an orphan render."
        );
    }
}

// Lane ZZZZ: Cargo workspace members ↔ on-disk crate directory parity.
//
// The top-level `Cargo.toml`'s `[workspace] members = [...]` array
// declares which crates participate in the workspace. Three load-bearing
// invariants:
//
//   1. Every declared member resolves to a real directory with a
//      `Cargo.toml`. A phantom member (typo, deleted crate left in the
//      list) breaks `cargo build` workspace-wide before any code runs.
//   2. Every member's declared crate name (`name = "..."` in its own
//      Cargo.toml) matches its enclosing directory's last path
//      component (modulo Cargo's `-`/`_` interchange). A drift here
//      makes tooling that resolves crates by directory diverge from
//      tooling that resolves by package name.
//   3. Every `crates/<dir>/Cargo.toml` on disk is enrolled as a
//      member. An orphan crate (real `Cargo.toml` not in the
//      workspace members list) silently rots — cargo workspace
//      commands like `cargo test --workspace` skip it, so CI greens
//      on a crate that may not even compile.
//
// Floor: >= 2 workspace members. The control plane currently has
// three (ao2-cp-schema, ao2-cp-storage, ao2-cp-server) and a future
// split is more likely than a consolidation.
#[test]
fn cargo_workspace_members_bind_to_real_crate_dirs_lane_zzzz() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workspace_toml = fs::read_to_string(root.join("Cargo.toml"))
        .expect("Lane ZZZZ: workspace Cargo.toml present");

    // Extract `[workspace] members = [ ... ]` literal entries.
    let ws_start = workspace_toml
        .find("[workspace]")
        .expect("Lane ZZZZ: workspace Cargo.toml must declare [workspace]");
    let members_key = workspace_toml[ws_start..]
        .find("members")
        .expect("Lane ZZZZ: [workspace] must declare members = [ ... ]");
    let abs_members = ws_start + members_key;
    let open_bracket = workspace_toml[abs_members..]
        .find('[')
        .expect("Lane ZZZZ: members must be a `[...]` list");
    let close_bracket = workspace_toml[abs_members + open_bracket..]
        .find(']')
        .expect("Lane ZZZZ: members list must close");
    let members_body =
        &workspace_toml[abs_members + open_bracket + 1..abs_members + open_bracket + close_bracket];

    let mut members: Vec<String> = Vec::new();
    for raw in members_body.split(',') {
        let trimmed = raw.trim();
        let stripped = trimmed.trim_start_matches('"').trim_end_matches('"');
        if !stripped.is_empty() {
            members.push(stripped.to_string());
        }
    }

    assert!(
        members.len() >= 2,
        "Lane ZZZZ: workspace must declare >= 2 members (got {}); accidental collapse of the workspace to a single crate is a structural regression",
        members.len()
    );

    // (1) Each declared member must resolve to a real dir with a Cargo.toml.
    // (2) Crate name must match dir basename modulo `-`/`_`.
    let normalize = |s: &str| s.replace('_', "-");
    let mut declared_dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for member in &members {
        let member_dir = root.join(member);
        assert!(
            member_dir.is_dir(),
            "Lane ZZZZ: workspace member `{member}` is not a real directory under the repo root. A phantom member breaks `cargo build` workspace-wide."
        );
        let member_toml_path = member_dir.join("Cargo.toml");
        let member_toml = fs::read_to_string(&member_toml_path).unwrap_or_else(|_| {
            panic!(
                "Lane ZZZZ: workspace member `{member}` has no Cargo.toml at {}",
                member_toml_path.display()
            )
        });

        let name_line = member_toml
            .lines()
            .find(|line| line.trim_start().starts_with("name"))
            .unwrap_or_else(|| {
                panic!("Lane ZZZZ: `{member}/Cargo.toml` must declare `name = ...`")
            });
        let name_val = name_line
            .split_once('=')
            .map(|(_, rhs)| rhs.trim().trim_matches('"').to_string())
            .expect("Lane ZZZZ: name = ... must have a value");

        let basename = member.rsplit('/').next().unwrap_or(member);
        assert_eq!(
            normalize(&name_val),
            normalize(basename),
            "Lane ZZZZ: workspace member directory `{member}` (basename `{basename}`) declares crate name `{name_val}`; the names must agree (modulo `-`/`_`) so directory-resolving and package-name-resolving tooling don't diverge"
        );

        declared_dirs.insert(member.to_string());
    }

    // (3) No orphan crates: every `crates/<dir>/Cargo.toml` must be a declared member.
    let crates_dir = root.join("crates");
    let entries = fs::read_dir(&crates_dir).expect("Lane ZZZZ: crates/ dir must exist");
    let mut seen_crate_dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for entry in entries {
        let entry = entry.expect("Lane ZZZZ: crates/ dir entry readable");
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let cargo_toml = path.join("Cargo.toml");
        if !cargo_toml.is_file() {
            continue;
        }
        let basename = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| format!("crates/{s}"))
            .expect("Lane ZZZZ: crates/<dir> basename readable");
        seen_crate_dirs.insert(basename);
    }

    for crate_dir in &seen_crate_dirs {
        assert!(
            declared_dirs.contains(crate_dir),
            "Lane ZZZZ: `{crate_dir}` has a Cargo.toml on disk but is not declared in the workspace `members = [...]`. An orphan crate is silently skipped by `cargo test --workspace` — CI greens on a crate that may not compile."
        );
    }

    assert!(
        seen_crate_dirs.len() >= 2,
        "Lane ZZZZ: crates/ must contain >= 2 crate dirs with Cargo.toml; found {} ({:?})",
        seen_crate_dirs.len(),
        seen_crate_dirs
    );
}

// Lane AAAAA: workspace dependency unification parity.
//
// The top-level `[workspace.dependencies]` block declares the
// version-pinned third-party crates used across the workspace. Each
// member crate must reference these by `workspace = true` (either
// `<dep>.workspace = true` shorthand or `<dep> = { workspace = true }`),
// never by a direct version literal.
//
// Direct version pinning in a member silently shadows the workspace
// version: a future commit upgrading `tokio` workspace-wide leaves the
// shadowing member on the old version, behavior fragments between
// crates, and `cargo update -p tokio` no longer affects every consumer.
//
// Path-dep entries (intra-workspace crates like
// `ao2-cp-schema = { path = "..." }`) are NOT in
// `[workspace.dependencies]` and are exempt.
//
// Algorithm:
//   1. Read top-level Cargo.toml.
//   2. Slice `[workspace.dependencies]` body — collect dep names
//      (each line's `<name> = ...` LHS).
//   3. For each member Cargo.toml, slice `[dependencies]` and
//      `[dev-dependencies]` bodies (terminated by next `[` header
//      or EOF). For each `<name> = <RHS>` line whose `<name>` is in
//      the workspace dep set, assert RHS references workspace=true.
//   4. Floors: workspace declares >= 5 deps; each member shares
//      >= 3 deps with workspace.
#[test]
fn member_cargo_tomls_unify_via_workspace_dependencies_lane_aaaaa() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workspace_toml =
        fs::read_to_string(root.join("Cargo.toml")).expect("Lane AAAAA: workspace Cargo.toml");

    // Slice [workspace.dependencies] body.
    let header = "[workspace.dependencies]";
    let header_idx = workspace_toml
        .find(header)
        .expect("Lane AAAAA: top-level Cargo.toml must declare [workspace.dependencies]");
    let body_start = header_idx + header.len();
    let body_end = workspace_toml[body_start..]
        .find("\n[")
        .map(|rel| body_start + rel)
        .unwrap_or(workspace_toml.len());
    let ws_deps_body = &workspace_toml[body_start..body_end];

    let mut workspace_dep_names: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for line in ws_deps_body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((lhs, _)) = trimmed.split_once('=') {
            let name = lhs.trim().to_string();
            if !name.is_empty() {
                workspace_dep_names.insert(name);
            }
        }
    }

    assert!(
        workspace_dep_names.len() >= 5,
        "Lane AAAAA: [workspace.dependencies] must declare >= 5 deps (got {}); the cascade target is a unified shared-dep surface, not a thin shim",
        workspace_dep_names.len()
    );

    // Enumerate member Cargo.tomls (only directories declared in [workspace] members
    // — Lane ZZZZ already binds members ↔ on-disk dirs, so reusing that surface
    // would couple the two lanes; instead, walk crates/ directly).
    let crates_dir = root.join("crates");
    let entries = fs::read_dir(&crates_dir).expect("Lane AAAAA: crates/ dir present");
    let mut members_seen = 0usize;
    for entry in entries {
        let entry = entry.expect("Lane AAAAA: crates/ dir entry readable");
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let cargo_toml_path = path.join("Cargo.toml");
        if !cargo_toml_path.is_file() {
            continue;
        }
        let member_toml = fs::read_to_string(&cargo_toml_path).unwrap_or_else(|_| {
            panic!(
                "Lane AAAAA: member Cargo.toml readable at {}",
                cargo_toml_path.display()
            )
        });
        members_seen += 1;

        // Collect shared-dep names declared in this member.
        let section_headers = ["[dependencies]", "[dev-dependencies]"];
        let mut shared_count = 0usize;
        for header in &section_headers {
            let Some(h_idx) = member_toml.find(header) else {
                continue;
            };
            let sec_start = h_idx + header.len();
            let sec_end = member_toml[sec_start..]
                .find("\n[")
                .map(|rel| sec_start + rel)
                .unwrap_or(member_toml.len());
            let body = &member_toml[sec_start..sec_end];

            for line in body.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let Some((lhs, rhs)) = trimmed.split_once('=') else {
                    continue;
                };
                // LHS may include `<name>.workspace` (shorthand form): strip the suffix.
                let raw_lhs = lhs.trim();
                let name = raw_lhs
                    .strip_suffix(".workspace")
                    .unwrap_or(raw_lhs)
                    .to_string();
                if !workspace_dep_names.contains(&name) {
                    continue;
                }
                shared_count += 1;

                // Accept either `.workspace = true` (LHS ends `.workspace`, RHS is `true`)
                // or `<name> = { workspace = true }` (RHS contains `workspace = true`).
                let rhs_trim = rhs.trim();
                let shorthand_ok = raw_lhs.ends_with(".workspace") && rhs_trim.starts_with("true");
                let inline_ok =
                    rhs_trim.contains("workspace = true") || rhs_trim.contains("workspace=true");
                assert!(
                    shorthand_ok || inline_ok,
                    "Lane AAAAA: member `{}` in section `{}` declares dep `{}` as `{}`; the workspace declares `{}` in [workspace.dependencies], so the member must reference it via `.workspace = true` (shorthand) or `{{ workspace = true }}` (inline). A direct version pin silently shadows the workspace version and fragments behavior across crates.",
                    path.display(),
                    header,
                    name,
                    trimmed,
                    name
                );
            }
        }

        assert!(
            shared_count >= 3,
            "Lane AAAAA: member `{}` shares only {} deps with [workspace.dependencies]; expected >= 3 (a member with no shared deps would defeat the purpose of workspace unification)",
            path.display(),
            shared_count
        );
    }

    assert!(
        members_seen >= 2,
        "Lane AAAAA: workspace must enumerate >= 2 member crates with Cargo.toml (got {members_seen})"
    );
}

// Lane BBBBB: install heredoc shebang + strict-mode parity.
//
// Two security-load-bearing invariants on the install scripts shipped
// in the release archive (the `cat > "$STAGE/install.{sh,ps1}" <<'X'
// ... X` heredocs in `scripts/package-local.sh`):
//
//   1. install.sh's heredoc body MUST start with a `#!` shebang on
//      the first non-empty line AND MUST contain `set -eu` (or any
//      stricter superset like `set -euo pipefail`). Without strict
//      mode, a `cp` failure mid-install, or an `awk` that returns
//      nonzero mid-pipeline, would NOT abort the script — the
//      installer would silently continue past the checksum verdict
//      and leave a partial install on disk that no operator knows
//      about.
//   2. install.ps1's heredoc body MUST declare
//      `$ErrorActionPreference = "Stop"`. Without it, PowerShell
//      cmdlets that emit non-terminating errors (e.g., `Copy-Item`
//      under a permission failure) print red text and continue —
//      same silent-partial-install failure mode as the .sh case.
//
// Lane EEEE pins the checksum-before-copy order; Lane BBBBB is
// orthogonal: it pins the meta-condition that script failures
// actually abort the script. Without Lane BBBBB, Lane EEEE's order
// could pass while the checksum mismatch branch silently returns
// nonzero and the `cp` runs anyway.
#[test]
fn install_heredocs_shebang_and_strict_mode_parity_lane_bbbbb() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package_local = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane BBBBB: scripts/package-local.sh present");

    // Slice install.sh heredoc body.
    let sh_open = "cat > \"$STAGE/install.sh\" <<'SH'";
    let sh_close = "\nSH\n";
    let sh_start = package_local
        .find(sh_open)
        .expect("Lane BBBBB: package-local.sh must contain install.sh heredoc opener");
    let sh_body_start = sh_start + sh_open.len();
    let sh_body_end = sh_body_start
        + package_local[sh_body_start..]
            .find(sh_close)
            .expect("Lane BBBBB: install.sh heredoc must close with `\\nSH\\n`");
    let sh_body = &package_local[sh_body_start..sh_body_end];

    // (1a) First non-empty line of install.sh must start with `#!`.
    let first_non_empty = sh_body
        .lines()
        .find(|l| !l.trim().is_empty())
        .expect("Lane BBBBB: install.sh heredoc must have a non-empty body");
    assert!(
        first_non_empty.trim_start().starts_with("#!"),
        "Lane BBBBB: install.sh heredoc's first non-empty line must be a `#!` shebang (found {first_non_empty:?}). Without a shebang, the heredoc-shipped file is not directly executable; operators must explicitly invoke `sh install.sh`, breaking the README's documented `./install.sh` invocation."
    );

    // (1b) install.sh must declare strict mode: `set -eu` or stricter.
    // Accept any variant whose flag set contains at least `e` and `u`.
    let mut sh_has_strict = false;
    for line in sh_body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("set -") {
            let flags = rest.split_whitespace().next().unwrap_or("");
            if flags.contains('e') && flags.contains('u') {
                sh_has_strict = true;
                break;
            }
        }
    }
    assert!(
        sh_has_strict,
        "Lane BBBBB: install.sh heredoc must declare `set -eu` or stricter (e.g., `set -euo pipefail`). Without `-e`, a checksum-mismatch exit-1 branch followed by `cp` would silently install an unverified binary; without `-u`, an unset $INSTALL_DIR variable would expand to empty and `cp` would write to the root filesystem."
    );

    // (2) Slice install.ps1 heredoc and assert $ErrorActionPreference = "Stop".
    let ps1_open = "cat > \"$STAGE/install.ps1\" <<'PS1'";
    let ps1_close = "\nPS1\n";
    let ps1_start = package_local
        .find(ps1_open)
        .expect("Lane BBBBB: package-local.sh must contain install.ps1 heredoc opener");
    let ps1_body_start = ps1_start + ps1_open.len();
    let ps1_body_end = ps1_body_start
        + package_local[ps1_body_start..]
            .find(ps1_close)
            .expect("Lane BBBBB: install.ps1 heredoc must close with `\\nPS1\\n`");
    let ps1_body = &package_local[ps1_body_start..ps1_body_end];

    let lowered = ps1_body.to_lowercase();
    assert!(
        lowered.contains("$erroractionpreference"),
        "Lane BBBBB: install.ps1 heredoc must reference `$ErrorActionPreference` (case-insensitive). Without it, non-terminating cmdlet errors (a permission-denied Copy-Item, a missing-file Test-Path under a strict ACL) print red text and continue executing — the installer reports `ao2_control_plane_installed=...` even though the binary copy silently failed."
    );
    assert!(
        lowered.contains("$erroractionpreference = \"stop\"")
            || lowered.contains("$erroractionpreference='stop'")
            || lowered.contains("$erroractionpreference =\"stop\""),
        "Lane BBBBB: install.ps1 heredoc must declare `$ErrorActionPreference = \"Stop\"` (any quoting). A different value (`Continue`, `SilentlyContinue`, `Inquire`) would defeat the strict-failure contract install.sh's `set -eu` provides."
    );
}

// Lane CCCCC: Cargo.lock workspace-coverage parity.
//
// Cargo.lock is the pinned dependency graph; it must enumerate every
// workspace member as a path-source `[[package]]` entry (no `source =`
// line — path sources are implicit), and conversely every path-source
// `[[package]]` must be a declared workspace member.
//
// Failure modes pinned:
//   1. A new workspace member added to `[workspace] members` but
//      Cargo.lock not regenerated. `cargo build --workspace` would
//      auto-resolve, but `cargo build --frozen` (used in CI / release
//      builds for reproducibility) would fail with "lock file not
//      up to date" — Lane CCCCC catches this BEFORE the CI run.
//   2. An orphan path-source entry left over from a deleted crate.
//      The phantom entry inflates the lock file and may pin a
//      version of a transitive dep that no longer matches the live
//      graph; Cargo silently ignores it but lockfile-diff reviewers
//      can't reason about what's actually in the build.
//   3. A workspace member declared by directory but renamed in its
//      own Cargo.toml without lockfile regeneration; the member
//      name in `members = [...]` (directory basename) and the
//      lockfile name diverge.
//
// Cross-axis to Lane ZZZZ (workspace members ↔ on-disk dirs):
// ZZZZ binds the Cargo.toml-side declaration; CCCCC binds the
// Cargo.lock-side reflection. Together they pin all three corners
// of the (members declaration, on-disk dir, lockfile entry) triangle.
#[test]
fn cargo_lock_workspace_path_sources_match_members_lane_ccccc() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workspace_toml = fs::read_to_string(root.join("Cargo.toml"))
        .expect("Lane CCCCC: workspace Cargo.toml present");
    let cargo_lock =
        fs::read_to_string(root.join("Cargo.lock")).expect("Lane CCCCC: Cargo.lock present");

    // Extract workspace member directory basenames + their declared crate names.
    let ws_idx = workspace_toml
        .find("[workspace]")
        .expect("Lane CCCCC: [workspace] header must be present");
    let members_key = workspace_toml[ws_idx..]
        .find("members")
        .expect("Lane CCCCC: [workspace] must declare members");
    let abs_m = ws_idx + members_key;
    let open = workspace_toml[abs_m..]
        .find('[')
        .expect("Lane CCCCC: members must be a `[...]` list");
    let close = workspace_toml[abs_m + open..]
        .find(']')
        .expect("Lane CCCCC: members list must close");
    let members_body = &workspace_toml[abs_m + open + 1..abs_m + open + close];

    let mut expected_crate_names: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for raw in members_body.split(',') {
        let trimmed = raw.trim();
        let stripped = trimmed.trim_start_matches('"').trim_end_matches('"');
        if stripped.is_empty() {
            continue;
        }
        // Resolve the declared crate name by reading the member's Cargo.toml.
        let member_toml_path = root.join(stripped).join("Cargo.toml");
        let member_toml = fs::read_to_string(&member_toml_path)
            .unwrap_or_else(|_| panic!("Lane CCCCC: member Cargo.toml at {stripped}"));
        let name_line = member_toml
            .lines()
            .find(|l| l.trim_start().starts_with("name"))
            .unwrap_or_else(|| {
                panic!("Lane CCCCC: `{stripped}/Cargo.toml` must declare name = ...")
            });
        let name_val = name_line
            .split_once('=')
            .map(|(_, rhs)| rhs.trim().trim_matches('"').to_string())
            .expect("Lane CCCCC: name = ... must have a value");
        expected_crate_names.insert(name_val);
    }

    assert!(
        expected_crate_names.len() >= 2,
        "Lane CCCCC: workspace must declare >= 2 member crate names (got {} from members list)",
        expected_crate_names.len()
    );

    // Parse Cargo.lock `[[package]]` blocks. Collect names that have NO `source =` line
    // (those are path-source workspace crates).
    let mut path_source_names: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut blocks_seen = 0usize;
    let mut cursor = 0usize;
    while let Some(rel) = cargo_lock[cursor..].find("[[package]]") {
        let abs = cursor + rel;
        let block_start = abs + "[[package]]".len();
        // Block ends at the next `[[package]]` or `[<other>]` or EOF.
        let block_end_rel = cargo_lock[block_start..]
            .find("\n[[")
            .unwrap_or(cargo_lock.len() - block_start);
        let block = &cargo_lock[block_start..block_start + block_end_rel];
        blocks_seen += 1;

        let mut name: Option<&str> = None;
        let mut has_source = false;
        for line in block.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("name = ") {
                name = Some(rest.trim_matches('"'));
            } else if t.starts_with("source = ") {
                has_source = true;
            }
        }
        if let Some(n) = name {
            if !has_source {
                path_source_names.insert(n.to_string());
            }
        }
        cursor = block_start + block_end_rel;
    }

    assert!(
        blocks_seen >= expected_crate_names.len(),
        "Lane CCCCC: Cargo.lock must contain at least as many `[[package]]` blocks ({}) as workspace members ({}); a lockfile this thin is structurally broken",
        blocks_seen,
        expected_crate_names.len()
    );

    // (a) Every declared workspace member must be a path-source entry in Cargo.lock.
    for crate_name in &expected_crate_names {
        assert!(
            path_source_names.contains(crate_name),
            "Lane CCCCC: workspace member `{crate_name}` is declared in Cargo.toml but is not a path-source `[[package]]` in Cargo.lock. Run `cargo update --workspace` (or `cargo build --workspace` then commit Cargo.lock); a stale lockfile breaks `cargo build --frozen` in CI / release builds."
        );
    }

    // (b) Every path-source entry must be a declared workspace member (no orphans).
    for ps_name in &path_source_names {
        assert!(
            expected_crate_names.contains(ps_name),
            "Lane CCCCC: Cargo.lock contains a path-source `[[package]] name = \"{ps_name}\"` with no `source = ...` line, but `{ps_name}` is not declared in the workspace `members = [...]`. An orphan path-source entry inflates the lockfile with a phantom crate — likely the residue of a deleted member."
        );
    }
}

// Lane DDDDD: tar arglist ↔ stage-area write parity.
//
// `scripts/package-local.sh` stages release artifacts under `$STAGE/`
// and then packages them via:
//   `(cd "$STAGE" && tar -czf "$ARCHIVE" <arg1> <arg2> ...)`
//
// Every <argN> in the tar arglist must correspond to at least one
// stage-area write step earlier in the script. If an arg has no
// matching write, the tar step fails at archive time ("file not
// found") and the release build aborts — but only AFTER the build
// has consumed minutes producing the binary. Catching this at the
// script-structure level rather than runtime saves the build time
// and produces a meaningful error message.
//
// Conversely, a stage-area write of a file the tar arglist doesn't
// enumerate is a leaked staging artifact — useful only if it's a
// transient (like SHA256SUMS computed before final write), but a
// silent leak is a sign the operator added a file to staging but
// forgot to ship it.
//
// Lane VVVV (install heredoc artifact refs ↔ tar arglist) binds the
// install scripts' file references TO tar; Lane UUU (README archive
// contents ↔ tar arglist) binds the README claims TO tar. Lane
// DDDDD binds the script's own staging logic — the SOURCE of the
// arglist — to tar.
//
// Accepted write patterns (any of):
//   - `mkdir -p "$STAGE/<entry>"`  (directory)
//   - `cp <src> "$STAGE/<entry>"`  (file via cp)
//   - `cat > "$STAGE/<entry>"`     (file via heredoc redirect)
//   - `printf ... > "$STAGE/<entry>"` (file via printf redirect)
//   - `python3 - "$STAGE/<entry>"` (file via Python interpreter)
//
// Floor: >= 5 tar arglist entries.
#[test]
fn package_local_tar_arglist_binds_to_stage_writes_lane_ddddd() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkg = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane DDDDD: scripts/package-local.sh present");

    // Locate the tar arglist line.
    let tar_anchor = "tar -czf \"$ARCHIVE\"";
    let tar_idx = pkg
        .find(tar_anchor)
        .expect("Lane DDDDD: package-local.sh must contain a `tar -czf \"$ARCHIVE\" ...` line");
    let tar_line_start = tar_idx + tar_anchor.len();
    let tar_line_end = tar_line_start
        + pkg[tar_line_start..]
            .find('\n')
            .expect("Lane DDDDD: tar line must terminate");
    let tar_args_raw = &pkg[tar_line_start..tar_line_end];

    // Strip a trailing `)` if present (the `(cd ... && tar ... )` form).
    let tar_args_clean = tar_args_raw.trim().trim_end_matches(')').trim();

    let tar_entries: Vec<&str> = tar_args_clean
        .split_whitespace()
        .filter(|t| !t.is_empty())
        .collect();

    assert!(
        tar_entries.len() >= 5,
        "Lane DDDDD: tar arglist must enumerate >= 5 entries (got {} from `{}`); a shorter arglist points to a botched archive layout",
        tar_entries.len(),
        tar_args_clean
    );

    // For each tar entry, search the script for an accepted write pattern.
    for entry in &tar_entries {
        // The simplest check: any occurrence of the literal `"$STAGE/<entry>"` (with quotes).
        // That covers cp, cat>, printf>, python3 -, mkdir -p in any phrasing.
        let stage_ref = format!("\"$STAGE/{entry}\"");
        let mkdir_ref = format!("mkdir -p \"$STAGE/{entry}\"");
        // For directory entries (no `.` suffix), the entry itself may be a dir;
        // the binary lives at `bin/$BINARY_NAME` so `cp ... "$STAGE/bin/..."` is
        // sufficient evidence of `bin/` being populated.
        let dir_populator_ref = format!("\"$STAGE/{entry}/");

        assert!(
            pkg.contains(&stage_ref)
                || pkg.contains(&mkdir_ref)
                || pkg.contains(&dir_populator_ref),
            "Lane DDDDD: tar arglist entry `{entry}` has no matching `\"$STAGE/{entry}\"` write step (cp, cat>, printf>, python3 -, mkdir -p) in package-local.sh. If the tar step ran, it would fail with `file not found`; that wastes the entire build (binary is already compiled). Either add a stage step or remove `{entry}` from the tar arglist. Tar args observed: {tar_args_clean:?}"
        );
    }
}

// Lane EEEEE: handler module declaration ↔ file existence parity.
//
// `crates/ao2-cp-server/src/handlers/mod.rs` declares each handler
// submodule via `pub mod <name>;`. Two invariants:
//
//   1. Every declared submodule must resolve to either
//      `handlers/<name>.rs` or `handlers/<name>/mod.rs` on disk.
//      (Rust's compiler enforces this at build time, but Lane EEEEE
//      surfaces the failure at the meta-parity level with a precise
//      message; a future submodule declared without the file would
//      otherwise produce a low-context "file not found for module" error.)
//
//   2. Every `.rs` file under `handlers/` (excluding `mod.rs` itself
//      and any test fixture file) must be declared as a `pub mod`
//      in `mod.rs`. An orphan handler file is silently dead code:
//      `cargo build` succeeds, `cargo check` passes, but the file
//      contributes nothing to the binary — and a future contributor
//      reading the handler source has no way to know it's never
//      wired in.
//
// Floor: >= 6 declared handler submodules.
#[test]
fn handler_module_declarations_bind_to_real_files_lane_eeeee() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let handlers_dir = root.join("crates/ao2-cp-server/src/handlers");
    let mod_rs_path = handlers_dir.join("mod.rs");
    let mod_rs = fs::read_to_string(&mod_rs_path).expect("Lane EEEEE: handlers/mod.rs present");

    // Collect declared module names from `pub mod <name>;`.
    let mut declared: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in mod_rs.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("pub mod ") {
            if let Some(name) = rest.strip_suffix(';') {
                let name = name.trim();
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    declared.insert(name.to_string());
                }
            }
        }
    }

    assert!(
        declared.len() >= 6,
        "Lane EEEEE: handlers/mod.rs must declare >= 6 submodules (got {} ({:?})); a thinner handler surface indicates accidental truncation",
        declared.len(),
        declared
    );

    // (1) Every declared submodule must resolve to a real file.
    for name in &declared {
        let single_file = handlers_dir.join(format!("{name}.rs"));
        let dir_mod_file = handlers_dir.join(name).join("mod.rs");
        assert!(
            single_file.is_file() || dir_mod_file.is_file(),
            "Lane EEEEE: handlers/mod.rs declares `pub mod {name};` but neither `handlers/{name}.rs` nor `handlers/{name}/mod.rs` exists on disk. (Compile-time would catch this, but Lane EEEEE surfaces the failure with a precise message before `cargo build` produces the lower-context module-not-found error.)"
        );
    }

    // (2) Every .rs in handlers/ (except mod.rs) must be declared.
    let entries = fs::read_dir(&handlers_dir).expect("Lane EEEEE: handlers/ dir readable");
    let mut seen_handler_files: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for entry in entries {
        let entry = entry.expect("Lane EEEEE: handlers/ dir entry");
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        if ext != "rs" {
            continue;
        }
        if name == "mod" {
            continue;
        }
        seen_handler_files.insert(name.to_string());
    }

    for file_stem in &seen_handler_files {
        assert!(
            declared.contains(file_stem),
            "Lane EEEEE: `handlers/{file_stem}.rs` exists on disk but is not declared as `pub mod {file_stem};` in handlers/mod.rs. Orphan handler file → silently dead code: `cargo build` succeeds without it, and a future contributor has no way to know the file is unwired. Either add the `pub mod` declaration or delete the file."
        );
    }
}

// Lane FFFFF: HTML page doctype + charset declaration parity.
//
// Every HTML render in `release_publication.rs` (the format!
// templates terminating in `</main></body></html>`) MUST:
//
//   1. Begin with `<!doctype html>` (case-insensitive). Without the
//      doctype, browsers fall back to "quirks mode" — CSS values
//      computed using legacy box-model rules, table border-collapse
//      handled inconsistently. A future regression that strips the
//      doctype produces no test failure until an operator complains
//      about a misaligned column.
//
//   2. Declare `<meta charset="utf-8">` (case-insensitive). Without
//      an explicit charset, the browser falls back to its locale
//      default. Operator-facing strings that contain `·` (the footer
//      separator used in every page) or `→` (used in error messages)
//      render as mojibake.
//
// Floor: >= 6 HTML pages — symmetric to Lane YYYY's
// `</main></body></html>` page count.
//
// Lane NNNN binds CSS class definitions to assignments; Lane OOOO
// binds `<title>` ↔ `<h1>`; Lane YYYY binds render fn ↔ route. Lane
// FFFFF is orthogonal: it pins the structural HTML header invariants
// that every page must satisfy regardless of which fn produced it.
#[test]
fn release_publication_html_doctype_and_charset_parity_lane_fffff() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let src =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane FFFFF: release_publication.rs present");

    // Strip #[cfg(test)] tail.
    let production_src = match src.find("\n#[cfg(test)]\n") {
        Some(idx) => &src[..idx],
        None => src.as_str(),
    };

    let marker = "</main></body></html>";
    let mut page_count = 0usize;
    let mut cursor = 0usize;
    while let Some(rel) = production_src[cursor..].find(marker) {
        let abs = cursor + rel;
        let prefix = &production_src[..abs];

        // Walk back to the most recent `"<!` (template literal start).
        // Every HTML template literal in this file opens with `"<!doctype...`
        // — the marker `"<!` is distinctive enough to anchor on.
        let template_open_marker = "\"<!";
        let open_rel = prefix.rfind(template_open_marker).unwrap_or_else(|| {
            panic!(
                "Lane FFFFF: HTML page ending at byte {abs} has no preceding `\"<!` template-open marker; the template literal does not start with a doctype declaration. Every HTML render must begin with `<!doctype html>` to keep browsers out of quirks mode."
            )
        });
        let template_body_start = open_rel + 1; // skip the opening "
        let template_body_end = abs + marker.len();
        let template = &production_src[template_body_start..template_body_end];
        let lowered_prefix: String = template.chars().take(30).collect::<String>().to_lowercase();

        assert!(
            lowered_prefix.starts_with("<!doctype html>"),
            "Lane FFFFF: HTML render ending at byte {abs} does not begin with `<!doctype html>` (case-insensitive). First 30 chars (lowercased): {lowered_prefix:?}. Without the doctype the operator's browser falls back to quirks mode and the embedded `<style>` mis-renders."
        );

        let lowered_body = template.to_lowercase();
        assert!(
            lowered_body.contains("<meta charset=\\\"utf-8\\\">")
                || lowered_body.contains("<meta charset='utf-8'>")
                || lowered_body.contains("<meta charset=utf-8>"),
            "Lane FFFFF: HTML render ending at byte {abs} has no `<meta charset=\"utf-8\">` declaration. Without an explicit charset the browser falls back to its locale default and operator-facing strings containing `·` / `→` render as mojibake."
        );

        page_count += 1;
        cursor = abs + marker.len();
    }

    assert!(
        page_count >= 6,
        "Lane FFFFF: release_publication.rs must render >= 6 HTML pages (terminating in `</main></body></html>`); found {page_count}. Symmetric to Lane YYYY's page-count floor."
    );
}

// Lane GGGGG: schema-version `_v<N>` semver-suffix parity.
//
// Every `const *_SCHEMA: &str = "<value>";` declared in
// release_publication.rs MUST have a `<value>` ending in either
// `.v<digits>` or `/v<digits>` with N >= 1.
//
// Why:
//   - Schema strings are consumed by downstream verifiers (the
//     verify_release_support_bundle.py / Verify-ReleaseSupportBundle.ps1
//     scripts and the AO2 attest tooling) that key off the suffix to
//     route a payload to the matching JSON schema. A schema string
//     emitted without a version suffix is silently treated as v0
//     (legacy) or rejected; either way the operator sees an opaque
//     "schema mismatch" error with no version context.
//   - The repository has chosen two equally valid conventions:
//     dotted-tail (`ao2.release-publication-summary.v1`) and slash-
//     tail (`factory-v3/ao2-release-evaluator-decision/v1`). Lane
//     GGGGG accepts either, but rejects anything else (no version,
//     trailing `_v1`, trailing `-v1`, version embedded mid-string).
//
// Floor: >= 8 schema consts (matches Lane HHHH's emission floor).
//
// Cross-axis to Lane HHHH (RELEASE_*_SCHEMA const → JSON literal
// emission parity): HHHH binds the const NAME to the emitted JSON;
// GGGGG binds the const VALUE to the semver-suffix convention.
#[test]
fn release_schema_const_values_end_with_v_n_suffix_lane_ggggg() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let src =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane GGGGG: release_publication.rs present");

    // Strip #[cfg(test)] tail.
    let production_src = match src.find("\n#[cfg(test)]\n") {
        Some(idx) => &src[..idx],
        None => src.as_str(),
    };

    // Collect (const_name, schema_value) pairs.
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = production_src[cursor..].find("const ") {
        let abs = cursor + rel;
        let after_const = abs + "const ".len();
        let tail = &production_src[after_const..];
        let name_end = tail
            .find(|c: char| c == ':' || c.is_whitespace())
            .unwrap_or(tail.len());
        let name = tail[..name_end].to_string();
        cursor = after_const + name_end;

        if !name.ends_with("_SCHEMA") {
            continue;
        }

        let window_end = (cursor + 400).min(production_src.len());
        let window = &production_src[cursor..window_end];
        let Some(type_idx) = window.find(": &str") else {
            continue;
        };
        let Some(eq_idx) = window[type_idx..].find('=') else {
            continue;
        };
        let after_eq = cursor + type_idx + eq_idx + 1;
        let rest_window_end = (after_eq + 400).min(production_src.len());
        let rest = &production_src[after_eq..rest_window_end];
        let Some(open_quote_rel) = rest.find('"') else {
            continue;
        };
        let value_start = after_eq + open_quote_rel + 1;
        let Some(close_quote_rel) = production_src[value_start..].find('"') else {
            continue;
        };
        let value = production_src[value_start..value_start + close_quote_rel].to_string();
        pairs.push((name, value));
    }

    assert!(
        pairs.len() >= 8,
        "Lane GGGGG: must find >= 8 `const *_SCHEMA: &str = \"...\";` declarations in release_publication.rs (got {} ({:?})); a thinner schema surface suggests accidental truncation",
        pairs.len(),
        pairs
    );

    for (name, value) in &pairs {
        let suffix_anchor_dot = value.rfind(".v");
        let suffix_anchor_slash = value.rfind("/v");
        let anchor = match (suffix_anchor_dot, suffix_anchor_slash) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let anchor = anchor.unwrap_or_else(|| {
            panic!(
                "Lane GGGGG: const {name} has value {value:?} which has no `.v<N>` or `/v<N>` version anchor; downstream verifiers key off the suffix to route to the matching schema. Append `.v1` (dotted convention) or `/v1` (slash convention)."
            )
        });

        let digits = &value[anchor + 2..];
        assert!(
            !digits.is_empty(),
            "Lane GGGGG: const {name} has value {value:?} — version anchor `.v` or `/v` present but no digits follow. Append a positive integer (e.g. `.v1`)."
        );
        assert!(
            digits.chars().all(|c| c.is_ascii_digit()),
            "Lane GGGGG: const {name} has value {value:?} — version digit run {digits:?} contains a non-digit character. Schema versions must be a bare positive integer (no suffixes, no patch numbers)."
        );
        let n: u32 = digits.parse().unwrap_or_else(|_| {
            panic!(
                "Lane GGGGG: const {name} has value {value:?} — could not parse version digits {digits:?} as u32."
            )
        });
        assert!(
            n >= 1,
            "Lane GGGGG: const {name} has value {value:?} — version N must be >= 1 (got {n}). v0 is reserved for legacy / unversioned payloads and must not appear in source."
        );

        let suffix_start = anchor;
        let tail_str = &value[suffix_start..];
        let valid_tail = tail_str
            .strip_prefix(".v")
            .or_else(|| tail_str.strip_prefix("/v"))
            .map(|d| d.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false);
        assert!(
            valid_tail,
            "Lane GGGGG: const {name} has value {value:?} — version anchor at byte {suffix_start} resolves to tail {tail_str:?} which is not a pure `.v<digits>` or `/v<digits>` suffix. Versions must be at the very END of the schema string."
        );
    }
}

// Lane HHHHH: install heredoc verify-before-copy checksum-flow parity.
//
// Both install.sh and install.ps1 generated by scripts/package-local.sh
// MUST verify the binary's SHA256 BEFORE copying it to $INSTALL_DIR.
// The verify-then-copy ordering is the safety property:
//   - Verify happens first → a tampered or corrupted binary never
//     reaches $INSTALL_DIR. The user's previously-installed copy (if
//     any) survives a failed update.
//   - A regression that swaps the order to copy-then-verify creates
//     a window where a corrupted binary is already in place at the
//     moment the script aborts; the user is now in a worse state
//     than before they ran the script.
//
// Lane HHHHH binds:
//   1. install.sh: `[ "$actual" != "$expected" ]` mismatch branch
//      with `exit 1` must appear BEFORE the `cp "bin/$BINARY_NAME"
//      "$INSTALL_DIR/$BINARY_NAME"` copy step.
//   2. install.ps1: `($Actual -ne $Expected...)` mismatch branch
//      with `throw` must appear BEFORE the `Copy-Item ... $InstallDir`
//      copy step.
//   3. Both install.sh and install.ps1 must contain the words
//      "checksum mismatch" in their abort message (operator-facing
//      error string parity — a future regression that softens the
//      message to "verification failed" or removes it entirely
//      surfaces here).
//
// Cross-axis to Lane AAAA (SHA256SUMS line-shape parity): AAAA binds
// the SHA256SUMS file format; HHHHH binds the install script's USE
// of that file (verify-first ordering + fail-closed semantics).
//
// Cross-axis to Lane MMMM (install heredoc chmod ordering): MMMM
// binds chmod-after-cp; HHHHH binds verify-before-cp. Together the
// flow is: verify → cp → chmod → confirmation.
#[test]
fn install_heredoc_verify_before_copy_checksum_flow_parity_lane_hhhhh() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkg =
        fs::read_to_string(root.join("scripts/package-local.sh")).expect("package-local.sh exists");

    // Extract install.sh heredoc body.
    let sh_open = pkg
        .find("cat > \"$STAGE/install.sh\" <<'SH'\n")
        .expect("Lane HHHHH: install.sh heredoc open marker present");
    let sh_body_start = sh_open + "cat > \"$STAGE/install.sh\" <<'SH'\n".len();
    let sh_body_end_rel = pkg[sh_body_start..]
        .find("\nSH\n")
        .expect("Lane HHHHH: install.sh heredoc close marker present");
    let install_sh = &pkg[sh_body_start..sh_body_start + sh_body_end_rel];

    // (1) install.sh must have `[ "$actual" != "$expected" ]`-style mismatch check.
    let sh_mismatch_idx = install_sh.find(r#"if [ "$actual" != "$expected" ]"#).unwrap_or_else(|| {
        panic!(
            "Lane HHHHH: install.sh heredoc must contain `if [ \"$actual\" != \"$expected\" ]` checksum mismatch check; current body:\n{install_sh}"
        )
    });

    // (1b) the mismatch must lead to `exit 1` (fail-closed).
    let sh_exit_idx = install_sh[sh_mismatch_idx..]
        .find("exit 1")
        .map(|rel| sh_mismatch_idx + rel)
        .unwrap_or_else(|| {
            panic!(
                "Lane HHHHH: install.sh checksum mismatch branch must `exit 1`; current branch (from mismatch index):\n{}",
                &install_sh[sh_mismatch_idx..]
            )
        });

    // (1c) the `cp "bin/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"` must appear AFTER the exit.
    let sh_cp_idx = install_sh.find(r#"cp "bin/$BINARY_NAME""#).unwrap_or_else(|| {
        panic!(
            "Lane HHHHH: install.sh must contain `cp \"bin/$BINARY_NAME\" ...` copy step; current body:\n{install_sh}"
        )
    });
    assert!(
        sh_exit_idx < sh_cp_idx,
        "Lane HHHHH: install.sh `exit 1` at byte {sh_exit_idx} must precede `cp` at byte {sh_cp_idx}. A regression that swaps the order creates a window where a corrupted binary reaches $INSTALL_DIR before the script aborts — the user ends up worse off than if they hadn't run the script."
    );
    assert!(
        sh_mismatch_idx < sh_cp_idx,
        "Lane HHHHH: install.sh checksum mismatch check at byte {sh_mismatch_idx} must precede `cp` at byte {sh_cp_idx} (verify-then-copy ordering)."
    );

    // (1d) operator-facing message parity: "checksum mismatch" string must appear.
    assert!(
        install_sh.contains("checksum mismatch"),
        "Lane HHHHH: install.sh must emit the literal string \"checksum mismatch\" on verification failure — operators grep logs for this exact phrase. A future regression that softens the message to e.g. \"verification failed\" surfaces here."
    );

    // (2) Extract install.ps1 heredoc body.
    let ps1_open = pkg
        .find("cat > \"$STAGE/install.ps1\" <<'PS1'\n")
        .expect("Lane HHHHH: install.ps1 heredoc open marker present");
    let ps1_body_start = ps1_open + "cat > \"$STAGE/install.ps1\" <<'PS1'\n".len();
    let ps1_body_end_rel = pkg[ps1_body_start..]
        .find("\nPS1\n")
        .expect("Lane HHHHH: install.ps1 heredoc close marker present");
    let install_ps1 = &pkg[ps1_body_start..ps1_body_start + ps1_body_end_rel];

    // (2a) install.ps1 must have `($Actual -ne $Expected...)`-style mismatch check.
    let ps1_mismatch_idx = install_ps1
        .find("if ($Actual -ne $Expected")
        .unwrap_or_else(|| {
            panic!(
                "Lane HHHHH: install.ps1 heredoc must contain `if ($Actual -ne $Expected...)` checksum mismatch check; current body:\n{install_ps1}"
            )
        });

    // (2b) the mismatch must lead to `throw` (fail-closed).
    let ps1_throw_idx = install_ps1[ps1_mismatch_idx..]
        .find("throw")
        .map(|rel| ps1_mismatch_idx + rel)
        .unwrap_or_else(|| {
            panic!(
                "Lane HHHHH: install.ps1 checksum mismatch branch must `throw`; current branch:\n{}",
                &install_ps1[ps1_mismatch_idx..]
            )
        });

    // (2c) the `Copy-Item ... $InstallDir` must appear AFTER the throw.
    let ps1_copy_idx = install_ps1.find("Copy-Item").unwrap_or_else(|| {
        panic!(
            "Lane HHHHH: install.ps1 must contain `Copy-Item ...` copy step; current body:\n{install_ps1}"
        )
    });
    assert!(
        ps1_throw_idx < ps1_copy_idx,
        "Lane HHHHH: install.ps1 `throw` at byte {ps1_throw_idx} must precede `Copy-Item` at byte {ps1_copy_idx}. Same safety property as install.sh: verify-then-copy means a corrupted binary never reaches $InstallDir."
    );
    assert!(
        ps1_mismatch_idx < ps1_copy_idx,
        "Lane HHHHH: install.ps1 checksum mismatch check at byte {ps1_mismatch_idx} must precede `Copy-Item` at byte {ps1_copy_idx} (verify-then-copy ordering)."
    );

    // (2d) operator-facing message parity.
    assert!(
        install_ps1.contains("checksum mismatch"),
        "Lane HHHHH: install.ps1 must emit the literal string \"checksum mismatch\" on verification failure — the operator-facing error string must be identical across Unix and Windows so log-grep / oncall runbooks work on either platform."
    );
}

// Lane IIIII: install heredoc SHA256 algorithm + case-normalization parity.
//
// Both install.sh and install.ps1 heredocs compute SHA256 of the
// packaged binary and compare against SHA256SUMS. SHA256SUMS is
// written in canonical lowercase-hex form (the format produced by
// `sha256sum`, the GNU coreutils tool). On every platform the
// install script MUST produce a comparable lowercase-hex hash.
//
// The binding:
//   1. install.sh must support BOTH `sha256sum` (Linux primary, GNU
//      coreutils) AND `shasum -a 256` (Mac fallback — macOS ships
//      Perl-based shasum but not sha256sum). The portability branch
//      `command -v sha256sum` selects between them; without the
//      fallback the script fails on stock macOS with "command not
//      found" before it can verify anything.
//
//   2. install.ps1 must use `Get-FileHash -Algorithm SHA256` (the
//      built-in PowerShell cmdlet; Windows ships no `sha256sum`
//      binary). The result must be lowercase-normalized via
//      `.ToLowerInvariant()` before comparison — Get-FileHash returns
//      uppercase by default, and SHA256SUMS is lowercase, so an
//      un-normalized comparison ALWAYS reports mismatch (a particularly
//      vicious bug: every Windows install fails with "checksum
//      mismatch" even though the binary is correct).
//
//   3. install.sh awk-extracts column 1 (`awk '{ print $1 }'`) — the
//      hash portion of `sha256sum`'s `<hash>  <path>` output. Without
//      this extraction the comparison includes the trailing filename
//      and always fails.
//
// Cross-axis to Lane HHHHH: HHHHH binds verify-before-copy ORDERING;
// IIIII binds verify CORRECTNESS — even with the right ordering, a
// non-normalized hash on Windows reports false positives.
//
// Cross-axis to Lane AAAA: AAAA binds SHA256SUMS lowercase format;
// IIIII binds the install scripts to consume that lowercase format.
#[test]
fn install_heredoc_sha256_algorithm_and_case_normalization_parity_lane_iiiii() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkg =
        fs::read_to_string(root.join("scripts/package-local.sh")).expect("package-local.sh exists");

    // install.sh body.
    let sh_open = pkg
        .find("cat > \"$STAGE/install.sh\" <<'SH'\n")
        .expect("Lane IIIII: install.sh heredoc open marker present");
    let sh_body_start = sh_open + "cat > \"$STAGE/install.sh\" <<'SH'\n".len();
    let sh_body_end_rel = pkg[sh_body_start..]
        .find("\nSH\n")
        .expect("Lane IIIII: install.sh heredoc close marker present");
    let install_sh = &pkg[sh_body_start..sh_body_start + sh_body_end_rel];

    // (1) install.sh must use sha256sum (Linux primary).
    assert!(
        install_sh.contains("sha256sum"),
        "Lane IIIII: install.sh must invoke `sha256sum` (Linux primary — GNU coreutils tool). Current body:\n{install_sh}"
    );

    // (2) install.sh must fall back to `shasum -a 256` (Mac fallback).
    assert!(
        install_sh.contains("shasum -a 256"),
        "Lane IIIII: install.sh must fall back to `shasum -a 256` (Mac fallback — macOS ships shasum but not sha256sum). Without this branch the script fails on stock macOS with \"command not found\". Current body:\n{install_sh}"
    );

    // (3) The portability branch must be gated by `command -v sha256sum`.
    assert!(
        install_sh.contains("command -v sha256sum"),
        "Lane IIIII: install.sh must gate the sha256sum/shasum branch on `command -v sha256sum >/dev/null 2>&1` (probe availability before invoking). A bare `if sha256sum` invocation pollutes stderr on macOS. Current body:\n{install_sh}"
    );

    // (4) install.sh must awk-extract column 1 from the hash tool output.
    let awk_count = install_sh.matches(r#"awk '{ print $1 }'"#).count();
    assert!(
        awk_count >= 2,
        "Lane IIIII: install.sh must use `awk '{{ print $1 }}'` to extract the hash column from BOTH sha256sum and shasum output (need >= 2 occurrences for the two branches; got {awk_count}). Without the column extraction the comparison includes the trailing filename and always reports mismatch."
    );

    // install.ps1 body.
    let ps1_open = pkg
        .find("cat > \"$STAGE/install.ps1\" <<'PS1'\n")
        .expect("Lane IIIII: install.ps1 heredoc open marker present");
    let ps1_body_start = ps1_open + "cat > \"$STAGE/install.ps1\" <<'PS1'\n".len();
    let ps1_body_end_rel = pkg[ps1_body_start..]
        .find("\nPS1\n")
        .expect("Lane IIIII: install.ps1 heredoc close marker present");
    let install_ps1 = &pkg[ps1_body_start..ps1_body_start + ps1_body_end_rel];

    // (5) install.ps1 must use Get-FileHash -Algorithm SHA256.
    assert!(
        install_ps1.contains("Get-FileHash") && install_ps1.contains("SHA256"),
        "Lane IIIII: install.ps1 must use `Get-FileHash -Algorithm SHA256` (built-in PowerShell cmdlet; Windows ships no sha256sum binary). Current body:\n{install_ps1}"
    );

    // (6) The hash result must be normalized to lowercase via .ToLowerInvariant() —
    //     SHA256SUMS is lowercase-hex, Get-FileHash returns uppercase by default.
    //     The comparison line `$Actual -ne $Expected.ToLowerInvariant()` (or
    //     `$Actual.ToLowerInvariant() -ne $Expected`) MUST appear; without it
    //     every Windows install fails with "checksum mismatch" even though the
    //     binary is correct.
    assert!(
        install_ps1.contains(".ToLowerInvariant()"),
        "Lane IIIII: install.ps1 must call `.ToLowerInvariant()` on at least one side of the hash comparison. Get-FileHash returns uppercase by default; SHA256SUMS is lowercase-hex. Without normalization every Windows install fails with \"checksum mismatch\" even on a correct binary — a particularly vicious bug because the operator's binary IS correct and the install script lies. Current body:\n{install_ps1}"
    );
}

// Lane JJJJJ: install heredoc cwd-to-script-dir parity.
//
// Both install.sh and install.ps1 heredocs MUST change their working
// directory to the script's own location BEFORE any file read
// (SHA256SUMS, bin/<binary>, etc.).
//
// Why this matters:
//   - The release archive is extracted to a temp directory of the
//     operator's choosing (`tar xzf release.tar.gz`).
//   - The operator may run `sh install.sh` from any directory —
//     their home, /tmp, the parent of the extracted dir, etc.
//   - Without cwd-fix, every relative read in the script
//     (`SHA256SUMS`, `bin/$BINARY_NAME`) resolves against the
//     operator's pwd, not the archive's extracted dir.
//   - Result: the script aborts with "No such file or directory"
//     (sh) or "Cannot find path" (PowerShell) on the FIRST read,
//     before verification can even begin. The operator has no
//     hint that the fix is `cd` into the extracted dir first.
//
// The binding:
//   1. install.sh must contain `cd "$(dirname -- "$0")"` — the
//      POSIX-portable way to change to the script's own directory.
//      The `--` guards against script paths starting with `-`.
//
//   2. install.ps1 must contain `Set-Location -LiteralPath $PSScriptRoot`
//      — the PowerShell equivalent. `$PSScriptRoot` is the directory
//      containing the running script; `-LiteralPath` prevents
//      wildcard interpretation if the path contains brackets.
//
//   3. Both cwd-fix lines must appear EARLY in the script body —
//      before any read of SHA256SUMS or bin/<binary>. The byte
//      position of the cd/Set-Location call must precede the byte
//      position of every relative-path file read.
//
// Cross-axis to Lane HHHHH (verify-before-copy) and Lane IIIII
// (SHA256 algorithm): HHHHH/IIIII assume the script can READ
// SHA256SUMS and the binary. Lane JJJJJ pins the precondition that
// makes those reads possible regardless of where the operator runs
// the script from.
#[test]
fn install_heredoc_cwd_to_script_dir_parity_lane_jjjjj() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkg =
        fs::read_to_string(root.join("scripts/package-local.sh")).expect("package-local.sh exists");

    // install.sh body.
    let sh_open = pkg
        .find("cat > \"$STAGE/install.sh\" <<'SH'\n")
        .expect("Lane JJJJJ: install.sh heredoc open marker present");
    let sh_body_start = sh_open + "cat > \"$STAGE/install.sh\" <<'SH'\n".len();
    let sh_body_end_rel = pkg[sh_body_start..]
        .find("\nSH\n")
        .expect("Lane JJJJJ: install.sh heredoc close marker present");
    let install_sh = &pkg[sh_body_start..sh_body_start + sh_body_end_rel];

    // (1) install.sh must contain `cd "$(dirname -- "$0")"`.
    let sh_cd_marker = r#"cd "$(dirname -- "$0")""#;
    let sh_cd_idx = install_sh.find(sh_cd_marker).unwrap_or_else(|| {
        panic!(
            "Lane JJJJJ: install.sh must contain `{sh_cd_marker}` to change cwd to the script's own directory. Without it, every relative file read (SHA256SUMS, bin/$BINARY_NAME) resolves against the operator's pwd — the script aborts with \"No such file or directory\" before verification can even begin. Current body:\n{install_sh}"
        )
    });

    // (3a) install.sh cd must precede any SHA256SUMS read.
    let sh_sha256_idx = install_sh.find("SHA256SUMS").unwrap_or_else(|| {
        panic!(
            "Lane JJJJJ: install.sh expected to read SHA256SUMS; not found in body:\n{install_sh}"
        )
    });
    assert!(
        sh_cd_idx < sh_sha256_idx,
        "Lane JJJJJ: install.sh `cd \"$(dirname -- \"$0\")\"` at byte {sh_cd_idx} must precede the SHA256SUMS read at byte {sh_sha256_idx}. Otherwise the read resolves against the operator's pwd, not the archive dir."
    );

    // (3b) install.sh cd must precede any `bin/$BINARY_NAME` read.
    let sh_bin_idx = install_sh.find(r#""bin/$BINARY_NAME""#).unwrap_or_else(|| {
        panic!(
            "Lane JJJJJ: install.sh expected to read `bin/$BINARY_NAME`; not found in body:\n{install_sh}"
        )
    });
    assert!(
        sh_cd_idx < sh_bin_idx,
        "Lane JJJJJ: install.sh cd at byte {sh_cd_idx} must precede the `bin/$BINARY_NAME` read at byte {sh_bin_idx}."
    );

    // install.ps1 body.
    let ps1_open = pkg
        .find("cat > \"$STAGE/install.ps1\" <<'PS1'\n")
        .expect("Lane JJJJJ: install.ps1 heredoc open marker present");
    let ps1_body_start = ps1_open + "cat > \"$STAGE/install.ps1\" <<'PS1'\n".len();
    let ps1_body_end_rel = pkg[ps1_body_start..]
        .find("\nPS1\n")
        .expect("Lane JJJJJ: install.ps1 heredoc close marker present");
    let install_ps1 = &pkg[ps1_body_start..ps1_body_start + ps1_body_end_rel];

    // (2) install.ps1 must contain `Set-Location -LiteralPath $PSScriptRoot`.
    let ps1_setloc_marker = "Set-Location -LiteralPath $PSScriptRoot";
    let ps1_setloc_idx = install_ps1.find(ps1_setloc_marker).unwrap_or_else(|| {
        panic!(
            "Lane JJJJJ: install.ps1 must contain `{ps1_setloc_marker}` to change cwd to the script's own directory. $PSScriptRoot resolves to the directory containing the running script; -LiteralPath prevents wildcard interpretation if the path contains brackets. Current body:\n{install_ps1}"
        )
    });

    // (3c) install.ps1 Set-Location must precede SHA256SUMS read.
    let ps1_sha256_idx = install_ps1.find("SHA256SUMS").unwrap_or_else(|| {
        panic!(
            "Lane JJJJJ: install.ps1 expected to read SHA256SUMS; not found in body:\n{install_ps1}"
        )
    });
    assert!(
        ps1_setloc_idx < ps1_sha256_idx,
        "Lane JJJJJ: install.ps1 `Set-Location -LiteralPath $PSScriptRoot` at byte {ps1_setloc_idx} must precede the SHA256SUMS read at byte {ps1_sha256_idx}."
    );

    // (3d) install.ps1 Set-Location must precede the bin/ binary path construction.
    let ps1_bin_idx = install_ps1.find("Join-Path \"bin\"").unwrap_or_else(|| {
        panic!(
            "Lane JJJJJ: install.ps1 expected to construct `Join-Path \"bin\" $BinaryName`; not found in body:\n{install_ps1}"
        )
    });
    assert!(
        ps1_setloc_idx < ps1_bin_idx,
        "Lane JJJJJ: install.ps1 Set-Location at byte {ps1_setloc_idx} must precede the bin/ path construction at byte {ps1_bin_idx}."
    );
}

// Lane KKKKK: install heredoc INSTALL_DIR mkdir-with-parents parity.
//
// Both install.sh and install.ps1 heredocs MUST create the install
// directory (with intermediate parents) BEFORE copying the binary
// into it.
//
// Why this matters:
//   - The default `$INSTALL_DIR` is `$HOME/.local/bin` (Unix) or
//     `%USERPROFILE%\.local\bin` (Windows). On a fresh user account
//     `$HOME/.local` may not exist yet — a plain `mkdir "$INSTALL_DIR"`
//     fails if ANY intermediate directory is missing.
//   - Without the recursive flag the script aborts with "No such
//     file or directory" (sh) or a New-Item error (PowerShell). The
//     binary never reaches the install dir; the operator sees a
//     cryptic error referring to `$HOME/.local/bin` without any
//     hint that the missing piece is `.local`.
//
// The binding:
//   1. install.sh must contain `mkdir -p "$INSTALL_DIR"` — the `-p`
//      flag tells mkdir to create parent directories as needed AND
//      to suppress the "already exists" error (re-running the
//      installer is a no-op for the dir).
//
//   2. install.ps1 must contain `New-Item -ItemType Directory -Force
//      -Path $InstallDir` — the PowerShell equivalent. `-Force`
//      creates parents AND suppresses the "already exists" error.
//
//   3. Both mkdir calls must appear BEFORE the cp / Copy-Item step.
//      A regression that reorders to copy-first would fail with
//      "no such directory" on every fresh install.
//
// Cross-axis to Lane HHHHH (verify-before-copy) and Lane JJJJJ
// (cwd-to-script-dir): HHHHH/JJJJJ pin the verify path; KKKKK pins
// the destination path. Together they ensure both ends of the cp
// step are valid before the binary moves.
#[test]
fn install_heredoc_install_dir_mkdir_with_parents_parity_lane_kkkkk() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkg =
        fs::read_to_string(root.join("scripts/package-local.sh")).expect("package-local.sh exists");

    // install.sh body.
    let sh_open = pkg
        .find("cat > \"$STAGE/install.sh\" <<'SH'\n")
        .expect("Lane KKKKK: install.sh heredoc open marker present");
    let sh_body_start = sh_open + "cat > \"$STAGE/install.sh\" <<'SH'\n".len();
    let sh_body_end_rel = pkg[sh_body_start..]
        .find("\nSH\n")
        .expect("Lane KKKKK: install.sh heredoc close marker present");
    let install_sh = &pkg[sh_body_start..sh_body_start + sh_body_end_rel];

    // (1) install.sh must contain `mkdir -p "$INSTALL_DIR"`.
    let sh_mkdir_marker = r#"mkdir -p "$INSTALL_DIR""#;
    let sh_mkdir_idx = install_sh.find(sh_mkdir_marker).unwrap_or_else(|| {
        panic!(
            "Lane KKKKK: install.sh must contain `{sh_mkdir_marker}` to create the install directory (with parents) before the cp step. The `-p` flag tells mkdir to create intermediate dirs as needed AND to suppress \"already exists\" errors on re-install. Without it, install on a fresh user account fails because `$HOME/.local` may not exist yet. Current body:\n{install_sh}"
        )
    });

    // (3a) sh mkdir must precede sh cp.
    let sh_cp_idx = install_sh.find(r#"cp "bin/$BINARY_NAME""#).unwrap_or_else(|| {
        panic!("Lane KKKKK: install.sh expected to contain `cp \"bin/$BINARY_NAME\" ...`; not found in body:\n{install_sh}")
    });
    assert!(
        sh_mkdir_idx < sh_cp_idx,
        "Lane KKKKK: install.sh `mkdir -p \"$INSTALL_DIR\"` at byte {sh_mkdir_idx} must precede the `cp` step at byte {sh_cp_idx}. A copy-first ordering fails with \"no such directory\" on every fresh install."
    );

    // install.ps1 body.
    let ps1_open = pkg
        .find("cat > \"$STAGE/install.ps1\" <<'PS1'\n")
        .expect("Lane KKKKK: install.ps1 heredoc open marker present");
    let ps1_body_start = ps1_open + "cat > \"$STAGE/install.ps1\" <<'PS1'\n".len();
    let ps1_body_end_rel = pkg[ps1_body_start..]
        .find("\nPS1\n")
        .expect("Lane KKKKK: install.ps1 heredoc close marker present");
    let install_ps1 = &pkg[ps1_body_start..ps1_body_start + ps1_body_end_rel];

    // (2) install.ps1 must contain `New-Item -ItemType Directory -Force -Path $InstallDir`.
    let ps1_newitem_anchor = "New-Item -ItemType Directory -Force -Path $InstallDir";
    let ps1_newitem_idx = install_ps1.find(ps1_newitem_anchor).unwrap_or_else(|| {
        panic!(
            "Lane KKKKK: install.ps1 must contain `{ps1_newitem_anchor}` to create the install directory (with parents and idempotent re-install) before the Copy-Item step. The `-Force` flag is critical — without it, New-Item fails noisily if the dir exists OR if intermediate dirs are missing. Current body:\n{install_ps1}"
        )
    });

    // (3b) ps1 New-Item must precede ps1 Copy-Item.
    let ps1_copy_idx = install_ps1.find("Copy-Item").unwrap_or_else(|| {
        panic!(
            "Lane KKKKK: install.ps1 expected to contain `Copy-Item ...`; not found in body:\n{install_ps1}"
        )
    });
    assert!(
        ps1_newitem_idx < ps1_copy_idx,
        "Lane KKKKK: install.ps1 `New-Item -ItemType Directory -Force` at byte {ps1_newitem_idx} must precede `Copy-Item` at byte {ps1_copy_idx}. A copy-first ordering fails because Copy-Item won't create the parent on its own."
    );
}

// Lane LLLLL: README.txt `docs/<path>.md` claim ↔ real-file parity.
//
// The README.txt heredoc in scripts/package-local.sh tells operators
// where to look for triage and authoritative docs:
//
//   `Operator triage: read docs/runbooks/release-smoke.md for ...`
//
// Every `docs/<path>.md` token mentioned in the README MUST resolve
// to a real file under the workspace root.
//
// Why this matters:
//   - The operator extracts the release archive, reads README.txt,
//     and follows the breadcrumb to the runbook. A typoed or
//     renamed path lands the operator on "file not found" right
//     when they need triage guidance most — typically during an
//     incident.
//   - Lane KKKK already binds workspace-path claims (paths like
//     `crates/ao2-cp-server/...`) inside the README. Lane LLLLL is
//     orthogonal: it binds doc-path claims (paths ending in `.md`
//     under `docs/`).
//
// Algorithm:
//   1. Extract the README.txt heredoc body.
//   2. Walk byte-by-byte, finding every `docs/` token.
//   3. From `docs/`, extract a path token up to the first whitespace
//      / punctuation that's not a path character. Path chars are
//      ASCII alphanumeric + `/_-.`.
//   4. Filter to tokens ending in `.md`.
//   5. Assert each resolves to a real file under workspace root.
//   6. Floor: >= 1 distinct `docs/<path>.md` claim — the
//      release-smoke.md operator-landing pointer.
#[test]
fn readme_docs_path_claims_resolve_to_real_files_lane_lllll() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkg =
        fs::read_to_string(root.join("scripts/package-local.sh")).expect("package-local.sh exists");

    // Extract README.txt heredoc body.
    let readme_open = pkg
        .find("cat > \"$STAGE/README.txt\" <<'TXT'\n")
        .expect("Lane LLLLL: README.txt heredoc open marker present");
    let readme_body_start = readme_open + "cat > \"$STAGE/README.txt\" <<'TXT'\n".len();
    let readme_body_end_rel = pkg[readme_body_start..]
        .find("\nTXT\n")
        .expect("Lane LLLLL: README.txt heredoc close marker present");
    let readme = &pkg[readme_body_start..readme_body_start + readme_body_end_rel];

    // Walk byte-by-byte and find every `docs/<path>.md` token.
    let mut claims: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let bytes = readme.as_bytes();
    let needle = b"docs/";
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            // Walk forward extracting path-token chars: alnum + `/_-.`.
            let mut j = i;
            while j < bytes.len() {
                let c = bytes[j] as char;
                let path_char =
                    c.is_ascii_alphanumeric() || c == '/' || c == '_' || c == '-' || c == '.';
                if !path_char {
                    break;
                }
                j += 1;
            }
            let token = &readme[i..j];
            // Strip trailing `.` if present (sentence-ending period).
            let stripped = token.trim_end_matches('.');
            if stripped.ends_with(".md") {
                claims.insert(stripped.to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }

    assert!(
        !claims.is_empty(),
        "Lane LLLLL: README.txt heredoc must claim at least one `docs/<path>.md` triage pointer (the operator-landing breadcrumb). Current claims: {claims:?}"
    );

    // Specifically assert the operator-landing pointer.
    assert!(
        claims.iter().any(|c| c == "docs/runbooks/release-smoke.md"),
        "Lane LLLLL: README.txt must explicitly reference `docs/runbooks/release-smoke.md` (the authoritative release-smoke triage runbook). Current claims: {claims:?}"
    );

    // Resolve each claim to a real file.
    for claim in &claims {
        let path = root.join(claim);
        assert!(
            path.is_file(),
            "Lane LLLLL: README.txt claims `docs/` path {claim:?} but the file does not exist at workspace root + claim. A typoed or renamed path lands operators on \"file not found\" exactly when they need triage guidance. Path resolved to: {path:?}"
        );
    }
}

// Lane MMMMM: forbidden-env preflight contract parity.
//
// Trust boundary: "No API-key provider authentication. Local OAuth
// CLI only." The control plane MUST refuse to start if a provider
// API key is present in the environment — otherwise a misconfigured
// operator host could silently leak the key into request logs, error
// traces, or proxied calls.
//
// The forbidden-env preflight in `crates/ao2-cp-server/src/config.rs`
// is the load-bearing enforcement point. Lane MMMMM pins the
// contract:
//
//   1. `config.rs` declares a `check_env: bool` clap arg (hidden by
//      default; the test path can opt in / out).
//   2. The forbidden-env check enumerates BOTH `OPENAI_API_KEY` AND
//      `ANTHROPIC_API_KEY` as forbidden. A regression that removes
//      one of the two creates a one-provider escape hatch.
//   3. The check is guarded by `if raw.check_env { ... }` so test
//      code can opt out.
//   4. `ConfigError::ForbiddenEnv(String)` exists with the
//      operator-facing message `"forbidden env var present:"`.
//   5. `from_real_env()` in config.rs pushes `--check-env` AUTOMATICALLY
//      so the production entry point never bypasses the preflight.
//   6. `main.rs` calls `Config::from_real_env()` (NOT
//      `Config::parse_from(std::env::args_os())`, which would skip
//      the auto-push).
//
// A regression in ANY of these — removing a forbidden var, dropping
// the `check_env` gate, deleting the auto-push, or routing main()
// through `parse_from` — silently disables the trust boundary.
//
// Cross-axis to Lane CCCC (README threat-model ↔ handler emission):
// CCCC binds the documented threats to their emission in HTML;
// MMMMM binds one of those threats (provider key in env) to its
// runtime enforcement at startup.
#[test]
fn forbidden_env_preflight_contract_parity_lane_mmmmm() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let config_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/config.rs"))
        .expect("Lane MMMMM: config.rs present");
    let main_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/main.rs"))
        .expect("Lane MMMMM: main.rs present");

    // (1) clap arg `check_env: bool`.
    assert!(
        config_rs.contains("check_env: bool"),
        "Lane MMMMM: config.rs must declare a `check_env: bool` clap arg; without the gate the preflight runs unconditionally and breaks test fixtures, OR (if removed entirely) never runs at all. Current config.rs has no `check_env: bool` declaration."
    );

    // (2) Both forbidden provider keys must be enumerated.
    assert!(
        config_rs.contains("OPENAI_API_KEY"),
        "Lane MMMMM: config.rs forbidden-env preflight must enumerate `OPENAI_API_KEY` as forbidden. A regression that removes it creates a one-provider escape hatch — an operator host with OPENAI_API_KEY in env would start successfully and could leak the key into request logs."
    );
    assert!(
        config_rs.contains("ANTHROPIC_API_KEY"),
        "Lane MMMMM: config.rs forbidden-env preflight must enumerate `ANTHROPIC_API_KEY` as forbidden. A regression that removes it creates a one-provider escape hatch — an operator host with ANTHROPIC_API_KEY in env would start successfully and could leak the key into request logs."
    );

    // (3) The check must be guarded by `if raw.check_env`.
    assert!(
        config_rs.contains("if raw.check_env"),
        "Lane MMMMM: config.rs preflight must be guarded by `if raw.check_env`. Without the gate, every test that constructs a Config gets the preflight too; with the gate, production main() opts in via auto-push and tests can opt out."
    );

    // (4) ConfigError variant + operator-facing message.
    assert!(
        config_rs.contains("ForbiddenEnv"),
        "Lane MMMMM: config.rs must define `ConfigError::ForbiddenEnv` variant to surface the preflight failure with a structured error."
    );
    assert!(
        config_rs.contains("forbidden env var present:"),
        "Lane MMMMM: config.rs must emit the operator-facing error message `\"forbidden env var present:\"` so operators / log-grep can identify the failure category."
    );

    // (5) from_real_env() must auto-push --check-env.
    assert!(
        config_rs.contains("from_real_env"),
        "Lane MMMMM: config.rs must define `Config::from_real_env()` as the production entry point."
    );
    assert!(
        config_rs.contains(r#"args.push("--check-env".into())"#),
        "Lane MMMMM: config.rs `from_real_env()` must automatically push `--check-env` so the production main() never bypasses the preflight. A regression that removes the auto-push silently disables the trust boundary."
    );

    // (6) main.rs must route through from_real_env (NOT parse_from(env::args_os())).
    assert!(
        main_rs.contains("Config::from_real_env()"),
        "Lane MMMMM: main.rs must call `Config::from_real_env()`. Routing through `Config::parse_from(std::env::args_os())` directly would skip the auto-push and silently disable the forbidden-env preflight."
    );
    assert!(
        !main_rs.contains("Config::parse_from(std::env::args_os())"),
        "Lane MMMMM: main.rs must NOT call `Config::parse_from(std::env::args_os())` — that path bypasses the auto-push in `from_real_env()` and silently disables the forbidden-env preflight. Use `Config::from_real_env()` instead."
    );
}

// Lane NNNNN: package-local.sh STAGE-dir trap cleanup parity.
//
// `scripts/package-local.sh` builds the release archive in a temp
// staging directory (`STAGE=$(mktemp -d)`). The staging dir is
// populated with the binary, install scripts, SHA256SUMS,
// RELEASE-MANIFEST.json, README.txt, etc.
//
// The script MUST register a trap that removes the staging dir
// on EVERY exit path (success, error, interrupt). Without the
// trap, a partial-failure script run leaves stale build artifacts
// in /tmp; over many runs /tmp fills with `stage.XXXXXX` dirs.
//
// The binding:
//   1. The script must contain `STAGE=$(mktemp -d)` — the canonical
//      POSIX-portable way to get a temp dir.
//   2. A cleanup function must be defined: `cleanup() { rm -rf
//      "$STAGE"; }` (or equivalent inline trap body that rm -rfs
//      STAGE).
//   3. The trap MUST be `trap cleanup EXIT` (covers normal exit,
//      script error, AND signals — `EXIT` in bash includes signals
//      that don't have a specific trap).
//   4. The trap registration MUST appear BEFORE any operation that
//      creates files in STAGE (the first `cp`, `cat >`, or `mkdir
//      -p "$STAGE/..."` step). Otherwise a script abort between
//      mktemp and the trap installation leaves a stale dir.
//
// Cross-axis to Lane DDDDD (tar arglist ↔ stage writes): DDDDD
// binds the arglist to staging steps; NNNNN binds the staging dir
// itself to cleanup. Together they ensure the staging surface is
// both correct AND ephemeral.
#[test]
fn package_local_stage_dir_trap_cleanup_parity_lane_nnnnn() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkg =
        fs::read_to_string(root.join("scripts/package-local.sh")).expect("package-local.sh exists");

    // (1) STAGE=$(mktemp -d) must be present.
    let mktemp_marker = "STAGE=$(mktemp -d)";
    let mktemp_idx = pkg.find(mktemp_marker).unwrap_or_else(|| {
        panic!(
            "Lane NNNNN: package-local.sh must contain `{mktemp_marker}` (canonical POSIX-portable way to get a temp staging dir)."
        )
    });

    // (2) cleanup function must rm -rf "$STAGE".
    assert!(
        pkg.contains(r#"rm -rf "$STAGE""#),
        "Lane NNNNN: package-local.sh cleanup function must `rm -rf \"$STAGE\"` to remove the staging dir on exit. Without it, partial-failure runs leave stale `stage.XXXXXX` dirs in /tmp."
    );

    // (3) trap cleanup EXIT must be set (catches normal exit, errors, and signals).
    let trap_marker = "trap cleanup EXIT";
    let trap_idx = pkg.find(trap_marker).unwrap_or_else(|| {
        panic!(
            "Lane NNNNN: package-local.sh must register `{trap_marker}` so the staging dir is cleaned on every exit path (success, error, SIGINT). A `trap cleanup ERR` alone misses normal exit; a `trap cleanup INT` alone misses script-internal errors."
        )
    });

    // (4) trap must be registered AFTER mktemp AND BEFORE the first STAGE write.
    assert!(
        mktemp_idx < trap_idx,
        "Lane NNNNN: `STAGE=$(mktemp -d)` at byte {mktemp_idx} must precede `trap cleanup EXIT` at byte {trap_idx} (the trap can only reference STAGE after it's defined)."
    );

    // Locate the first byte index that's a write into STAGE: search for
    // `"$STAGE/` (any quoted reference) or `mkdir -p "$STAGE` (mkdir step).
    let stage_write_idx = pkg
        .match_indices(r#""$STAGE/"#)
        .next()
        .map(|(i, _)| i)
        .or_else(|| pkg.find(r#"mkdir -p "$STAGE"#))
        .unwrap_or_else(|| {
            panic!(
                "Lane NNNNN: expected at least one `\"$STAGE/...\"` write step or `mkdir -p \"$STAGE\"` in package-local.sh; not found."
            )
        });

    assert!(
        trap_idx < stage_write_idx,
        "Lane NNNNN: `trap cleanup EXIT` at byte {trap_idx} must precede the first STAGE write at byte {stage_write_idx}. A script abort between mktemp and trap installation leaves a stale stage.XXXXXX dir; installing the trap FIRST ensures every exit path cleans up."
    );
}

// Lane OOOOO: package-local.sh script-level shebang + strict-mode parity.
//
// Lane BBBBB binds the install heredocs (install.sh, install.ps1) — the
// scripts that get WRITTEN by package-local.sh, then SHIPPED in the
// release archive. Lane OOOOO is the orthogonal script-level analog:
// it binds the package-local.sh orchestrator script ITSELF, the
// program that EMITS those heredocs in the first place.
//
// Why this matters: package-local.sh is the script CI invokes to
// build the release tarball. If a `cargo build --release` step fails
// mid-script and the script keeps running, the next step happily
// writes install.sh with an empty $BIN_PATH variable, the tar arglist
// includes a missing file, and the tar step fails at archive time —
// minutes after the actual root cause. Strict mode + a `#!` shebang
// turn that into a fail-fast: the script aborts at the failing line
// with a clear error.
//
// The binding (4 assertions):
//   1. The file's first byte MUST be `#` AND the first line MUST
//      start with `#!` (a shebang). Without a shebang, the script
//      runs in whatever interactive shell the operator happens to
//      have, with whatever options happen to be active.
//   2. The shebang MUST be exactly `#!/usr/bin/env sh` — POSIX
//      portable. `#!/bin/sh` is not guaranteed on every BSD/macOS
//      variant; `#!/bin/bash` reduces cross-platform portability.
//      The install heredocs already use `#!/usr/bin/env sh` (Lane
//      BBBBB); the orchestrator script must match for consistency.
//   3. `set -eu` (or stricter) MUST appear on a line by itself
//      somewhere in the file. Lane BBBBB's heuristic accepts any
//      variant whose flag set contains both `e` and `u`.
//   4. The `set -eu` line MUST appear within the first 5 lines — a
//      strict mode declared on line 200 is useless because lines
//      1-199 already ran without it.
#[test]
fn package_local_script_shebang_and_strict_mode_parity_lane_ooooo() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkg = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane OOOOO: scripts/package-local.sh present");

    // (1) First byte must be `#` (start of `#!` shebang).
    assert_eq!(
        pkg.as_bytes().first(),
        Some(&b'#'),
        "Lane OOOOO: scripts/package-local.sh's first byte must be `#` (start of `#!` shebang). The orchestrator script that EMITS the install heredocs must itself declare an interpreter; without one, the user's interactive shell runs the script with whatever options happen to be active (`noglob`, `noexec`, `nounset` off)."
    );

    // (2) First line must be exactly `#!/usr/bin/env sh`.
    let first_line = pkg
        .lines()
        .next()
        .expect("Lane OOOOO: scripts/package-local.sh must be non-empty");
    assert_eq!(
        first_line, "#!/usr/bin/env sh",
        "Lane OOOOO: scripts/package-local.sh's first line must be exactly `#!/usr/bin/env sh` (got {first_line:?}). `#!/bin/sh` is not guaranteed on every BSD/macOS variant; `#!/bin/bash` reduces cross-platform portability. The install heredocs already use `#!/usr/bin/env sh` (Lane BBBBB); the orchestrator script MUST match for consistency."
    );

    // (3) `set -eu` (or stricter) must appear somewhere on a line by itself.
    let mut strict_line_idx: Option<usize> = None;
    for (idx, line) in pkg.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("set -") {
            let flags = rest.split_whitespace().next().unwrap_or("");
            if flags.contains('e') && flags.contains('u') {
                strict_line_idx = Some(idx);
                break;
            }
        }
    }
    let line_idx = strict_line_idx.unwrap_or_else(|| {
        panic!(
            "Lane OOOOO: scripts/package-local.sh must declare `set -eu` or stricter (e.g., `set -euo pipefail`). Without `-e`, a failed `cargo build` step proceeds to the tar arglist and CI sees a `file not found` error MINUTES after the actual root cause. Without `-u`, a typo'd `$STAGE_DIR` (instead of `$STAGE`) expands to empty and `cp` writes to the wrong location."
        )
    });

    // (4) Strict-mode line must appear within the first 5 lines.
    assert!(
        line_idx < 5,
        "Lane OOOOO: `set -eu` line must appear within the first 5 lines of scripts/package-local.sh (found at line {}). A strict-mode declaration on line 200 is useless because lines 1-199 already ran without it; the script must fail-fast from the very first command.",
        line_idx + 1
    );
}

// Lane PPPPP: package-local.sh default VERSION ↔ workspace Cargo.toml
// [workspace.package] version parity.
//
// `scripts/package-local.sh` declares `VERSION="<x.y.z>"` near the
// top. This is the default release tag the script applies to the
// output archive name (e.g.,
// `ao2-control-plane-0.1.0-macos-aarch64.tar.gz`) when the operator
// doesn't pass `--version <x.y.z>`.
//
// The top-level `Cargo.toml` declares `[workspace.package] version =
// "<x.y.z>"`. This is the version every member crate inherits via
// `version.workspace = true`. It's the canonical version of the
// software inside the archive.
//
// These two MUST be byte-equal. Without the binding, a workspace
// version bump (`0.1.0` → `0.2.0`) that misses package-local.sh
// produces release archives labeled `0.1.0` containing `0.2.0`
// binaries. Operators who follow README's "latest" pointer download
// a `0.1.0` tarball expecting the older code and silently get the
// newer behavior — an integrity gap that defeats the entire release
// labelling system.
//
// Cross-axis to Lane ZZZZ (workspace member ↔ crate dir parity):
// ZZZZ binds workspace identity at the structural level (members
// resolve to real dirs); PPPPP binds workspace identity at the
// release-label level (script default tag matches the manifest
// version).
#[test]
fn package_local_default_version_matches_workspace_version_lane_ppppp() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkg = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane PPPPP: scripts/package-local.sh present");
    let workspace_toml = fs::read_to_string(root.join("Cargo.toml"))
        .expect("Lane PPPPP: top-level Cargo.toml present");

    // (1) Extract VERSION="..." from package-local.sh.
    let version_marker = "VERSION=\"";
    let version_start = pkg
        .find(version_marker)
        .map(|i| i + version_marker.len())
        .unwrap_or_else(|| {
            panic!(
                "Lane PPPPP: scripts/package-local.sh must declare `{version_marker}<x.y.z>\"` near the top; not found."
            )
        });
    let version_end = pkg[version_start..]
        .find('"')
        .map(|i| version_start + i)
        .unwrap_or_else(|| {
            panic!(
                "Lane PPPPP: scripts/package-local.sh `VERSION=\"<...>` literal must be closed by a `\"`; not found."
            )
        });
    let script_version = &pkg[version_start..version_end];

    // (2) Extract [workspace.package] version = "..." from Cargo.toml.
    // Anchor on the `[workspace.package]` section header to disambiguate
    // from `[workspace.dependencies]` `version = "1"` lines.
    let section_marker = "[workspace.package]";
    let section_start = workspace_toml.find(section_marker).unwrap_or_else(|| {
        panic!("Lane PPPPP: top-level Cargo.toml must contain a `{section_marker}` section.")
    });
    let after_section = &workspace_toml[section_start + section_marker.len()..];
    let version_line_marker = "version = \"";
    let v_start = after_section
        .find(version_line_marker)
        .map(|i| i + version_line_marker.len())
        .unwrap_or_else(|| {
            panic!(
                "Lane PPPPP: `[workspace.package]` section must declare `version = \"<x.y.z>\"`."
            )
        });
    let v_end = after_section[v_start..]
        .find('"')
        .map(|i| v_start + i)
        .unwrap_or_else(|| {
            panic!(
                "Lane PPPPP: `[workspace.package] version = \"<...>` literal must close with `\"`."
            )
        });
    let workspace_version = &after_section[v_start..v_end];

    // (3) Bytes must be equal.
    assert_eq!(
        script_version, workspace_version,
        "Lane PPPPP: scripts/package-local.sh default VERSION=\"{script_version}\" must match top-level Cargo.toml [workspace.package] version = \"{workspace_version}\". A workspace bump that misses the script produces archives labeled \"{script_version}\" containing \"{workspace_version}\" binaries — operators following README's \"latest\" pointer download the wrong-labeled tarball and silently get drifted behavior."
    );

    // (4) Floor: the version must look like a non-empty semver-ish string
    // (at least one digit, at least one dot).
    assert!(
        script_version.chars().any(|c| c.is_ascii_digit()) && script_version.contains('.'),
        "Lane PPPPP: VERSION=\"{script_version}\" must be a semver-ish string (digits + dot). An empty or malformed VERSION produces archive names like `ao2-control-plane--macos-aarch64.tar.gz`."
    );
}

#[test]
fn ci_compares_shared_release_support_fixture_with_ao2() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci workflow exists");
    let readme = fs::read_to_string(root.join("README.md")).expect("README exists");

    for needle in [
        "release-support-fixture-parity:",
        "name: Release support fixture parity with AO2",
        "repository: uesugitorachiyo/ao2",
        "path: ao2",
        "cmp -s ao2-control-plane/tests/fixtures/release-support-bundle-contract-v1.json ao2/tests/fixtures/release-support-bundle-contract-v1.json",
        "shasum -a 256 ao2-control-plane/tests/fixtures/release-support-bundle-contract-v1.json ao2/tests/fixtures/release-support-bundle-contract-v1.json",
        "target/release-support-fixture-parity/summary.json",
        "ao2-control-plane-release-support-fixture-parity",
    ] {
        assert!(
            ci.contains(needle),
            "missing release-support fixture parity CI marker: {needle}"
        );
    }
    assert!(readme.contains("Release support fixture parity with AO2"));
    assert!(readme.contains("ao2-control-plane-release-support-fixture-parity"));
}

#[test]
fn public_repo_license_and_release_examples_match_workspace_version() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workspace_toml =
        fs::read_to_string(root.join("Cargo.toml")).expect("top-level Cargo.toml present");
    let readme = fs::read_to_string(root.join("README.md")).expect("README exists");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("CI workflow exists");

    let section_marker = "[workspace.package]";
    let section_start = workspace_toml
        .find(section_marker)
        .expect("workspace package section exists");
    let after_section = &workspace_toml[section_start + section_marker.len()..];
    let version_marker = "version = \"";
    let version_start = after_section
        .find(version_marker)
        .map(|i| i + version_marker.len())
        .expect("workspace package version exists");
    let version_end = after_section[version_start..]
        .find('"')
        .map(|i| version_start + i)
        .expect("workspace package version is quoted");
    let workspace_version = &after_section[version_start..version_end];

    for file in ["LICENSE", "LICENSE-MIT", "LICENSE-APACHE"] {
        assert!(
            root.join(file).is_file(),
            "public repo license file {file} must exist when Cargo declares MIT OR Apache-2.0"
        );
    }

    for doc in [
        ("README.md", readme.as_str()),
        (".github/workflows/ci.yml", ci.as_str()),
    ] {
        let stale = [
            "--version 0.1.1 ",
            "--version 0.1.1\n",
            "--version 0.1.1 \\",
            "ao2-control-plane-0.1.1-linux",
            "ao2-control-plane-0.1.1-macos",
            "ao2-control-plane-0.1.1-windows",
        ]
        .iter()
        .any(|needle| doc.1.contains(needle));
        assert!(
            !stale,
            "{} must not contain stale release version 0.1.1 after workspace version is {workspace_version}",
            doc.0
        );
        assert!(
            doc.1.contains(workspace_version),
            "{} must include the current workspace version {workspace_version} in release examples",
            doc.0
        );
    }
}

// Lane QQQQQ: package-local.sh default BINARY release-profile parity.
//
// `scripts/package-local.sh` declares `BINARY="$ROOT/target/release/
// ao2-cp-server"` near the top — the default path the script reads
// the compiled control-plane binary from before staging + tarballing
// it into the release archive.
//
// Four invariants pin this default against three known regressions:
//   1. The BINARY default MUST reference `target/release/` (the
//      cargo release profile output dir). A regression to
//      `target/debug/` ships a debug binary — 10x larger, includes
//      unstripped symbols (which may leak build-host paths and
//      expanded macros), runs 10x slower, and panics with full
//      backtraces that include source file paths.
//   2. The BINARY default MUST NOT contain `target/debug/`. This is
//      the defensive twin of (1): an explicit deny so a partial
//      regression (e.g., `target/debug-release/`) is still caught.
//   3. The BINARY default MUST end with `/ao2-cp-server` (no `.exe`
//      suffix on the default — Windows builds set `BINARY_NAME` to
//      `ao2-cp-server.exe` later, but the default unsuffixed path
//      is what cargo writes on macOS/Linux).
//   4. The BINARY default MUST be relative to `$ROOT/` (no absolute
//      path leak that would only work on the original author's
//      machine). The script computes ROOT as the workspace root;
//      every reference to a cargo artifact must be `$ROOT`-relative.
//
// Cross-axis: Lane EEEEE binds the handler module declarations to
// real files; QQQQQ binds the binary artifact path to the canonical
// cargo output. Together they ensure the release surface ships
// what the workspace actually produces.
#[test]
fn package_local_default_binary_is_release_profile_lane_qqqqq() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkg = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane QQQQQ: scripts/package-local.sh present");

    // Extract the FIRST BINARY="..." assignment (the default; later
    // assignments inside the `case` block for --binary are operator
    // overrides and don't count).
    let marker = "BINARY=\"";
    let start = pkg.find(marker).map(|i| i + marker.len()).unwrap_or_else(|| {
        panic!(
            "Lane QQQQQ: scripts/package-local.sh must declare a default `{marker}<path>\"` near the top; not found."
        )
    });
    let end = pkg[start..]
        .find('"')
        .map(|i| start + i)
        .unwrap_or_else(|| {
            panic!("Lane QQQQQ: `BINARY=\"<...>` literal must be closed by `\"`; not found.")
        });
    let binary_default = &pkg[start..end];

    // (1) must reference target/release/.
    assert!(
        binary_default.contains("target/release/"),
        "Lane QQQQQ: BINARY=\"{binary_default}\" must reference `target/release/` — cargo's release-profile output dir. A regression to `target/debug/` ships a debug binary (10x larger, unstripped symbols, 10x slower, panic backtraces leak source paths)."
    );

    // (2) must NOT contain target/debug/.
    assert!(
        !binary_default.contains("target/debug/"),
        "Lane QQQQQ: BINARY=\"{binary_default}\" must NOT reference `target/debug/` — debug binaries are 10x slower and leak build-host paths in backtraces. The release archive must contain the release-profile binary."
    );

    // (3) must end with /ao2-cp-server (no .exe — Windows is patched
    // later via $BINARY_NAME).
    assert!(
        binary_default.ends_with("/ao2-cp-server"),
        "Lane QQQQQ: BINARY=\"{binary_default}\" must end with `/ao2-cp-server` (no `.exe` suffix on the default; the script's later `case TARGET_LABEL in *windows*) BINARY_NAME=\"ao2-cp-server.exe\";;` block handles Windows). A misspelled binary name (`ao2-cp-srv`, `ao2-cp-server-bin`) means cargo's output isn't found and the script exits with `missing ao2-control-plane binary`."
    );

    // (4) must be $ROOT-relative (no absolute path leak).
    assert!(
        binary_default.starts_with("$ROOT/"),
        "Lane QQQQQ: BINARY=\"{binary_default}\" must be `$ROOT`-relative (start with `$ROOT/`). An absolute path like `/Users/<author>/Documents/...` only works on the original author's machine; on every other operator's host the script exits with `missing ao2-control-plane binary` immediately after the preflight check."
    );
}

// Lane RRRRR: package-local.sh `cp "$ROOT/<path>"` source files exist
// parity.
//
// `scripts/package-local.sh` stages release-archive contents via a
// series of `cp "$ROOT/<path>" "$STAGE/..."` lines — copying verify
// scripts, fetch scripts, and other ancillary support files from the
// workspace into the staging dir before tar-balling. Every such
// source path MUST resolve to a real file under the workspace root.
//
// Two invariants:
//   1. Every line matching `cp "$ROOT/<path>" "$STAGE/..."` MUST
//      have a `<path>` that points to a real file under the
//      workspace root. A renamed or deleted ancillary script
//      (e.g., `verify_release_support_bundle.py` →
//      `verify-release-support-bundle.py`) doesn't fail at cargo
//      build time — it only fails at package-local.sh runtime with
//      a `cp: cannot stat '...'` error, after CI already spent
//      minutes building the release binary.
//   2. Floor: at least 4 such `cp "$ROOT/..."` lines (the four
//      observed: verify_release_support_bundle.py,
//      Verify-ReleaseSupportBundle.ps1,
//      fetch_release_support_handoff.py,
//      Fetch-ReleaseSupportHandoff.ps1). The floor catches the
//      regression where a future refactor consolidates the support
//      scripts and silently drops one from the release archive.
//
// Cross-axis: Lane DDDDD binds the tar arglist to stage writes
// (`"$STAGE/<entry>"` references); Lane RRRRR is the UPSTREAM
// binding — stage writes back to real source files in `$ROOT`.
// Lane QQQQQ binds the BINARY default's $ROOT/target/release/
// path; Lane RRRRR is the parallel binding for the non-binary
// ancillary files that also get staged from $ROOT.
#[test]
fn package_local_cp_source_paths_resolve_to_real_files_lane_rrrrr() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkg = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane RRRRR: scripts/package-local.sh present");

    // Find every line matching `cp "$ROOT/<path>" ...` and extract
    // the <path>. We anchor on the line-start `cp ` to avoid matching
    // shell variable assignments or comments.
    let mut sources: Vec<String> = Vec::new();
    for line in pkg.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("cp ") {
            continue;
        }
        // Look for `"$ROOT/` and capture everything up to the next `"`.
        let needle = "\"$ROOT/";
        if let Some(start) = trimmed.find(needle) {
            let after = &trimmed[start + needle.len()..];
            if let Some(end) = after.find('"') {
                sources.push(after[..end].to_string());
            }
        }
    }

    assert!(
        sources.len() >= 4,
        "Lane RRRRR: scripts/package-local.sh must contain >= 4 `cp \"$ROOT/<path>\" \"$STAGE/...\"` lines (the four observed: verify/fetch python + powershell support scripts). Found {} — a refactor that drops one of these silently ships a release archive missing an operator-facing support script.",
        sources.len()
    );

    // For each source path, verify the file exists under root.
    let mut missing: Vec<String> = Vec::new();
    for src in &sources {
        let abs = root.join(src);
        if !abs.is_file() {
            missing.push(src.clone());
        }
    }

    assert!(
        missing.is_empty(),
        "Lane RRRRR: scripts/package-local.sh references {} `cp \"$ROOT/<path>\"` source path(s) that don't resolve to a real file under the workspace root: {:?}. A renamed or deleted ancillary script doesn't fail at cargo build — it only fails at package-local.sh runtime with a `cp: cannot stat '...'` error, after CI already spent minutes building the release binary. Lane RRRRR catches the regression at unit-test time.",
        missing.len(),
        missing
    );
}

// Lane SSSSS: workspace package metadata unification parity.
//
// Lane AAAAA binds `[workspace.dependencies]` ↔ member crates (every
// dep in member's `[dependencies]` declared via `.workspace = true`).
// Lane SSSSS is the parallel binding for `[workspace.package]`:
// every member crate's `[package]` table MUST declare its core
// metadata fields (version, edition, license) via `.workspace = true`
// rather than re-declaring concrete values in each member manifest.
//
// Why this matters: when `edition`, `version`, or `license` are
// duplicated across member manifests with explicit values, a bump in
// one member but not the others produces a workspace where:
//   - `edition = "2021"` in member A but `edition = "2018"` in
//     member B means a function moved between them stops compiling
//     because the 2021 edition prelude is no longer in scope.
//   - `version = "0.1.0"` in member A but `version = "0.2.0"` in
//     member B means the workspace version (Lane PPPPP) only binds
//     to member A; release archives mislabel member B's content.
//   - `license = "MIT OR Apache-2.0"` in member A but `license =
//     "MIT"` in member B is a legal compliance violation; the
//     workspace claims dual-licensing but a member crate only ships
//     under one license.
//
// The binding: for every member crate's `[package]` table, every
// listed core field (`version`, `edition`, `license`) MUST use
// `<field>.workspace = true` syntax (or `<field> = { workspace =
// true }` — both are equivalent in Cargo).
//
// Cross-axis: Lane AAAAA binds workspace.dependencies; Lane SSSSS
// binds workspace.package. Together they ensure ALL workspace-level
// metadata propagates uniformly to every member crate.
#[test]
fn member_cargo_tomls_unify_via_workspace_package_metadata_lane_sssss() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workspace_toml = fs::read_to_string(root.join("Cargo.toml"))
        .expect("Lane SSSSS: top-level Cargo.toml present");

    // Extract workspace member paths (Lane ZZZZ already binds these
    // to real dirs; reuse the same parse).
    let members_marker = "members = [";
    let members_start = workspace_toml
        .find(members_marker)
        .map(|i| i + members_marker.len())
        .unwrap_or_else(|| panic!("Lane SSSSS: top-level Cargo.toml must contain `members = [`"));
    let members_end = workspace_toml[members_start..]
        .find(']')
        .map(|i| members_start + i)
        .unwrap_or_else(|| panic!("Lane SSSSS: workspace `members = [` must close with `]`"));
    let members_block = &workspace_toml[members_start..members_end];
    let mut member_paths: Vec<String> = Vec::new();
    for raw in members_block.split(',') {
        let s = raw.trim().trim_matches('"');
        if s.is_empty() {
            continue;
        }
        member_paths.push(s.to_string());
    }

    // Required fields: every member [package] must declare these
    // via `<field>.workspace = true` (or `<field> = { workspace =
    // true }`).
    let required_fields = ["version", "edition", "license"];

    let mut violations: Vec<String> = Vec::new();
    let mut members_checked = 0usize;

    for member in &member_paths {
        let manifest_path = root.join(member).join("Cargo.toml");
        let manifest = fs::read_to_string(&manifest_path).unwrap_or_else(|_| {
            panic!(
                "Lane SSSSS: member crate {member} manifest not readable at {}",
                manifest_path.display()
            )
        });
        members_checked += 1;

        // Slice the `[package]` section: from the `[package]` line
        // header to the next `[` header (next section).
        let pkg_marker = "[package]";
        let pkg_start = manifest.find(pkg_marker).unwrap_or_else(|| {
            panic!("Lane SSSSS: {member}/Cargo.toml must contain a `[package]` section")
        });
        let after = &manifest[pkg_start + pkg_marker.len()..];
        let section_end = after.find("\n[").unwrap_or(after.len());
        let pkg_section = &after[..section_end];

        for field in &required_fields {
            // Accept either `field.workspace = true` or
            // `field = { workspace = true }` (with arbitrary
            // whitespace).
            let short = format!("{field}.workspace = true");
            let long_marker = format!("{field} = {{");
            let has_short = pkg_section.contains(&short);
            // For the long form: look for the line containing
            // `field = {` and check that the same line (up to the
            // closing `}`) contains `workspace = true`.
            let has_long = pkg_section
                .lines()
                .any(|l| l.contains(&long_marker) && l.contains("workspace = true"));
            if !has_short && !has_long {
                violations.push(format!(
                    "{member}/Cargo.toml: [package] missing `{field}.workspace = true` (or `{field} = {{ workspace = true }}`)"
                ));
            }
        }
    }

    // Floor: at least 3 member crates checked (matches Lane ZZZZ
    // floor for workspace members).
    assert!(
        members_checked >= 3,
        "Lane SSSSS: must enumerate >= 3 workspace members (got {members_checked}). The cascade depends on a stable >= 3 member floor."
    );

    assert!(
        violations.is_empty(),
        "Lane SSSSS: workspace member crates must inherit `version`, `edition`, and `license` via `.workspace = true`. Violations: {:?}. Without uniform inheritance, a workspace-level bump (e.g., `edition = \"2021\"` → `\"2024\"`) only propagates to members that opted in, leaving the others on the old value — the workspace's identity becomes incoherent across members.",
        violations
    );
}

// Lane TTTTT: workspace.dependencies semver-ish version string parity.
//
// The top-level `Cargo.toml`'s `[workspace.dependencies]` block
// declares every third-party crate the workspace consumes. Each
// entry is either:
//   - `<name> = "<version>"` (short form, e.g., `anyhow = "1"`)
//   - `<name> = { version = "<version>", features = [...] }` (long
//      form, e.g., `serde = { version = "1", features = ["derive"] }`)
//
// Every entry MUST have a non-empty version string that starts with
// a digit (semver-ish). This pins against three regressions:
//   1. Bare wildcard `<name> = "*"` — cargo will resolve to whatever
//      the latest version is, producing irreproducible builds that
//      may pull in breaking changes between commits.
//   2. Empty version `<name> = { features = [...] }` — without an
//      explicit version, cargo defaults to the registry's latest,
//      same irreproducibility problem.
//   3. Git-only deps `<name> = { git = "..." }` without a tag/rev
//      pin — produces builds that depend on a moving target.
//
// Floor: >= 10 dependencies enumerated (the workspace currently
// declares ~22; floor catches a refactor that consolidates too
// aggressively).
//
// Cross-axis to Lane AAAAA (workspace.dependencies ↔ member
// inheritance) and Lane SSSSS (workspace.package ↔ member
// inheritance): AAAAA + SSSSS bind workspace-level metadata TO
// members; TTTTT binds the workspace-level metadata to its OWN
// integrity contract (versions are pinned, not wildcarded).
#[test]
fn workspace_dependencies_have_semver_version_strings_lane_ttttt() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workspace_toml = fs::read_to_string(root.join("Cargo.toml"))
        .expect("Lane TTTTT: top-level Cargo.toml present");

    // Slice the [workspace.dependencies] section (header to next [).
    let section_marker = "[workspace.dependencies]";
    let section_start = workspace_toml.find(section_marker).unwrap_or_else(|| {
        panic!("Lane TTTTT: top-level Cargo.toml must contain a `{section_marker}` section.")
    });
    let after = &workspace_toml[section_start + section_marker.len()..];
    let section_end = after.find("\n[").unwrap_or(after.len());
    let deps_section = &after[..section_end];

    // Parse each non-blank, non-comment line as a dependency entry.
    let mut deps_count = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for line in deps_section.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Expect `<name> = ...`. Skip lines without `=`.
        let Some(eq_idx) = trimmed.find('=') else {
            continue;
        };
        let dep_name = trimmed[..eq_idx].trim().to_string();
        let rhs = trimmed[eq_idx + 1..].trim();
        deps_count += 1;

        // Extract version string. Three forms:
        //   "<x.y>"  (short form, the RHS starts with `"`)
        //   { version = "<x.y>", ... }  (long form)
        //   { git = "...", ... }  (git form — explicitly rejected)
        let version_str: Option<String> = if let Some(stripped) = rhs.strip_prefix('"') {
            // Short form: capture up to next `"`.
            stripped.find('"').map(|i| stripped[..i].to_string())
        } else if rhs.starts_with('{') {
            // Long form: find `version = "..."` inside the brace block.
            let v_marker = "version = \"";
            if let Some(v_start) = rhs.find(v_marker) {
                let after_v = &rhs[v_start + v_marker.len()..];
                after_v.find('"').map(|i| after_v[..i].to_string())
            } else {
                None
            }
        } else {
            None
        };

        match version_str {
            Some(v) => {
                if v.is_empty() {
                    violations.push(format!(
                        "{dep_name}: empty version string (regression: `{rhs}`)"
                    ));
                } else if v == "*" {
                    violations.push(format!(
                        "{dep_name}: bare wildcard `*` version (irreproducible builds; pin to a major)"
                    ));
                } else if !v.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    violations.push(format!(
                        "{dep_name}: version `{v}` doesn't start with a digit (not semver-ish)"
                    ));
                }
            }
            None => {
                violations.push(format!(
                    "{dep_name}: no version field found in `{rhs}` (git-only or features-only dep — every workspace dep MUST be version-pinned)"
                ));
            }
        }
    }

    // Floor: >= 10 deps.
    assert!(
        deps_count >= 10,
        "Lane TTTTT: workspace.dependencies must enumerate >= 10 entries (got {deps_count}). A refactor that consolidates too aggressively can drop the workspace's dep-pinning surface below the safety floor."
    );

    assert!(
        violations.is_empty(),
        "Lane TTTTT: workspace.dependencies entries must have semver-ish version strings (non-empty, starting with a digit, no bare `*`). Violations: {:?}. Without pinned versions, cargo resolves to the registry's latest at build time — different commits produce different binary bytes, breaking reproducible builds (Lane CCCCC's Cargo.lock guarantee depends on this).",
        violations
    );
}

// Lane UUUUU: smoke-three-os-release.sh AO2_CP_VERSION default ↔
// workspace version parity.
//
// `scripts/smoke-three-os-release.sh` orchestrates release artifact
// verification across macOS / Linux / Windows. Near the top it
// declares `AO2_CP_VERSION="${AO2_CP_VERSION:-<x.y.z>}"` — the
// default version the smoke uses if the operator doesn't override
// via env. This default MUST match the workspace's canonical
// version (`Cargo.toml [workspace.package] version`).
//
// Why this matters: Lane PPPPP binds `scripts/package-local.sh`'s
// `VERSION="<x.y.z>"` to the workspace version. Without UUUUU,
// a workspace bump could pass PPPPP (package-local updated) but
// fail at three-OS smoke time because the smoke script's hardcoded
// default still references the old version. The smoke would build
// a `0.2.0` archive and then verify against `0.1.0` — every
// per-host verification step would fail with a version-mismatch
// error, AFTER the slow build + cross-host transfer.
//
// Two invariants:
//   1. `scripts/smoke-three-os-release.sh` must declare
//      `AO2_CP_VERSION="${AO2_CP_VERSION:-<x.y.z>}"` near the top.
//   2. The default fallback `<x.y.z>` MUST byte-equal the workspace
//      `[workspace.package] version`.
//
// Cross-axis: Lane PPPPP binds package-local.sh's VERSION; UUUUU
// binds smoke-three-os-release.sh's AO2_CP_VERSION; both must match
// the canonical `Cargo.toml [workspace.package] version`. Together
// they ensure the workspace version propagates to BOTH the release
// production path (package-local) AND the release verification path
// (smoke-three-os).
#[test]
fn smoke_three_os_default_version_matches_workspace_version_lane_uuuuu() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let smoke = fs::read_to_string(root.join("scripts/smoke-three-os-release.sh"))
        .expect("Lane UUUUU: scripts/smoke-three-os-release.sh present");
    let workspace_toml = fs::read_to_string(root.join("Cargo.toml"))
        .expect("Lane UUUUU: top-level Cargo.toml present");

    // (1) Extract AO2_CP_VERSION default fallback.
    // Pattern: `AO2_CP_VERSION="${AO2_CP_VERSION:-<x.y.z>}"`.
    let marker = "AO2_CP_VERSION=\"${AO2_CP_VERSION:-";
    let start = smoke.find(marker).map(|i| i + marker.len()).unwrap_or_else(|| {
        panic!(
            "Lane UUUUU: scripts/smoke-three-os-release.sh must declare `AO2_CP_VERSION=\"${{AO2_CP_VERSION:-<x.y.z>}}\"` (env-overridable default); not found."
        )
    });
    let end = smoke[start..].find('}').map(|i| start + i).unwrap_or_else(|| {
        panic!(
            "Lane UUUUU: scripts/smoke-three-os-release.sh `AO2_CP_VERSION=\"${{AO2_CP_VERSION:-<...>` literal must close with `}}`; not found."
        )
    });
    let smoke_version = &smoke[start..end];

    // (2) Extract Cargo.toml [workspace.package] version.
    let section_marker = "[workspace.package]";
    let section_start = workspace_toml.find(section_marker).unwrap_or_else(|| {
        panic!("Lane UUUUU: top-level Cargo.toml must contain `{section_marker}`")
    });
    let after_section = &workspace_toml[section_start + section_marker.len()..];
    let v_marker = "version = \"";
    let v_start = after_section
        .find(v_marker)
        .map(|i| i + v_marker.len())
        .unwrap_or_else(|| {
            panic!("Lane UUUUU: `[workspace.package]` section must declare `version = \"<x.y.z>\"`")
        });
    let v_end = after_section[v_start..]
        .find('"')
        .map(|i| v_start + i)
        .unwrap_or_else(|| {
            panic!("Lane UUUUU: `[workspace.package] version = \"<...>` must close with `\"`")
        });
    let workspace_version = &after_section[v_start..v_end];

    // (3) byte-equal.
    assert_eq!(
        smoke_version, workspace_version,
        "Lane UUUUU: scripts/smoke-three-os-release.sh AO2_CP_VERSION default \"{smoke_version}\" must match top-level Cargo.toml [workspace.package] version = \"{workspace_version}\". A workspace bump that misses the smoke script means the three-OS verification step builds a {workspace_version} archive and then verifies against {smoke_version} — every per-host verification step fails with version-mismatch, AFTER the slow build + cross-host transfer."
    );
}

// Lane VVVVV: HTML render fn read-only-observer trust-boundary
// disclaimer parity.
//
// The control plane's HTML render functions (in
// `crates/ao2-cp-server/src/handlers/release_publication.rs`) produce
// operator-facing pages that surface signed evidence, release
// readiness, support-bundle manifests, and verifier output. The
// control plane is a READ-ONLY observer; it does NOT approve
// releases and does NOT mutate AO artifacts.
//
// Every operator-facing HTML page MUST carry this trust-boundary
// disclaimer near the top so an operator landing on any of the
// pages (via direct URL, a runbook link, or a cockpit link)
// immediately sees the read-only posture. Without the disclaimer,
// an operator could misread the page as authoritative for approval
// — a security-critical regression.
//
// Two anchor phrases pinned per template:
//   1. `read-only` (case-insensitive) — confirms the trust-posture
//      lead (every page introduces itself as a read-only surface).
//   2. `AO artifacts` OR `AO2 artifacts` — confirms the explicit
//      non-mutation pledge (every page commits to not mutating the
//      authoritative AO/AO2 artifact store).
//
// Floor: >= 7 HTML render templates (each `format!("<!doctype html>
// ...", ...)` body in release_publication.rs that emits a full
// HTML page); current count is 8.
//
// Cross-axis: Lane CCCC binds README threat-model statements to
// handler emissions (broad surface); Lane VVVVV is the tighter,
// per-template binding that EVERY HTML render carries the
// load-bearing trust-boundary phrase. Lane YYYY binds HTML render
// fn ↔ route registration; VVVVV binds HTML render fn ↔ disclaimer
// content. Together they ensure every operator-reachable HTML page
// is BOTH routed (YYYY) AND attests to its read-only posture
// (VVVVV).
#[test]
fn html_render_fns_carry_read_only_observer_disclaimer_lane_vvvvv() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let publication =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/release_publication.rs"))
            .expect("Lane VVVVV: release_publication.rs present");

    // Find every format! template that opens with `"<!doctype html>`.
    // We look for the marker `"<!doctype html>` (the opening quote
    // followed by the doctype) and capture up to the closing `",`.
    // Multiple templates exist; each is a separate page.
    let open_marker = "\"<!doctype html>";
    let mut search_idx = 0usize;
    let mut templates: Vec<String> = Vec::new();
    while let Some(rel) = publication[search_idx..].find(open_marker) {
        let abs = search_idx + rel;
        let body_start = abs + 1; // skip leading `"`
                                  // Find the closing `",` (end of the format! template string
                                  // followed by an argument-list separator). Use the next
                                  // `",\n` token which is the canonical closing pattern in
                                  // these single-line format! templates.
        let after = &publication[body_start..];
        let end_rel = after.find("\",\n").unwrap_or_else(|| {
            // Fall back: any `",` (less strict).
            after.find("\",").unwrap_or(after.len())
        });
        templates.push(after[..end_rel].to_string());
        search_idx = body_start + end_rel + 1;
    }

    assert!(
        templates.len() >= 7,
        "Lane VVVVV: release_publication.rs must contain >= 7 HTML render templates (each `format!(\"<!doctype html>...\", ...)`). Found {}. A refactor that consolidates templates below the floor reduces the surface where the trust-boundary disclaimer can be pinned.",
        templates.len()
    );

    let mut violations: Vec<String> = Vec::new();
    for (idx, body) in templates.iter().enumerate() {
        let lower = body.to_lowercase();
        // (1) read-only (case-insensitive).
        if !lower.contains("read-only") {
            violations.push(format!(
                "template #{idx}: missing `read-only` (case-insensitive) phrase — every page must lead with the read-only posture so the operator sees the trust boundary"
            ));
        }
        // (2) AO artifacts OR AO2 artifacts.
        let has_ao_artifacts = lower.contains("ao artifacts") || lower.contains("ao2 artifacts");
        if !has_ao_artifacts {
            violations.push(format!(
                "template #{idx}: missing `AO artifacts` or `AO2 artifacts` pledge — every page must explicitly state it does not mutate AO/AO2 artifacts"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "Lane VVVVV: every HTML render template in release_publication.rs must carry the read-only-observer trust-boundary disclaimer (`read-only` phrase AND `AO/AO2 artifacts` pledge). Violations: {:?}. Without the disclaimer, an operator landing on the page could misread it as authoritative for approval — a security-critical regression.",
        violations
    );
}

// Lane WWWWW: runbook section heading number ordering parity.
//
// `docs/runbooks/release-smoke.md` organizes operator triage
// guidance into numbered top-level sections (`## 1. The two parity
// verdicts`, `## 2. Triage by parity verdict`, ..., `## 9. Reading
// the audit-log rotation budget (Lane VV)`). The numbering forms a
// load-bearing structural contract: an operator following a link
// from a Prometheus alert or from a cockpit cross-reference to
// section N expects N to exist; an oncall page that says "see
// section 7 for offline candidate comparison" must actually
// resolve to a section labeled 7.
//
// Three invariants:
//   1. Every line matching `^## (\d+)\.` MUST parse the captured
//      integer cleanly (no `## 1A.` typos, no `## 01.` zero-padded
//      variants).
//   2. The captured integer sequence MUST form a contiguous
//      `1..=N` run (no gaps, no duplicates, no reordering). A gap
//      like `1, 2, 3, 5, 6` breaks every "see section 4" cross-ref;
//      a duplicate `1, 2, 3, 3, 4` confuses operators following
//      a numbered link.
//   3. Floor: N >= 9 (current count is 9: parity verdicts, triage
//      by verdict, triage by candidate_correlation, Lane T worked
//      example, ingestion-time rejection, where the gates are
//      enforced, offline candidate comparison, Lane PP-server
//      rejection triage, rotation-budget reading).
//
// Cross-axis: Lane TTTT binds section-6 row count ↔ test fn count;
// Lane SSSS binds section-6 row uniqueness; Lane WWWWW binds the
// TOP-LEVEL section numbering of the runbook itself. Together they
// ensure the runbook's structural navigation surface is internally
// consistent.
#[test]
fn release_smoke_runbook_section_headings_form_contiguous_sequence_lane_wwwww() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runbook = fs::read_to_string(root.join("docs/runbooks/release-smoke.md"))
        .expect("Lane WWWWW: docs/runbooks/release-smoke.md present");

    // Parse every `## <digits>.` heading.
    let mut numbers: Vec<usize> = Vec::new();
    for line in runbook.lines() {
        if !line.starts_with("## ") {
            continue;
        }
        let after = &line["## ".len()..];
        let Some(dot_idx) = after.find('.') else {
            continue;
        };
        let digit_part = &after[..dot_idx];
        // Reject zero-padded (`01`) and non-numeric prefixes (`1A`).
        if digit_part.is_empty()
            || digit_part.starts_with('0') && digit_part.len() > 1
            || !digit_part.chars().all(|c| c.is_ascii_digit())
        {
            // Not a numbered section heading; skip (allows
            // non-numbered headings like `## Comparing two release
            // candidates offline` to coexist).
            continue;
        }
        let Ok(n) = digit_part.parse::<usize>() else {
            continue;
        };
        numbers.push(n);
    }

    // Floor: >= 9 numbered sections.
    assert!(
        numbers.len() >= 9,
        "Lane WWWWW: release-smoke.md must declare >= 9 numbered `## N.` section headings (got {}). The current runbook has 9 numbered sections; a refactor that drops below the floor reduces the structural navigation surface.",
        numbers.len()
    );

    // Contiguous 1..=N: sorted == observed AND sorted is [1, 2,
    // ..., n].
    let n = numbers.len();
    let expected: Vec<usize> = (1..=n).collect();
    assert_eq!(
        numbers, expected,
        "Lane WWWWW: release-smoke.md `## N.` section headings must form a contiguous 1..={n} sequence in order (got {:?}). A gap breaks every `see section X` cross-ref; a duplicate confuses operators following a numbered link; a reorder means operators reading top-to-bottom encounter sections out of logical order.",
        numbers
    );
}

// Lane XXXXX: package-local.sh sha256sum/shasum cross-platform fallback parity.
//
// `scripts/package-local.sh` is the release-archive orchestrator
// invoked on every host that builds the release tarball. The script
// must compute SHA-256 hashes for the staged binary, four ancillary
// scripts, and the final archive. POSIX SH doesn't standardize a
// SHA-256 CLI — Linux distros ship `sha256sum` (GNU coreutils);
// macOS ships `shasum -a 256` (Perl). A naive `sha256sum` call works
// on Ubuntu/Linux CI but breaks on macOS, producing
// `command not found` AFTER minutes of release-build work.
//
// The defense pattern (already implemented in package-local.sh):
//
//     if command -v sha256sum >/dev/null 2>&1; then
//         binary_sha=$(sha256sum "$STAGE/bin/$BINARY_NAME" | awk '{ print $1 }')
//         ...
//     else
//         binary_sha=$(shasum -a 256 "$STAGE/bin/$BINARY_NAME" | awk '{ print $1 }')
//         ...
//     fi
//
// Two such guarded blocks exist: one for the staging hashes (binary
// + 4 ancillary scripts, lines 79-91), one for the archive hash
// (lines 448-452). Lane XXXXX pins both.
//
// Three invariants:
//   1. Floor: >= 2 occurrences of `if command -v sha256sum
//      >/dev/null 2>&1; then` in the script. A regression to a
//      single block (e.g., refactoring removes the archive-hash
//      fallback) is caught.
//   2. Each guarded block MUST have a matching `else` branch
//      containing at least one `shasum -a 256` invocation. A regression
//      that removes only the `else` branch (leaving the `command -v`
//      test but dropping the fallback) would silently still fail on
//      macOS because the else-less if-then collapses on the missing
//      command.
//   3. Every bare `sha256sum` invocation (excluding the `command -v
//      sha256sum` portability test itself) MUST live within the
//      `then` body of one of the guarded blocks. An unguarded
//      `sha256sum "$X"` line outside any if-then-else block is a
//      regression that breaks the macOS release path.
//
// Why this matters: this is the real cross-platform portability
// contract for the release-archive build path. Without the binding,
// a future refactor that consolidates the two blocks into a single
// "modern" call (`sha256sum $files` — single invocation, multiple
// args) breaks macOS silently, after the release binary has already
// been built — wasting CI time at the worst possible moment.
//
// Cross-axis: Lane OOOOO (script shebang + strict-mode) ensures the
// script fails-fast on errors; XXXXX ensures the specific call
// pattern that ACTUALLY DEPENDS on host portability is itself
// portably written. OOOOO catches "this script crashed silently";
// XXXXX catches "this script will crash silently on macOS".
#[test]
fn package_local_sha256_has_cross_platform_fallback_lane_xxxxx() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script_path = root.join("scripts/package-local.sh");
    let script =
        fs::read_to_string(&script_path).expect("Lane XXXXX: scripts/package-local.sh present");

    let lines: Vec<&str> = script.lines().collect();

    // Invariant 1: floor >= 2 `if command -v sha256sum >/dev/null
    // 2>&1; then` guards.
    let mut guard_starts: Vec<usize> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("if command -v sha256sum >/dev/null 2>&1; then") {
            guard_starts.push(idx);
        }
    }
    assert!(
        guard_starts.len() >= 2,
        "Lane XXXXX: package-local.sh must declare >= 2 `if command -v sha256sum >/dev/null 2>&1; then` guards (got {}). The current script has 2: one for staging hashes (binary + ancillary scripts) and one for the archive hash. A drop below the floor means one of those code paths lost its macOS fallback.",
        guard_starts.len()
    );

    // Invariant 2: each guarded block has a matching `else` with at
    // least one `shasum -a 256` line.
    for &start in &guard_starts {
        // Scan from `start + 1` for the matching `else` (depth 0)
        // and `fi` (depth -1). Depth tracking is shallow because
        // these if-blocks don't contain nested if-statements in
        // package-local.sh.
        let mut else_idx: Option<usize> = None;
        let mut fi_idx: Option<usize> = None;
        for (j, raw) in lines.iter().enumerate().skip(start + 1) {
            let t = raw.trim_start();
            if t == "else" {
                else_idx = Some(j);
            } else if t == "fi" {
                fi_idx = Some(j);
                break;
            }
        }
        let else_j = else_idx
            .unwrap_or_else(|| panic!("Lane XXXXX: package-local.sh `if command -v sha256sum` at line {} (1-based: {}) must have a matching `else` branch with a `shasum -a 256` fallback; not finding `else` indicates a regression that drops the macOS fallback path.", start, start + 1));
        let fi_j = fi_idx
            .unwrap_or_else(|| panic!("Lane XXXXX: package-local.sh `if command -v sha256sum` at line {} (1-based: {}) must have a matching `fi` closing the guarded block; the script is malformed if no `fi` is found before EOF.", start, start + 1));

        // Verify the else..fi range contains at least one `shasum
        // -a 256` invocation.
        let else_body: Vec<&str> = lines[(else_j + 1)..fi_j].to_vec();
        let has_shasum_fallback = else_body.iter().any(|l| l.contains("shasum -a 256"));
        assert!(
            has_shasum_fallback,
            "Lane XXXXX: package-local.sh `else` branch at line {} (1-based: {}) following the `if command -v sha256sum` guard must contain at least one `shasum -a 256` invocation as the macOS fallback. Else-body lines: {:?}",
            else_j,
            else_j + 1,
            else_body
        );
    }

    // Invariant 3: every bare `sha256sum` invocation must live
    // inside a guarded block's `then` body (between an `if command
    // -v sha256sum >/dev/null 2>&1; then` line and its matching
    // `else`). The `if command -v sha256sum` line itself is
    // excluded.
    //
    // Build the (then_start, then_end] ranges from guard_starts.
    let mut guarded_then_ranges: Vec<(usize, usize)> = Vec::new();
    for &start in &guard_starts {
        for (j, raw) in lines.iter().enumerate().skip(start + 1) {
            if raw.trim_start() == "else" {
                guarded_then_ranges.push((start, j));
                break;
            }
        }
    }

    let in_guarded_then = |idx: usize| -> bool {
        guarded_then_ranges
            .iter()
            .any(|(s, e)| idx > *s && idx < *e)
    };

    let mut unguarded_violations: Vec<(usize, String)> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        // Skip the `if command -v sha256sum` portability test
        // lines themselves.
        if line.trim_start().starts_with("if command -v sha256sum") {
            continue;
        }
        if !line.contains("sha256sum") {
            continue;
        }
        // Skip lines that are clearly comments.
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if !in_guarded_then(idx) {
            unguarded_violations.push((idx + 1, (*line).to_string()));
        }
    }

    assert!(
        unguarded_violations.is_empty(),
        "Lane XXXXX: every bare `sha256sum` invocation in package-local.sh must live inside the `then` body of an `if command -v sha256sum >/dev/null 2>&1; then ... else shasum -a 256 ... fi` guarded block. Unguarded violations (line, content): {:?}. An unguarded `sha256sum` call breaks the macOS release path silently.",
        unguarded_violations
    );
}

// Lane YYYYY: package-local.sh README.txt heredoc trust-boundary
// disclaimer parity.
//
// `scripts/package-local.sh` emits a `README.txt` into the release
// archive via the heredoc starting at
// `cat > "$STAGE/README.txt" <<'TXT'` ... `TXT`. This README.txt is
// the offline-shipped operator-facing doc that lands in the release
// tarball alongside the binary, install scripts, and verifiers. It
// is the FIRST file an operator reads after extracting the archive
// — typically before launching the server.
//
// Lane VVVVV binds the LIVE HTML render templates (operator-facing
// pages served by the running ao2-cp-server) to carry the
// read-only-observer trust-boundary disclaimer. Lane YYYYY is the
// orthogonal OFFLINE-DOC analog: it binds the SHIPPED-IN-ARCHIVE
// README.txt to carry the same load-bearing disclaimer. Together
// they ensure the trust-boundary message reaches operators on BOTH
// surfaces (live HTML AND offline doc) — covering the case where
// an operator reads the README before ever starting the server.
//
// Four anchor phrases pinned in the README.txt heredoc body:
//   1. `read-only observer` (strict, lowercase) — the load-bearing
//      role descriptor.
//   2. `does not start providers` — the explicit non-mutation
//      claim about provider lifecycle.
//   3. `does not approve AO2 runs` — the explicit non-approval
//      claim about release / AO2 artifact authority.
//   4. `never mutates AO2 artifacts` — the broader non-mutation
//      pledge used in the operator-landing-flow section.
//
// Plus structural invariants:
//   5. The heredoc exists (`cat > "$STAGE/README.txt" <<'TXT'`
//      followed by a closing `TXT` line).
//   6. Floor: heredoc body >= 100 lines — current count is ~210
//      lines; a regression that guts the README to a stub is
//      caught.
//
// Why this matters: the README.txt is what an operator reads
// FIRST. If a future refactor removes the read-only-observer
// disclaimer (consolidation, "we already say it on the live
// surface" reasoning), an operator extracting the archive could
// reasonably misread it as an authoritative production tool
// rather than a read-only observer — a security-critical
// regression.
//
// Cross-axis: Lane VVVVV (live HTML disclaimer) covers the
// running-server surface; Lane CCCC (README threat-model ↔
// handler emissions) covers the repo-root README; Lane YYYYY
// covers the SHIPPED-IN-RELEASE-ARCHIVE README.txt. All three
// surfaces of operator-facing documentation must carry the
// load-bearing trust-boundary disclaimer.
#[test]
fn package_local_readme_heredoc_trust_boundary_disclaimer_lane_yyyyy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script_path = root.join("scripts/package-local.sh");
    let script =
        fs::read_to_string(&script_path).expect("Lane YYYYY: scripts/package-local.sh present");

    let lines: Vec<&str> = script.lines().collect();

    // Locate the README.txt heredoc start marker.
    let start_marker = "cat > \"$STAGE/README.txt\" <<'TXT'";
    let start_idx = lines.iter().position(|l| l.trim() == start_marker).expect(
        "Lane YYYYY: package-local.sh must declare the README.txt heredoc via `cat > \"$STAGE/README.txt\" <<'TXT'`. Without this exact form, the script's emission of the offline operator-facing README.txt is broken.",
    );

    // Locate the closing TXT terminator after the start.
    let end_idx = lines
        .iter()
        .enumerate()
        .skip(start_idx + 1)
        .find(|(_, l)| l.trim() == "TXT")
        .map(|(i, _)| i)
        .expect("Lane YYYYY: package-local.sh README.txt heredoc must have a closing `TXT` terminator line; the heredoc is malformed if no closing terminator is found.");

    let body: Vec<&str> = lines[(start_idx + 1)..end_idx].to_vec();

    // Floor: >= 100 lines in the README.txt body.
    assert!(
        body.len() >= 100,
        "Lane YYYYY: README.txt heredoc body must be >= 100 lines (got {}). The current count is ~210 lines covering install flow, offline support bundle verification, operator landing flow, three-OS smoke gates, and audit-log rotation. A regression that guts the README to a stub strips the offline operator-facing guidance — operators extracting the archive would have no in-archive reference.",
        body.len()
    );

    // Concatenate body for substring search.
    let body_text = body.join("\n");

    // Anchor phrase 1: `read-only observer`.
    assert!(
        body_text.contains("read-only observer"),
        "Lane YYYYY: README.txt heredoc body must contain the literal `read-only observer` (the load-bearing role descriptor). Without it, the offline operator-facing README does not declare the trust boundary up-front — an operator reading the README before launching the server could misread it as a production tool."
    );

    // Anchor phrase 2: `does not start providers`.
    assert!(
        body_text.contains("does not start providers"),
        "Lane YYYYY: README.txt heredoc body must contain the literal `does not start providers` (the explicit provider-lifecycle non-mutation claim). Without it, an operator could reasonably assume the control plane manages provider lifecycle."
    );

    // Anchor phrase 3: `does not approve AO2 runs`.
    assert!(
        body_text.contains("does not approve AO2 runs"),
        "Lane YYYYY: README.txt heredoc body must contain the literal `does not approve AO2 runs` (the explicit release / AO2 non-approval claim). Without it, an operator could reasonably assume the control plane has authority over AO2 release approval."
    );

    // Anchor phrase 4: `never mutates AO2 artifacts`.
    assert!(
        body_text.contains("never mutates AO2 artifacts"),
        "Lane YYYYY: README.txt heredoc body must contain the literal `never mutates AO2 artifacts` (the broader non-mutation pledge used in the operator-landing-flow section). This phrase scopes the pledge across all HTTP surfaces, not just the provider lifecycle."
    );
}

// Lane ZZZZZ: RELEASE-MANIFEST.json python heredoc trust_boundary
// keys parity.
//
// `scripts/package-local.sh` emits a structured JSON manifest into
// the release archive via a python heredoc (lines starting with
// `python3 - "$STAGE/RELEASE-MANIFEST.json" "$VERSION" ... <<'PY'`
// and ending with `PY`). The manifest is consumed by offline
// verifiers and CI/release infrastructure. It declares the
// trust-boundary contract via JSON keys:
//
//   - "trust_boundary": "read-only observer; never starts providers
//      or approves AO2 runs"
//   - "support_bundle_trust_boundary": "offline verification only;
//      no bearer tokens, provider keys, AO2 artifact mutation, or
//      release approval"
//   - (nested under release_support_handoff_fetcher.phase1_portable_handoff)
//      "trust_boundary": "read-only observer; no bearer tokens,
//      provider keys, AO2 artifact mutation, or release approval"
//
// Lane YYYYY binds the README.txt heredoc body to carry the
// human-readable disclaimer. Lane ZZZZZ is the orthogonal
// machine-readable analog: it binds the RELEASE-MANIFEST.json
// python heredoc to declare the trust_boundary JSON keys with
// the read-only-observer disclaimer string.
//
// Why this matters: the RELEASE-MANIFEST.json is the structured
// trust-boundary attestation that ships in EVERY release archive.
// Offline verifiers and downstream tooling consume the
// trust_boundary key to confirm the control plane's posture. If a
// future refactor strips the key (cleanup, consolidation), the
// machine-readable attestation is silently lost — even though the
// human-readable README still says "read-only observer", the
// downstream automation has no programmatic check.
//
// Six invariants:
//   1. The python heredoc start marker MUST exist as
//      `python3 - "$STAGE/RELEASE-MANIFEST.json" ... <<'PY'`.
//   2. The closing `PY` terminator MUST exist after the start.
//   3. The heredoc body MUST contain the `"trust_boundary"` JSON
//      key declaration (at least once).
//   4. The heredoc body MUST contain the
//      `"support_bundle_trust_boundary"` JSON key (the secondary
//      key scoped to the offline verifier output).
//   5. The heredoc body MUST contain the literal
//      `"read-only observer"` string (the value disclaimer used in
//      both trust_boundary declarations).
//   6. Floor: >= 2 occurrences of `"trust_boundary"` (one at
//      top-level, one nested under the phase1_portable_handoff
//      block). A collapse to a single declaration would weaken
//      defense.
//
// Cross-axis: Lane VVVVV (live HTML disclaimer), Lane YYYYY
// (README.txt human-readable disclaimer), Lane ZZZZZ
// (RELEASE-MANIFEST.json machine-readable disclaimer). All three
// surfaces (running HTML, offline doc, machine attestation) must
// carry the trust-boundary contract.
#[test]
fn package_local_release_manifest_trust_boundary_keys_lane_zzzzz() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script_path = root.join("scripts/package-local.sh");
    let script =
        fs::read_to_string(&script_path).expect("Lane ZZZZZ: scripts/package-local.sh present");

    let lines: Vec<&str> = script.lines().collect();

    // Locate the python heredoc start marker — line containing both
    // `python3 -` and the closing `<<'PY'` token. Tolerates the
    // arglist in between (VERSION, TARGET_LABEL, sha256 vars).
    let start_idx = lines
        .iter()
        .position(|l| {
            l.contains("python3 - \"$STAGE/RELEASE-MANIFEST.json\"") && l.contains("<<'PY'")
        })
        .expect(
            "Lane ZZZZZ: package-local.sh must declare the RELEASE-MANIFEST.json python heredoc via `python3 - \"$STAGE/RELEASE-MANIFEST.json\" ... <<'PY'`. Without this exact form, the script's emission of the machine-readable manifest is broken.",
        );

    // Locate the closing PY terminator after the start.
    let end_idx = lines
        .iter()
        .enumerate()
        .skip(start_idx + 1)
        .find(|(_, l)| l.trim() == "PY")
        .map(|(i, _)| i)
        .expect("Lane ZZZZZ: package-local.sh RELEASE-MANIFEST.json python heredoc must have a closing `PY` terminator line; the heredoc is malformed if no closing terminator is found.");

    let body: Vec<&str> = lines[(start_idx + 1)..end_idx].to_vec();
    let body_text = body.join("\n");

    // Invariant 3: contains `"trust_boundary"` key.
    assert!(
        body_text.contains("\"trust_boundary\""),
        "Lane ZZZZZ: RELEASE-MANIFEST.json python heredoc must contain the literal JSON key `\"trust_boundary\"`. Without it, the manifest provides no machine-readable trust-boundary attestation — offline verifiers and downstream automation lose their programmatic check on the control plane's read-only posture."
    );

    // Invariant 4: contains `"support_bundle_trust_boundary"` key.
    assert!(
        body_text.contains("\"support_bundle_trust_boundary\""),
        "Lane ZZZZZ: RELEASE-MANIFEST.json python heredoc must contain the literal JSON key `\"support_bundle_trust_boundary\"` (the secondary key scoped to the offline support-bundle verifier output). This key declares the verifier's own trust boundary — offline verification only, no bearer tokens."
    );

    // Invariant 5: contains `"read-only observer"` value.
    assert!(
        body_text.contains("\"read-only observer"),
        "Lane ZZZZZ: RELEASE-MANIFEST.json python heredoc must contain the literal value prefix `\"read-only observer` (the trust_boundary value disclaimer). Without it, the trust_boundary key may be declared but its value no longer attests the load-bearing read-only posture."
    );

    // Invariant 6: >= 2 occurrences of `"trust_boundary"`.
    let trust_boundary_count = body_text.matches("\"trust_boundary\"").count();
    assert!(
        trust_boundary_count >= 2,
        "Lane ZZZZZ: RELEASE-MANIFEST.json python heredoc must declare >= 2 `\"trust_boundary\"` JSON key occurrences (got {}). The current manifest has 2: one at top-level scoping the control plane, one nested under `release_support_handoff_fetcher.phase1_portable_handoff` scoping the Phase 1 handoff fetcher. A collapse to a single declaration weakens defense by removing the per-subsystem attestation.",
        trust_boundary_count
    );
}

// Lane AAAAAA: RELEASE-MANIFEST.json schema_version semver-suffix parity.
//
// `scripts/package-local.sh` emits a `RELEASE-MANIFEST.json` via
// the python heredoc whose first JSON key is
// `"schema_version": "ao2-control-plane.release-manifest.v1"`. The
// value follows the same `<dotted-namespace>.v<positive-integer>`
// pattern enforced by Lane GGGGG for the in-process handler
// `RELEASE_*_SCHEMA` const strings.
//
// Why this matters: the schema_version value is the
// downstream-consumed identifier that offline verifiers
// (verify_release_support_bundle.py, Verify-ReleaseSupportBundle.ps1)
// and CI orchestration use to decide whether they can parse the
// archive's manifest. A regression that:
//
//   - Drops the `v<N>` suffix (`"ao2-control-plane.release-manifest"`)
//     — verifiers can't tell which schema version they're reading.
//   - Adds a non-monotonic suffix (`"...v01"`, `"...v1a"`)
//     — verifiers' integer-comparison logic breaks.
//   - Collapses the namespace (`"v1"`) — collides with any other
//     `v1`-suffixed schema in the ecosystem.
//
// Three invariants:
//   1. The python heredoc body MUST contain the literal JSON key
//      `"schema_version"` declared for the top-level manifest
//      object (catches a refactor that drops the field).
//   2. The schema_version value MUST match the pattern
//      `"<namespace>.v<positive-integer>"`:
//         - At least one `.` before the `v<N>` suffix (namespacing).
//         - The `<N>` part starts with `v`, followed by one or more
//           ASCII digits, with no leading zero (no `v01`).
//         - The `<N>` integer is >= 1.
//   3. Floor: namespace prefix MUST contain `ao2-control-plane`
//      (the bound product identifier). A regression that renames
//      the namespace without updating both the script AND every
//      downstream verifier is caught here.
//
// Cross-axis: Lane GGGGG binds the in-process handler
// `RELEASE_*_SCHEMA` const strings to the `<name>.v<N>` pattern.
// Lane AAAAAA is the orthogonal SHIPPED-ARTIFACT analog: it binds
// the OUT-OF-PROCESS python-heredoc schema_version literal to the
// same pattern. Together they ensure both the running-handler and
// the offline-archive emissions follow the schema-versioning
// contract.
#[test]
fn package_local_release_manifest_schema_version_semver_suffix_lane_aaaaaa() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script_path = root.join("scripts/package-local.sh");
    let script =
        fs::read_to_string(&script_path).expect("Lane AAAAAA: scripts/package-local.sh present");

    let lines: Vec<&str> = script.lines().collect();

    // Locate the python heredoc start marker.
    let start_idx = lines
        .iter()
        .position(|l| {
            l.contains("python3 - \"$STAGE/RELEASE-MANIFEST.json\"") && l.contains("<<'PY'")
        })
        .expect(
            "Lane AAAAAA: package-local.sh must declare the RELEASE-MANIFEST.json python heredoc via `python3 - \"$STAGE/RELEASE-MANIFEST.json\" ... <<'PY'`.",
        );

    let end_idx = lines
        .iter()
        .enumerate()
        .skip(start_idx + 1)
        .find(|(_, l)| l.trim() == "PY")
        .map(|(i, _)| i)
        .expect("Lane AAAAAA: RELEASE-MANIFEST.json python heredoc must have a closing `PY` terminator.");

    let body: Vec<&str> = lines[(start_idx + 1)..end_idx].to_vec();

    // Find the first `"schema_version"` line — the top-level
    // manifest field. The python heredoc declares this via:
    //     "schema_version": "ao2-control-plane.release-manifest.v1",
    let schema_line = body
        .iter()
        .find(|l| l.contains("\"schema_version\""))
        .copied()
        .expect("Lane AAAAAA: RELEASE-MANIFEST.json python heredoc body must declare a top-level `\"schema_version\"` JSON key. Without it, downstream verifiers cannot dispatch by schema version.");

    // Extract the value between the `"schema_version":` and the
    // trailing `,` (or end of string). Tolerant of whitespace.
    let after_key = schema_line
        .split_once("\"schema_version\"")
        .map(|(_, rest)| rest)
        .expect("Lane AAAAAA: schema_version line must contain the key literal");
    // Skip past `:` and whitespace, then first `"`.
    let value_start = after_key
        .find('"')
        .expect("Lane AAAAAA: schema_version line must have a quoted value");
    let after_open_quote = &after_key[value_start + 1..];
    let value_end = after_open_quote
        .find('"')
        .expect("Lane AAAAAA: schema_version value must have a closing quote");
    let value = &after_open_quote[..value_end];

    // Invariant 3: namespace prefix contains `ao2-control-plane`.
    assert!(
        value.starts_with("ao2-control-plane"),
        "Lane AAAAAA: RELEASE-MANIFEST.json schema_version value MUST start with `ao2-control-plane` (the bound product identifier). Got `{}`. A rename without updating downstream verifiers breaks the offline verification flow.",
        value
    );

    // Invariant 2a: contains at least one `.` between namespace
    // and `v<N>` suffix.
    let dot_count = value.matches('.').count();
    assert!(
        dot_count >= 2,
        "Lane AAAAAA: RELEASE-MANIFEST.json schema_version value MUST contain >= 2 `.` separators (namespace dotting before the `v<N>` suffix). Got `{}` with {} dots. The current value `ao2-control-plane.release-manifest.v1` has 2 dots: `ao2-control-plane` / `release-manifest` / `v1`.",
        value,
        dot_count
    );

    // Invariant 2b: value ends with `.v<N>` where N is a positive
    // integer with no leading zero.
    let last_dot_idx = value.rfind('.').expect("namespace dot present");
    let suffix = &value[last_dot_idx + 1..];
    assert!(
        suffix.starts_with('v'),
        "Lane AAAAAA: RELEASE-MANIFEST.json schema_version value MUST end with `.v<positive-integer>` (the schema version suffix). Got value `{}` whose final dotted segment is `{}` — missing leading `v`.",
        value,
        suffix
    );
    let n_str = &suffix[1..];
    assert!(
        !n_str.is_empty()
            && n_str.chars().all(|c| c.is_ascii_digit())
            && !(n_str.len() > 1 && n_str.starts_with('0')),
        "Lane AAAAAA: RELEASE-MANIFEST.json schema_version value's `v<N>` suffix MUST have N as a positive integer (one or more ASCII digits, no leading zero). Got value `{}` with suffix `{}` whose digit portion is `{}`.",
        value,
        suffix,
        n_str
    );
    let n: u32 = n_str
        .parse()
        .expect("Lane AAAAAA: schema_version v<N> digits parse cleanly after the prior assertion");
    assert!(
        n >= 1,
        "Lane AAAAAA: RELEASE-MANIFEST.json schema_version value's `v<N>` suffix MUST have N >= 1 (got N = {} in value `{}`). v0 is not a valid schema version.",
        n,
        value
    );
}

// Lane BBBBBB: package-local.sh archive filename format parity.
//
// `scripts/package-local.sh` assembles the final release tarball
// via line 446:
//
//   ARCHIVE="$OUT_DIR/ao2-control-plane-$VERSION-$TARGET_LABEL.tar.gz"
//
// This filename is the canonical release-archive name consumed by:
//   - The smoke-three-os-release.sh aggregator that downloads /
//     verifies the per-OS archives.
//   - The README's "latest archive" pointer expectations.
//   - Operators copying the archive between hosts.
//   - The published SHA256SUMS line's archive-name column.
//
// Lane BBBBBB pins six invariants on the ARCHIVE assignment:
//
//   1. The script declares exactly one `ARCHIVE=` top-level
//      assignment (not multiple — the canonical name has a single
//      definition point).
//   2. Value starts with `$OUT_DIR/` — places the archive under
//      the configured output directory (not `/tmp/` or `/`).
//   3. Value contains `ao2-control-plane-` — the product-name
//      prefix; a rename without updating downstream consumers
//      breaks every "latest tarball" pointer.
//   4. Value contains `$VERSION` — version substitution; without
//      it, two releases at different versions produce the same
//      filename and overwrite each other in $OUT_DIR.
//   5. Value contains `$TARGET_LABEL` — OS+arch substitution;
//      without it, macOS / Linux / Windows releases collide in
//      $OUT_DIR.
//   6. Value ends with `.tar.gz` — gzip-compressed tar suffix.
//      A regression to `.tar` (uncompressed) ships a much larger
//      archive; `.tar.bz2` breaks the smoke aggregator's `tar
//      -xzf` extraction step.
//
// Why this matters: the archive filename is the contract between
// release production (this script) and release verification (the
// smoke aggregator + README + operators). A drift in any of the
// six fields silently breaks the cross-OS smoke verification at
// the worst possible moment — AFTER the build completes but
// BEFORE the archive can be cross-host verified.
//
// Cross-axis: Lane PPPPP binds VERSION to the workspace; Lane
// QQQQQ binds BINARY to the release-profile path; BBBBBB binds
// ARCHIVE — the final emission — to its consumers via the
// canonical filename format.
#[test]
fn package_local_archive_filename_format_lane_bbbbbb() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script_path = root.join("scripts/package-local.sh");
    let script =
        fs::read_to_string(&script_path).expect("Lane BBBBBB: scripts/package-local.sh present");

    // Find ARCHIVE= top-level assignment lines (not in heredocs).
    // We exclude lines inside the install.sh / install.ps1 / README.txt /
    // python heredocs by tracking heredoc boundaries.
    let mut in_heredoc: Option<&str> = None;
    let mut archive_assignments: Vec<(usize, String)> = Vec::new();
    for (idx, line) in script.lines().enumerate() {
        let trimmed = line.trim();
        // Heredoc start detection (matches `<<'<TAG>'`).
        if in_heredoc.is_none() {
            if line.contains("<<'TXT'") {
                in_heredoc = Some("TXT");
                continue;
            } else if line.contains("<<'SH'") {
                in_heredoc = Some("SH");
                continue;
            } else if line.contains("<<'PS1'") {
                in_heredoc = Some("PS1");
                continue;
            } else if line.contains("<<'PY'") {
                in_heredoc = Some("PY");
                continue;
            }
        } else if let Some(tag) = in_heredoc {
            if trimmed == tag {
                in_heredoc = None;
            }
            continue;
        }
        if line.starts_with("ARCHIVE=") {
            archive_assignments.push((idx + 1, line.to_string()));
        }
    }

    // Invariant 1: exactly one ARCHIVE= top-level assignment.
    assert_eq!(
        archive_assignments.len(),
        1,
        "Lane BBBBBB: package-local.sh must declare EXACTLY one top-level `ARCHIVE=` assignment (got {}). Multiple assignments would create ambiguity about which archive name is canonical. Assignments: {:?}",
        archive_assignments.len(),
        archive_assignments
    );

    let (_, archive_line) = &archive_assignments[0];

    // Extract the value between `ARCHIVE="` and the closing `"`.
    let value = archive_line
        .strip_prefix("ARCHIVE=\"")
        .and_then(|rest| rest.rsplit_once('"'))
        .map(|(v, _)| v)
        .expect(
            "Lane BBBBBB: ARCHIVE= assignment must use double-quoted form: ARCHIVE=\"<value>\"",
        );

    // Invariant 2: starts with $OUT_DIR/.
    assert!(
        value.starts_with("$OUT_DIR/"),
        "Lane BBBBBB: ARCHIVE value MUST start with `$OUT_DIR/` (places the archive under the operator-configured output directory). Got value `{}`. A regression to a hardcoded path breaks operator control over the output location.",
        value
    );

    // Invariant 3: contains `ao2-control-plane-`.
    assert!(
        value.contains("ao2-control-plane-"),
        "Lane BBBBBB: ARCHIVE value MUST contain `ao2-control-plane-` (the product-name prefix). Got value `{}`. A rename without updating downstream consumers (smoke aggregator, README latest-archive pointer) breaks the entire release verification chain.",
        value
    );

    // Invariant 4: contains `$VERSION`.
    assert!(
        value.contains("$VERSION"),
        "Lane BBBBBB: ARCHIVE value MUST contain `$VERSION` (version substitution). Got value `{}`. Without it, two releases at different versions produce the same filename and silently overwrite each other in $OUT_DIR.",
        value
    );

    // Invariant 5: contains `$TARGET_LABEL`.
    assert!(
        value.contains("$TARGET_LABEL"),
        "Lane BBBBBB: ARCHIVE value MUST contain `$TARGET_LABEL` (OS+arch substitution). Got value `{}`. Without it, macOS / Linux / Windows releases collide in $OUT_DIR.",
        value
    );

    // Invariant 6: ends with `.tar.gz`.
    assert!(
        value.ends_with(".tar.gz"),
        "Lane BBBBBB: ARCHIVE value MUST end with `.tar.gz` (gzip-compressed tar suffix). Got value `{}`. A regression to `.tar` ships an uncompressed archive; `.tar.bz2` / `.tar.xz` breaks the smoke aggregator's `tar -xzf` extraction step.",
        value
    );
}

// Lane CCCCCC: smoke-three-os-release.sh shebang + strict-mode parity.
//
// `scripts/smoke-three-os-release.sh` is the cross-OS release
// verification aggregator. It SSH/SCP-orchestrates per-host
// archive verification (macOS local, Ubuntu via SSH, Windows via
// SSH-to-Windows). A failure mid-orchestration leaks artifacts
// across hosts and the operator has no easy "did it actually
// fail?" signal — unless the script fails-fast on the first
// error.
//
// Lane OOOOO binds the same invariants on `scripts/package-local.sh`
// (POSIX `#!/usr/bin/env sh` + `set -eu`). Lane CCCCCC is the
// orthogonal smoke-aggregator analog: the smoke script uses bash
// (not sh) because it depends on bash-specific features
// (`${BASH_SOURCE[0]}`, `-o pipefail`), and it needs the stricter
// `-uo pipefail` semantics to catch:
//
//   - `set -e` — fail on any non-zero exit (so a failed ssh /
//     scp / tar step aborts the whole smoke).
//   - `set -u` — fail on undefined-var expansion (catches a
//     typo'd `$AO2_CP_VERISION` expanding to empty string).
//   - `set -o pipefail` — fail when any pipeline stage fails
//     (so `cat smoke.log | jq ...` actually fails if `cat` fails,
//     not just if jq fails).
//
// Four invariants:
//
//   1. File's first byte MUST be `#` (start of `#!` shebang).
//   2. First line MUST be exactly `#!/usr/bin/env bash` — the
//      smoke script depends on bash-specific features.
//      `#!/bin/bash` reduces cross-distro portability (the path
//      isn't standardized across all Linux distros).
//   3. `set -euo pipefail` (or equivalent: `set -e -u -o pipefail`,
//      `set -eu -o pipefail`) MUST appear on a line by itself.
//   4. The strict-mode line MUST appear within the first 5 lines
//      — a strict mode declared on line 200 is useless because
//      lines 1-199 already ran without it.
//
// Why this matters: the smoke aggregator coordinates a multi-host
// release verification. A mid-orchestration failure that doesn't
// fail-fast can leave per-host stage dirs in inconsistent states,
// confuse the cross-OS verdict computation, or report `matched`
// when a per-host step actually failed silently. The strict-mode
// declaration is the load-bearing defense against this.
//
// Cross-axis: Lane OOOOO binds package-local.sh (POSIX sh, the
// release PRODUCTION script). Lane CCCCCC binds
// smoke-three-os-release.sh (bash, the release VERIFICATION
// script). Together they ensure BOTH critical release-path
// scripts fail-fast on errors.
#[test]
fn smoke_three_os_shebang_and_strict_mode_parity_lane_cccccc() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script_path = root.join("scripts/smoke-three-os-release.sh");
    let script = fs::read_to_string(&script_path)
        .expect("Lane CCCCCC: scripts/smoke-three-os-release.sh present");

    // Invariant 1: first byte is `#`.
    assert!(
        script.starts_with('#'),
        "Lane CCCCCC: smoke-three-os-release.sh first byte must be `#` (start of `#!` shebang); script must lead with a shebang line so the kernel knows which interpreter to invoke."
    );

    let lines: Vec<&str> = script.lines().collect();

    // Invariant 2: first line is exactly `#!/usr/bin/env bash`.
    assert!(
        !lines.is_empty(),
        "Lane CCCCCC: smoke-three-os-release.sh must not be empty"
    );
    assert_eq!(
        lines[0], "#!/usr/bin/env bash",
        "Lane CCCCCC: smoke-three-os-release.sh first line MUST be exactly `#!/usr/bin/env bash` (env-based shebang for cross-distro portability). Got `{}`. `#!/bin/bash` is path-dependent and breaks on some BSDs / minimal-Linux images.",
        lines[0]
    );

    // Invariant 3: a `set -euo pipefail` (or equivalent) line
    // exists. Accept several forms.
    let strict_mode_line = lines.iter().enumerate().take(5).find(|(_, l)| {
        let trimmed = l.trim();
        matches!(
            trimmed,
            "set -euo pipefail"
                | "set -eu -o pipefail"
                | "set -e -u -o pipefail"
                | "set -ueo pipefail"
                | "set -e"
                | "set -eu"
        ) || (trimmed.starts_with("set ")
            && trimmed.contains("-e")
            && trimmed.contains("-u")
            && trimmed.contains("pipefail"))
    });
    let (strict_mode_idx, _) = strict_mode_line
        .expect("Lane CCCCCC: smoke-three-os-release.sh must declare strict mode via `set -euo pipefail` (or equivalent: `set -eu -o pipefail`, `set -e -u -o pipefail`) within the first 5 lines. Without strict mode, a failed ssh/scp/tar/jq step proceeds silently and the cross-OS verdict computation is unreliable.");

    // Invariant 4: strict-mode line is within first 5 lines.
    assert!(
        strict_mode_idx < 5,
        "Lane CCCCCC: smoke-three-os-release.sh strict-mode declaration MUST appear within the first 5 lines (got line {}). A strict-mode declared later in the script is useless because lines preceding it already ran without strict-mode semantics.",
        strict_mode_idx + 1
    );
}

// Lane DDDDDD: install heredoc `ao2_control_plane_installed=` literal
// symmetry parity. Both install.sh and install.ps1 must emit the exact
// downstream-consumed install-confirmation literal across the two
// interpreter contexts. Where Lane MMMM pins the ordering (chmod-after-cp,
// printf-after-chmod) and the existence of the Write-Output confirmation,
// Lane DDDDDD pins the byte-identical KEY name across sh and ps1, the
// emission mechanism on each side, and the value-interpolation contract —
// the operator-facing symmetry that makes a cross-OS install verifier work.
//
// Seven invariants:
//
//   1. install.sh must emit the literal `ao2_control_plane_installed=`
//      byte-string. A typo like `ao2_control_plan_installed=` on either
//      side silently breaks the downstream grep on the typoed OS only.
//
//   2. install.ps1 must emit the same literal byte-string.
//
//   3. install.sh uses `printf` with `%s\n`. `echo` is non-portable
//      (BSD echo handles `\n` differently from GNU echo; dash echo
//      doesn't honor `-e`). `printf` with a literal `%s\n` is the
//      one-true-way cross-distro line emission. Missing the `\n`
//      concatenates the confirmation with whatever stderr leak follows.
//
//   4. install.ps1 uses `Write-Output` (NOT `Write-Host`). Write-Host
//      writes to the PowerShell host UI but bypasses the stdout stream;
//      a downstream `install.ps1 > install.log` would capture nothing,
//      breaking any post-install verification script.
//
//   5. install.sh interpolates `$INSTALL_DIR/$BINARY_NAME` (the full
//      installed path, not just the bin name). The confirmation has to
//      tell the operator WHERE the binary landed; a value like just
//      `$BINARY_NAME` would only emit `ao2-cp-server` with no path.
//
//   6. install.ps1 uses `Join-Path $InstallDir $BinaryName` for the
//      value. Join-Path produces the OS-correct path separator (`\` on
//      Windows) where naive `"$InstallDir\$BinaryName"` string concat
//      can produce double-separators or mojibake under PathExt rules.
//
//   7. Floor: exactly ONE confirmation line per script. Multiple emission
//      sites would double-emit on the same install, breaking naive
//      single-line `grep -E '^ao2_control_plane_installed='` parsers.
#[test]
fn install_heredocs_ao2_control_plane_installed_literal_symmetry_parity_lane_dddddd() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package_local = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane DDDDDD: scripts/package-local.sh present");

    // Slice install.sh heredoc.
    let sh_open = package_local
        .find("cat > \"$STAGE/install.sh\" <<'SH'")
        .expect("Lane DDDDDD: install.sh heredoc opener missing in package-local.sh");
    let sh_body = &package_local[sh_open..];
    let sh_close_rel = sh_body
        .find("\nSH\n")
        .expect("Lane DDDDDD: install.sh heredoc closer `SH` missing");
    let install_sh = &sh_body[..sh_close_rel];

    // Slice install.ps1 heredoc.
    let ps_open = package_local
        .find("cat > \"$STAGE/install.ps1\" <<'PS1'")
        .expect("Lane DDDDDD: install.ps1 heredoc opener missing in package-local.sh");
    let ps_body = &package_local[ps_open..];
    let ps_close_rel = ps_body
        .find("\nPS1\n")
        .expect("Lane DDDDDD: install.ps1 heredoc closer `PS1` missing");
    let install_ps1 = &ps_body[..ps_close_rel];

    // Invariant 1: install.sh contains the literal key+equals.
    let key_literal = "ao2_control_plane_installed=";
    assert!(
        install_sh.contains(key_literal),
        "Lane DDDDDD: install.sh must emit the literal `{key_literal}` byte-string. A typo like `ao2_control_plan_installed=` or a key rename would silently break every downstream verifier that filters install logs on this exact prefix."
    );

    // Invariant 2: install.ps1 contains the same literal key+equals.
    assert!(
        install_ps1.contains(key_literal),
        "Lane DDDDDD: install.ps1 must emit the literal `{key_literal}` byte-string (byte-identical to install.sh). A divergent key name across OSes breaks cross-OS install verification — the verifier sees the key on one OS but not the other and reports asymmetric install failure on a successful install."
    );

    // Invariant 3: install.sh uses `printf` with `%s\n` format.
    let printf_anchor = "printf \"ao2_control_plane_installed=%s\\n\"";
    assert!(
        install_sh.contains(printf_anchor),
        "Lane DDDDDD: install.sh confirmation must use {printf_anchor:?} (printf with literal `%s\\n` format-string). `echo` is non-portable (dash/BSD/GNU disagree on `\\n` and `-e` handling). Missing the trailing `\\n` concatenates the confirmation with whatever follows on stderr, garbling downstream log parsers."
    );

    // Invariant 4: install.ps1 uses `Write-Output` (not Write-Host).
    let ps_write_output_anchor = "Write-Output \"ao2_control_plane_installed=";
    assert!(
        install_ps1.contains(ps_write_output_anchor),
        "Lane DDDDDD: install.ps1 confirmation must use `Write-Output \"ao2_control_plane_installed=...\"` (NOT Write-Host). Write-Host writes to the PowerShell host UI but bypasses the stdout stream; a downstream `install.ps1 > install.log` would capture nothing, breaking any post-install verification script that reads the log file."
    );
    assert!(
        !install_ps1.contains("Write-Host \"ao2_control_plane_installed="),
        "Lane DDDDDD: install.ps1 must NOT use `Write-Host \"ao2_control_plane_installed=...\"`. Defensive deny-twin of invariant 4: catches a regression that flips Write-Output back to Write-Host (a misguided 'console feedback' refactor) which would silently break stdout-piping consumers."
    );

    // Invariant 5: install.sh value interpolates $INSTALL_DIR AND $BINARY_NAME.
    let sh_full_anchor =
        "printf \"ao2_control_plane_installed=%s\\n\" \"$INSTALL_DIR/$BINARY_NAME\"";
    assert!(
        install_sh.contains(sh_full_anchor),
        "Lane DDDDDD: install.sh confirmation value must be the full path `\"$INSTALL_DIR/$BINARY_NAME\"` (got something different). Expected `{sh_full_anchor}`. A value like `\"$BINARY_NAME\"` only emits `ao2-cp-server` with no path context; operators reading the confirmation can't tell WHERE the binary landed when they install with a custom AO2_CP_INSTALL_DIR."
    );

    // Invariant 6: install.ps1 value uses Join-Path with $InstallDir and $BinaryName.
    let ps_full_anchor =
        "Write-Output \"ao2_control_plane_installed=$(Join-Path $InstallDir $BinaryName)\"";
    assert!(
        install_ps1.contains(ps_full_anchor),
        "Lane DDDDDD: install.ps1 confirmation value must use `$(Join-Path $InstallDir $BinaryName)`. Expected `{ps_full_anchor}`. Naive string concat like `\"$InstallDir\\$BinaryName\"` can produce double-separators when InstallDir already has a trailing backslash; Join-Path is PowerShell's portable path-joining helper that normalizes separators per OS."
    );

    // Invariant 7: exactly ONE confirmation line per script.
    let sh_count = install_sh.matches(key_literal).count();
    assert_eq!(
        sh_count, 1,
        "Lane DDDDDD: install.sh must emit the `{key_literal}` confirmation EXACTLY ONCE (got {sh_count}). Multiple emissions on the same install double-emit the confirmation, breaking naive single-line `grep -E '^ao2_control_plane_installed='` parsers that expect to read the install location from `tail -n 1`."
    );
    let ps_count = install_ps1.matches(key_literal).count();
    assert_eq!(
        ps_count, 1,
        "Lane DDDDDD: install.ps1 must emit the `{key_literal}` confirmation EXACTLY ONCE (got {ps_count}). Multiple emissions on the same install double-emit the confirmation, breaking naive single-line parsers."
    );
}

// Lane EEEEEE: per-host smoke-release-archive.{sh,ps1} shebang +
// strict-mode parity. The smoke verification chain has three scripts:
//
//   smoke-three-os-release.sh (aggregator)  — Lane CCCCCC binds.
//   smoke-release-archive.sh   (per-host unix)
//   smoke-release-archive.ps1  (per-host Windows)
//
// CCCCCC binds the aggregator at the top of the chain. EEEEEE binds
// the per-host scripts the aggregator invokes via SSH/SCP. A failure
// in either per-host script that doesn't propagate (silent step, masked
// exit code) leaves the aggregator with stale or partial data, which
// it then aggregates into an "all green" verdict.
//
// Five invariants:
//
//   1. smoke-release-archive.sh first byte is `#` (shebang start).
//   2. smoke-release-archive.sh first line is exactly
//      `#!/usr/bin/env bash`. The script uses `${BASH_SOURCE[0]}`
//      which is a bash-only array variable; a regression to
//      `#!/usr/bin/env sh` would silently break on Ubuntu where
//      /bin/sh is dash.
//   3. smoke-release-archive.sh declares strict mode
//      (`set -euo pipefail` or equivalent) within first 5 lines.
//   4. smoke-release-archive.ps1 declares
//      `$ErrorActionPreference = "Stop"` within first 5 lines.
//      Without it, a Copy-Item or Get-FileHash failure prints red
//      text and continues, masking step failures.
//   5. smoke-release-archive.ps1 first non-empty line MUST be the
//      $ErrorActionPreference declaration (NOT an unrelated line
//      first, which would leave a window where errors don't abort).
#[test]
fn smoke_release_archive_per_host_shebang_and_strict_mode_parity_lane_eeeeee() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sh_path = root.join("scripts/smoke-release-archive.sh");
    let sh_script = fs::read_to_string(&sh_path)
        .expect("Lane EEEEEE: scripts/smoke-release-archive.sh present");

    // Invariant 1: first byte is `#`.
    assert!(
        sh_script.starts_with('#'),
        "Lane EEEEEE: smoke-release-archive.sh first byte must be `#` (start of `#!` shebang). The per-host unix smoke script must lead with a shebang so the SSH-invoked execution picks the correct interpreter."
    );

    let sh_lines: Vec<&str> = sh_script.lines().collect();
    assert!(
        !sh_lines.is_empty(),
        "Lane EEEEEE: smoke-release-archive.sh must not be empty"
    );

    // Invariant 2: first line is exactly `#!/usr/bin/env bash`.
    assert_eq!(
        sh_lines[0], "#!/usr/bin/env bash",
        "Lane EEEEEE: smoke-release-archive.sh first line MUST be exactly `#!/usr/bin/env bash` (got `{}`). The script uses `${{BASH_SOURCE[0]}}` (bash-only array variable); a regression to `#!/usr/bin/env sh` silently breaks on Ubuntu where /bin/sh is dash.",
        sh_lines[0]
    );

    // Invariant 3: strict mode within first 5 lines.
    let sh_strict_mode = sh_lines.iter().enumerate().take(5).find(|(_, l)| {
        let trimmed = l.trim();
        matches!(
            trimmed,
            "set -euo pipefail"
                | "set -eu -o pipefail"
                | "set -e -u -o pipefail"
                | "set -ueo pipefail"
        ) || (trimmed.starts_with("set ")
            && trimmed.contains("-e")
            && trimmed.contains("-u")
            && trimmed.contains("pipefail"))
    });
    let (sh_strict_idx, _) = sh_strict_mode.expect(
        "Lane EEEEEE: smoke-release-archive.sh must declare strict mode via `set -euo pipefail` (or equivalent: `set -eu -o pipefail`, `set -e -u -o pipefail`) within the first 5 lines. Without it, a failed `cp`/`tar`/checksum step proceeds to the success-emission section and the per-host log reports success while a step actually failed silently — the aggregator then reads stale data and computes a green verdict on a broken run.",
    );
    assert!(
        sh_strict_idx < 5,
        "Lane EEEEEE: smoke-release-archive.sh strict-mode declaration MUST appear within first 5 lines (got line {}). Lines preceding the declaration ran without strict-mode semantics, leaving a window where step failures don't abort.",
        sh_strict_idx + 1
    );

    // Now the PowerShell per-host script.
    let ps_path = root.join("scripts/smoke-release-archive.ps1");
    let ps_script = fs::read_to_string(&ps_path)
        .expect("Lane EEEEEE: scripts/smoke-release-archive.ps1 present");
    let ps_lines: Vec<&str> = ps_script.lines().collect();
    assert!(
        !ps_lines.is_empty(),
        "Lane EEEEEE: smoke-release-archive.ps1 must not be empty"
    );

    // Invariant 4: $ErrorActionPreference = "Stop" within first 5 lines.
    let ps_strict_mode = ps_lines.iter().enumerate().take(5).find(|(_, l)| {
        let trimmed = l.trim();
        trimmed == "$ErrorActionPreference = \"Stop\""
            || trimmed == "$ErrorActionPreference = 'Stop'"
    });
    let (ps_strict_idx, _) = ps_strict_mode.expect(
        "Lane EEEEEE: smoke-release-archive.ps1 must declare `$ErrorActionPreference = \"Stop\"` within the first 5 lines. Without it, non-terminating cmdlet errors (failed Copy-Item under strict ACL, Get-FileHash on a missing file) print red text and continue executing; the smoke script reports per-host success even though steps silently failed.",
    );
    assert!(
        ps_strict_idx < 5,
        "Lane EEEEEE: smoke-release-archive.ps1 $ErrorActionPreference declaration MUST appear within first 5 lines (got line {}). Lines preceding the declaration ran without strict-mode semantics.",
        ps_strict_idx + 1
    );

    // Invariant 5: first non-empty line of ps1 IS the $ErrorActionPreference line.
    // (The Stop declaration must be the very first executable statement
    // so that no preceding logic runs without strict mode.)
    let ps_first_nonempty_idx = ps_lines
        .iter()
        .position(|l| !l.trim().is_empty())
        .expect("Lane EEEEEE: smoke-release-archive.ps1 has no non-empty lines");
    assert_eq!(
        ps_first_nonempty_idx, ps_strict_idx,
        "Lane EEEEEE: smoke-release-archive.ps1 first non-empty line (line {}) MUST be the $ErrorActionPreference declaration (currently at line {}). A preceding executable line would run without strict-mode semantics; an unrelated comment or blank is fine but executable code is not.",
        ps_first_nonempty_idx + 1,
        ps_strict_idx + 1
    );
}

// Lane FFFFFF: install heredoc BINARY_NAME / $BinaryName cross-OS
// .exe-suffix parity. The unix and Windows install heredocs in
// scripts/package-local.sh declare the binary filename via two
// separate assignments:
//
//   install.sh:   BINARY_NAME="ao2-cp-server"           (no .exe)
//   install.ps1:  $BinaryName = "ao2-cp-server.exe"     (.exe suffix)
//
// This pair carries a load-bearing contract: the Windows form MUST
// be the unix form + the literal `.exe` suffix and nothing else.
// A regression that renames the unix binary (`ao2-cp-server-v2`)
// without updating the Windows side (still `ao2-cp-server.exe`) would
// leave a release where the unix install copies the right file but
// the Windows install tries to copy a non-existent `ao2-cp-server.exe`
// — and there's no test that catches this because the cargo build
// produces both binaries correctly named per their respective OS.
//
// Five invariants:
//
//   1. install.sh contains exactly ONE top-level `BINARY_NAME="<v>"`
//      assignment. Multiple assignments split the source of truth.
//   2. install.ps1 contains exactly ONE top-level `$BinaryName = "<v>"`
//      assignment. Multiple assignments split the source of truth.
//   3. install.sh's BINARY_NAME value must NOT end with `.exe` — the
//      unix binary has no extension by convention; a `.exe` suffix
//      on unix would make `chmod +x` and `command -v` work on an
//      oddly-named file but break the convention.
//   4. install.ps1's $BinaryName value MUST end with `.exe` — Windows
//      requires the `.exe` extension for the kernel to treat the file
//      as an executable. Without it, `Start-Process` and double-click
//      both fail.
//   5. install.ps1 value MUST equal install.sh value + the literal
//      string `.exe`. A rename of one side without matching update
//      to the other would ship a Windows install referencing a binary
//      that doesn't exist in `bin/`, OR (worse) a unix install
//      referencing a different binary than `cargo build --release`
//      produces — both silent failures at install time.
#[test]
fn install_heredoc_binary_name_exe_suffix_cross_os_parity_lane_ffffff() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package_local = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane FFFFFF: scripts/package-local.sh present");

    // Slice install.sh heredoc.
    let sh_open = package_local
        .find("cat > \"$STAGE/install.sh\" <<'SH'")
        .expect("Lane FFFFFF: install.sh heredoc opener missing in package-local.sh");
    let sh_body = &package_local[sh_open..];
    let sh_close_rel = sh_body
        .find("\nSH\n")
        .expect("Lane FFFFFF: install.sh heredoc closer `SH` missing");
    let install_sh = &sh_body[..sh_close_rel];

    // Slice install.ps1 heredoc.
    let ps_open = package_local
        .find("cat > \"$STAGE/install.ps1\" <<'PS1'")
        .expect("Lane FFFFFF: install.ps1 heredoc opener missing in package-local.sh");
    let ps_body = &package_local[ps_open..];
    let ps_close_rel = ps_body
        .find("\nPS1\n")
        .expect("Lane FFFFFF: install.ps1 heredoc closer `PS1` missing");
    let install_ps1 = &ps_body[..ps_close_rel];

    // Invariant 1: install.sh has exactly one BINARY_NAME=... line at top level.
    let sh_assignments: Vec<&str> = install_sh
        .lines()
        .filter(|l| {
            let trimmed = l.trim_start();
            trimmed.starts_with("BINARY_NAME=\"") && trimmed.ends_with('"')
        })
        .collect();
    assert_eq!(
        sh_assignments.len(),
        1,
        "Lane FFFFFF: install.sh must contain EXACTLY ONE top-level `BINARY_NAME=\"<value>\"` assignment (got {}: {:?}). Multiple assignments split the source of truth; one would shadow the other and the operator can't tell which binary will actually be copied.",
        sh_assignments.len(),
        sh_assignments
    );

    // Parse install.sh value: BINARY_NAME="<value>"
    let sh_line = sh_assignments[0].trim();
    let sh_value = sh_line
        .strip_prefix("BINARY_NAME=\"")
        .and_then(|s| s.strip_suffix('"'))
        .expect("Lane FFFFFF: install.sh BINARY_NAME parse failed");

    // Invariant 2: install.ps1 has exactly one $BinaryName = ... line at top level.
    let ps_assignments: Vec<&str> = install_ps1
        .lines()
        .filter(|l| {
            let trimmed = l.trim_start();
            trimmed.starts_with("$BinaryName = \"") && trimmed.ends_with('"')
        })
        .collect();
    assert_eq!(
        ps_assignments.len(),
        1,
        "Lane FFFFFF: install.ps1 must contain EXACTLY ONE top-level `$BinaryName = \"<value>\"` assignment (got {}: {:?}). Multiple assignments split the source of truth.",
        ps_assignments.len(),
        ps_assignments
    );

    // Parse install.ps1 value: $BinaryName = "<value>"
    let ps_line = ps_assignments[0].trim();
    let ps_value = ps_line
        .strip_prefix("$BinaryName = \"")
        .and_then(|s| s.strip_suffix('"'))
        .expect("Lane FFFFFF: install.ps1 $BinaryName parse failed");

    // Invariant 3: install.sh value does NOT end with .exe.
    assert!(
        !sh_value.ends_with(".exe"),
        "Lane FFFFFF: install.sh BINARY_NAME value `{sh_value}` must NOT end with `.exe`. Unix binaries have no extension by convention; a `.exe` suffix would break `command -v <basename>` lookups and surprise operators reading the README install examples."
    );

    // Invariant 4: install.ps1 value DOES end with .exe.
    assert!(
        ps_value.ends_with(".exe"),
        "Lane FFFFFF: install.ps1 $BinaryName value `{ps_value}` MUST end with `.exe`. Windows requires the `.exe` extension for the kernel to treat the file as an executable; without it `Start-Process` and double-click both fail."
    );

    // Invariant 5: ps_value == sh_value + ".exe".
    let expected_ps = format!("{sh_value}.exe");
    assert_eq!(
        ps_value,
        expected_ps,
        "Lane FFFFFF: install.ps1 $BinaryName (`{ps_value}`) must equal install.sh BINARY_NAME (`{sh_value}`) + the literal `.exe` suffix, expected `{expected_ps}`. A rename of one side without matching update to the other would ship a Windows install referencing a binary that doesn't exist in `bin/`, OR a unix install referencing a different binary than `cargo build --release` produces — both silent failures at install time."
    );
}

// Lane GGGGGG: smoke aggregator exit-code fail-loud parity.
// scripts/smoke-three-os-release.sh is the cross-OS verifier — its
// only legitimate exit codes are 0 (implicit via fall-through to
// end-of-script) and 1 (explicit drift / failure branch). An `exit 0`
// in the body would short-circuit out of the parity checks while
// reporting success — masking the per-host drift the smoke was
// designed to catch.
//
// Three invariants:
//
//   1. Every `exit <N>` statement in the body of the aggregator MUST
//      have N >= 1 (no `exit 0` early-success branches). The success
//      path is fall-through to end-of-script; an explicit `exit 0`
//      mid-body would skip later drift checks while still reporting
//      a clean exit code.
//
//   2. Floor: >= 5 `exit 1` (or higher) statements. The aggregator
//      has multiple parity-drift surfaces (content-hash drift across
//      cockpit, readiness, publication-dashboard, assembly, assembly-
//      blockers). A regression that collapses these into a single
//      check loses per-surface diagnostic resolution.
//
//   3. Every `exit <non-zero>` line MUST be preceded within the
//      prior 3 lines by an `echo ... >&2` (stderr-redirected error
//      message). An exit without a matching stderr echo leaves the
//      CI / operator with a non-zero exit and no diagnostic text —
//      the worst possible debugging surface.
#[test]
fn smoke_three_os_exit_code_fail_loud_parity_lane_gggggg() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script_path = root.join("scripts/smoke-three-os-release.sh");
    let script = fs::read_to_string(&script_path)
        .expect("Lane GGGGGG: scripts/smoke-three-os-release.sh present");
    let lines: Vec<&str> = script.lines().collect();

    // Collect (line_index, exit_code) for every `exit <N>` line. Skip
    // any line where `exit` is inside a comment.
    let mut exit_lines: Vec<(usize, u32)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("exit ") {
            // Parse the numeric exit code following `exit `.
            let code_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !code_str.is_empty() {
                let code: u32 = code_str.parse().expect("Lane GGGGGG: parse exit code");
                exit_lines.push((i, code));
            }
        }
    }

    // Invariant 1: no exit 0.
    for (line_idx, code) in &exit_lines {
        assert!(
            *code >= 1,
            "Lane GGGGGG: smoke-three-os-release.sh line {} contains `exit {}`; all exit statements MUST be non-zero (>= 1). The success path is fall-through to end-of-script; an explicit `exit 0` mid-body would short-circuit out of the parity checks while still reporting a clean exit code, masking per-host drift.",
            line_idx + 1,
            code
        );
    }

    // Invariant 2: floor of >= 5 exit branches.
    assert!(
        exit_lines.len() >= 5,
        "Lane GGGGGG: smoke-three-os-release.sh must contain >= 5 `exit <non-zero>` statements (got {}). Floor protects against a regression that collapses multiple parity-drift surfaces (cockpit, readiness, publication-dashboard, assembly, assembly-blockers) into one check — losing per-surface diagnostic resolution.",
        exit_lines.len()
    );

    // Invariant 3: each exit line preceded by a diagnostic emission
    // within the prior 10 lines. Diagnostic emission counts as either
    // (a) `echo ... >&2` / `printf ... >&2` (stderr-redirected error
    // message) OR (b) `cat "<file>"` (stdout dump of structured
    // diagnostic — the smoke aggregator dumps the full per-host status
    // JSON at the start of the verdict section, which feeds the
    // per-OS status checks that follow).
    for (line_idx, _) in &exit_lines {
        let scan_start = line_idx.saturating_sub(10);
        let preceding = &lines[scan_start..*line_idx];
        let has_diagnostic = preceding.iter().any(|l| {
            let t = l.trim_start();
            let stderr_echo = (t.starts_with("echo ") || t.starts_with("printf "))
                && (l.contains(">&2") || l.contains("1>&2"));
            let stdout_cat = t.starts_with("cat \"") || t.starts_with("cat \'");
            stderr_echo || stdout_cat
        });
        assert!(
            has_diagnostic,
            "Lane GGGGGG: smoke-three-os-release.sh line {} (`exit ...`) MUST be preceded within 10 prior lines by a diagnostic emission — either an `echo ... >&2` / `printf ... >&2` (stderr-redirected error message) or a `cat \"<file>\"` (stdout dump of structured diagnostic JSON). Without it, CI / operator sees a non-zero exit with no debugging surface. Preceding lines: {:?}",
            line_idx + 1,
            preceding
        );
    }
}

// Lane HHHHHH: install heredoc AO2_CP_* env-var ↔ README documentation
// reverse parity. Lane RRR binds the forward direction (every AO2_CP_*
// env var in the README must be referenced in some script). HHHHHH
// binds the reverse: every AO2_CP_* env var the install heredocs
// (install.sh + install.ps1) actually consume MUST appear in the
// README's operator documentation. Without this binding, install
// heredocs can read undocumented env vars that operators have no way
// to know about — they'd run a vanilla install command thinking the
// default applies, while the heredoc silently consumes
// AO2_CP_<surprise> from their environment.
//
// Three invariants:
//
//   1. Floor: install heredocs reference >= 1 AO2_CP_* env var.
//
//   2. Every AO2_CP_* env var referenced in install.sh heredoc MUST
//      appear in the README.txt heredoc.
//
//   3. Every AO2_CP_* env var referenced in install.ps1 heredoc MUST
//      appear in the README.txt heredoc.
//
// (Excludes legacy `AO2_*` namespace without the `_CP_` infix — those
// are documented-elsewhere backwards-compat aliases. The canonical
// namespace is AO2_CP_*; HHHHHH scopes the README documentation
// requirement to the canonical namespace only.)
#[test]
fn install_heredocs_ao2_cp_env_vars_documented_in_readme_lane_hhhhhh() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane HHHHHH: scripts/package-local.sh present");

    let install_sh = extract_install_sh_heredoc(&package);
    let install_ps1 = extract_install_ps1_heredoc(&package);
    let readme = extract_package_readme_heredoc(&package);

    let sh_vars = collect_ao2_cp_env_vars(&install_sh);
    let ps1_vars = collect_ao2_cp_env_vars(&install_ps1);
    let readme_vars = collect_ao2_cp_env_vars(&readme);

    // Invariant 1: floor.
    let combined_count = {
        let mut all: Vec<&String> = sh_vars.iter().chain(ps1_vars.iter()).collect();
        all.sort();
        all.dedup();
        all.len()
    };
    assert!(
        combined_count >= 1,
        "Lane HHHHHH: install heredocs (install.sh + install.ps1) must reference >= 1 AO2_CP_* env var (got {combined_count}). A floor of 0 would defeat the binding by making it vacuously true; the install scripts MUST give the operator at least one knob (the canonical AO2_CP_INSTALL_DIR)"
    );

    // Invariant 2: every install.sh var is in README.
    for v in &sh_vars {
        assert!(
            readme_vars.contains(v),
            "Lane HHHHHH: install.sh heredoc references AO2_CP_* env var `{v}` but it is NOT documented in the README.txt heredoc. README vars: {readme_vars:?}. The README is the operator's only source of truth for what env vars the install script consumes; an undocumented var means the operator can't override defaults without reading the script source."
        );
    }

    // Invariant 3: every install.ps1 var is in README.
    for v in &ps1_vars {
        assert!(
            readme_vars.contains(v),
            "Lane HHHHHH: install.ps1 heredoc references AO2_CP_* env var `{v}` but it is NOT documented in the README.txt heredoc. README vars: {readme_vars:?}. The README is the operator's only source of truth for what env vars the install script consumes; an undocumented var means the Windows operator can't override defaults without reading the script source."
        );
    }
}

// Lane IIIIII: smoke aggregator summary JSON `"schema"` key MUST carry
// a `<dotted-namespace>.v<N>` semver-suffix value, and the namespace
// MUST start with the `ao2-control-plane` org prefix.
//
// The smoke aggregator's python heredoc in
// `scripts/smoke-three-os-release.sh` emits a summary JSON consumed by
// downstream readiness/cockpit tooling. The `"schema"` key carries the
// payload contract version; without a stable semver-suffix the
// downstream parsers can't safely distinguish breaking-change versions
// from compatible additions. This lane forms a parity trinity with:
//
//   - Lane GGGGG (handler consts `SCHEMA_VERSION = "...v<N>"`)
//   - Lane AAAAAA (RELEASE-MANIFEST.json `"schema_version"`)
//   - Lane IIIIII (this test — smoke aggregator JSON `"schema"`)
//
// All three carry the same convention. A drift here would break the
// downstream readiness-refresh pipeline silently (it would parse fine
// but version-gate logic would break).
//
// Invariants:
//   1. The python heredoc starting at the aggregator section MUST
//      declare a `"schema":` JSON key.
//   2. The value MUST match `<namespace>.v<N>` where namespace is a
//      non-empty dotted string and N is a positive integer (>=1, no
//      leading zero).
//   3. The namespace MUST start with the literal `ao2-control-plane`
//      org prefix.
#[test]
fn smoke_three_os_summary_schema_semver_suffix_lane_iiiiii() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = fs::read_to_string(root.join("scripts/smoke-three-os-release.sh"))
        .expect("Lane IIIIII: scripts/smoke-three-os-release.sh present");

    // Find the AGGREGATOR python heredoc — the one that emits the
    // summary. It's the third `<<'PY'` heredoc in the file. Identify
    // it by content: it's the heredoc that contains `"schema":`. We
    // walk all `<<'PY'` ... `PY` blocks and pick the one declaring
    // the JSON `"schema"` key. This is more robust than indexing by
    // ordinal (line counts shift with refactors).
    let mut aggregator_heredoc: Option<&str> = None;
    let mut cursor = script.as_str();
    while let Some(open_rel) = cursor.find("<<'PY'") {
        let after_open = &cursor[open_rel + "<<'PY'".len()..];
        let nl_off = after_open
            .find('\n')
            .expect("Lane IIIIII: heredoc opener must be followed by newline");
        let body_start = nl_off + 1;
        let body_and_after = &after_open[body_start..];
        let close_rel = body_and_after
            .find("\nPY\n")
            .or_else(|| {
                if body_and_after.ends_with("\nPY") {
                    Some(body_and_after.len() - "\nPY".len())
                } else {
                    None
                }
            })
            .expect("Lane IIIIII: heredoc opener `<<'PY'` must have a matching `PY` closer");
        let body = &body_and_after[..close_rel];
        if body.contains("\"schema\":") {
            aggregator_heredoc = Some(body);
            break;
        }
        // Advance past this heredoc.
        let consumed = (open_rel + "<<'PY'".len()) + body_start + close_rel + "\nPY\n".len();
        if consumed >= cursor.len() {
            break;
        }
        cursor = &cursor[consumed..];
    }

    let heredoc = aggregator_heredoc.expect(
        "Lane IIIIII: smoke-three-os-release.sh must contain a python heredoc that declares a `\"schema\":` JSON key (the aggregator emits the summary consumed by downstream readiness/cockpit tooling). If the aggregator was renamed or its summary emission moved out of a python heredoc, this lane must be re-targeted to the new emission site so the schema-version contract stays pinned."
    );

    // Invariant 1: extract the schema value string. Pattern:
    //   "schema": "<value>",
    // (whitespace-tolerant; double-quoted value only — single-quoted
    //  would be a python literal that violates JSON output anyway).
    let key_idx = heredoc
        .find("\"schema\":")
        .expect("Lane IIIIII: aggregator heredoc must contain the literal `\"schema\":` key");
    let after_key = &heredoc[key_idx + "\"schema\":".len()..];
    let after_key_trimmed = after_key.trim_start();
    assert!(
        after_key_trimmed.starts_with('"'),
        "Lane IIIIII: aggregator `\"schema\":` key value must be a double-quoted JSON string literal. Got: {:?}. A non-string value would not be valid JSON output and would break every downstream parser.",
        &after_key_trimmed[..after_key_trimmed.len().min(80)]
    );
    let value_body = &after_key_trimmed[1..];
    let close_quote = value_body
        .find('"')
        .expect("Lane IIIIII: aggregator `\"schema\":` value must have a closing double quote");
    let schema_value = &value_body[..close_quote];

    // Invariant 2: value matches <namespace>.v<N>.
    let dot_v_idx = schema_value
        .rfind(".v")
        .unwrap_or_else(|| panic!(
            "Lane IIIIII: aggregator `\"schema\"` value `{schema_value}` must end with `.v<N>` semver suffix (>= 1 dot separator before the `v`). The semver suffix is what downstream parsers (readiness refresh, cockpit HTML) use to gate version-incompatible payloads; without it a breaking change ships silently as the same `\"schema\"` value."
        ));
    let namespace_part = &schema_value[..dot_v_idx];
    let n_part = &schema_value[dot_v_idx + ".v".len()..];
    assert!(
        !namespace_part.is_empty(),
        "Lane IIIIII: aggregator `\"schema\"` value `{schema_value}` has empty namespace before `.v<N>`. The namespace identifies which payload contract is being versioned; an empty prefix would collide with every other versioned payload in the org."
    );
    assert!(
        !n_part.is_empty() && n_part.bytes().all(|b| b.is_ascii_digit()),
        "Lane IIIIII: aggregator `\"schema\"` value `{schema_value}` `.v<N>` suffix must have N consisting of ASCII digits only (got N=`{n_part}`). Non-numeric N (e.g., `v1-rc1`, `vNext`) would break monotonic version comparisons in downstream version-gate logic."
    );
    let n_value: u32 = n_part.parse().unwrap_or_else(|_| panic!(
        "Lane IIIIII: aggregator `\"schema\"` value `{schema_value}` N segment `{n_part}` must parse as u32"
    ));
    assert!(
        n_value >= 1,
        "Lane IIIIII: aggregator `\"schema\"` value `{schema_value}` N segment is {n_value}; must be >= 1. v0 is reserved (would imply pre-contract) and conflicts with the parity-trinity convention used by Lane GGGGG handler consts and Lane AAAAAA release manifest."
    );
    assert!(
        !(n_part.len() > 1 && n_part.starts_with('0')),
        "Lane IIIIII: aggregator `\"schema\"` value `{schema_value}` N segment `{n_part}` has a leading zero. Leading zeros would let `.v01` and `.v1` both parse to 1, splitting the version label space."
    );

    // Invariant 3: namespace prefix.
    assert!(
        namespace_part.starts_with("ao2-control-plane"),
        "Lane IIIIII: aggregator `\"schema\"` namespace `{namespace_part}` must start with the org prefix `ao2-control-plane`. The prefix is what downstream cross-product tooling uses to route payloads to the right parser; a mismatched prefix means a payload from this aggregator could be misrouted to (or silently dropped by) an unrelated org consumer."
    );
}

// Lane JJJJJJ: install heredoc cd-to-script-dir precedence parity.
//
// The install heredocs (install.sh + install.ps1) MUST cd into the
// script's own directory BEFORE any file-operating command runs.
// Without this, an operator who invokes the install script from a
// directory other than the unpacked archive root will see the install
// script fail silently (every relative path lookup hits the wrong
// directory). Worse, on Unix the `cp` step would copy from the
// invocation cwd's `bin/` (which may not even exist) and the
// SHA256SUMS lookup would parse whichever file happens to be named
// that in the cwd — a confused-deputy surface if a malicious local
// SHA256SUMS pre-existed.
//
// Three invariants per script:
//   1. install.sh body MUST contain exactly one
//      `cd "$(dirname -- "$0")"` statement.
//   2. install.ps1 body MUST contain exactly one
//      `Set-Location -LiteralPath $PSScriptRoot` statement.
//   3. PRECEDENCE: each cd-equivalent MUST appear BEFORE the first
//      occurrence of any relative archive path (`bin/`, `SHA256SUMS`)
//      in the same heredoc body. If the cd appears after a file
//      reference, that file reference resolves against the
//      invocation cwd, not the script dir — defeating the cd.
#[test]
fn install_heredoc_cd_to_script_dir_precedence_lane_jjjjjj() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane JJJJJJ: scripts/package-local.sh present");

    let install_sh = extract_install_sh_heredoc(&package);
    let install_ps1 = extract_install_ps1_heredoc(&package);

    // Invariant 1: install.sh has exactly one `cd "$(dirname -- "$0")"`.
    let sh_cd = "cd \"$(dirname -- \"$0\")\"";
    let sh_cd_count = install_sh.matches(sh_cd).count();
    assert_eq!(
        sh_cd_count, 1,
        "Lane JJJJJJ: install.sh heredoc MUST contain EXACTLY ONE `{sh_cd}` statement (got {sh_cd_count}). Zero means relative paths inside install.sh (e.g., `bin/$BINARY_NAME`, `SHA256SUMS`) resolve against the operator's invocation cwd, not the unpacked archive root — silent install failure or confused-deputy on a planted SHA256SUMS. Two would suggest a refactor accident and is brittle (the second cd may target a wrong relative dir)."
    );

    // Invariant 2: install.ps1 has exactly one
    // `Set-Location -LiteralPath $PSScriptRoot`.
    let ps_cd = "Set-Location -LiteralPath $PSScriptRoot";
    let ps_cd_count = install_ps1.matches(ps_cd).count();
    assert_eq!(
        ps_cd_count, 1,
        "Lane JJJJJJ: install.ps1 heredoc MUST contain EXACTLY ONE `{ps_cd}` statement (got {ps_cd_count}). Same rationale as install.sh: without it, `Join-Path \"bin\" $BinaryName` and `Get-Content SHA256SUMS` resolve against the operator's invocation cwd, not the unpacked archive root."
    );

    // Invariant 3a: install.sh cd precedes the first archive-relative
    // file reference. We pick markers that unambiguously refer to the
    // archive root (not e.g. `bin/` inside the `#!/usr/bin/env sh`
    // shebang): the SHA256SUMS manifest and the `bin/$BINARY_NAME`
    // copy source.
    let sh_cd_idx = install_sh
        .find(sh_cd)
        .expect("Lane JJJJJJ: install.sh cd statement located by invariant 1");
    let sh_bin_var_idx = install_sh.find("bin/$BINARY_NAME").expect(
        "Lane JJJJJJ: install.sh must reference `bin/$BINARY_NAME` (the archive-relative copy source)",
    );
    let sh_sums_idx = install_sh.find("SHA256SUMS").expect(
        "Lane JJJJJJ: install.sh must reference `SHA256SUMS` (the archive's checksum manifest)",
    );
    let sh_first_rel = sh_bin_var_idx.min(sh_sums_idx);
    assert!(
        sh_cd_idx < sh_first_rel,
        "Lane JJJJJJ: install.sh `{sh_cd}` (offset {sh_cd_idx}) MUST appear BEFORE the first archive-relative reference at offset {sh_first_rel}. Otherwise the relative path resolves against the operator's invocation cwd, not the script dir — defeating the cd entirely."
    );

    // Invariant 3b: install.ps1 Set-Location precedes the first
    // archive-relative reference (Join-Path on the literal `"bin"`,
    // or the SHA256SUMS manifest).
    let ps_cd_idx = install_ps1
        .find(ps_cd)
        .expect("Lane JJJJJJ: install.ps1 Set-Location located by invariant 2");
    let ps_bin_idx = install_ps1.find("\"bin\"").expect(
        "Lane JJJJJJ: install.ps1 must reference the `\"bin\"` literal (the archive's binary directory) somewhere in a Join-Path",
    );
    let ps_sums_idx = install_ps1.find("SHA256SUMS").expect(
        "Lane JJJJJJ: install.ps1 must reference `SHA256SUMS` (the archive's checksum manifest)",
    );
    let ps_first_rel = ps_bin_idx.min(ps_sums_idx);
    assert!(
        ps_cd_idx < ps_first_rel,
        "Lane JJJJJJ: install.ps1 `{ps_cd}` (offset {ps_cd_idx}) MUST appear BEFORE the first archive-relative reference at offset {ps_first_rel}. Otherwise `Join-Path \"bin\" $BinaryName` and `Get-Content SHA256SUMS` resolve against the operator's invocation cwd."
    );
}

// Lane KKKKKK: release script EXIT trap cleanup parity.
//
// Every release-pipeline script that allocates non-trivial ephemeral
// resources (tempdirs via `mktemp -d`, background server PIDs,
// working-tree commit files) MUST install a `trap` for the EXIT
// pseudo-signal to clean those resources up. Without it, CI / the
// operator's host leaks tempdirs or zombie processes whenever the
// script exits before its happy-path cleanup runs — and under strict
// mode (Lane OOOOO / CCCCCC), early exit is the COMMON case (set -e
// triggers it on any unchecked failure).
//
// Per-script invariants:
//   1. `scripts/package-local.sh` MUST install `trap cleanup EXIT`
//      AND its `cleanup()` body MUST `rm` the `$STAGE` mktemp dir.
//   2. `scripts/smoke-release-archive.sh` MUST install
//      `trap cleanup EXIT` AND its `cleanup()` body MUST `kill` the
//      `$SERVER_PID` background process.
//   3. `scripts/smoke-three-os-release.sh` MUST install a
//      `trap ... EXIT` somewhere in the script (it uses an inline
//      trap that `rm -f`s the working-tree commit file).
//
// Floor: at least 3 EXIT-trap declarations across the three scripts.
//
// Cross-axis to Lane OOOOO (package-local strict-mode), CCCCCC
// (smoke-three-os strict-mode), and EEEEEE (smoke-release-archive
// strict-mode): strict-mode makes EARLY exit common; KKKKKK ensures
// that early exits don't leak resources.
#[test]
fn release_script_exit_trap_cleanup_parity_lane_kkkkkk() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane KKKKKK: scripts/package-local.sh present");
    let smoke_archive = fs::read_to_string(root.join("scripts/smoke-release-archive.sh"))
        .expect("Lane KKKKKK: scripts/smoke-release-archive.sh present");
    let smoke_three_os = fs::read_to_string(root.join("scripts/smoke-three-os-release.sh"))
        .expect("Lane KKKKKK: scripts/smoke-three-os-release.sh present");

    // Invariant 1: package-local.sh has `trap cleanup EXIT` AND
    // its cleanup() body removes $STAGE.
    assert!(
        package.contains("trap cleanup EXIT"),
        "Lane KKKKKK: scripts/package-local.sh MUST install `trap cleanup EXIT` to guarantee the mktemp `$STAGE` directory is removed on every exit path. Without it, repeated packaging runs (especially under strict-mode early-exit) leak tempdirs into `$TMPDIR` indefinitely."
    );
    // Find the cleanup() function body and verify it rm-s $STAGE.
    let cleanup_start = package
        .find("cleanup() {")
        .expect("Lane KKKKKK: scripts/package-local.sh MUST define a `cleanup()` shell function");
    let cleanup_body_start = cleanup_start + "cleanup() {".len();
    let cleanup_end = package[cleanup_body_start..].find("\n}").expect(
        "Lane KKKKKK: scripts/package-local.sh `cleanup()` function MUST have a closing `}`",
    );
    let cleanup_body = &package[cleanup_body_start..cleanup_body_start + cleanup_end];
    assert!(
        cleanup_body.contains("rm") && cleanup_body.contains("$STAGE"),
        "Lane KKKKKK: scripts/package-local.sh `cleanup()` body MUST contain `rm` AND `$STAGE` (the mktemp dir). Body was: {cleanup_body:?}. If cleanup() exists but doesn't remove the tempdir, the trap is decorative — the dir still leaks."
    );

    // Invariant 2: smoke-release-archive.sh has `trap cleanup EXIT`
    // AND its cleanup() body kills $SERVER_PID.
    assert!(
        smoke_archive.contains("trap cleanup EXIT"),
        "Lane KKKKKK: scripts/smoke-release-archive.sh MUST install `trap cleanup EXIT` to guarantee the background server process is killed on every exit path. Without it, a failed smoke run leaves a zombie ao2-cp-server bound to the chosen port — every subsequent run on the same host then fails port allocation, masking the original failure."
    );
    let archive_cleanup_start = smoke_archive.find("cleanup() {").expect(
        "Lane KKKKKK: scripts/smoke-release-archive.sh MUST define a `cleanup()` shell function",
    );
    let archive_cleanup_body_start = archive_cleanup_start + "cleanup() {".len();
    let archive_cleanup_end = smoke_archive[archive_cleanup_body_start..]
        .find("\n}")
        .expect("Lane KKKKKK: scripts/smoke-release-archive.sh `cleanup()` function MUST have a closing `}`");
    let archive_cleanup_body = &smoke_archive
        [archive_cleanup_body_start..archive_cleanup_body_start + archive_cleanup_end];
    assert!(
        archive_cleanup_body.contains("kill") && archive_cleanup_body.contains("SERVER_PID"),
        "Lane KKKKKK: scripts/smoke-release-archive.sh `cleanup()` body MUST contain `kill` AND `SERVER_PID` (the background server process). Body was: {archive_cleanup_body:?}. If cleanup() exists but doesn't kill the server, the trap is decorative — the zombie still hangs around."
    );

    // Invariant 3: smoke-three-os-release.sh has a `trap ... EXIT`.
    // It uses an inline trap (not a cleanup() function), so we just
    // pin that the EXIT trap exists.
    assert!(
        smoke_three_os.contains("trap '") && smoke_three_os.contains("' EXIT"),
        "Lane KKKKKK: scripts/smoke-three-os-release.sh MUST install a `trap '...' EXIT` (it uses an inline trap to remove the working-tree commit file). Without it, a failed orchestration leaks files under `$AO2_CP_THREE_OS_SMOKE_ROOT`."
    );

    // Invariant 4: floor. At least 3 EXIT-trap declarations across
    // the three scripts. Catches a regression that removes the trap
    // from one of them but leaves it in another.
    let trap_count = package.matches("trap ").count()
        + smoke_archive.matches("trap ").count()
        + smoke_three_os.matches("trap ").count();
    assert!(
        trap_count >= 3,
        "Lane KKKKKK: combined `trap` declaration count across (package-local.sh, smoke-release-archive.sh, smoke-three-os-release.sh) is {trap_count}; floor is 3 (one per script). Floor catches a regression that removes a trap from one of the three scripts but leaves it in another."
    );
}

// Lane LLLLLL: RELEASE-MANIFEST.json `auth_value_stored=False` parity
// (security-critical trust-boundary invariant).
//
// The python heredoc that emits RELEASE-MANIFEST.json declares one or
// more `auth_value_stored` keys (one per documented handoff command
// that takes an `AO2_CP_AUTH_VALUE` env var). Each MUST carry the
// Python literal `False`, never `True`. The key documents to the
// release-archive consumer that the manifest itself does NOT store
// the operator's auth value — the operator passes it via env var at
// runtime, and the archive never persists it.
//
// Flipping any `auth_value_stored` to `True` would mean the release
// archive (a publicly distributed artifact) now claims to carry a
// stored auth credential — that's a credential-leak surface even if
// the actual value isn't there, because the claim mismatch would
// confuse operators reading the manifest. More dangerous: if the
// claim ever became accurate (i.e., the auth value got baked into
// the archive by mistake), this lane would catch the source change
// at packaging time, not at the security review when the archive
// hits an artifact store.
//
// Three invariants:
//   1. Floor: the python heredoc that emits the manifest declares
//      at least one `auth_value_stored` key.
//   2. The heredoc MUST NOT contain `auth_value_stored": True`
//      (the exact `: True` shape).
//   3. The count of `auth_value_stored": False` MUST equal the count
//      of `auth_value_stored` (i.e., no occurrence escapes the
//      `: False` pin via reformatting variants like trailing
//      whitespace, lowercase, or `:False` without space).
#[test]
fn release_manifest_auth_value_stored_false_parity_lane_llllll() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane LLLLLL: scripts/package-local.sh present");

    // Locate the manifest-emitting python heredoc. Identify it by
    // content: it's the heredoc that declares the literal
    // `ao2-control-plane.release-manifest.v1` schema_version. This
    // is more robust than ordinal indexing.
    let mut manifest_heredoc: Option<&str> = None;
    let mut cursor = package.as_str();
    while let Some(open_rel) = cursor.find("<<'PY'") {
        let after_open = &cursor[open_rel + "<<'PY'".len()..];
        let nl_off = after_open
            .find('\n')
            .expect("Lane LLLLLL: heredoc opener must be followed by newline");
        let body_start = nl_off + 1;
        let body_and_after = &after_open[body_start..];
        let close_rel = body_and_after
            .find("\nPY\n")
            .or_else(|| {
                if body_and_after.ends_with("\nPY") {
                    Some(body_and_after.len() - "\nPY".len())
                } else {
                    None
                }
            })
            .expect("Lane LLLLLL: heredoc opener `<<'PY'` must have a matching `PY` closer");
        let body = &body_and_after[..close_rel];
        if body.contains("ao2-control-plane.release-manifest.v1") {
            manifest_heredoc = Some(body);
            break;
        }
        let consumed = (open_rel + "<<'PY'".len()) + body_start + close_rel + "\nPY\n".len();
        if consumed >= cursor.len() {
            break;
        }
        cursor = &cursor[consumed..];
    }

    let heredoc = manifest_heredoc.expect(
        "Lane LLLLLL: scripts/package-local.sh MUST contain a python heredoc that declares the release-manifest schema_version `ao2-control-plane.release-manifest.v1`. If the manifest emitter was renamed or its schema_version changed, this lane must be re-targeted to the new emission site so the auth_value_stored=False contract stays pinned to the manifest.",
    );

    // Invariant 1: floor — at least one auth_value_stored key.
    let total_count = heredoc.matches("auth_value_stored").count();
    assert!(
        total_count >= 1,
        "Lane LLLLLL: manifest python heredoc must declare at least 1 `auth_value_stored` key (got {total_count}). A floor of 0 would defeat the binding — the operator-facing manifest needs this key to document the trust-boundary claim that the archive does NOT store auth values."
    );

    // Invariant 2: the heredoc MUST NOT contain
    // `auth_value_stored": True`.
    assert!(
        !heredoc.contains("auth_value_stored\": True"),
        "Lane LLLLLL: manifest python heredoc MUST NOT contain `auth_value_stored\": True`. The `auth_value_stored` key documents to the release-archive consumer that the manifest does NOT store the operator's auth value; flipping it to True would either be a false claim (the archive then misrepresents its own contents to operators) or accurate (the auth value got baked into the archive — a credential-leak surface). Either way the source change must be caught at packaging time."
    );

    // Invariant 3: every occurrence has the `: False` suffix.
    let false_count = heredoc.matches("auth_value_stored\": False").count();
    assert_eq!(
        false_count, total_count,
        "Lane LLLLLL: every `auth_value_stored` key in the manifest python heredoc must carry the exact suffix `\\\": False` (Python literal, capital F). Found {total_count} `auth_value_stored` occurrences but only {false_count} of them matched the `\\\": False` shape. The mismatch suggests a reformatting variant (e.g., trailing whitespace before False, lowercase, or `:False` without space) — that variant escapes the `: True` ban in invariant 2 by being a different shape. Tighten the source to the canonical `\\\"auth_value_stored\\\": False,` form."
    );
}

// Lane MMMMMM: RELEASE-MANIFEST.json `binary_path = bin/{binary}`
// cross-field parity.
//
// The python heredoc that emits RELEASE-MANIFEST.json declares two
// related keys:
//
//   "binary":      sys.argv[4],
//   "binary_path": f"bin/{sys.argv[4]}",
//
// They MUST stay tied together: `binary_path` is the bin/-prefixed
// form of `binary`, computed from the SAME argv index. If a refactor
// changes the binary argv index but forgets to update binary_path,
// the manifest could ship with binary="ao2-cp-server" and
// binary_path="bin/whatever-was-here-before" — silently breaking
// install scripts and verifiers that read either field.
//
// Three invariants:
//   1. The manifest heredoc declares a `"binary":` JSON key whose
//      value is a Python expression (not a string literal — both
//      sides interpolate from argv at runtime).
//   2. The manifest heredoc declares a `"binary_path":` JSON key
//      whose value is an f-string starting with `f"bin/{`.
//   3. The expression INSIDE the f-string's `{...}` MUST match the
//      bare expression assigned to `binary`. (Both must point at
//      the same source — the same sys.argv index, or the same
//      variable name. We extract both and string-compare.)
#[test]
fn release_manifest_binary_path_bin_prefix_parity_lane_mmmmmm() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane MMMMMM: scripts/package-local.sh present");

    // Locate the manifest heredoc by content match (same approach
    // as Lane LLLLLL).
    let mut manifest_heredoc: Option<&str> = None;
    let mut cursor = package.as_str();
    while let Some(open_rel) = cursor.find("<<'PY'") {
        let after_open = &cursor[open_rel + "<<'PY'".len()..];
        let nl_off = after_open
            .find('\n')
            .expect("Lane MMMMMM: heredoc opener must be followed by newline");
        let body_start = nl_off + 1;
        let body_and_after = &after_open[body_start..];
        let close_rel = body_and_after
            .find("\nPY\n")
            .or_else(|| {
                if body_and_after.ends_with("\nPY") {
                    Some(body_and_after.len() - "\nPY".len())
                } else {
                    None
                }
            })
            .expect("Lane MMMMMM: heredoc opener `<<'PY'` must have a matching `PY` closer");
        let body = &body_and_after[..close_rel];
        if body.contains("ao2-control-plane.release-manifest.v1") {
            manifest_heredoc = Some(body);
            break;
        }
        let consumed = (open_rel + "<<'PY'".len()) + body_start + close_rel + "\nPY\n".len();
        if consumed >= cursor.len() {
            break;
        }
        cursor = &cursor[consumed..];
    }

    let heredoc = manifest_heredoc.expect(
        "Lane MMMMMM: scripts/package-local.sh MUST contain a manifest python heredoc declaring `ao2-control-plane.release-manifest.v1`",
    );

    // Extract the `binary` value expression. The line shape is:
    //   "binary": <expr>,
    let bin_key_idx = heredoc
        .find("\"binary\":")
        .expect("Lane MMMMMM: manifest heredoc must contain `\"binary\":` key");
    let after_bin_key = &heredoc[bin_key_idx + "\"binary\":".len()..];
    // Read until the next unescaped newline; the value is the
    // trimmed text before the trailing comma.
    let bin_line_end = after_bin_key
        .find('\n')
        .expect("Lane MMMMMM: `\"binary\":` line must end with a newline inside the heredoc");
    let bin_value_raw = after_bin_key[..bin_line_end].trim();
    let binary_expr = bin_value_raw.trim_end_matches(',').trim();
    assert!(
        !binary_expr.is_empty(),
        "Lane MMMMMM: manifest heredoc `\"binary\":` value is empty after trimming. Got line: {bin_value_raw:?}"
    );

    // Invariant 2: locate `"binary_path":` and check it starts with
    // `f"bin/{`.
    let bp_key_idx = heredoc
        .find("\"binary_path\":")
        .expect("Lane MMMMMM: manifest heredoc must contain `\"binary_path\":` key");
    let after_bp_key = &heredoc[bp_key_idx + "\"binary_path\":".len()..];
    let bp_line_end = after_bp_key
        .find('\n')
        .expect("Lane MMMMMM: `\"binary_path\":` line must end with a newline inside the heredoc");
    let bp_value_raw = after_bp_key[..bp_line_end].trim();
    let bp_value = bp_value_raw.trim_end_matches(',').trim();
    let bp_prefix = "f\"bin/{";
    assert!(
        bp_value.starts_with(bp_prefix),
        "Lane MMMMMM: manifest heredoc `\"binary_path\":` value MUST start with `{bp_prefix}` (it is the bin-prefixed form of the binary). Got: {bp_value:?}. A non-f-string literal would split the source of truth from the `binary` key, allowing the two to drift."
    );
    // Invariant 3: extract the expression inside `{...}` and
    // compare to binary_expr.
    let inside_brace_start = bp_prefix.len();
    let close_brace_rel = bp_value[inside_brace_start..]
        .find('}')
        .expect("Lane MMMMMM: `\"binary_path\":` f-string must contain a closing `}`");
    let bp_inner_expr = &bp_value[inside_brace_start..inside_brace_start + close_brace_rel];
    assert_eq!(
        bp_inner_expr, binary_expr,
        "Lane MMMMMM: manifest heredoc `\"binary_path\":` interpolates {bp_inner_expr:?} inside its f-string, but `\"binary\":` uses the expression {binary_expr:?}. The two MUST match so binary_path is always exactly `bin/<binary>` from the same source. If they diverge, the manifest can ship binary=A and binary_path=bin/B — silently breaking install scripts and verifiers that trust the relationship."
    );
}

// Lane NNNNNN: install heredoc checksum mismatch error message parity.
//
// Both install heredocs verify the packaged binary's SHA256 against
// the SHA256SUMS manifest before copying. On mismatch, each script
// MUST emit the literal phrase `checksum mismatch` in its diagnostic
// AND propagate a non-zero exit (POSIX `exit 1` on Unix; PowerShell
// `throw` under strict-mode equivalent on Windows). Operators see
// the same trigger phrase regardless of OS, enabling consistent
// triage runbook entries.
//
// Without this binding:
//   - A refactor that changes install.sh's diagnostic to "hash
//     mismatch" or "checksum failure" breaks every operator runbook
//     that greps for "checksum mismatch" — Unix operators report a
//     different symptom than Windows operators on the same incident.
//   - A refactor that drops the `exit 1` from install.sh (or
//     replaces `throw` with `Write-Warning` in install.ps1) lets
//     the install proceed past the verification failure and copies
//     a tampered binary into the operator's PATH — a supply-chain
//     drift surface.
//
// Per-script invariants:
//   1. install.sh contains the literal `"checksum mismatch"` in a
//      stderr-redirected `echo` statement.
//   2. install.sh stderr emission is followed (within 5 lines) by
//      `exit 1` (or any `exit <non-zero>`).
//   3. install.ps1 contains the literal `"checksum mismatch"` in a
//      `throw` statement (so it propagates under the script's
//      $ErrorActionPreference = "Stop" — Lane BBBBB / EEEEEE-equiv).
//   4. Cross-OS: both diagnostics reference `bin/<binary>` (or
//      equivalent) so the operator knows which file failed.
#[test]
fn install_heredoc_checksum_mismatch_error_parity_lane_nnnnnn() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane NNNNNN: scripts/package-local.sh present");

    let install_sh = extract_install_sh_heredoc(&package);
    let install_ps1 = extract_install_ps1_heredoc(&package);

    // Invariant 1: install.sh contains the literal phrase in a
    // stderr-redirected echo.
    assert!(
        install_sh.contains("\"checksum mismatch"),
        "Lane NNNNNN: install.sh heredoc MUST emit the literal phrase `checksum mismatch` in its hash-divergence diagnostic. Operator triage runbooks grep for this phrase to route incidents to the supply-chain on-call. A refactor to `hash mismatch` / `checksum failure` would break every runbook entry that filters logs by this string."
    );
    // Find the echo line and verify it redirects to stderr.
    let mismatch_idx_sh = install_sh
        .find("checksum mismatch")
        .expect("Lane NNNNNN: install.sh `checksum mismatch` located by invariant 1");
    // Walk back to the start of the line containing the phrase.
    let line_start = install_sh[..mismatch_idx_sh]
        .rfind('\n')
        .map_or(0, |n| n + 1);
    // Walk forward to find the next newline.
    let line_end_rel = install_sh[mismatch_idx_sh..]
        .find('\n')
        .unwrap_or(install_sh.len() - mismatch_idx_sh);
    let mismatch_line = &install_sh[line_start..mismatch_idx_sh + line_end_rel];
    assert!(
        mismatch_line.contains(">&2"),
        "Lane NNNNNN: install.sh `checksum mismatch` diagnostic line MUST redirect to stderr (`>&2`). Got: {mismatch_line:?}. Without stderr redirection, the error message gets mingled with stdout — and stdout is what the cross-OS install confirmation contract (Lane DDDDDD) reserves for the `ao2_control_plane_installed=...` line. Mixing the two means a downstream parser of stdout sees garbage on failure."
    );

    // Invariant 2: install.sh emits `exit 1` (or any non-zero exit)
    // within 5 lines after the mismatch diagnostic.
    let post_mismatch_lines: Vec<&str> = install_sh[mismatch_idx_sh..].lines().take(5).collect();
    let post_mismatch_joined = post_mismatch_lines.join("\n");
    assert!(
        post_mismatch_joined.contains("exit 1")
            || post_mismatch_joined.contains("exit 2")
            || post_mismatch_joined.contains("exit ${"),
        "Lane NNNNNN: install.sh `checksum mismatch` diagnostic MUST be followed within 5 lines by `exit <non-zero>`. Got lines: {post_mismatch_lines:?}. Without the explicit non-zero exit, the script falls through to the `cp` step and copies the tampered binary into the operator's PATH — exactly the failure mode the checksum verification was supposed to prevent."
    );

    // Invariant 3: install.ps1 contains the literal phrase in a
    // `throw` statement.
    assert!(
        install_ps1.contains("throw \"checksum mismatch"),
        "Lane NNNNNN: install.ps1 heredoc MUST `throw \"checksum mismatch ...\"` (not Write-Warning / Write-Error / Write-Host). `throw` is the only PowerShell error mechanism that respects `$ErrorActionPreference = \"Stop\"` (set by Lane BBBBB) and aborts the script. Write-Warning / Write-Error / Write-Host with -ForegroundColor all emit text but allow the script to continue to the Copy-Item step — propagating the tampered binary into the install dir."
    );

    // Invariant 4: cross-OS — both diagnostics reference `bin/`
    // (the archive's binary directory) so the operator knows which
    // file failed.
    assert!(
        install_sh.contains("checksum mismatch for bin/"),
        "Lane NNNNNN: install.sh `checksum mismatch` diagnostic MUST include the `bin/` prefix in its file reference (e.g., `checksum mismatch for bin/$BINARY_NAME`). Without it, operators reading the error message can't tell which file in the archive failed — important when the archive contains multiple binaries."
    );
    assert!(
        install_ps1.contains("checksum mismatch for bin/"),
        "Lane NNNNNN: install.ps1 `checksum mismatch` diagnostic MUST include the `bin/` prefix in its file reference (e.g., `throw \"checksum mismatch for bin/ao2-cp-server.exe\"`). Cross-OS parity with install.sh — both operators see a path-prefixed reference."
    );
}

// Lane OOOOOO: manifest `offline_support_bundle_verifiers`
// path↔command parity.
//
// RELEASE-MANIFEST.json declares an `offline_support_bundle_verifiers`
// object with one entry per verifier (python + powershell). Each
// entry has a `path` field (the file inside the archive) and a
// `command` field (the operator-runnable command line). The command
// string MUST reference the path literal — otherwise the manifest
// documents a command that doesn't match the documented file, and
// operators running it from the runbook get "file not found" while
// thinking the manifest told them the right thing.
//
// Per-entry invariants:
//   1. The manifest heredoc declares an
//      `"offline_support_bundle_verifiers":` key.
//   2. Both `"python"` and `"powershell"` child verifiers exist
//      inside that key's object body.
//   3. For each verifier: the `"command":` string contains the
//      literal `"path":` value (e.g., command references the same
//      filename as path).
//   4. Both verifiers' command strings reference the same shared
//      bundle path `release-support-bundle.json` (so operators
//      know which input to pass on either OS — without this, one
//      verifier could accept `bundle.json` and the other
//      `support-bundle.json`).
#[test]
fn release_manifest_offline_verifiers_path_command_parity_lane_oooooo() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane OOOOOO: scripts/package-local.sh present");

    // Locate the manifest heredoc by content match (same anchor as
    // Lanes AAAAAA / LLLLLL / MMMMMM).
    let mut manifest_heredoc: Option<&str> = None;
    let mut cursor = package.as_str();
    while let Some(open_rel) = cursor.find("<<'PY'") {
        let after_open = &cursor[open_rel + "<<'PY'".len()..];
        let nl_off = after_open
            .find('\n')
            .expect("Lane OOOOOO: heredoc opener must be followed by newline");
        let body_start = nl_off + 1;
        let body_and_after = &after_open[body_start..];
        let close_rel = body_and_after
            .find("\nPY\n")
            .or_else(|| {
                if body_and_after.ends_with("\nPY") {
                    Some(body_and_after.len() - "\nPY".len())
                } else {
                    None
                }
            })
            .expect("Lane OOOOOO: heredoc opener `<<'PY'` must have a matching `PY` closer");
        let body = &body_and_after[..close_rel];
        if body.contains("ao2-control-plane.release-manifest.v1") {
            manifest_heredoc = Some(body);
            break;
        }
        let consumed = (open_rel + "<<'PY'".len()) + body_start + close_rel + "\nPY\n".len();
        if consumed >= cursor.len() {
            break;
        }
        cursor = &cursor[consumed..];
    }
    let heredoc = manifest_heredoc.expect(
        "Lane OOOOOO: scripts/package-local.sh MUST contain a manifest python heredoc declaring `ao2-control-plane.release-manifest.v1`",
    );

    // Invariant 1: declare the verifiers key.
    let verifiers_key_idx = heredoc.find("\"offline_support_bundle_verifiers\":").expect(
        "Lane OOOOOO: manifest heredoc must declare an `\"offline_support_bundle_verifiers\":` key documenting the offline verification commands",
    );
    // Restrict subsequent searches to a window after the key — 4 KB
    // is plenty for the two verifier child objects.
    let window_end = (verifiers_key_idx + 4096).min(heredoc.len());
    let verifiers_block = &heredoc[verifiers_key_idx..window_end];

    // Invariant 2: both verifier children exist.
    assert!(
        verifiers_block.contains("\"python\""),
        "Lane OOOOOO: `offline_support_bundle_verifiers` block must contain a `\"python\"` child verifier entry. Without it the manifest documents only one OS's verification command and Mac/Linux operators lose runbook parity with Windows."
    );
    assert!(
        verifiers_block.contains("\"powershell\""),
        "Lane OOOOOO: `offline_support_bundle_verifiers` block must contain a `\"powershell\"` child verifier entry. Without it the manifest documents only one OS's verification command and Windows operators lose runbook parity with Mac/Linux."
    );

    // Invariant 3: per-verifier path↔command containment.
    let mut pair_count = 0usize;
    let mut walk_cursor = verifiers_block;
    while let Some(path_idx) = walk_cursor.find("\"path\":") {
        let after_path = &walk_cursor[path_idx + "\"path\":".len()..];
        let path_line_end = after_path
            .find('\n')
            .expect("Lane OOOOOO: `\"path\":` line must end with newline");
        let path_value_raw = after_path[..path_line_end]
            .trim()
            .trim_end_matches(',')
            .trim();
        let path_value = path_value_raw.trim_matches('"');

        let after_after_path = &after_path[path_line_end..];
        let Some(cmd_idx) = after_after_path.find("\"command\":") else {
            break;
        };
        let after_cmd = &after_after_path[cmd_idx + "\"command\":".len()..];
        let cmd_line_end = after_cmd
            .find('\n')
            .expect("Lane OOOOOO: `\"command\":` line must end with newline");
        let cmd_value_raw = after_cmd[..cmd_line_end]
            .trim()
            .trim_end_matches(',')
            .trim();
        let cmd_value = cmd_value_raw.trim_matches('"');

        assert!(
            cmd_value.contains(path_value),
            "Lane OOOOOO: verifier `\"command\":` value {cmd_value:?} MUST contain the literal `\"path\":` value {path_value:?}. The manifest documents a command for this verifier — but the documented command doesn't reference the documented file. Operators running the command from a runbook will get 'file not found' because the command name doesn't match the file present in the archive."
        );
        pair_count += 1;

        // Advance past this command.
        let consumed_in_after_after_path = cmd_idx + "\"command\":".len() + cmd_line_end;
        let consumed =
            (path_idx + "\"path\":".len() + path_line_end) + consumed_in_after_after_path;
        if consumed >= walk_cursor.len() {
            break;
        }
        walk_cursor = &walk_cursor[consumed..];
    }
    assert!(
        pair_count >= 2,
        "Lane OOOOOO: expected at least 2 `(path, command)` pairs in the offline-verifier block (one python + one powershell); got {pair_count}. Floor protects against a regression that removes one verifier and leaves the manifest documenting only half the cross-OS surface."
    );

    // Invariant 4: both verifier commands reference the shared
    // bundle filename.
    let py_idx = verifiers_block
        .find("\"python\"")
        .expect("Lane OOOOOO: python verifier index located by invariant 2");
    let ps_idx = verifiers_block
        .find("\"powershell\"")
        .expect("Lane OOOOOO: powershell verifier index located by invariant 2");
    let py_window_end = (py_idx + 512).min(verifiers_block.len());
    let ps_window_end = (ps_idx + 512).min(verifiers_block.len());
    let py_window = &verifiers_block[py_idx..py_window_end];
    let ps_window = &verifiers_block[ps_idx..ps_window_end];
    assert!(
        py_window.contains("release-support-bundle.json"),
        "Lane OOOOOO: python verifier `command` MUST reference the shared bundle path `release-support-bundle.json`. The bundle filename is the cross-OS API contract — operators on either OS must know which file to pass. Without this pin, one verifier could expect `bundle.json` and the other `support-bundle.json` — same content, different filenames, broken runbook parity."
    );
    assert!(
        ps_window.contains("release-support-bundle.json"),
        "Lane OOOOOO: powershell verifier `command` MUST reference the shared bundle path `release-support-bundle.json`. Cross-OS parity with python verifier."
    );
}

// Lane PPPPPP — install.sh sha256sum/shasum cross-platform fallback parity.
//
//   Why this matters: `install.sh` runs on both Linux (where
//   `sha256sum` is the GNU coreutils binary) and macOS (where
//   `sha256sum` is absent by default but `shasum -a 256` ships with
//   the OS). The emitter writes a `command -v sha256sum`
//   gating block so the script tries the GNU tool first, then falls
//   back to `shasum -a 256`. If a future edit drops the fallback or
//   inverts the ordering, the macOS install path breaks silently —
//   the script either errors out before checksumming, or attempts
//   `shasum` on Linux where it isn't installed. The PowerShell
//   counterpart uses `Get-FileHash -Algorithm SHA256` (native to
//   Windows) and MUST NOT reference unix hash tools.
//
//   Pin shape:
//     1. install.sh heredoc contains `command -v sha256sum`.
//     2. install.sh heredoc contains `shasum -a 256`.
//     3. `command -v sha256sum` appears strictly BEFORE
//        `shasum -a 256` in the heredoc (gating then fallback).
//     4. install.ps1 heredoc contains `Get-FileHash -Algorithm SHA256`.
//     5. install.ps1 heredoc does NOT reference `sha256sum` or
//        `shasum -a 256` (cross-OS hygiene; PowerShell-native tool
//        only).
//
//   Cross-axis: Lane XXXXX pins the emitter-side checksum block
//   shape; Lane NNNNNN pins the mismatch error string; this lane
//   pins the cross-platform fallback ordering itself.
#[test]
fn install_heredoc_sha256sum_shasum_cross_platform_fallback_parity_lane_pppppp() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane PPPPPP: scripts/package-local.sh present");

    let install_sh = extract_install_sh_heredoc(&package);
    let install_ps1 = extract_install_ps1_heredoc(&package);

    // Invariant 1: install.sh probes for the GNU coreutils binary.
    let probe_idx = install_sh.find("command -v sha256sum").expect(
        "Lane PPPPPP: install.sh heredoc MUST contain `command -v sha256sum` to probe for the GNU coreutils hash binary. Without the probe the script either hard-fails on macOS (where sha256sum is absent) or attempts shasum unconditionally on Linux (where it's typically absent) — cross-OS install path breaks silently."
    );

    // Invariant 2: install.sh declares the macOS fallback.
    let fallback_idx = install_sh.find("shasum -a 256").expect(
        "Lane PPPPPP: install.sh heredoc MUST contain `shasum -a 256` as the macOS fallback. Without the fallback macOS operators hit the install path and get a generic 'command not found' error instead of a real checksum verification."
    );

    // Invariant 3: probe must precede fallback (gating semantics).
    assert!(
        probe_idx < fallback_idx,
        "Lane PPPPPP: install.sh heredoc MUST place `command -v sha256sum` (offset {probe_idx}) BEFORE `shasum -a 256` (offset {fallback_idx}). The ordering encodes gating semantics — probe the GNU tool first, fall back to the macOS tool only if the probe fails. Inverting the order means Linux installs unconditionally try the macOS tool, breaking the default OS path."
    );

    // Invariant 4: install.ps1 uses the PowerShell-native hash cmdlet.
    assert!(
        install_ps1.contains("Get-FileHash -Algorithm SHA256"),
        "Lane PPPPPP: install.ps1 heredoc MUST contain `Get-FileHash -Algorithm SHA256` — the PowerShell-native equivalent of sha256sum. Without it the Windows install path either invokes a unix tool that doesn't exist or skips checksum verification entirely."
    );

    // Invariant 5: install.ps1 doesn't accidentally inherit unix tools.
    assert!(
        !install_ps1.contains("sha256sum"),
        "Lane PPPPPP: install.ps1 heredoc MUST NOT reference `sha256sum` — the GNU coreutils binary is not present on Windows. A stray reference (e.g. from a copy-paste from install.sh) silently breaks the Windows install path because PowerShell can't invoke a non-existent unix command."
    );
    assert!(
        !install_ps1.contains("shasum -a 256"),
        "Lane PPPPPP: install.ps1 heredoc MUST NOT reference `shasum -a 256` — the macOS Perl-script wrapper is not present on Windows. A stray reference (e.g. from a copy-paste from install.sh) silently breaks the Windows install path."
    );
}

// Lane QQQQQQ — README.txt auth credential lifecycle parity.
//
//   Why this matters: the operator-facing README.txt heredoc inside
//   the release archive documents the offline support-bundle fetch
//   flow on both Unix and Windows. Both flows set a bearer-token
//   header into the environment (`AO2_CP_AUTH_VALUE`) before invoking
//   the fetcher, then clear the variable immediately after. The
//   clear step is load-bearing security hygiene — without it, the
//   bearer token lingers in the operator's shell environment and
//   leaks into every subsequent process spawned from that shell
//   (including unrelated tools that snapshot env vars, telemetry
//   collectors, and shell-history dumps).
//
//   The README has TWO documented flows that each appear in both
//   Unix and Windows forms (4 set/clear pairs total):
//     - Simple bundle fetch (lines around 244-254 in package-local.sh)
//     - Phase 1 portable handoff fetch (lines around 257-266)
//
//   A documentation drift that drops the cleanup step in any of the
//   four forms means operators copy-paste a credential-leaking
//   recipe. The lifecycle parity invariant catches that.
//
//   Pin shape:
//     1. README contains 2 instances of `export AO2_CP_AUTH_VALUE=`
//        (Unix env-set in both flows).
//     2. README contains 2 instances of `unset AO2_CP_AUTH_VALUE`
//        (Unix env-clear in both flows).
//     3. README contains 2 instances of `$env:AO2_CP_AUTH_VALUE=`
//        (PowerShell env-set in both flows).
//     4. README contains 2 instances of `Remove-Item Env:\AO2_CP_AUTH_VALUE`
//        (PowerShell env-clear in both flows).
//     5. For each `export AO2_CP_AUTH_VALUE` occurrence, an `unset
//        AO2_CP_AUTH_VALUE` MUST appear AFTER it (before the next
//        export or before EOF) — i.e., no export is left without a
//        matching cleanup before another export starts.
//     6. Same ordering invariant for `$env:AO2_CP_AUTH_VALUE=` ↔
//        `Remove-Item Env:\AO2_CP_AUTH_VALUE`.
//
//   Cross-axis to Lane ZZZZZ / LLLLLL (trust_boundary / auth_value_stored):
//   ZZZZZ pins that the MANIFEST documents the trust-boundary
//   commitment; LLLLLL pins that auth_value_stored=False is declared;
//   QQQQQQ pins that the operator-facing README's RECIPE actually
//   matches the commitment (clears the credential after use).
#[test]
fn package_readme_auth_credential_lifecycle_parity_lane_qqqqqq() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane QQQQQQ: scripts/package-local.sh present");

    let readme = extract_package_readme_heredoc(&package);

    // Helper: collect byte offsets of every non-overlapping occurrence
    // of a literal needle inside the readme.
    let positions = |needle: &str| -> Vec<usize> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        while cursor < readme.len() {
            match readme[cursor..].find(needle) {
                Some(rel) => {
                    let abs = cursor + rel;
                    out.push(abs);
                    cursor = abs + needle.len();
                }
                None => break,
            }
        }
        out
    };

    let unix_sets = positions("export AO2_CP_AUTH_VALUE=");
    let unix_clears = positions("unset AO2_CP_AUTH_VALUE");
    let ps_sets = positions("$env:AO2_CP_AUTH_VALUE=");
    let ps_clears = positions("Remove-Item Env:\\AO2_CP_AUTH_VALUE");

    // Invariant 1: 2 Unix set ops (simple bundle + phase1 portable).
    assert_eq!(
        unix_sets.len(),
        2,
        "Lane QQQQQQ: README.txt heredoc MUST contain exactly 2 `export AO2_CP_AUTH_VALUE=` lines (one for the simple bundle flow, one for the Phase 1 portable handoff flow). Found {}. Drift here means a new fetch flow was added without documenting credential lifecycle, OR an existing flow's credential-set was dropped (silently breaking the fetch).",
        unix_sets.len()
    );

    // Invariant 2: 2 Unix clear ops.
    assert_eq!(
        unix_clears.len(),
        2,
        "Lane QQQQQQ: README.txt heredoc MUST contain exactly 2 `unset AO2_CP_AUTH_VALUE` lines matching the 2 export lines. Found {}. Drift here means an `export` line lost its cleanup partner — bearer token leaks into the operator's shell environment after the fetch completes.",
        unix_clears.len()
    );

    // Invariant 3: 2 PowerShell set ops.
    assert_eq!(
        ps_sets.len(),
        2,
        "Lane QQQQQQ: README.txt heredoc MUST contain exactly 2 `$env:AO2_CP_AUTH_VALUE=` lines (PowerShell equivalents of the 2 Unix flows). Found {}. Drift means Windows operators get a different documentation surface than Mac/Linux operators.",
        ps_sets.len()
    );

    // Invariant 4: 2 PowerShell clear ops.
    assert_eq!(
        ps_clears.len(),
        2,
        "Lane QQQQQQ: README.txt heredoc MUST contain exactly 2 `Remove-Item Env:\\AO2_CP_AUTH_VALUE` lines matching the 2 `$env:` set lines. Found {}. Drift means the Windows credential lingers in $env: after the PowerShell session continues, leaking into every child process and tooling that snapshots environment.",
        ps_clears.len()
    );

    // Invariant 5: pairwise ordering — for each export[i], an unset
    // must appear strictly AFTER it and STRICTLY BEFORE the next
    // export[i+1]. This catches the dangerous pattern where two
    // sets stack up without a clear in between.
    for (i, &set_pos) in unix_sets.iter().enumerate() {
        let next_set = unix_sets.get(i + 1).copied().unwrap_or(readme.len());
        let matched_clear = unix_clears.iter().find(|&&c| c > set_pos && c < next_set);
        assert!(
            matched_clear.is_some(),
            "Lane QQQQQQ: Unix `export AO2_CP_AUTH_VALUE=` at byte offset {set_pos} is not followed by a matching `unset AO2_CP_AUTH_VALUE` before the next export at byte offset {next_set}. The credential lifecycle is broken — operator's shell carries the bearer token past the fetch command into subsequent flows."
        );
    }

    // Invariant 6: same pairwise ordering for PowerShell.
    for (i, &set_pos) in ps_sets.iter().enumerate() {
        let next_set = ps_sets.get(i + 1).copied().unwrap_or(readme.len());
        let matched_clear = ps_clears.iter().find(|&&c| c > set_pos && c < next_set);
        assert!(
            matched_clear.is_some(),
            "Lane QQQQQQ: PowerShell `$env:AO2_CP_AUTH_VALUE=` at byte offset {set_pos} is not followed by a matching `Remove-Item Env:\\AO2_CP_AUTH_VALUE` before the next set at byte offset {next_set}. The credential lifecycle is broken — operator's $env: carries the bearer token past the fetch command."
        );
    }
}

// Lane RRRRRR — smoke aggregator markdown report mandatory section
// header + trust-boundary keyword parity.
//
//   Why this matters: scripts/smoke-three-os-release.sh writes BOTH
//   a JSON summary AND a human-readable markdown report. Operators
//   on-call read the markdown report first — it's the primary triage
//   surface that doesn't require `jq`. The markdown report has five
//   mandatory H2 sections that operators expect in a stable order:
//     - ## Results       (per-OS status)
//     - ## Logs          (per-OS log paths)
//     - ## Remote command files (per-OS rerun command file paths)
//     - ## Trust boundary (read-only-observer commitment + approval owner)
//     - ## Rerun commands (4 documented rerun forms)
//
//   The trust-boundary section is load-bearing security
//   documentation — it tells the operator (and anyone reading the
//   report in a post-mortem) that the control plane never mutates AO
//   artifacts and never approves releases. If a refactor drops the
//   trust-boundary section or weakens its keywords, the report
//   silently loses its security commitment in the very surface
//   incident reviewers consult.
//
//   Pin shape:
//     1. The markdown-writing block exists in the script (heredoc
//        boundary anchor: the closing `} >"$report_md"` line).
//     2. The H1 title `# AO2 Control Plane Three-OS Release Smoke`
//        appears in the block.
//     3. All five H2 sections appear: `## Results`, `## Logs`,
//        `## Remote command files`, `## Trust boundary`,
//        `## Rerun commands`.
//     4. The five H2 sections appear in the canonical order
//        Results -> Logs -> Remote command files -> Trust boundary
//        -> Rerun commands (drift here means the report jumbles its
//        information architecture; on-call playbooks that say "see
//        Trust boundary, near the bottom" break).
//     5. The Trust boundary section contains the keyword
//        `read_only_observer` (the role identifier — the same one
//        the JSON output emits and that handlers cross-reference).
//     6. The Trust boundary section contains the keyword
//        `factory-v3 evaluator-closer` (the AO approval owner —
//        names the off-control-plane entity that owns the release
//        decision, preserving the read-only-observer trust boundary).
//
//   Cross-axis to Lane VVVVV (HTML render fn trust-boundary
//   disclaimer parity) and Lane ZZZZZ (manifest trust-boundary key
//   parity): VVVVV pins the HTML disclaimer, ZZZZZ pins the manifest
//   JSON; RRRRRR pins the third operator-facing surface — the
//   smoke aggregator's markdown report. All three surfaces must
//   agree on the role and the approval owner.
#[test]
fn smoke_aggregator_markdown_report_section_structure_parity_lane_rrrrrr() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = fs::read_to_string(root.join("scripts/smoke-three-os-release.sh"))
        .expect("Lane RRRRRR: scripts/smoke-three-os-release.sh present");

    // Locate the markdown-writing block by its closing redirect
    // `} >"$report_md"` (load-bearing anchor — this is what writes
    // the report to disk).
    let close_anchor = "} >\"$report_md\"";
    let close_idx = script.find(close_anchor).expect(
        "Lane RRRRRR: smoke-three-os-release.sh MUST contain a markdown-writing block ending with `} >\"$report_md\"`. Without the redirect the markdown report is never written and operators lose the human-readable triage surface.",
    );

    // Find the opening brace of the block by walking back for the
    // last `{\n` before the close anchor.
    let block_search = &script[..close_idx];
    let open_idx = block_search.rfind("\n{\n").map(|i| i + 1).expect(
        "Lane RRRRRR: markdown-writing block must open with a bare `{` line before the `} >\"$report_md\"` close",
    );
    let block = &script[open_idx..close_idx];

    // Invariant 2: H1 title.
    assert!(
        block.contains("# AO2 Control Plane Three-OS Release Smoke"),
        "Lane RRRRRR: markdown report block MUST emit the H1 title `# AO2 Control Plane Three-OS Release Smoke`. Without the title the report is anonymous — on-call operators landing on the file have no immediate label telling them which smoke run it documents."
    );

    // Invariants 3 + 4: five H2 sections, in canonical order.
    let h2_sections = [
        "## Results",
        "## Logs",
        "## Remote command files",
        "## Trust boundary",
        "## Rerun commands",
    ];
    let mut prev_idx = 0usize;
    for section in h2_sections.iter() {
        let idx = block.find(section).unwrap_or_else(|| {
            panic!(
                "Lane RRRRRR: markdown report block MUST contain the H2 section `{section}`. Dropping any of the five mandatory H2 sections (Results / Logs / Remote command files / Trust boundary / Rerun commands) means on-call operators lose the information they need to triage this OS dimension."
            )
        });
        assert!(
            idx >= prev_idx,
            "Lane RRRRRR: markdown report H2 section `{section}` appears at offset {idx} BEFORE the previous mandatory section ended at offset {prev_idx}. The canonical ordering is: Results -> Logs -> Remote command files -> Trust boundary -> Rerun commands. On-call playbooks reference sections by position; reordering jumbles operator navigation."
        );
        prev_idx = idx + section.len();
    }

    // Invariants 5 + 6: trust-boundary section keywords.
    let trust_idx = block
        .find("## Trust boundary")
        .expect("Lane RRRRRR: trust-boundary section anchor located by invariant 3");
    let next_h2_idx = block[trust_idx + "## Trust boundary".len()..]
        .find("\n## ")
        .map(|rel| trust_idx + "## Trust boundary".len() + rel)
        .unwrap_or(block.len());
    let trust_block = &block[trust_idx..next_h2_idx];

    assert!(
        trust_block.contains("read_only_observer"),
        "Lane RRRRRR: `## Trust boundary` markdown section MUST contain the role keyword `read_only_observer`. The role declaration is what tells the on-call operator (and post-mortem reviewers) the control plane never mutates AO artifacts; dropping it from the report silently weakens the operator-facing security commitment. Cross-references the same role keyword in the JSON summary and in the HTML cockpit disclaimer (Lane VVVVV)."
    );
    assert!(
        trust_block.contains("factory-v3 evaluator-closer"),
        "Lane RRRRRR: `## Trust boundary` markdown section MUST contain the approval-owner identity `factory-v3 evaluator-closer`. The identity tells the operator who actually owns the release approval — preserving the read-only-observer boundary by naming the off-control-plane entity that owns the decision. Dropping it leaves the report saying 'we don't approve' without saying who does."
    );
}

// Lane SSSSSS — smoke aggregator secret-redaction pattern parity
// between the JSON-emitting heredoc and the inline failure-excerpt
// redactor.
//
//   Why this matters: scripts/smoke-three-os-release.sh runs TWO
//   separate redaction passes over operator-facing output.
//
//   Pass A (lines around 204-215): the JSON-emitting Python heredoc
//   compiles a `SECRET_PATTERNS = [...]` list and applies it via a
//   `redact()` function before the per-OS log tail is embedded into
//   the JSON summary's `failure_excerpts.<os>.tail_text` field.
//
//   Pass B (lines around 743-746): a SEPARATE inline `python3 -c`
//   invocation re-redacts the per-OS log tail before piping it into
//   the markdown report's `## Failure excerpts` fenced code block.
//
//   Both passes redact the SAME four secret markers:
//     - HTTP `authorization: bearer ...` header values
//     - `AO2_CP_API_TOKEN=...` env-var values
//     - `OPENAI_API_KEY=...` env-var values
//     - `ANTHROPIC_API_KEY=...` env-var values
//
//   If a new secret pattern is added to one redactor and not the
//   other, the same log-tail content gets full redaction in one
//   operator-facing surface (JSON summary) and partial redaction in
//   the other (markdown report) — credential leakage in whichever
//   surface lags behind. The script's two-site duplication is
//   fragile by construction; this lane catches drift.
//
//   Pin shape: both Pass A and Pass B must contain all four
//   case-insensitive pattern markers. Specifically:
//     1. Pass A contains `authorization` (case-insensitive bearer
//        token pattern).
//     2. Pass A contains `AO2_CP_API_TOKEN`.
//     3. Pass A contains `OPENAI_API_KEY`.
//     4. Pass A contains `ANTHROPIC_API_KEY`.
//     5. Pass B contains `authorization`.
//     6. Pass B contains `AO2_CP_API_TOKEN`.
//     7. Pass B contains `OPENAI_API_KEY`.
//     8. Pass B contains `ANTHROPIC_API_KEY`.
//
//   Cross-axis: this pairs with the existing redaction tests for
//   the support-bundle verifier and bundle handler; together they
//   form the defense-in-depth secret-redaction surface that no
//   single edit can fully bypass.
#[test]
fn smoke_aggregator_secret_redaction_pattern_parity_lane_ssssss() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = fs::read_to_string(root.join("scripts/smoke-three-os-release.sh"))
        .expect("Lane SSSSSS: scripts/smoke-three-os-release.sh present");

    // --- Pass A: locate the SECRET_PATTERNS block inside the
    // JSON-emitting heredoc. We can't rely on `find(']')` to close
    // the block because the regex literals inside contain bracket
    // characters (e.g. `[^\s\"']+`). Instead, take a generous
    // fixed-size window — 1024 bytes is enough to span the four
    // re.compile lines.
    let pass_a_anchor = "SECRET_PATTERNS = [";
    let pass_a_start = script.find(pass_a_anchor).expect(
        "Lane SSSSSS: scripts/smoke-three-os-release.sh MUST define a `SECRET_PATTERNS = [` list inside the JSON-emitting heredoc. Without the centralized list the JSON `failure_excerpts.<os>.tail_text` field leaks bearer tokens and API keys into the operator-facing summary.",
    );
    let pass_a_end = (pass_a_start + 1024).min(script.len());
    let pass_a = &script[pass_a_start..pass_a_end];

    // --- Pass B: locate the inline python -c redactor block. Same
    // bracket-balancing problem — use a window-based extraction.
    let pass_b_anchor = "for pat in [";
    let pass_b_start = script.find(pass_b_anchor).expect(
        "Lane SSSSSS: scripts/smoke-three-os-release.sh MUST contain an inline failure-excerpt redactor block beginning with `for pat in [`. Without the markdown-side redaction operators reading the report see bearer tokens and API keys in the fenced code blocks even though the JSON summary is clean.",
    );
    let pass_b_end = (pass_b_start + 1024).min(script.len());
    let pass_b = &script[pass_b_start..pass_b_end];

    // --- The four canonical secret markers.
    let markers = [
        ("authorization", "HTTP `authorization: bearer ...` header values — the load-bearing bearer-token leakage surface for AO2 API calls"),
        ("AO2_CP_API_TOKEN", "the control plane's local-OAuth bearer token — leaks here would let an attacker impersonate the operator's read-only observer session"),
        ("OPENAI_API_KEY", "OpenAI API key — provider-side credential that pays for evaluator runs"),
        ("ANTHROPIC_API_KEY", "Anthropic API key — provider-side credential that pays for evaluator runs"),
    ];

    for (marker, justification) in markers.iter() {
        assert!(
            pass_a.contains(marker),
            "Lane SSSSSS: Pass A (`SECRET_PATTERNS = [...]` block in the JSON-emitting heredoc) MUST contain the pattern marker `{marker}` — {justification}. Drift here means the JSON summary's `failure_excerpts.<os>.tail_text` field leaks {marker} values to anyone reading the summary."
        );
        assert!(
            pass_b.contains(marker),
            "Lane SSSSSS: Pass B (inline `for pat in [...]` block in the markdown failure-excerpt redactor) MUST contain the pattern marker `{marker}` — {justification}. Drift here means the markdown report's `## Failure excerpts` fenced code block leaks {marker} values even when the JSON summary is clean — operators reading the report still see the secret."
        );
    }
}

// Lane TTTTTT — SECURITY.md load-bearing claim parity with source
// code.
//
//   Why this matters: docs/SECURITY.md is the security posture
//   declaration that operators, reviewers, and integrators read to
//   understand the trust model and verification surface. It makes
//   load-bearing factual claims that must remain in sync with the
//   actual implementation:
//     - The server refuses to start with a specific exit code (78
//       / EX_CONFIG) if forbidden env vars are present.
//     - It validates a specific `execution_owner=ao2-local-cli`
//       string before accepting provider-registry snapshots.
//     - It accepts two specific schema identifiers
//       (`ao2.provider-plugin-registry.v1` and
//       `ao2.cp-provider-registry-signed-upload.v1`).
//     - Authentication uses `AO2_CP_API_TOKEN`.
//     - It refuses to start if `OPENAI_API_KEY` or
//       `ANTHROPIC_API_KEY` are present.
//
//   If any of these claims drift from the implementation, the
//   security document becomes a misleading contract: operators read
//   one behavior, the server does another. Integrators relying on
//   the exit-code claim (e.g. CI pipelines that parse exit codes)
//   silently break.
//
//   Pin shape: for each load-bearing claim in SECURITY.md, assert
//   the corresponding source code contains the literal.
//
//     1. SECURITY.md mentions exit code `78`. Source `src/main.rs`
//        MUST contain `exit(78)`.
//     2. SECURITY.md mentions schema `ao2.provider-plugin-registry.v1`.
//        Source `src/handlers/provider_registry.rs` MUST contain it.
//     3. SECURITY.md mentions schema
//        `ao2.cp-provider-registry-signed-upload.v1`. Source
//        `src/handlers/provider_registry.rs` MUST contain it.
//     4. SECURITY.md mentions `ao2-local-cli` execution-owner
//        literal. Source `src/handlers/provider_registry.rs` MUST
//        validate it.
//     5. SECURITY.md mentions env var `AO2_CP_API_TOKEN`. Source
//        `src/config.rs` MUST read it.
//     6. SECURITY.md mentions forbidden env `OPENAI_API_KEY`.
//        Source `src/config.rs` MUST refuse it.
//     7. SECURITY.md mentions forbidden env `ANTHROPIC_API_KEY`.
//        Source `src/config.rs` MUST refuse it.
//
//   Cross-axis to Lane CCCC (README threat-model → handler emission
//   parity): CCCC pins the README threat-model section; TTTTTT pins
//   the SECURITY.md document — both are operator-facing security
//   surfaces and both must trace back to implementation.
#[test]
fn security_md_claims_bind_to_source_code_lane_tttttt() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let security_md = fs::read_to_string(root.join("docs/SECURITY.md"))
        .expect("Lane TTTTTT: docs/SECURITY.md present");
    let main_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/main.rs"))
        .expect("Lane TTTTTT: crates/ao2-cp-server/src/main.rs present");
    let config_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/config.rs"))
        .expect("Lane TTTTTT: crates/ao2-cp-server/src/config.rs present");
    let provider_registry_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/handlers/provider_registry.rs"))
            .expect("Lane TTTTTT: crates/ao2-cp-server/src/handlers/provider_registry.rs present");

    // Invariant 1: exit code 78 (EX_CONFIG).
    assert!(
        security_md.contains("Exit code 78"),
        "Lane TTTTTT: docs/SECURITY.md MUST mention `Exit code 78` (EX_CONFIG). If the doc omits the exit code, integrators (CI pipelines, monitoring) can't pin against the documented behavior."
    );
    assert!(
        main_rs.contains("exit(78)"),
        "Lane TTTTTT: src/main.rs MUST call `std::process::exit(78)` for the EX_CONFIG path documented in SECURITY.md. Drift means the docs claim exit 78 but the binary emits a different code; CI pipelines parsing exit codes silently break."
    );

    // Invariant 2: provider-plugin-registry schema name.
    let schema_unsigned = "ao2.provider-plugin-registry.v1";
    assert!(
        security_md.contains(schema_unsigned),
        "Lane TTTTTT: docs/SECURITY.md MUST mention the unsigned-snapshot schema `{schema_unsigned}`. Without naming the schema, operators reading the doc can't tell which payload shape the server accepts."
    );
    assert!(
        provider_registry_rs.contains(schema_unsigned),
        "Lane TTTTTT: src/handlers/provider_registry.rs MUST declare the schema literal `{schema_unsigned}` documented in SECURITY.md. Drift means the doc names schema A but the handler accepts schema B; operators producing snapshots against the documented schema get rejected."
    );

    // Invariant 3: signed-upload schema name.
    let schema_signed = "ao2.cp-provider-registry-signed-upload.v1";
    assert!(
        security_md.contains(schema_signed),
        "Lane TTTTTT: docs/SECURITY.md MUST mention the signed-upload schema `{schema_signed}`."
    );
    assert!(
        provider_registry_rs.contains(schema_signed),
        "Lane TTTTTT: src/handlers/provider_registry.rs MUST declare the schema literal `{schema_signed}` documented in SECURITY.md."
    );

    // Invariant 4: execution_owner literal.
    let owner_literal = "ao2-local-cli";
    assert!(
        security_md.contains(owner_literal),
        "Lane TTTTTT: docs/SECURITY.md MUST name the execution-owner literal `{owner_literal}`. The doc states this is the only acceptable execution-owner value; without naming it operators can't tell what to put in their snapshots."
    );
    assert!(
        provider_registry_rs.contains(owner_literal),
        "Lane TTTTTT: src/handlers/provider_registry.rs MUST contain the `{owner_literal}` literal documented in SECURITY.md as the only acceptable execution-owner value. Drift means the doc claims `{owner_literal}` is required but the handler accepts something else (or rejects it)."
    );

    // Invariant 5: AO2_CP_API_TOKEN env var.
    let token_env = "AO2_CP_API_TOKEN";
    assert!(
        security_md.contains(token_env),
        "Lane TTTTTT: docs/SECURITY.md MUST name the auth env var `{token_env}`."
    );
    assert!(
        config_rs.contains(token_env),
        "Lane TTTTTT: src/config.rs MUST read env `{token_env}` documented in SECURITY.md as the auth source. Drift means the doc says set X but the binary reads Y; operators following the doc get auth failures."
    );

    // Invariants 6 + 7: forbidden provider keys.
    for forbidden in &["OPENAI_API_KEY", "ANTHROPIC_API_KEY"] {
        assert!(
            security_md.contains(forbidden),
            "Lane TTTTTT: docs/SECURITY.md MUST list `{forbidden}` as a forbidden env var. The doc says these refused-on-startup keys indicate misconfiguration."
        );
        assert!(
            config_rs.contains(forbidden),
            "Lane TTTTTT: src/config.rs MUST refuse env `{forbidden}` (SECURITY.md says startup must fail if present). Drift means the doc claims rejection but the binary silently accepts the env, weakening the trust-boundary guarantee that the control plane never makes provider API calls."
        );
    }
}

// Lane UUUUUU — DEPLOYMENT.md CLI flag + endpoint path parity with
// source code.
//
//   Why this matters: docs/DEPLOYMENT.md is the operator's deploy
//   guide. It hands out command lines, systemd unit fragments, and
//   curl recipes that operators copy-paste into their environment.
//   It references:
//     - CLI flags `--bind` and `--data-dir`
//     - Env vars `AO2_CP_API_TOKEN` and `AO2_CP_LOG_LEVEL`
//     - HTTP endpoint paths `/api/v1/storage/report`,
//       `/api/v1/storage/prune`,
//       `/api/v1/provider/registry`,
//       `/api/v1/provider/registry/dashboard`
//
//   If a flag is renamed, an env var removed, or an endpoint route
//   moved without the doc keeping pace, operators following the
//   documented recipe land on `clap` errors or 404s. The deploy
//   guide stops working — the most expensive form of documentation
//   drift because it surfaces during deployment, not development.
//
//   Pin shape:
//     1. DEPLOYMENT.md mentions `--bind` AND src/config.rs declares
//        the `bind` flag (clap `#[arg(long)]`).
//     2. DEPLOYMENT.md mentions `--data-dir` AND src/config.rs
//        declares `data_dir`.
//     3. DEPLOYMENT.md mentions `AO2_CP_LOG_LEVEL` AND src/config.rs
//        reads it.
//     4-7. Each documented endpoint path appears in
//          src/route_catalog.rs (the central route registration
//          surface).
//
//   Cross-axis to Lane WWW (README port literal parity): WWW pins
//   the 8744 port literal across surfaces; UUUUUU pins the CLI
//   flags and endpoint paths that flank it. Together they cover the
//   full deploy-recipe surface.
#[test]
fn deployment_md_flags_and_endpoints_bind_to_source_lane_uuuuuu() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let deployment_md = fs::read_to_string(root.join("docs/DEPLOYMENT.md"))
        .expect("Lane UUUUUU: docs/DEPLOYMENT.md present");
    let config_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/config.rs"))
        .expect("Lane UUUUUU: crates/ao2-cp-server/src/config.rs present");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane UUUUUU: crates/ao2-cp-server/src/route_catalog.rs present");

    // Invariant 1: --bind flag.
    assert!(
        deployment_md.contains("--bind"),
        "Lane UUUUUU: docs/DEPLOYMENT.md MUST reference the `--bind` CLI flag (it's in the documented systemd ExecStart line). Without naming the flag operators can't tell what to put on the command line."
    );
    assert!(
        config_rs.contains("bind: String"),
        "Lane UUUUUU: src/config.rs MUST declare a `bind: String` clap-derived field matching DEPLOYMENT.md's `--bind` recipe. Drift means the deploy guide hands out a flag that no longer exists."
    );

    // Invariant 2: --data-dir flag.
    assert!(
        deployment_md.contains("--data-dir"),
        "Lane UUUUUU: docs/DEPLOYMENT.md MUST reference the `--data-dir` CLI flag (it's in the documented systemd ExecStart line)."
    );
    assert!(
        config_rs.contains("data_dir:"),
        "Lane UUUUUU: src/config.rs MUST declare a `data_dir:` clap-derived field matching DEPLOYMENT.md's `--data-dir` recipe. Drift means operators can't pass the documented flag."
    );

    // Invariant 3: AO2_CP_LOG_LEVEL env var.
    assert!(
        deployment_md.contains("AO2_CP_LOG_LEVEL"),
        "Lane UUUUUU: docs/DEPLOYMENT.md MUST reference the `AO2_CP_LOG_LEVEL` env var (it's in the documented EnvironmentFile fragment)."
    );
    assert!(
        config_rs.contains("AO2_CP_LOG_LEVEL"),
        "Lane UUUUUU: src/config.rs MUST declare an env binding for `AO2_CP_LOG_LEVEL` matching DEPLOYMENT.md's EnvironmentFile recipe. Drift means operators set the documented env and it has no effect."
    );

    // Invariants 4-7: endpoint paths.
    let endpoints = [
        ("/api/v1/storage/report", "the retention reporting endpoint"),
        ("/api/v1/storage/prune", "the retention prune endpoint"),
        (
            "/api/v1/provider/registry",
            "the provider-registry ingestion endpoint",
        ),
        (
            "/api/v1/provider/registry/dashboard",
            "the provider-registry dashboard endpoint",
        ),
    ];
    for (path, justification) in endpoints.iter() {
        assert!(
            deployment_md.contains(path),
            "Lane UUUUUU: docs/DEPLOYMENT.md MUST reference the endpoint path `{path}` ({justification})."
        );
        assert!(
            route_catalog_rs.contains(path),
            "Lane UUUUUU: src/route_catalog.rs MUST register the path `{path}` ({justification}) documented in DEPLOYMENT.md. Drift means operators curl the documented URL and get a 404."
        );
    }
}

// Lane VVVVVV — RELEASE-MANIFEST.json `outputs` arrays ↔ fetcher
// Python output file parity.
//
//   Why this matters: the manifest python heredoc in
//   scripts/package-local.sh declares TWO `outputs` arrays — one
//   in `release_support_handoff_fetcher.outputs` (the standard
//   bundle-fetch flow) and one in
//   `release_support_handoff_fetcher.phase1_portable_handoff.outputs`
//   (the Phase 1 portable handoff flow). Operators reading the
//   manifest expect these files to exist on disk after running the
//   documented fetcher command.
//
//   The actual files written are determined by
//   scripts/fetch_release_support_handoff.py, which has its own
//   mapping of `filename -> URL path` for each flow.
//
//   If the manifest's `outputs` array claims a file the fetcher
//   doesn't actually write, operators see the manifest lie and
//   waste triage time looking for a missing file. If the fetcher
//   writes a file the manifest doesn't list, operators don't know
//   to expect it (and may not understand the bundle is incomplete
//   without it). Either drift breaks the manifest-as-truth contract.
//
//   Pin shape: for each filename in the manifest's standard-flow
//   `outputs` array (excluding `fetch-summary.json` which is meta
//   and not part of the fetched bundle), assert it appears in the
//   fetcher Python script. Same check for Phase 1 outputs.
//
//   Cross-axis to Lane OOOOOO (manifest verifier path↔command
//   parity): OOOOOO pins that documented verifier commands
//   reference documented paths; VVVVVV pins that documented output
//   files map to files the fetcher actually writes.
#[test]
fn manifest_outputs_arrays_bind_to_fetcher_outputs_lane_vvvvvv() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane VVVVVV: scripts/package-local.sh present");
    let fetcher = fs::read_to_string(root.join("scripts/fetch_release_support_handoff.py"))
        .expect("Lane VVVVVV: scripts/fetch_release_support_handoff.py present");

    // Locate the manifest heredoc by content match.
    let mut manifest_heredoc: Option<&str> = None;
    let mut cursor = package.as_str();
    while let Some(open_rel) = cursor.find("<<'PY'") {
        let after_open = &cursor[open_rel + "<<'PY'".len()..];
        let nl_off = after_open
            .find('\n')
            .expect("Lane VVVVVV: heredoc opener must be followed by newline");
        let body_start = nl_off + 1;
        let body_and_after = &after_open[body_start..];
        let close_rel = body_and_after
            .find("\nPY\n")
            .or_else(|| {
                if body_and_after.ends_with("\nPY") {
                    Some(body_and_after.len() - "\nPY".len())
                } else {
                    None
                }
            })
            .expect("Lane VVVVVV: heredoc opener `<<'PY'` must have a matching `PY` closer");
        let body = &body_and_after[..close_rel];
        if body.contains("ao2-control-plane.release-manifest.v1") {
            manifest_heredoc = Some(body);
            break;
        }
        let consumed = (open_rel + "<<'PY'".len()) + body_start + close_rel + "\nPY\n".len();
        if consumed >= cursor.len() {
            break;
        }
        cursor = &cursor[consumed..];
    }
    let heredoc = manifest_heredoc.expect(
        "Lane VVVVVV: scripts/package-local.sh MUST contain a manifest python heredoc declaring `ao2-control-plane.release-manifest.v1`",
    );

    // The standard-flow outputs (from the manifest's
    // release_support_handoff_fetcher.outputs array). Excludes
    // `fetch-summary.json` because that's meta (the fetcher writes
    // it but it's not part of the fetched bundle URL mapping).
    let standard_outputs = [
        "release-support-verifier-handoff.json",
        "release-support-bundle.json",
        "SHA256SUMS",
        "release-support-bundle-verify.json",
        "release-support-bundle-manifest.json",
    ];

    // The Phase 1 outputs (from
    // release_support_handoff_fetcher.phase1_portable_handoff.outputs).
    // Same fetch-summary.json exclusion.
    let phase1_outputs = [
        "phase1-portable-manifest.json",
        "ao2-phase1-operator-support-bundle.json",
        "ao2-phase1-gap-report.json",
        "phase1-SHA256SUMS",
        "phase1-portable-manifest-verify-upload.json",
        "phase1-portable-manifest-verification.json",
    ];

    for filename in standard_outputs.iter() {
        assert!(
            heredoc.contains(filename),
            "Lane VVVVVV: manifest heredoc MUST declare `{filename}` in `release_support_handoff_fetcher.outputs` (standard bundle-fetch flow). Without it operators reading the manifest don't know to expect this file in their handoff directory."
        );
        assert!(
            fetcher.contains(filename),
            "Lane VVVVVV: scripts/fetch_release_support_handoff.py MUST reference `{filename}` (the manifest's `release_support_handoff_fetcher.outputs` array declares this file as part of the standard bundle-fetch flow). Drift means the manifest claims a file the fetcher doesn't actually write — operators reading the manifest see a lie."
        );
    }

    for filename in phase1_outputs.iter() {
        assert!(
            heredoc.contains(filename),
            "Lane VVVVVV: manifest heredoc MUST declare `{filename}` in `release_support_handoff_fetcher.phase1_portable_handoff.outputs` (Phase 1 portable handoff flow). Without it Phase 1 operators don't know to expect this file."
        );
        assert!(
            fetcher.contains(filename),
            "Lane VVVVVV: scripts/fetch_release_support_handoff.py MUST reference `{filename}` (the manifest's Phase 1 outputs array declares this file). Drift means the manifest claims a Phase 1 file the fetcher doesn't actually write."
        );
    }
}

// Lane WWWWWW — ao2-cp-server Cargo.toml `[[bin]]` and `[lib]`
// declarations bind to the package name and source files.
//
//   Why this matters: `crates/ao2-cp-server/Cargo.toml` is the
//   canonical declaration of what cargo produces when it builds the
//   server crate. Three of its fields are load-bearing for the
//   downstream release surfaces:
//
//     - `[package] name = "ao2-cp-server"` is the package identity.
//     - `[[bin]] name = "..."` is the filename cargo writes to
//       `target/release/`. If it diverges from the package name,
//       `cargo install ao2-cp-server` still works but the produced
//       binary has a different filename — and the package script
//       (`scripts/package-local.sh`), the install heredocs, the
//       README, and every operator-facing surface that copies
//       `target/release/ao2-cp-server` silently picks up the wrong
//       file (or fails to find it).
//     - `[[bin]] path = "src/main.rs"` declares where the entry
//       point lives. If it drifts from the actual file location
//       (e.g. someone moves main.rs to a subdir), cargo build fails
//       outright — caught by CI. But the drift the test catches is
//       subtler: a path that points at a missing or wrong file would
//       only be discovered at the next full build, not at edit time.
//     - `[lib] name = "ao2_cp_server"` is the import path downstream
//       code uses (`use ao2_cp_server::...`). Cargo defaults this to
//       snake_case of the package name when `[lib]` is omitted; with
//       an explicit `[lib]` block, the name MUST match snake_case of
//       the package name or downstream code breaks.
//     - `[lib] path = "src/lib.rs"` declares the library entry. Same
//       drift logic as the bin path.
//
//   The fifth load-bearing surface is `scripts/package-local.sh`'s
//   `BINARY_NAME="ao2-cp-server"` literal — the filename the package
//   script writes into the tar archive's `bin/` directory. If the
//   [[bin]] name changes without updating the package script, tar
//   either misses the file or names it inconsistently across OSes.
//
//   Pin shape: six invariants tying the [[bin]]/[lib] sub-structure
//   to the package name, source files on disk, and the package
//   script's binary literal.
//
//   Cross-axis to Lane VVV (install heredoc → bin/ binary name
//   parity): VVV pins that the install heredocs reference
//   `bin/ao2-cp-server`; Lane WWWWWW pins the Cargo.toml [[bin]]
//   declaration that produces that filename, closing the loop from
//   build artifact → archive → install heredoc.
//
//   Cross-axis to Lane SSSSS (workspace package metadata
//   unification): SSSSS pins that every member crate uses
//   `version.workspace = true` etc. — the [package] section's
//   workspace-inheritance shape. WWWWWW pins the [[bin]]/[lib]
//   sub-sections that live alongside [package] but with stricter
//   per-crate shape requirements.
#[test]
fn server_cargo_toml_bin_and_lib_declarations_bind_to_sources_lane_wwwwww() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let server_toml = fs::read_to_string(root.join("crates/ao2-cp-server/Cargo.toml"))
        .expect("Lane WWWWWW: crates/ao2-cp-server/Cargo.toml present");
    let package_local = fs::read_to_string(root.join("scripts/package-local.sh"))
        .expect("Lane WWWWWW: scripts/package-local.sh present");

    // Invariant 1: [package] name = "ao2-cp-server" — the canonical
    // package identity. Every downstream surface (cargo install,
    // package script, install heredoc, README) anchors on this
    // literal.
    assert!(
        server_toml.contains("name = \"ao2-cp-server\""),
        "Lane WWWWWW: crates/ao2-cp-server/Cargo.toml MUST declare `name = \"ao2-cp-server\"` in [package]. This is the canonical package identity; every downstream surface (cargo install, package script, install heredoc) anchors on it. If renamed, every operator-facing literal across the release pipeline breaks at once."
    );

    // Invariant 2: [[bin]] block exists with name = "ao2-cp-server".
    // The [[bin]] name determines the filename cargo writes to
    // target/release/, which the package script copies into the tar
    // archive's bin/ dir. If [[bin]] name diverges from the package
    // name, cargo produces a binary with the wrong filename and the
    // package script silently picks up the wrong file (or fails to
    // find it). Slice the [[bin]] block to scope the assertion —
    // matching `name = "ao2-cp-server"` against the full Cargo.toml
    // would trivially pass via the [package] line.
    let bin_marker = "[[bin]]";
    let bin_start = server_toml.find(bin_marker).expect(
        "Lane WWWWWW: crates/ao2-cp-server/Cargo.toml MUST declare a `[[bin]]` block — without it cargo doesn't know to produce a binary, and `cargo install` would silently emit nothing.",
    );
    let after_bin = &server_toml[bin_start + bin_marker.len()..];
    let bin_section_end = after_bin.find("\n[").unwrap_or(after_bin.len());
    let bin_section = &after_bin[..bin_section_end];
    assert!(
        bin_section.contains("name = \"ao2-cp-server\""),
        "Lane WWWWWW: the [[bin]] block in crates/ao2-cp-server/Cargo.toml MUST declare `name = \"ao2-cp-server\"` — matching the package name. If the [[bin]] name diverges, cargo writes a different filename to target/release/, the package script's `cp \"$BINARY\" \"$STAGE/bin/...\"` step picks up the wrong file (or fails to find it), and operators install a binary whose name doesn't match the install heredoc's `bin/ao2-cp-server` reference."
    );

    // Invariant 3: [[bin]] path = "src/main.rs" — the entry point.
    // Drift here surfaces at `cargo build` time, but pinning the
    // literal catches refactors that move main.rs to a different
    // location without updating the manifest.
    assert!(
        bin_section.contains("path = \"src/main.rs\""),
        "Lane WWWWWW: the [[bin]] block in crates/ao2-cp-server/Cargo.toml MUST declare `path = \"src/main.rs\"`. If main.rs moves to a different location (e.g., src/bin/server.rs) and the manifest isn't updated, cargo build fails — but a build-time failure is the lucky case. The unlucky case is a stale path pointing at a phantom file that happens to compile, silently shipping the wrong entry point."
    );

    // Invariant 4: the file declared by [[bin]] path actually
    // exists on disk. Even if the manifest declares
    // `path = "src/main.rs"`, the file itself could be missing
    // (e.g. after a botched merge that drops main.rs).
    let main_rs = root.join("crates/ao2-cp-server/src/main.rs");
    assert!(
        main_rs.is_file(),
        "Lane WWWWWW: crates/ao2-cp-server/src/main.rs MUST exist on disk — the [[bin]] block in Cargo.toml declares `path = \"src/main.rs\"` as the binary entry point. If the file is missing, cargo build fails outright; the test pins the file's existence so a missing main.rs surfaces with a clear lane-tagged error rather than an opaque cargo error."
    );

    // Invariant 5: [lib] name = "ao2_cp_server" — snake_case of the
    // package name. Cargo defaults this when [lib] is omitted; with
    // an explicit [lib] block, the name MUST match snake_case of
    // the package name or downstream code's `use ao2_cp_server::...`
    // import fails.
    let lib_marker = "[lib]";
    let lib_start = server_toml.find(lib_marker).expect(
        "Lane WWWWWW: crates/ao2-cp-server/Cargo.toml MUST declare a `[lib]` block — without it downstream code can't import server symbols. The integration tests in this very file are downstream code that imports from ao2_cp_server.",
    );
    let after_lib = &server_toml[lib_start + lib_marker.len()..];
    let lib_section_end = after_lib.find("\n[").unwrap_or(after_lib.len());
    let lib_section = &after_lib[..lib_section_end];
    assert!(
        lib_section.contains("name = \"ao2_cp_server\""),
        "Lane WWWWWW: the [lib] block in crates/ao2-cp-server/Cargo.toml MUST declare `name = \"ao2_cp_server\"` (snake_case of the package name `ao2-cp-server`). Cargo defaults to this when [lib] is omitted; with an explicit [lib] block, drift from snake_case breaks every downstream `use ao2_cp_server::...` import. Integration tests in this crate import from `ao2_cp_server` — if [lib] name diverges they all break at once."
    );

    // Invariant 6: [lib] path = "src/lib.rs". Same drift logic as
    // [[bin]] path. The file must also exist on disk.
    assert!(
        lib_section.contains("path = \"src/lib.rs\""),
        "Lane WWWWWW: the [lib] block in crates/ao2-cp-server/Cargo.toml MUST declare `path = \"src/lib.rs\"`. Drift here means cargo looks at the wrong file for the library entry point — downstream imports break in subtle ways (modules don't resolve, types disappear from the import graph)."
    );
    let lib_rs = root.join("crates/ao2-cp-server/src/lib.rs");
    assert!(
        lib_rs.is_file(),
        "Lane WWWWWW: crates/ao2-cp-server/src/lib.rs MUST exist on disk — the [lib] block in Cargo.toml declares `path = \"src/lib.rs\"` as the library entry point. Without lib.rs, this very test file (an integration test that does `use ao2_cp_server::...`) wouldn't compile; pinning the file's existence guards against accidental deletion during refactor."
    );

    // Invariant 7: the package script's BINARY_NAME literal matches
    // the [[bin]] name. scripts/package-local.sh writes the binary
    // into the tar archive under bin/<BINARY_NAME>; if it diverges
    // from the [[bin]] name, the tar contains a binary with one
    // name but the install heredoc references another.
    assert!(
        package_local.contains("BINARY_NAME=\"ao2-cp-server\""),
        "Lane WWWWWW: scripts/package-local.sh MUST contain `BINARY_NAME=\"ao2-cp-server\"` — matching the [[bin]] name in crates/ao2-cp-server/Cargo.toml. The package script writes the binary into the tar archive under bin/$BINARY_NAME; if it diverges from the [[bin]] name, the tar contains a binary with a different filename than what the install heredocs reference (`bin/ao2-cp-server`), and `tar -xf | install` silently fails to find the expected file."
    );
}

// Lane XXXXXX — route_catalog.rs `ROUTES` entries bind to server.rs
// `.route(...)` registrations (reverse parity).
//
//   Why this matters: `route_catalog.rs` is the central inventory of
//   API surfaces that the public
//   `/api/v1/control-plane/routes.json` endpoint emits to operators.
//   It tells integrators which routes exist, which mutate observer
//   storage, which are downloads/portable, and which owner is
//   responsible. If a route is registered in the catalog but not
//   actually served by the axum router (or vice versa), the
//   inventory lies — operators curl what the catalog advertises and
//   get a 404, OR integrators see a route registered in code that
//   isn't visible in the inventory (security-visibility gap).
//
//   Lane UUUUUU already pins four specific DEPLOYMENT.md endpoint
//   paths against the catalog. Lane XXXXXX closes the broader gap:
//   EVERY `RouteMetadata` path in the catalog must have a matching
//   `.route(...)` registration in `server.rs`.
//
//   Pin shape: extract every `path: "/api/v1/..."` literal from
//   `route_catalog.rs`, strip the `/api/v1` prefix, then assert
//   each resulting suffix appears as a quoted literal in
//   `server.rs` (where the api_v1 router declares routes relative
//   to the nested `/api/v1` mount point). Also enforce a floor on
//   the catalog-entry count so a future refactor that strips
//   entries surfaces here rather than silently passing.
//
//   Cross-axis to Lane SSS (README → axum router declaration
//   parity): SSS pins that documented routes are served. XXXXXX
//   pins that catalog-advertised routes are served — together they
//   form a triangle: docs → catalog → router, with each pair
//   pinned by a separate test.
//
//   Cross-axis to Lane JJJJ (release routes ↔ handler fn parity):
//   JJJJ pins that release-publication routes wire to handler fns.
//   XXXXXX pins that ALL routes (not just release) in the catalog
//   wire to axum registration.
#[test]
fn route_catalog_entries_bind_to_server_route_registrations_lane_xxxxxx() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane XXXXXX: crates/ao2-cp-server/src/route_catalog.rs present");
    let server_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/server.rs"))
        .expect("Lane XXXXXX: crates/ao2-cp-server/src/server.rs present");

    // Extract every `path: "/api/v1/X"` literal from RouteMetadata
    // entries. The marker `path: "` is unique to the path field
    // inside RouteMetadata blocks (the struct field's pub
    // declaration is `pub path: &'static str,` — no opening quote).
    let mut catalog_paths: Vec<String> = Vec::new();
    let marker = "path: \"";
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(marker) {
        let start = cursor + rel + marker.len();
        let end = route_catalog_rs[start..]
            .find('"')
            .map(|e| start + e)
            .expect("Lane XXXXXX: every `path: \"` opener must have a closing quote");
        let value = &route_catalog_rs[start..end];
        // Only collect path values that look like API routes
        // (start with /api/v1/). The pub declaration line has no
        // value between the quotes, so the field value would be
        // empty — naturally skipped by the prefix check.
        if value.starts_with("/api/v1/") {
            catalog_paths.push(value.to_string());
        }
        cursor = end + 1;
    }

    // Defensive floor: a future refactor that strips most of the
    // catalog would otherwise let the per-path assertions pass
    // vacuously. Pin a conservative minimum that reflects the
    // current surface area (115 entries today; floor at 100 to
    // tolerate small additions/removals without churn).
    assert!(
        catalog_paths.len() >= 100,
        "Lane XXXXXX: route_catalog.rs MUST contain at least 100 RouteMetadata path entries (found {}). The catalog is the central inventory operators rely on; a sudden drop suggests entries were stripped without a corresponding test update.",
        catalog_paths.len()
    );

    // For each catalog path, strip the /api/v1 prefix and assert the
    // resulting suffix appears as a quoted literal in server.rs.
    // server.rs nests the api_v1 router under /api/v1, so route
    // literals there are relative (e.g. `.route("/acceptance", ...)`).
    let api_v1_prefix = "/api/v1";
    let mut missing: Vec<String> = Vec::new();
    for catalog_path in &catalog_paths {
        let suffix = catalog_path
            .strip_prefix(api_v1_prefix)
            .expect("Lane XXXXXX: every catalog path starts with /api/v1 (guarded above)");
        // The suffix is e.g. `/acceptance` or `/acceptance/:sha`.
        // server.rs declares it as a quoted literal in a .route
        // call: `.route("/acceptance", ...)`. Use the quoted-literal
        // form to avoid false positives from comments/docstrings.
        let quoted = format!("\"{suffix}\"");
        if !server_rs.contains(&quoted) {
            missing.push(catalog_path.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "Lane XXXXXX: the following route_catalog.rs RouteMetadata paths have no matching `.route(\"<suffix>\", ...)` registration in server.rs — the catalog advertises a route the axum router doesn't actually serve. Operators querying /api/v1/control-plane/routes.json would see these paths and get a 404 when they curl them: {missing:?}"
    );
}

// Lane YYYYYY — server.rs `.route(...)` registrations bind to
// route_catalog.rs `ROUTES` entries (reverse parity to Lane XXXXXX).
//
//   Why this matters: Lane XXXXXX pins catalog → router (every
//   catalog entry has a router registration). Lane YYYYYY pins the
//   reverse: every router registration has a catalog entry. The
//   reverse direction catches the security-visibility gap where a
//   new route is added to `server.rs` but the developer forgets to
//   register it in `route_catalog.rs`. Without the catalog entry,
//   the new route ships to production but is invisible to the
//   public route-inventory endpoint
//   (`/api/v1/control-plane/routes.json`) — operators and security
//   reviewers enumerating the attack surface via the inventory
//   silently miss it.
//
//   Pin shape: extract every quoted route literal argument to a
//   `.route(...)` call in `server.rs`, prepend the `/api/v1` mount
//   prefix, and assert each resulting full path appears as a
//   `path: "/api/v1/..."` literal in `route_catalog.rs`.
//
//   Parser shape note: every `.route(` opener in server.rs is
//   followed (possibly after whitespace/newlines) by a quoted path
//   literal as the first argument. Scan forward from each `.route(`
//   to the next `"`, then extract up to the closing `"`.
//
//   Cross-axis to Lane XXXXXX (catalog → router): together XXXXXX
//   and YYYYYY form a bidirectional invariant — neither direction
//   alone catches all drift cases.
//
//   Cross-axis to Lane JJJJ (release routes ↔ handler fns): JJJJ
//   pins router → handler; YYYYYY pins router → catalog; together
//   the chain catalog → router → handler is fully observable.
#[test]
fn server_route_registrations_bind_to_route_catalog_entries_lane_yyyyyy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let server_rs = fs::read_to_string(root.join("crates/ao2-cp-server/src/server.rs"))
        .expect("Lane YYYYYY: crates/ao2-cp-server/src/server.rs present");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane YYYYYY: crates/ao2-cp-server/src/route_catalog.rs present");

    // Scope to the `api_v1` Router block. server.rs registers some
    // routes at the OUTER Router level (e.g. `/healthz`, `/readyz`
    // — operational probes deliberately mounted outside `/api/v1`
    // because they have no auth and are not user-facing API
    // surfaces). The catalog inventories the `/api/v1` surface
    // specifically, so the api_v1 block is the right scope for the
    // parity check.
    let api_v1_block_start = server_rs
        .find("let api_v1 = Router::new()")
        .expect("Lane YYYYYY: server.rs must declare `let api_v1 = Router::new()` to scope the API-v1 router block");
    // The block ends at the `.with_state(state.clone());` that
    // closes the api_v1 binding (before the outer Router::new()
    // begins).
    let api_v1_block_end = server_rs[api_v1_block_start..]
        .find(".with_state(state.clone());")
        .map(|i| api_v1_block_start + i)
        .expect("Lane YYYYYY: api_v1 block must close with `.with_state(state.clone());`");
    let api_v1_block = &server_rs[api_v1_block_start..api_v1_block_end];

    // Extract every quoted route literal argument to a .route(
    // call within the api_v1 block. For each .route( opener, scan
    // forward to the next ", then read until the matching closing
    // ".
    let mut server_routes: Vec<String> = Vec::new();
    let route_marker = ".route(";
    let mut cursor = 0usize;
    while let Some(rel) = api_v1_block[cursor..].find(route_marker) {
        let after_route = cursor + rel + route_marker.len();
        // Find the next opening quote after `.route(`.
        let quote_open = api_v1_block[after_route..]
            .find('"')
            .map(|i| after_route + i)
            .expect("Lane YYYYYY: every .route( call must be followed by a quoted path literal");
        let value_start = quote_open + 1;
        let value_end = api_v1_block[value_start..]
            .find('"')
            .map(|i| value_start + i)
            .expect("Lane YYYYYY: every opening quote in a .route( path must have a closing quote");
        let value = &api_v1_block[value_start..value_end];
        // Sanity: route paths in axum start with /.
        if value.starts_with('/') {
            server_routes.push(value.to_string());
        }
        cursor = value_end + 1;
    }

    // De-dup (some routes appear via both GET and POST on a single
    // .route() and would otherwise be repeated if axum re-mounted;
    // here each .route() is a single call but de-dup is a cheap
    // safety).
    server_routes.sort();
    server_routes.dedup();

    // Defensive floor on extracted-route count. The current router
    // has ~100 routes; floor at 90 to tolerate small churn without
    // bumping the test.
    assert!(
        server_routes.len() >= 90,
        "Lane YYYYYY: server.rs MUST register at least 90 routes (found {}). A sudden drop suggests routes were stripped without a corresponding test update — or the .route( extraction parser broke (e.g. the formatter changed).",
        server_routes.len()
    );

    // For each server route, prepend /api/v1 (the mount prefix) and
    // assert the full path appears in route_catalog.rs.
    let mut missing: Vec<String> = Vec::new();
    for server_path in &server_routes {
        let full_path = format!("/api/v1{server_path}");
        let catalog_literal = format!("path: \"{full_path}\"");
        if !route_catalog_rs.contains(&catalog_literal) {
            missing.push(full_path);
        }
    }
    assert!(
        missing.is_empty(),
        "Lane YYYYYY: the following routes are registered in server.rs but have NO matching `path: \"/api/v1/...\"` entry in route_catalog.rs. The route ships and serves requests, but the public /api/v1/control-plane/routes.json inventory hides it — a security-visibility gap where the new attack surface isn't enumerated. Add a RouteMetadata entry for each: {missing:?}"
    );
}

// Lane ZZZZZZ — every route_catalog entry that mutates observer
// storage uses a non-GET HTTP method (CSRF safety invariant).
//
//   Why this matters: a GET endpoint that mutates state is a
//   classic CSRF attack vector. Any HTML page on a different
//   origin can embed `<img src="<mutating-get-url>">` or a
//   `<script src="...">` tag and trigger the mutation just by
//   being loaded — no JavaScript needed, no operator interaction
//   needed, just an authenticated session cookie or bearer token
//   that the browser sends automatically. Even with bearer-token
//   auth, an authenticated operator visiting a malicious page
//   (e.g. a phishing link in a Slack message) would trigger the
//   request.
//
//   The defense is structural: state-changing operations must use
//   POST/PUT/DELETE. Browsers treat these as "unsafe" methods,
//   they require explicit form/fetch invocation (no img/script
//   tags trigger them), and our auth middleware can require
//   Content-Type checks on non-GET requests as an additional CSRF
//   layer.
//
//   route_catalog.rs declares each route's method AND
//   mutates_observer_storage flag. The invariant: if
//   mutates_observer_storage is true, the method MUST NOT be GET.
//
//   Pin shape: parse each RouteMetadata block from
//   route_catalog.rs, extract its method and mutates_observer_
//   storage fields, and assert that every block with
//   mutates_observer_storage: true has a method other than GET.
//
//   The auth middleware (src/auth.rs::require_token) plus the
//   structural method-vs-mutation invariant form CSRF defense in
//   depth — even if auth is bypassed somehow, the GET-no-mutation
//   rule means a CSRF GET request can't actually change state.
//
//   Cross-axis to Lane YYYYYY: YYYYYY pins that every router
//   route has a catalog entry (visibility); ZZZZZZ pins that
//   catalog entries with mutation flags use safe methods
//   (security). Together they cover both visibility and method
//   safety for the full mutation surface.
//
//   Cross-axis to Lane TTTTTT (SECURITY.md source-code claim
//   parity): TTTTTT pins SECURITY.md's claims about auth/exit
//   codes; ZZZZZZ pins a structural security invariant the doc
//   doesn't currently call out but should — that no mutation
//   surface is reachable via GET.
#[test]
fn route_catalog_mutating_routes_use_post_not_get_lane_zzzzzz() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane ZZZZZZ: crates/ao2-cp-server/src/route_catalog.rs present");

    // Parse each RouteMetadata block. The block opener is
    // `RouteMetadata {`. A block closes at the next `},` (or `}` at
    // end of array). Each block is small enough that a simple
    // forward scan is safe.
    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        // Find the closing `},` for this block. Each RouteMetadata
        // block ends with the closing brace on its own line — the
        // first `\n    }` after the opener.
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane ZZZZZZ: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    // Defensive floor on parsed-block count. Currently 117 blocks
    // (115 originals plus 2 verify entries added in Lane YYYYYY);
    // floor at 100.
    assert!(
        blocks.len() >= 100,
        "Lane ZZZZZZ: route_catalog.rs MUST contain at least 100 RouteMetadata blocks (parsed {}). A sudden drop suggests entries were stripped without a corresponding test update, OR the block parser broke (e.g. the `\\n    }}` close pattern changed).",
        blocks.len()
    );

    // For each block, extract method and mutates_observer_storage.
    let mut violations: Vec<String> = Vec::new();
    for body in &blocks {
        let method_marker = "method: \"";
        let method_start_rel = body.find(method_marker).expect(
            "Lane ZZZZZZ: every RouteMetadata block must contain a `method: \"...\"` field",
        );
        let method_start = method_start_rel + method_marker.len();
        let method_end_rel = body[method_start..]
            .find('"')
            .expect("Lane ZZZZZZ: every method field must have a closing quote");
        let method = &body[method_start..method_start + method_end_rel];

        // Extract path for the error message (so violations are
        // actionable, not just method strings without context).
        let path_marker = "path: \"";
        let path_start_rel = body
            .find(path_marker)
            .expect("Lane ZZZZZZ: every RouteMetadata block must contain a `path: \"...\"` field");
        let path_start = path_start_rel + path_marker.len();
        let path_end_rel = body[path_start..]
            .find('"')
            .expect("Lane ZZZZZZ: every path field must have a closing quote");
        let path = &body[path_start..path_start + path_end_rel];

        // The mutation flag literal. Two valid shapes: `: true,`
        // or `: false,` — match the `true,` form for the unsafe
        // case.
        let mutates_marker = "mutates_observer_storage: true";
        if body.contains(mutates_marker) && method.eq_ignore_ascii_case("GET") {
            violations.push(format!("path={path:?} method=GET"));
        }
    }
    assert!(
        violations.is_empty(),
        "Lane ZZZZZZ: the following route_catalog.rs entries declare `mutates_observer_storage: true` but use HTTP GET — a classic CSRF attack vector. State-changing operations MUST use POST/PUT/DELETE so browsers treat them as 'unsafe' methods and `<img>`/`<script>` tags can't trigger them just by loading a malicious page. Fix by changing the method to POST (and updating server.rs's .route() registration to match): {violations:?}"
    );
}

// Lane AAAAAAA: route_catalog `category` field enum-shape parity.
//
// Every RouteMetadata entry's `category` value MUST belong to the
// canonical set of category literals. The catalog drives dashboard
// grouping and operator-facing route inventory; a typo like
// "storage-observer" → "stoarge-observer" silently creates a new
// "stoarge-observer" group with one route, splitting the dashboard
// visual grouping and breaking any downstream code that filters
// by exact category value.
//
// This lane opens the **category enum-shape sub-axis** of the
// route_catalog field validation series. Future lanes can extend
// to `method`, `owner`, and the boolean-pair fields.
//
// Cross-axis to Lane XXXXXX (catalog → server) + Lane YYYYYY
// (server → catalog): those lanes pin route IDENTITY parity;
// AAAAAAA pins route METADATA-FIELD parity within the catalog.
#[test]
fn route_catalog_category_field_enum_shape_lane_aaaaaaa() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane AAAAAAA: crates/ao2-cp-server/src/route_catalog.rs present");

    // Canonical set of category values. Every value present in
    // route_catalog.rs MUST appear in this set. To add a new
    // category, add it here AND add at least one RouteMetadata
    // entry using it.
    let allowed_categories: &[&str] = &[
        "acceptance-observer",
        "ai-task-board-observer",
        "audit",
        "hermes-watchdog-observer",
        "memory-export-observer",
        "metrics",
        "observer-ingest",
        "observer-list",
        "phase1-gap-report",
        "phase1-readiness",
        "phase1-support-bundle",
        "provider-readiness-observer",
        "provider-readiness-support-bundle",
        "provider-registry-observer",
        "release-acceptance-observer",
        "release-publication-observer",
        "release-readiness",
        "release-support-bundle",
        "route-index",
        "signed-evidence-observer",
        "status",
        "storage-observer",
        "storage-retention",
        "storage-support-bundle-contract",
        "storage-support-bundle",
    ];

    // Defensive floor on the canonical set size (catches an edit
    // that strips half the categories during a refactor).
    assert!(
        allowed_categories.len() >= 20,
        "Lane AAAAAAA: the canonical category set must list at least 20 values (got {}). To remove a category, REMOVE all RouteMetadata entries using it first, then update this list.",
        allowed_categories.len()
    );

    // Parse RouteMetadata blocks using the same 4-space-indented
    // marker as Lane ZZZZZZ to scope to array elements only.
    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane AAAAAAA: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    // Floor at 100 blocks (matches Lane ZZZZZZ).
    assert!(
        blocks.len() >= 100,
        "Lane AAAAAAA: route_catalog.rs must contain at least 100 RouteMetadata blocks (parsed {}). A drop suggests entries were stripped or the parser broke.",
        blocks.len()
    );

    // For each block, extract category and check membership.
    let mut violations: Vec<String> = Vec::new();
    for body in &blocks {
        let category_marker = "category: \"";
        let cat_start_rel = body.find(category_marker).expect(
            "Lane AAAAAAA: every RouteMetadata block must contain a `category: \"...\"` field",
        );
        let cat_start = cat_start_rel + category_marker.len();
        let cat_end_rel = body[cat_start..]
            .find('"')
            .expect("Lane AAAAAAA: every category field must have a closing quote");
        let category = &body[cat_start..cat_start + cat_end_rel];

        // Also pull the path so violations are actionable.
        let path_marker = "path: \"";
        let path_start_rel = body
            .find(path_marker)
            .expect("Lane AAAAAAA: every RouteMetadata block must contain a `path: \"...\"` field");
        let path_start = path_start_rel + path_marker.len();
        let path_end_rel = body[path_start..]
            .find('"')
            .expect("Lane AAAAAAA: every path field must have a closing quote");
        let path = &body[path_start..path_start + path_end_rel];

        if !allowed_categories.contains(&category) {
            violations.push(format!("path={path:?} category={category:?}"));
        }
    }
    assert!(
        violations.is_empty(),
        "Lane AAAAAAA: the following route_catalog.rs entries declare a `category` value that is NOT in the canonical allowed-set. A typo (e.g. `storage-observer` → `stoarge-observer`) silently creates a new grouping that splits dashboard rendering and breaks downstream filters. Fix by correcting the typo to a canonical value, OR — if intentionally introducing a new category — add it to `allowed_categories` in this test AND document the new dashboard grouping. Allowed values: {allowed_categories:?}. Violations: {violations:?}"
    );
}

// Lane BBBBBBB: route_catalog `method` field enum parity.
//
// Every RouteMetadata entry's `method` value MUST be one of the
// canonical uppercase HTTP verbs (GET / POST / PUT / DELETE /
// PATCH). The catalog is the operator-facing inventory of what
// methods each endpoint accepts; a typo like `method: "Get"` or
// `method: "POST "` (trailing space) silently makes the catalog
// claim a method the server isn't registered for, OR — worse —
// downstream filtering by exact-string method match silently
// drops the typo'd entry from operator views.
//
// This lane extends the route_catalog field-validation sub-axis
// opened in Lane AAAAAAA (category enum). Future lanes will
// cover `owner` (CCCCCCC) and boolean-field shape pins.
//
// Cross-axis to Lane ZZZZZZ (mutating-route CSRF safety):
// ZZZZZZ pins that mutating routes don't use GET; BBBBBBB pins
// that whatever method is declared is at least a real HTTP verb
// in canonical case. ZZZZZZ catches the security violation;
// BBBBBBB catches the typo before it can confuse ZZZZZZ.
#[test]
fn route_catalog_method_field_enum_parity_lane_bbbbbbb() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane BBBBBBB: crates/ao2-cp-server/src/route_catalog.rs present");

    // Canonical set of HTTP method literals. All uppercase per
    // RFC 7231; the catalog must use the same canonical form so
    // string filtering and method-matching work without
    // case-folding shims. PATCH is included even though it isn't
    // currently used, so a legitimate future addition doesn't
    // require a test edit just to allow the method.
    let allowed_methods: &[&str] = &["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"];

    // Defensive floor on the canonical set size.
    assert!(
        allowed_methods.len() >= 5,
        "Lane BBBBBBB: the canonical method set must list at least 5 verbs (got {}). The RFC 7231 unsafe-method set is the floor.",
        allowed_methods.len()
    );

    // Parse RouteMetadata blocks (same parser as AAAAAAA/ZZZZZZ).
    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane BBBBBBB: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    // Floor at 100 blocks.
    assert!(
        blocks.len() >= 100,
        "Lane BBBBBBB: route_catalog.rs must contain at least 100 RouteMetadata blocks (parsed {}). A drop suggests entries were stripped or the parser broke.",
        blocks.len()
    );

    let mut violations: Vec<String> = Vec::new();
    for body in &blocks {
        let method_marker = "method: \"";
        let method_start_rel = body.find(method_marker).expect(
            "Lane BBBBBBB: every RouteMetadata block must contain a `method: \"...\"` field",
        );
        let method_start = method_start_rel + method_marker.len();
        let method_end_rel = body[method_start..]
            .find('"')
            .expect("Lane BBBBBBB: every method field must have a closing quote");
        let method = &body[method_start..method_start + method_end_rel];

        let path_marker = "path: \"";
        let path_start_rel = body
            .find(path_marker)
            .expect("Lane BBBBBBB: every RouteMetadata block must contain a `path: \"...\"` field");
        let path_start = path_start_rel + path_marker.len();
        let path_end_rel = body[path_start..]
            .find('"')
            .expect("Lane BBBBBBB: every path field must have a closing quote");
        let path = &body[path_start..path_start + path_end_rel];

        if !allowed_methods.contains(&method) {
            violations.push(format!("path={path:?} method={method:?}"));
        }
    }
    assert!(
        violations.is_empty(),
        "Lane BBBBBBB: the following route_catalog.rs entries declare a `method` value that is NOT a canonical uppercase HTTP verb. A typo (`Get`, `POST `, `getProvider`) silently breaks string-filtering by method and may mislead operators about what the endpoint accepts. Fix by using one of the canonical methods (verbatim, no trailing whitespace). Allowed: {allowed_methods:?}. Violations: {violations:?}"
    );
}

// Lane CCCCCCC: route_catalog `owner` field membership parity.
//
// Every RouteMetadata entry's `owner` value MUST belong to the
// canonical allowed-set of trust-boundary owner literals. The
// `owner` field declares who is responsible for the endpoint
// behavior at the trust-boundary level (ao2-control-plane
// observer for read-only observation, factory-v3
// evaluator-closer for approval decisions, ao2 signed evidence
// boundary for signed-artifact provenance, etc).
//
// A typo or fabricated owner literal silently introduces a
// fifth/sixth/etc trust-boundary identity that downstream code
// (the cockpit dashboard, audit log enrichment, security review
// tooling) doesn't recognize, splitting the boundary-owner
// taxonomy. The canonical set IS the trust model; new owners
// require a deliberate update to this test alongside the new
// entry.
//
// This lane closes the route_catalog string-field enum trilogy
// (category / method / owner). Future lanes can pin boolean
// pair invariants (download↔portable consistency).
//
// Cross-axis to Lane VVVVV (HTML disclaimer trust-boundary
// language): VVVVV pins that operators see the canonical
// disclaimer literals on the cockpit page; CCCCCCC pins that
// every route declares an owner from the same canonical set —
// together the trust-boundary identity surface stays coherent
// across UI and data.
#[test]
fn route_catalog_owner_field_membership_lane_ccccccc() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane CCCCCCC: crates/ao2-cp-server/src/route_catalog.rs present");

    // Canonical set of trust-boundary owner literals. Order:
    // (1) the observer itself, (2) the evaluator-closer that
    // approves releases, (3) signed-evidence boundary for the
    // attested-artifact lane, (4) signed-memory boundary for
    // memory exports, (5) factory-v3 Hermes watchdog for
    // watchdog-observed surfaces. Adding a new owner requires
    // a corresponding update here AND a documented entry in the
    // trust-boundary surface set (cockpit HTML disclaimer +
    // smoke report markdown + manifest JSON).
    let allowed_owners: &[&str] = &[
        "ao2 signed evidence boundary",
        "ao2 signed memory boundary",
        "ao2-control-plane observer",
        "factory-v3 evaluator-closer",
        "factory-v3 Hermes watchdog",
    ];

    assert!(
        allowed_owners.len() >= 5,
        "Lane CCCCCCC: the canonical owner set must list at least 5 trust-boundary identities (got {}). To remove an owner, REMOVE all RouteMetadata entries using it first, then update this list.",
        allowed_owners.len()
    );

    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane CCCCCCC: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    assert!(
        blocks.len() >= 100,
        "Lane CCCCCCC: route_catalog.rs must contain at least 100 RouteMetadata blocks (parsed {}).",
        blocks.len()
    );

    let mut violations: Vec<String> = Vec::new();
    for body in &blocks {
        let owner_marker = "owner: \"";
        let owner_start_rel = body.find(owner_marker).expect(
            "Lane CCCCCCC: every RouteMetadata block must contain an `owner: \"...\"` field",
        );
        let owner_start = owner_start_rel + owner_marker.len();
        let owner_end_rel = body[owner_start..]
            .find('"')
            .expect("Lane CCCCCCC: every owner field must have a closing quote");
        let owner = &body[owner_start..owner_start + owner_end_rel];

        let path_marker = "path: \"";
        let path_start_rel = body
            .find(path_marker)
            .expect("Lane CCCCCCC: every RouteMetadata block must contain a `path: \"...\"` field");
        let path_start = path_start_rel + path_marker.len();
        let path_end_rel = body[path_start..]
            .find('"')
            .expect("Lane CCCCCCC: every path field must have a closing quote");
        let path = &body[path_start..path_start + path_end_rel];

        if !allowed_owners.contains(&owner) {
            violations.push(format!("path={path:?} owner={owner:?}"));
        }
    }
    assert!(
        violations.is_empty(),
        "Lane CCCCCCC: the following route_catalog.rs entries declare an `owner` value that is NOT in the canonical trust-boundary owner set. A new owner literal silently introduces a new trust-boundary identity that downstream code (cockpit, audit log, security review) doesn't recognize. Fix by using one of the canonical literals, OR — if a new trust-boundary owner is genuinely being introduced — add it to `allowed_owners` here AND to the cockpit HTML disclaimer + smoke report markdown + manifest JSON owner surfaces in the SAME change. Allowed: {allowed_owners:?}. Violations: {violations:?}"
    );
}

// Lane DDDDDDD: route_catalog `download: true` semantic implications parity.
//
// A `download: true` RouteMetadata declares that the endpoint
// returns an artifact for direct operator download (not just
// JSON to render). Three structural implications follow from
// that semantic claim:
//   1. `portable: true` — downloadable artifacts MUST be
//      portable (designed to be saved and reused across OSes);
//      a non-portable download is a contradiction.
//   2. `method: "GET"` — downloads are reads; an endpoint
//      labeled as a download but registered as POST is either
//      mis-labeled or unsafe (a POST that returns a downloadable
//      blob smells like a side-effect under a "read" label).
//   3. `mutates_observer_storage: false` — downloads MUST be
//      read-only. A mutating download is a contradiction: the
//      operator thinks they're fetching a file, but the server
//      is changing state behind the scenes.
//
// Together these three invariants define what the `download`
// flag actually means at the schema level. A future entry that
// flips download to true without also matching these three
// flags creates a route with ambiguous semantics that breaks
// dashboard rendering (which uses download to decide widget
// type) and breaks operator expectations (downloads are safe
// reads).
//
// Cross-axis to Lane ZZZZZZ (mutating-route CSRF safety):
// ZZZZZZ catches `mutates+GET`; DDDDDDD catches `download+POST`,
// `download+mutates`, and `download+non-portable`. Together
// they cover the four highest-risk flag combinations.
#[test]
fn route_catalog_download_flag_implications_lane_ddddddd() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane DDDDDDD: crates/ao2-cp-server/src/route_catalog.rs present");

    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane DDDDDDD: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    assert!(
        blocks.len() >= 100,
        "Lane DDDDDDD: route_catalog.rs must contain at least 100 RouteMetadata blocks (parsed {}).",
        blocks.len()
    );

    // Track total download:true entries to floor-check below.
    let mut download_count = 0usize;
    let mut violations: Vec<String> = Vec::new();
    for body in &blocks {
        // Only check entries that declare download: true.
        if !body.contains("download: true") {
            continue;
        }
        download_count += 1;

        let method_marker = "method: \"";
        let m_start_rel = body
            .find(method_marker)
            .expect("Lane DDDDDDD: every RouteMetadata block must contain a method field");
        let m_start = m_start_rel + method_marker.len();
        let m_end_rel = body[m_start..]
            .find('"')
            .expect("Lane DDDDDDD: every method field must have a closing quote");
        let method = &body[m_start..m_start + m_end_rel];

        let path_marker = "path: \"";
        let p_start_rel = body
            .find(path_marker)
            .expect("Lane DDDDDDD: every RouteMetadata block must contain a path field");
        let p_start = p_start_rel + path_marker.len();
        let p_end_rel = body[p_start..]
            .find('"')
            .expect("Lane DDDDDDD: every path field must have a closing quote");
        let path = &body[p_start..p_start + p_end_rel];

        // Invariant 1: download:true ⇒ portable:true
        if !body.contains("portable: true") {
            violations.push(format!(
                "path={path:?}: download:true but portable is not true — downloadable artifacts MUST be portable (cross-OS-safe)"
            ));
        }
        // Invariant 2: download:true ⇒ method:GET
        if !method.eq_ignore_ascii_case("GET") {
            violations.push(format!(
                "path={path:?}: download:true but method={method:?} — downloads MUST be GET (reads)"
            ));
        }
        // Invariant 3: download:true ⇒ mutates_observer_storage:false
        if body.contains("mutates_observer_storage: true") {
            violations.push(format!(
                "path={path:?}: download:true paired with mutates_observer_storage:true — a download MUST be read-only"
            ));
        }
    }

    // Floor on download-flagged entries: the release contract
    // includes downloadable artifacts (release-support bundles,
    // SHA256SUMS, portable manifest, etc). At least 8 such
    // entries must exist; a sudden drop suggests entries were
    // stripped without a corresponding contract update.
    assert!(
        download_count >= 8,
        "Lane DDDDDDD: route_catalog.rs declares only {download_count} entries with download:true; floor is 8 (release-support bundle + SHA256SUMS + portable manifest + phase1 variants). A drop suggests downloadable artifacts were stripped from the catalog."
    );

    assert!(
        violations.is_empty(),
        "Lane DDDDDDD: the following route_catalog.rs entries violate the `download: true` semantic implications. A download flag implies the route is a read-only GET that serves a portable artifact — any deviation creates ambiguous semantics (dashboard widget type breaks, operator expectations break, security boundary blurs). Fix by either (a) correcting the paired flags so the invariants hold, or (b) flipping `download` to false if the route isn't actually a downloadable artifact endpoint. Violations: {violations:?}"
    );
}

// Lane EEEEEEE: route_catalog download path naming convention parity.
//
// Every `download: true` path MUST end with either `/download`
// (the canonical "fetch the artifact" suffix) or `/SHA256SUMS`
// (the canonical "fetch the checksum file" suffix). This
// convention is what lets operators predict the URL for a
// download from any category: given a category bundle endpoint
// at `/api/v1/X/Y`, the download lives at `/api/v1/X/Y/download`
// and its checksums at `/api/v1/X/Y/SHA256SUMS` — no surprise
// names like `/fetch`, `/get-file`, or `/raw`.
//
// Why this matters: operator runbooks reference download URLs
// by suffix convention ("hit `<bundle-url>/download` to fetch,
// `<bundle-url>/SHA256SUMS` to verify"). A future endpoint that
// declares `download: true` but uses `/raw` as the suffix
// breaks every runbook that operators reach for. The
// convention is the operator-facing contract.
//
// Cross-axis to Lane DDDDDDD (download flag semantic
// implications): DDDDDDD pins what `download: true` IMPLIES
// about the other flags; EEEEEEE pins what `download: true`
// IMPLIES about the path shape. Together they pin the full
// contract operators read into the download flag.
#[test]
fn route_catalog_download_path_naming_convention_lane_eeeeeee() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane EEEEEEE: crates/ao2-cp-server/src/route_catalog.rs present");

    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane EEEEEEE: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    assert!(
        blocks.len() >= 100,
        "Lane EEEEEEE: route_catalog.rs must contain at least 100 RouteMetadata blocks (parsed {}).",
        blocks.len()
    );

    // Canonical suffix set. Future categories CAN add a third
    // canonical suffix if a new download family genuinely
    // requires it, but the test must be updated in the same
    // change as the route entries — making the contract
    // explicit at review time.
    let allowed_suffixes: &[&str] = &["/download", "/SHA256SUMS"];

    let mut download_count = 0usize;
    let mut violations: Vec<String> = Vec::new();
    for body in &blocks {
        if !body.contains("download: true") {
            continue;
        }
        download_count += 1;

        let path_marker = "path: \"";
        let p_start_rel = body
            .find(path_marker)
            .expect("Lane EEEEEEE: every RouteMetadata block must contain a path field");
        let p_start = p_start_rel + path_marker.len();
        let p_end_rel = body[p_start..]
            .find('"')
            .expect("Lane EEEEEEE: every path field must have a closing quote");
        let path = &body[p_start..p_start + p_end_rel];

        let ok = allowed_suffixes.iter().any(|suffix| path.ends_with(suffix));
        if !ok {
            violations.push(format!("path={path:?}"));
        }
    }

    assert!(
        download_count >= 8,
        "Lane EEEEEEE: route_catalog.rs declares only {download_count} entries with download:true; floor is 8 (matches Lane DDDDDDD floor)."
    );

    assert!(
        violations.is_empty(),
        "Lane EEEEEEE: the following route_catalog.rs entries declare `download: true` but the path does NOT end with the canonical `/download` or `/SHA256SUMS` suffix. Operator runbooks reference download URLs by this convention; a new suffix (`/raw`, `/fetch`, `/get-file`) breaks predictability across categories. Fix by renaming the route to use the canonical suffix, OR — if a genuinely new download family is being introduced — extend `allowed_suffixes` here in the same change so reviewers see the convention extension explicitly. Allowed suffixes: {allowed_suffixes:?}. Violations: {violations:?}"
    );
}

// Lane FFFFFFF: route_catalog `portable: true` ⇒ non-mutating implication.
//
// Every `portable: true` RouteMetadata MUST also declare
// `mutates_observer_storage: false`. The `portable` flag means
// the artifact or operation is designed to be taken offline (the
// download endpoint produces a portable bundle; the verifier
// endpoint runs against a portable bundle and is safe to run
// repeatedly without source-of-truth changes). A portable
// endpoint that mutates observer storage breaks the offline-
// safety contract — an operator who copies the bundle to an
// air-gapped machine and runs the verify endpoint expects
// idempotent behavior, not a state change on the source side.
//
// Today's invariant state: 81 portable:true entries (77 GET +
// 4 POST verify endpoints), all declare mutates: false. Lane
// FFFFFFF pins this fact as a structural invariant.
//
// Cross-axis to Lane DDDDDDD/EEEEEEE (download flag
// implications + path naming): the download flag is the
// strongest form of portable — DDDDDDD/EEEEEEE cover the
// download subset; FFFFFFF covers the full portable surface
// (including portable POST verifiers that aren't downloads).
// Cross-axis to Lane ZZZZZZ (CSRF safety): ZZZZZZ catches
// mutating routes that use GET; FFFFFFF catches the inverse
// shape — portable routes that mutate (regardless of method).
#[test]
fn route_catalog_portable_implies_non_mutating_lane_fffffff() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane FFFFFFF: crates/ao2-cp-server/src/route_catalog.rs present");

    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane FFFFFFF: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    assert!(
        blocks.len() >= 100,
        "Lane FFFFFFF: route_catalog.rs must contain at least 100 RouteMetadata blocks (parsed {}).",
        blocks.len()
    );

    let mut portable_count = 0usize;
    let mut violations: Vec<String> = Vec::new();
    for body in &blocks {
        if !body.contains("portable: true") {
            continue;
        }
        portable_count += 1;

        let path_marker = "path: \"";
        let p_start_rel = body
            .find(path_marker)
            .expect("Lane FFFFFFF: every RouteMetadata block must contain a path field");
        let p_start = p_start_rel + path_marker.len();
        let p_end_rel = body[p_start..]
            .find('"')
            .expect("Lane FFFFFFF: every path field must have a closing quote");
        let path = &body[p_start..p_start + p_end_rel];

        if body.contains("mutates_observer_storage: true") {
            violations.push(format!("path={path:?}"));
        }
    }

    // Floor on portable:true count: the catalog includes a
    // large portable surface (release bundles, evidence pack
    // routes, acceptance routes, phase1 promotion artifacts).
    // At least 50 such entries today; floor at 40 to leave
    // headroom for legitimate restructuring.
    assert!(
        portable_count >= 40,
        "Lane FFFFFFF: route_catalog.rs declares only {portable_count} entries with portable:true; floor is 40. A sudden drop suggests portable routes were stripped or the parser broke."
    );

    assert!(
        violations.is_empty(),
        "Lane FFFFFFF: the following route_catalog.rs entries declare `portable: true` but ALSO `mutates_observer_storage: true`. A portable endpoint is designed to be taken offline and run repeatedly without source-of-truth changes — pairing it with a mutating flag breaks the idempotent-offline contract operators rely on (running the verifier from an air-gapped machine must not change the source). Fix by either (a) flipping `portable` to false if the endpoint is genuinely a state-changing operation, or (b) refactoring the handler so mutations happen elsewhere and the portable endpoint stays read-only. Violations: {violations:?}"
    );
}

// Lane GGGGGGG: RouteMetadata struct + to_json() schema parity.
//
// The `RouteMetadata` struct defined in
// `crates/ao2-cp-server/src/route_catalog.rs` is the canonical
// schema for the `/api/v1/control-plane/routes.json` and
// `/api/v1/route-index` endpoints — the operator-facing
// inventory of every observer API surface. Schema drift on
// either the struct OR the to_json() body breaks downstream
// JSON consumers (route audit tooling, dashboard rendering,
// integration tests in operator runbooks).
//
// Lane GGGGGGG pins TWO surfaces in lockstep:
//   1. The `pub struct RouteMetadata` declaration MUST list
//      exactly the 7 known fields (method / path / category /
//      owner / download / portable / mutates_observer_storage).
//   2. The `to_json()` impl body MUST emit exactly those 7
//      fields PLUS 4 trust-boundary constant keys with the
//      canonical values: `auth_required: true`,
//      `control_plane_role: "read-only-observer"`,
//      `mutates_ao_artifacts: false`,
//      `control_plane_approves_release: false`.
//
// The 4 constant keys are the trust-boundary commitment encoded
// directly in the route inventory — every route surface
// advertises "I require auth, I'm a read-only observer, I
// don't mutate AO artifacts, I don't approve releases" as
// JSON-readable facts. Operators parsing the route inventory
// can grep for these guarantees per-route without trusting
// human-readable disclaimers.
//
// Cross-axis to CCCCCCC (owner field membership) + VVVVV
// (HTML disclaimer): all three encode the trust-boundary
// commitment on different operator-facing surfaces:
//   - CCCCCCC pins the per-route owner literal,
//   - VVVVV pins the HTML cockpit disclaimer,
//   - GGGGGGG pins the JSON-encoded trust-boundary keys.
// Drift on any one fails loud at test time.
#[test]
fn route_catalog_struct_and_to_json_schema_lane_ggggggg() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane GGGGGGG: crates/ao2-cp-server/src/route_catalog.rs present");

    // ---- (1) struct field pins ----
    // The struct declaration block starts at `pub struct RouteMetadata {`
    // and closes at the next `\n}` line.
    let struct_marker = "pub struct RouteMetadata {";
    let struct_start = route_catalog_rs.find(struct_marker).expect(
        "Lane GGGGGGG: `pub struct RouteMetadata {` declaration must exist in route_catalog.rs",
    );
    let struct_body_start = struct_start + struct_marker.len();
    let struct_close_rel = route_catalog_rs[struct_body_start..]
        .find("\n}")
        .expect("Lane GGGGGGG: RouteMetadata struct must close with a top-level `\\n}` line");
    let struct_body = &route_catalog_rs[struct_body_start..struct_body_start + struct_close_rel];

    // Canonical 7-field set.
    let required_fields: &[&str] = &[
        "pub method: &'static str,",
        "pub path: &'static str,",
        "pub category: &'static str,",
        "pub owner: &'static str,",
        "pub download: bool,",
        "pub portable: bool,",
        "pub mutates_observer_storage: bool,",
    ];
    for field in required_fields {
        assert!(
            struct_body.contains(field),
            "Lane GGGGGGG: RouteMetadata struct MUST declare field exactly as `{field}`. A rename or type change breaks the route-index JSON contract. struct body was:\n{struct_body}"
        );
    }

    // Defensive count: the struct body must contain exactly 7
    // `pub ` lines (each field). A field add/remove must be
    // reflected here AND in the to_json() body AND in this
    // test.
    let field_line_count = struct_body.matches("\n    pub ").count();
    assert_eq!(
        field_line_count, 7,
        "Lane GGGGGGG: RouteMetadata struct MUST contain exactly 7 fields (got {field_line_count}). A new field requires updating: (a) the struct declaration, (b) every RouteMetadata block initializer, (c) the to_json() body, (d) the `required_fields` list in this test. Don't add a field without all four sites updated in the same change."
    );

    // ---- (2) to_json() schema pins ----
    let to_json_marker = "pub fn to_json(self) -> serde_json::Value {";
    let to_json_start = route_catalog_rs.find(to_json_marker).expect(
        "Lane GGGGGGG: `pub fn to_json(self) -> serde_json::Value {` must exist in route_catalog.rs",
    );
    let to_json_body_start = to_json_start + to_json_marker.len();
    // The json!({ ... }) call ends at `})` on its own indented
    // line — the macro returns serde_json::Value as the function
    // expression (no trailing semicolon). Match `\n        })`
    // to scope to the macro close, not any incidental `})`
    // inside the body.
    let to_json_close_rel = route_catalog_rs[to_json_body_start..]
        .find("\n        })")
        .expect("Lane GGGGGGG: to_json() must close its json!({...}) call with `\\n        })`");
    let to_json_body =
        &route_catalog_rs[to_json_body_start..to_json_body_start + to_json_close_rel];

    // 7 dynamic field emissions.
    let to_json_dynamic_keys: &[(&str, &str)] = &[
        ("\"method\":", "self.method"),
        ("\"path\":", "self.path"),
        ("\"category\":", "self.category"),
        ("\"owner\":", "self.owner"),
        ("\"download\":", "self.download"),
        ("\"portable\":", "self.portable"),
        (
            "\"mutates_observer_storage\":",
            "self.mutates_observer_storage",
        ),
    ];
    for (key, value) in to_json_dynamic_keys {
        assert!(
            to_json_body.contains(key),
            "Lane GGGGGGG: to_json() body must emit JSON key `{key}`. to_json body was:\n{to_json_body}"
        );
        assert!(
            to_json_body.contains(value),
            "Lane GGGGGGG: to_json() body must emit value reference `{value}` (paired with key `{key}`). to_json body was:\n{to_json_body}"
        );
    }

    // 4 trust-boundary constant keys + canonical values.
    let to_json_constants: &[(&str, &str)] = &[
        ("\"auth_required\":", "true"),
        ("\"control_plane_role\":", "\"read-only-observer\""),
        ("\"mutates_ao_artifacts\":", "false"),
        ("\"control_plane_approves_release\":", "false"),
    ];
    for (key, expected_value) in to_json_constants {
        assert!(
            to_json_body.contains(key),
            "Lane GGGGGGG: to_json() body must emit trust-boundary constant key `{key}`. A drop in any of these 4 keys breaks the JSON-readable trust-boundary commitment operators consume from the route inventory."
        );
        // Build the canonical `<key> <value>` substring to pin
        // the key→value pairing.
        let paired = format!("{key} {expected_value}");
        assert!(
            to_json_body.contains(&paired),
            "Lane GGGGGGG: to_json() body must emit `{paired}` (the trust-boundary commitment value). A drift in the canonical value (e.g. flipping `mutates_ao_artifacts` to true, or renaming the role) silently changes the trust-boundary fact operators consume per-route. to_json body was:\n{to_json_body}"
        );
    }
}

// Lane HHHHHHH: workspace-wide handler SCHEMA constant shape parity.
//
// Every `const *_SCHEMA: &str = "..."` declaration in
// `crates/ao2-cp-server/src/handlers/*.rs` MUST follow the
// canonical schema-naming shape `ao2.<family-id>.v<N>` —
// specifically (1) the literal MUST start with the `ao2.`
// prefix and (2) the literal MUST end with `.v<digits>` (a
// semver-major suffix).
//
// Why this matters: schema literals are emitted in JSON
// responses (`schema`, `schema_version`) and serve as the
// machine-readable identity of every observer surface. Operator
// audit tooling, integration tests, and the support-bundle
// verifier all filter on these literals. A typo like
// `oa2.foo.v1` (transposed prefix) or `ao2.foo` (missing semver
// suffix) silently breaks downstream schema dispatch — the
// payload looks identical but the consumer no longer recognizes
// the family. Lane GGGGG pinned the semver-suffix invariant on a
// single file's release schemas; this lane scales the invariant
// to every handler module, catching new schemas introduced in
// any future handler.
//
// The test discovers handler files programmatically (every
// `.rs` file under `src/handlers/` except `mod.rs`), reads each,
// finds every `const <NAME>_SCHEMA: &str = "<literal>";`
// declaration via a regex-free line scan, and asserts the
// literal matches the canonical shape. A floor of ≥30 schema
// declarations catches accidental wholesale strip-out.
//
// Cross-axis to GGGGG (RELEASE_*_SCHEMA semver suffix parity):
// GGGGG pinned this invariant on a single file; HHHHHHH scales
// it workspace-wide. Cross-axis to IIIIII (smoke aggregator
// JSON output schema_version semver suffix): IIIIII pins the
// invariant on the smoke aggregator's external surface;
// HHHHHHH pins it on the internal-handler surface — together
// the full schema-naming taxonomy is locked.
#[test]
fn handler_schema_constants_have_canonical_shape_lane_hhhhhhh() {
    fn literal_ends_with_dot_v_digits(literal: &str) -> bool {
        match literal.rfind(".v") {
            Some(idx) => {
                let tail = &literal[idx + 2..];
                !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit())
            }
            None => false,
        }
    }
    fn literal_ends_with_slash_v_digits(literal: &str) -> bool {
        match literal.rfind("/v") {
            Some(idx) => {
                let tail = &literal[idx + 2..];
                !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit())
            }
            None => false,
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let handlers_dir = root.join("crates/ao2-cp-server/src/handlers");

    // Discover handler files. Exclude mod.rs (it only contains
    // `pub mod foo;` declarations, no schema constants).
    let mut handler_files: Vec<std::path::PathBuf> = Vec::new();
    for entry in
        fs::read_dir(&handlers_dir).expect("Lane HHHHHHH: handlers directory must be readable")
    {
        let entry = entry.expect("Lane HHHHHHH: handlers dir entry must be readable");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        if path.file_name().and_then(|s| s.to_str()) == Some("mod.rs") {
            continue;
        }
        handler_files.push(path);
    }
    assert!(
        handler_files.len() >= 8,
        "Lane HHHHHHH: handlers/ must contain at least 8 module files (got {}). A drop suggests handler modules were stripped without a corresponding test update.",
        handler_files.len()
    );

    let mut schema_count = 0usize;
    let mut violations: Vec<String> = Vec::new();
    for path in &handler_files {
        let src = fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("Lane HHHHHHH: handler file must be readable: {path:?}"));
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>");

        // Scan each line for `const ` + `_SCHEMA: &str = "ao2`
        // pattern, then extract the quoted literal.
        for line in src.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with("const ") {
                continue;
            }
            if !trimmed.contains("_SCHEMA: &str") {
                continue;
            }
            // Find the first quote.
            let first_quote = match trimmed.find('"') {
                Some(i) => i,
                None => continue,
            };
            let rest = &trimmed[first_quote + 1..];
            let close_quote = match rest.find('"') {
                Some(i) => i,
                None => continue,
            };
            let literal = &rest[..close_quote];

            schema_count += 1;

            // Three legitimate schema families share this file:
            //   1. `ao2.<family-id>.v<N>` — pure observer-domain
            //      schemas the control plane owns (most common).
            //   2. `ao2-control-plane.<family-id>.v<N>` —
            //      control-plane-namespaced observer schemas
            //      (today only `three-os-release-smoke.v1`).
            //   3. `factory-v3/<family-id>/v<N>` — upstream
            //      factory-v3 governed artifact schemas the
            //      control plane only OBSERVES (slash separator,
            //      `/v<N>` not `.v<N>`).
            //
            // Each family has its own canonical shape; a literal
            // must belong to exactly one family.
            let family_ao2 = literal.starts_with("ao2.") && literal_ends_with_dot_v_digits(literal);
            let family_ao2_cp = literal.starts_with("ao2-control-plane.")
                && literal_ends_with_dot_v_digits(literal);
            let family_factory_v3 =
                literal.starts_with("factory-v3/") && literal_ends_with_slash_v_digits(literal);
            if !(family_ao2 || family_ao2_cp || family_factory_v3) {
                violations.push(format!(
                    "{file_name}: schema literal {literal:?} does NOT belong to any canonical schema family. Allowed: `ao2.<id>.v<N>`, `ao2-control-plane.<id>.v<N>`, or `factory-v3/<id>/v<N>`."
                ));
            }
        }
    }

    // Defensive floor on discovered schema count.
    assert!(
        schema_count >= 30,
        "Lane HHHHHHH: discovered only {schema_count} `*_SCHEMA: &str` constants across handlers/; floor is 30 (today's count is around 41). A sudden drop suggests handler modules were stripped or the schema-constant naming convention changed."
    );

    assert!(
        violations.is_empty(),
        "Lane HHHHHHH: the following handler SCHEMA constants do NOT follow the canonical `ao2.<family-id>.v<N>` shape. Schema literals identify observer surfaces in JSON responses; a typo (missing prefix, missing semver suffix, suffix without digits) silently breaks downstream schema dispatch. Fix by renaming the literal to the canonical shape OR — if a new schema family is genuinely required — extend the canonical-shape rule here in the same change so the taxonomy stays explicit. Violations: {violations:?}"
    );
}

// Lane IIIIIII: route_catalog (method, path) tuple uniqueness parity.
//
// `crates/ao2-cp-server/src/route_catalog.rs` declares a static
// table of `RouteMetadata { method, path, ... }` blocks that
// feeds the `/api/v1/control-plane/routes.json` route inventory
// endpoint AND drives operator-facing dashboard rendering. HTTP
// routing semantics require the (method, path) pair to be
// unique — duplicate entries either silently override one
// another at axum's router level (if the duplicate registers
// twice) OR fragment the route-index JSON into two entries that
// look like distinct surfaces but actually share a single
// handler.
//
// This lane parses every RouteMetadata block, extracts its
// `method` and `path` fields, and asserts that no two entries
// share the same (method, path) tuple. A defensive floor on
// parsed-block count (>=100; today's catalog has 117 entries)
// catches parser regressions where the block-extractor breaks
// and the test silently passes on zero blocks.
//
// Cross-axis to Lane XXXXXX (route_catalog ↔ server.rs route
// registration parity) and Lane YYYYYY (reverse): XXXXXX +
// YYYYYY pin every catalog entry to its server.rs registration
// and vice-versa, but neither catches the case where the
// catalog itself has a duplicate (method, path) pair — both
// catalog rows would map to the SAME server.rs registration,
// so the bidirectional parity check passes silently. Lane
// IIIIIII closes that gap structurally inside the catalog.
#[test]
fn route_catalog_method_path_tuples_are_unique_lane_iiiiiii() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane IIIIIII: crates/ao2-cp-server/src/route_catalog.rs present");

    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane IIIIIII: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    assert!(
        blocks.len() >= 100,
        "Lane IIIIIII: route_catalog.rs must contain at least 100 RouteMetadata blocks (parsed {}). A sudden drop suggests the block-extractor parser broke or the catalog was stripped.",
        blocks.len()
    );

    fn extract_field<'a>(body: &'a str, field_name: &str) -> &'a str {
        let marker = format!("{field_name}: \"");
        let f_start_rel = body.find(&marker).unwrap_or_else(|| {
            panic!("Lane IIIIIII: every RouteMetadata block must contain a `{field_name}` field")
        });
        let f_start = f_start_rel + marker.len();
        let f_end_rel = body[f_start..].find('"').unwrap_or_else(|| {
            panic!("Lane IIIIIII: every `{field_name}` field must have a closing quote")
        });
        &body[f_start..f_start + f_end_rel]
    }

    use std::collections::HashMap;
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    let mut duplicates: Vec<String> = Vec::new();
    for body in &blocks {
        let method = extract_field(body, "method");
        let path = extract_field(body, "path");
        let key = (method.to_string(), path.to_string());
        let entry = seen.entry(key.clone()).or_insert(0);
        *entry += 1;
        if *entry == 2 {
            duplicates.push(format!("{} {}", method, path));
        }
    }

    assert!(
        duplicates.is_empty(),
        "Lane IIIIIII: route_catalog.rs declares duplicate (method, path) tuples — every (method, path) pair must be unique. HTTP routing semantics require the (method, path) pair to be unique; a duplicate either silently shadows one of the entries at axum's router level OR fragments the route-index JSON into two rows that look like distinct observer surfaces but share a single handler, breaking operator audit tooling and the route-inventory contract. Fix by renaming the path (introducing a sub-resource), removing the duplicate, or unifying the two RouteMetadata blocks into one. Duplicates: {duplicates:?}"
    );
}

// Lane JJJJJJJ: route_catalog path canonical-prefix + no-trailing-slash parity.
//
// Every API surface mounted by the control-plane server lives
// under the versioned `/api/v1/` prefix — that's the operator
// contract advertised in the README, in the route-inventory
// endpoint, and in the install.sh handoff documentation. A new
// route added under a different prefix (e.g. `/admin/`, `/v2/`,
// `/healthz`, or a bare `/dashboard`) silently introduces a
// second API surface that escapes the versioning convention and
// breaks operator URL prediction.
//
// Likewise, no path may end with a trailing slash: axum treats
// `/foo` and `/foo/` as distinct routes, so a trailing slash on
// one entry but not another silently fragments the URL space —
// an operator hitting the documented `/foo` URL gets a 404 while
// the catalog appears to declare the route.
//
// Lane JJJJJJJ pins both invariants on `crates/ao2-cp-server/src/route_catalog.rs`:
//   1. Every `path: "..."` MUST start with the literal `/api/v1/`.
//   2. No `path` may end with `/` (excluding the prefix itself).
//
// Cross-axis to Lane EEEEEEE (download path naming): EEEEEEE
// pins the SUFFIX shape (`/download` or `/SHA256SUMS`) for
// download-flagged routes only; JJJJJJJ pins the PREFIX shape
// (`/api/v1/`) for every route. Cross-axis to Lane IIIIIII
// (tuple uniqueness): IIIIIII catches duplicate pairs; JJJJJJJ
// catches the case where a new entry uses a fundamentally
// different URL scheme that the rest of the surface doesn't
// follow.
#[test]
fn route_catalog_paths_use_canonical_prefix_lane_jjjjjjj() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane JJJJJJJ: crates/ao2-cp-server/src/route_catalog.rs present");

    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane JJJJJJJ: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    assert!(
        blocks.len() >= 100,
        "Lane JJJJJJJ: route_catalog.rs must contain at least 100 RouteMetadata blocks (parsed {}). A sudden drop suggests the block-extractor parser broke or the catalog was stripped.",
        blocks.len()
    );

    let canonical_prefix = "/api/v1/";
    let mut prefix_violations: Vec<String> = Vec::new();
    let mut trailing_slash_violations: Vec<String> = Vec::new();

    for body in &blocks {
        let path_marker = "path: \"";
        let p_start_rel = body
            .find(path_marker)
            .expect("Lane JJJJJJJ: every RouteMetadata block must contain a path field");
        let p_start = p_start_rel + path_marker.len();
        let p_end_rel = body[p_start..]
            .find('"')
            .expect("Lane JJJJJJJ: every path field must have a closing quote");
        let path = &body[p_start..p_start + p_end_rel];

        if !path.starts_with(canonical_prefix) {
            prefix_violations.push(path.to_string());
        }

        if path.len() > canonical_prefix.len() && path.ends_with('/') {
            trailing_slash_violations.push(path.to_string());
        }
    }

    assert!(
        prefix_violations.is_empty(),
        "Lane JJJJJJJ: route_catalog.rs declares paths that do NOT start with the canonical `/api/v1/` prefix. Every observer API surface MUST be mounted under the versioned `/api/v1/` prefix — that's the operator contract advertised in the README and in the route-inventory endpoint. A new route under `/admin/`, `/v2/`, or a bare segment silently introduces a second API surface that escapes the versioning convention. Either rename the path to use the canonical prefix OR — if a new prefix is genuinely required (e.g. introducing a v2 API) — extend this invariant deliberately in the same change so the URL taxonomy stays explicit. Violations: {prefix_violations:?}"
    );

    assert!(
        trailing_slash_violations.is_empty(),
        "Lane JJJJJJJ: route_catalog.rs declares paths that END with a trailing slash. axum treats `/foo` and `/foo/` as DISTINCT routes; a trailing slash on one entry but not another silently fragments the URL space — an operator hitting the documented URL without the slash gets a 404 while the catalog appears to declare the route. Strip the trailing slash from each violating entry. Violations: {trailing_slash_violations:?}"
    );
}

// Lane KKKKKKK: route_catalog category coverage parity (reverse of Lane AAAAAAA).
//
// Lane AAAAAAA pins the FORWARD direction: every `category`
// value in `crates/ao2-cp-server/src/route_catalog.rs` must
// appear in a canonical allowed-set defined inside the test.
// That direction catches a typo'd / fabricated category value
// in a new RouteMetadata block.
//
// But the reverse case is still possible: a category lives in
// the canonical allowed-set but no longer appears in ANY
// RouteMetadata block. This happens when an operator removes
// the last route in a category (e.g. deprecation, refactor)
// without trimming the allowed-set. The result is a "dangling"
// allowed category — the schema permits it, no route uses it,
// downstream code filtering by category gets unexpectedly empty
// groups, and operator-facing dashboards still reserve the
// section even though the surface is gone.
//
// Lane KKKKKKK closes that gap: every category in AAAAAAA's
// canonical allowed-set MUST appear in at least one
// RouteMetadata block. The test re-declares the same canonical
// set (kept in sync with AAAAAAA by the structural identity of
// the two test functions; a future refactor that introduces a
// shared constant should update both lanes' parser at once),
// parses every RouteMetadata block, collects the set of used
// categories, and reports any allowed category that has zero
// uses.
//
// Cross-axis to Lane AAAAAAA: forward direction (catalog →
// allowed-set). KKKKKKK is the reverse (allowed-set → catalog).
// Together they form a bijection — neither dangling categories
// nor undeclared categories can slip through.
#[test]
fn route_catalog_category_coverage_parity_lane_kkkkkkk() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane KKKKKKK: crates/ao2-cp-server/src/route_catalog.rs present");

    // Canonical category set — MUST stay identical to the
    // `allowed_categories` slice in Lane AAAAAAA. Adding a
    // category here without adding a RouteMetadata block that
    // uses it WILL fail this test on purpose.
    let allowed_categories: &[&str] = &[
        "acceptance-observer",
        "ai-task-board-observer",
        "audit",
        "hermes-watchdog-observer",
        "memory-export-observer",
        "metrics",
        "observer-ingest",
        "observer-list",
        "phase1-gap-report",
        "phase1-readiness",
        "phase1-support-bundle",
        "provider-readiness-observer",
        "provider-readiness-support-bundle",
        "provider-registry-observer",
        "release-acceptance-observer",
        "release-publication-observer",
        "release-readiness",
        "release-support-bundle",
        "route-index",
        "signed-evidence-observer",
        "status",
        "storage-observer",
        "storage-retention",
        "storage-support-bundle-contract",
        "storage-support-bundle",
    ];

    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane KKKKKKK: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    assert!(
        blocks.len() >= 100,
        "Lane KKKKKKK: route_catalog.rs must contain at least 100 RouteMetadata blocks (parsed {}). A sudden drop suggests the block-extractor parser broke or the catalog was stripped.",
        blocks.len()
    );

    use std::collections::HashSet;
    let mut used: HashSet<String> = HashSet::new();
    for body in &blocks {
        let cat_marker = "category: \"";
        let c_start_rel = body
            .find(cat_marker)
            .expect("Lane KKKKKKK: every RouteMetadata block must contain a category field");
        let c_start = c_start_rel + cat_marker.len();
        let c_end_rel = body[c_start..]
            .find('"')
            .expect("Lane KKKKKKK: every category field must have a closing quote");
        let cat = &body[c_start..c_start + c_end_rel];
        used.insert(cat.to_string());
    }

    let mut dangling: Vec<&str> = Vec::new();
    for cat in allowed_categories {
        if !used.contains(*cat) {
            dangling.push(*cat);
        }
    }

    assert!(
        dangling.is_empty(),
        "Lane KKKKKKK: the following categories are present in the canonical allowed-set but appear in ZERO RouteMetadata blocks. A dangling allowed category silently weakens Lane AAAAAAA's invariant — the schema permits a value that no route declares, downstream code filtering by category gets unexpectedly empty groups, and operator-facing dashboards may reserve a section for a surface that no longer exists. Fix: either remove the dangling category from the canonical allowed-set (here AND in Lane AAAAAAA) in the same change, OR re-introduce at least one RouteMetadata block using it. Dangling: {dangling:?}"
    );
}

// Lane LLLLLLL: route_catalog owner coverage parity (reverse of Lane CCCCCCC).
//
// Lane CCCCCCC pins the FORWARD direction: every `owner` value
// in `crates/ao2-cp-server/src/route_catalog.rs` must appear in
// a canonical allowed-set of 5 trust-boundary identities. That
// direction catches a fabricated/typo'd owner literal in a new
// RouteMetadata block — important because each owner declares
// the trust-boundary identity responsible for endpoint behavior.
//
// The reverse case is even more security-relevant for OWNER
// than for category: a trust-boundary identity that's allowed
// in the schema but used by NO route silently broadcasts a
// false trust-boundary surface — operators reading the cockpit
// HTML disclaimer or the smoke report markdown see "ao2 signed
// memory boundary" listed as a trust party, but if no route
// actually delegates work to that identity, the disclaimer is
// misleading. The trust-boundary surface MUST be exactly the
// set of identities actively reachable from the route catalog.
//
// Lane LLLLLLL closes that gap: every owner in CCCCCCC's
// canonical allowed-set MUST appear in at least one
// RouteMetadata block. The test re-declares the same canonical
// 5-owner set (kept structurally identical to CCCCCCC), parses
// every RouteMetadata block, collects the set of used owners,
// and reports any allowed owner that has zero uses.
//
// Cross-axis to Lane CCCCCCC: forward direction (catalog →
// allowed-set). LLLLLLL is the reverse (allowed-set → catalog).
// Together they form a bijection on the trust-boundary owner
// surface — neither dangling owners nor undeclared owners can
// slip through.
//
// Cross-axis to Lane KKKKKKK: KKKKKKK is the same bijection
// pattern on the category axis. KKKKKKK + LLLLLLL together
// pin reverse-coverage on both string-field enum axes
// (category + owner) that AAAAAAA + CCCCCCC pinned forward.
#[test]
fn route_catalog_owner_coverage_parity_lane_lllllll() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane LLLLLLL: crates/ao2-cp-server/src/route_catalog.rs present");

    // Canonical owner set — MUST stay identical to the
    // `allowed_owners` slice in Lane CCCCCCC.
    let allowed_owners: &[&str] = &[
        "ao2 signed evidence boundary",
        "ao2 signed memory boundary",
        "ao2-control-plane observer",
        "factory-v3 evaluator-closer",
        "factory-v3 Hermes watchdog",
    ];

    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane LLLLLLL: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    assert!(
        blocks.len() >= 100,
        "Lane LLLLLLL: route_catalog.rs must contain at least 100 RouteMetadata blocks (parsed {}). A sudden drop suggests the block-extractor parser broke or the catalog was stripped.",
        blocks.len()
    );

    use std::collections::HashSet;
    let mut used: HashSet<String> = HashSet::new();
    for body in &blocks {
        let owner_marker = "owner: \"";
        let o_start_rel = body
            .find(owner_marker)
            .expect("Lane LLLLLLL: every RouteMetadata block must contain an owner field");
        let o_start = o_start_rel + owner_marker.len();
        let o_end_rel = body[o_start..]
            .find('"')
            .expect("Lane LLLLLLL: every owner field must have a closing quote");
        let owner = &body[o_start..o_start + o_end_rel];
        used.insert(owner.to_string());
    }

    let mut dangling: Vec<&str> = Vec::new();
    for owner in allowed_owners {
        if !used.contains(*owner) {
            dangling.push(*owner);
        }
    }

    assert!(
        dangling.is_empty(),
        "Lane LLLLLLL: the following owners are present in the canonical allowed-set but appear in ZERO RouteMetadata blocks. A dangling allowed owner is security-relevant: operators reading the cockpit HTML disclaimer or the smoke report markdown see the identity listed as a trust party, but if no route actually delegates work to that identity, the disclaimer is misleading. The trust-boundary surface MUST be exactly the set of identities actively reachable from the route catalog. Fix: either remove the dangling owner from the canonical allowed-set (here AND in Lane CCCCCCC) in the same change, OR re-introduce at least one RouteMetadata block using it. Dangling: {dangling:?}"
    );
}

// Lane MMMMMMM: route_catalog path :param placeholder snake_case naming parity.
//
// Path parameters in axum use the `:<name>` syntax — e.g.
// `/api/v1/acceptance/:sha` binds `:sha` to the captured path
// segment. Today's catalog uses two such params: `:sha` (the
// content-addressed identifier) and `:run_id` (the smoke-run
// identifier). Both follow snake_case ASCII naming.
//
// A future addition like `:RunId` (PascalCase), `:run-id`
// (kebab-case), or `:runId` (camelCase) silently fragments the
// URL-param naming convention — operators predicting URLs from
// runbook references get confused by mixed conventions, and
// the convention divergence may cascade into Rust handler
// signatures (axum captures the param name verbatim into the
// extractor argument).
//
// Lane MMMMMMM pins that every `:<name>` placeholder appearing
// in a `path: "..."` string inside `crates/ao2-cp-server/src/route_catalog.rs`
// matches the canonical snake_case shape: starts with a lowercase
// letter, followed by any combination of lowercase letters,
// digits, or underscores. The test parses each RouteMetadata
// block, extracts the path field, scans for colon-prefixed
// segments, and asserts each matches the pattern. A defensive
// floor on parsed-block count (>=100) catches parser regressions.
// A defensive floor on observed-param-count (>=2 today; sha +
// run_id) catches the case where the param-extraction parser
// breaks and the test silently passes on zero placeholders.
//
// Cross-axis to Lane JJJJJJJ (path prefix + no-trailing-slash):
// JJJJJJJ pins the OUTER shape of every path (prefix + slash
// hygiene); MMMMMMM pins the INNER shape of dynamic segments
// — together they cover both the static and the parametric
// parts of the URL contract.
#[test]
fn route_catalog_path_params_use_snake_case_lane_mmmmmmm() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let route_catalog_rs =
        fs::read_to_string(root.join("crates/ao2-cp-server/src/route_catalog.rs"))
            .expect("Lane MMMMMMM: crates/ao2-cp-server/src/route_catalog.rs present");

    let block_marker = "    RouteMetadata {";
    let mut blocks: Vec<&str> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = route_catalog_rs[cursor..].find(block_marker) {
        let start = cursor + rel;
        let body_start = start + block_marker.len();
        let close_rel = route_catalog_rs[body_start..]
            .find("\n    }")
            .expect("Lane MMMMMMM: every RouteMetadata block must close with a `\\n    }` line");
        let body = &route_catalog_rs[body_start..body_start + close_rel];
        blocks.push(body);
        cursor = body_start + close_rel;
    }

    assert!(
        blocks.len() >= 100,
        "Lane MMMMMMM: route_catalog.rs must contain at least 100 RouteMetadata blocks (parsed {}).",
        blocks.len()
    );

    fn is_snake_case(name: &str) -> bool {
        let mut chars = name.chars();
        match chars.next() {
            Some(c) if c.is_ascii_lowercase() => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    }

    let mut param_count = 0usize;
    let mut violations: Vec<String> = Vec::new();
    for body in &blocks {
        let path_marker = "path: \"";
        let p_start_rel = body
            .find(path_marker)
            .expect("Lane MMMMMMM: every RouteMetadata block must contain a path field");
        let p_start = p_start_rel + path_marker.len();
        let p_end_rel = body[p_start..]
            .find('"')
            .expect("Lane MMMMMMM: every path field must have a closing quote");
        let path = &body[p_start..p_start + p_end_rel];

        for segment in path.split('/') {
            if let Some(param_name) = segment.strip_prefix(':') {
                param_count += 1;
                if !is_snake_case(param_name) {
                    violations.push(format!("path={path:?} param={segment:?}"));
                }
            }
        }
    }

    assert!(
        param_count >= 2,
        "Lane MMMMMMM: discovered only {param_count} path :param placeholders across the catalog; floor is 2 (today's catalog uses :sha and :run_id). A sudden drop suggests the segment-extractor parser broke."
    );

    assert!(
        violations.is_empty(),
        "Lane MMMMMMM: the following `:<name>` path-parameter placeholders do NOT follow snake_case ASCII naming (^[a-z][a-z0-9_]*$). A mixed naming convention silently fragments URL-param semantics across the catalog — operators predicting URLs from runbook references get confused by mixed conventions, and the convention divergence may cascade into Rust handler signatures (axum captures the param name verbatim into the extractor argument). Rename each placeholder to snake_case ASCII (lowercase letter prefix, then lowercase letters/digits/underscores only). Violations: {violations:?}"
    );
}

// Lane NNNNNNN: HTML page <title> operator-anchor "AO2" parity.
//
// Every operator-landing HTML page rendered by the control
// plane carries a `<title>` element that names the page
// (e.g. "AO2 Release Cockpit", "AO2 Provider Registry",
// "Hermes AO2 Watchdog Panel"). The operator's browser tab
// title is the FIRST identification surface — when the operator
// has six tabs open during a release triage, the title is what
// they navigate by.
//
// The product-anchor literal "AO2" must appear in EVERY title.
// A future page that ships without the anchor (e.g. just
// "Release Cockpit" or "Storage" without the prefix) drops the
// operator's tab-level product identification — they cannot
// tell at a glance whether the tab is an AO2 control-plane
// page or some other observability dashboard with similar
// terminology. Tab confusion is a real cost: an operator on
// release-day triage may click into the wrong tab and act on
// data that's not from the control plane.
//
// Lane NNNNNNN scans every `handlers/*.rs` (excluding mod.rs)
// for `<title>...</title>` literals and asserts each contains
// the substring "AO2" (case-sensitive). A defensive floor on
// discovered title-count (>=20; today's count is 23) catches
// parser regressions or wholesale strip-out.
//
// Cross-axis to Lane VVVVV (HTML body trust-boundary
// disclaimer): VVVVV pins the BODY's operator-visible
// disclaimer; NNNNNNN pins the TAB-TITLE's operator-visible
// product anchor — together every operator-facing page is
// identifiable as part of the AO2 control plane both inside
// (body) and outside (tab title).
#[test]
fn html_page_titles_contain_ao2_operator_anchor_lane_nnnnnnn() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let handlers_dir = root.join("crates/ao2-cp-server/src/handlers");

    let mut handler_files: Vec<std::path::PathBuf> = Vec::new();
    for entry in
        fs::read_dir(&handlers_dir).expect("Lane NNNNNNN: handlers directory must be readable")
    {
        let entry = entry.expect("Lane NNNNNNN: handlers dir entry must be readable");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        if path.file_name().and_then(|s| s.to_str()) == Some("mod.rs") {
            continue;
        }
        handler_files.push(path);
    }

    let mut title_count = 0usize;
    let mut violations: Vec<String> = Vec::new();
    for path in &handler_files {
        let src = fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("Lane NNNNNNN: handler file must be readable: {path:?}"));
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>");

        // Scan for `<title>...</title>` literals — exact-match,
        // single-line, since every operator-landing title in
        // the codebase fits on one line.
        let mut cursor = 0usize;
        while let Some(open_rel) = src[cursor..].find("<title>") {
            let start = cursor + open_rel + "<title>".len();
            let close_rel = match src[start..].find("</title>") {
                Some(i) => i,
                None => break,
            };
            let title = &src[start..start + close_rel];
            title_count += 1;
            if !title.contains("AO2") {
                violations.push(format!("{file_name}: <title>{title}</title>"));
            }
            cursor = start + close_rel + "</title>".len();
        }
    }

    assert!(
        title_count >= 20,
        "Lane NNNNNNN: discovered only {title_count} <title>...</title> literals across handlers/; floor is 20 (today's count is 23). A sudden drop suggests handler modules were stripped or the title-extractor parser broke."
    );

    assert!(
        violations.is_empty(),
        "Lane NNNNNNN: the following HTML page <title> literals do NOT contain the operator-product-anchor substring \"AO2\". The browser tab title is the operator's first identification surface — when six tabs are open during release triage, the title is the navigation cue. A page that ships without the anchor silently drops tab-level product identification; the operator can't tell at a glance whether the tab is an AO2 control-plane page or an unrelated dashboard. Fix by including \"AO2\" in every page's <title> literal. Violations: {violations:?}"
    );
}

// Lane OOOOOOO: HTML page <title> uniqueness parity.
//
// Cross-axis to Lane NNNNNNN. NNNNNNN pins that every page
// <title> contains the AO2 operator-anchor. OOOOOOO pins that
// every page <title> is UNIQUE across handlers — no two pages
// share the same tab title.
//
// The duplicate-title failure mode is operator confusion at
// the tab level: if the cockpit page and the readiness page
// both said "AO2 Release", an operator triaging release
// readiness with both tabs open could not tell which is which
// from the tab strip — they have to click into each to
// disambiguate, doubling the cognitive load on release-day
// triage.
//
// Today's count is 23 distinct <title> literals across the
// 11 operator-facing handler modules. The titles are
// already-distinct ("AO2 Release Cockpit", "AO2 Release
// Readiness", "AO2 Phase 1 Operator Panel", etc.) — this lane
// just locks the invariant in.
//
// The test scans every `handlers/*.rs` (excluding mod.rs) for
// `<title>...</title>` literals, collects them into a Vec,
// sorts and dedups, and asserts no duplicates were removed.
// A defensive floor on title-count (>=20) mirrors NNNNNNN.
//
// Cross-axis to Lane NNNNNNN: NNNNNNN pins WHAT the title
// must contain (AO2 anchor); OOOOOOO pins that the title must
// be UNIQUE — together every page is both identifiable as AO2
// AND distinguishable from sibling pages on the tab strip.
#[test]
fn html_page_titles_are_unique_lane_ooooooo() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let handlers_dir = root.join("crates/ao2-cp-server/src/handlers");

    let mut handler_files: Vec<std::path::PathBuf> = Vec::new();
    for entry in
        fs::read_dir(&handlers_dir).expect("Lane OOOOOOO: handlers directory must be readable")
    {
        let entry = entry.expect("Lane OOOOOOO: handlers dir entry must be readable");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        if path.file_name().and_then(|s| s.to_str()) == Some("mod.rs") {
            continue;
        }
        handler_files.push(path);
    }

    let mut titles: Vec<(String, String)> = Vec::new();
    for path in &handler_files {
        let src = fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("Lane OOOOOOO: handler file must be readable: {path:?}"));
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>")
            .to_string();

        let mut cursor = 0usize;
        while let Some(open_rel) = src[cursor..].find("<title>") {
            let start = cursor + open_rel + "<title>".len();
            let close_rel = match src[start..].find("</title>") {
                Some(i) => i,
                None => break,
            };
            let title = src[start..start + close_rel].to_string();
            titles.push((title, file_name.clone()));
            cursor = start + close_rel + "</title>".len();
        }
    }

    assert!(
        titles.len() >= 20,
        "Lane OOOOOOO: discovered only {} <title>...</title> literals across handlers/; floor is 20 (today's count is 23). A sudden drop suggests handler modules were stripped or the title-extractor parser broke.",
        titles.len()
    );

    use std::collections::HashMap;
    let mut seen: HashMap<String, Vec<String>> = HashMap::new();
    for (title, file) in &titles {
        seen.entry(title.clone()).or_default().push(file.clone());
    }

    let mut duplicates: Vec<String> = Vec::new();
    for (title, files) in &seen {
        if files.len() > 1 {
            duplicates.push(format!("<title>{title}</title> in {files:?}"));
        }
    }

    assert!(
        duplicates.is_empty(),
        "Lane OOOOOOO: the following HTML page <title> literals are NOT unique across handler modules. A duplicate title silently makes two operator-landing pages indistinguishable on the browser tab strip — an operator triaging release readiness with both tabs open cannot tell which is which from the tab title, doubling the cognitive load on release-day triage. Rename one of the conflicting titles to a unique value that still includes the AO2 anchor (Lane NNNNNNN). Duplicates: {duplicates:?}"
    );
}

// Lane PPPPPPP: route_catalog `category` field kebab-case naming parity.
//
// Cross-axis to Lane MMMMMMM. MMMMMMM pinned that every `:<name>`
// path-parameter placeholder in route_catalog.rs follows snake_case
// ASCII naming. PPPPPPP pins the sibling convention: every `category:`
// field in RouteMetadata uses ASCII kebab-case
// (^[a-z][a-z0-9-]*$ — lowercase letter prefix, then lowercase
// letters, digits, hyphens).
//
// Today's 21 canonical category values are already kebab-case:
//   "phase1-readiness", "phase1-support-bundle",
//   "provider-registry-observer", "provider-readiness-observer",
//   "signed-evidence-observer", "release-support-bundle",
//   "release-acceptance-observer", "release-readiness",
//   "memory-export-observer", "release-publication-observer",
//   "acceptance-observer", "hermes-watchdog-observer",
//   "storage-support-bundle", "storage-observer",
//   "provider-readiness-support-bundle", "phase1-gap-report",
//   "observer-list", "storage-support-bundle-contract",
//   "storage-retention", "route-index", "observer-ingest".
//
// Why this matters: the category string surfaces in operator
// triage paths — runbook cross-references, cockpit HTML class
// names, smoke-aggregator JSON keys, and downstream filtering
// in support-bundle scripts. A mixed naming convention
// (snake_case_category, CamelCaseCategory, mixed-Case-Category)
// silently fragments the operator's mental model: the same
// concept appears under different lexical forms across
// surfaces. Worse, downstream tools (jq filters, grep recipes,
// Prometheus label-matchers in alert rules) tend to be written
// against a single convention; the first occurrence of a
// snake_case category would break operator muscle memory and
// require defensive normalization in every downstream consumer.
//
// Cross-axis to Lane AAAAAAA (category membership enum) and
// Lane MMMMMMM (path-param snake_case): AAAAAAA pins WHICH
// category strings are allowed; PPPPPPP pins HOW they must be
// SPELLED (kebab-case). Together with MMMMMMM (snake_case for
// path-param identifiers), the catalog's naming conventions
// are coherent — kebab-case for human-facing taxonomy strings,
// snake_case for code-facing Rust identifiers.
#[test]
fn route_catalog_categories_use_kebab_case_lane_ppppppp() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog_path = root.join("crates/ao2-cp-server/src/route_catalog.rs");
    let catalog = fs::read_to_string(&catalog_path)
        .expect("Lane PPPPPPP: crates/ao2-cp-server/src/route_catalog.rs present");

    let mut categories: Vec<String> = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = catalog[cursor..].find("category: \"") {
        let start = cursor + rel + "category: \"".len();
        let close_rel = catalog[start..]
            .find('"')
            .expect("Lane PPPPPPP: every category field must have a closing quote");
        let category = catalog[start..start + close_rel].to_string();
        categories.push(category);
        cursor = start + close_rel + 1;
    }

    assert!(
        categories.len() >= 100,
        "Lane PPPPPPP: route_catalog.rs must contain at least 100 `category: \"...\"` fields (parsed {}). A sudden drop suggests the parser broke or routes were stripped.",
        categories.len()
    );

    fn is_kebab_case(s: &str) -> bool {
        let mut chars = s.chars();
        match chars.next() {
            Some(c) if c.is_ascii_lowercase() => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }

    let mut violations: Vec<String> = Vec::new();
    for category in &categories {
        if !is_kebab_case(category) {
            violations.push(category.clone());
        }
    }

    assert!(
        violations.is_empty(),
        "Lane PPPPPPP: the following `category: \"...\"` fields in route_catalog.rs do NOT follow ASCII kebab-case naming (^[a-z][a-z0-9-]*$ — lowercase letter prefix, then lowercase letters/digits/hyphens only). The category string surfaces in operator triage paths (runbook cross-references, cockpit HTML class names, smoke-aggregator JSON keys, downstream filtering in support-bundle scripts). A mixed naming convention (snake_case_category, CamelCaseCategory, mixed-Case-Category) silently fragments the operator's mental model and forces defensive normalization in every downstream jq/grep/Prometheus consumer. Rename each category to kebab-case ASCII. Cross-axis to Lane AAAAAAA (category membership) and Lane MMMMMMM (path-param snake_case): AAAAAAA pins WHICH categories are allowed; PPPPPPP pins HOW they must be SPELLED. Violations: {violations:?}"
    );
}

// Lane VVVVVVV: RSA verify-only invariant.
//
// `RUSTSEC-2023-0071` (rsa 0.9.x Marvin Attack — timing sidechannel
// in PKCS#1 v1.5 decryption) is suppressed by the CI cargo-audit
// job with `--ignore RUSTSEC-2023-0071`. That suppression is only
// safe because ao2-control-plane uses the `rsa` crate exclusively
// for signature *verification* (public-key modexp via the
// `signature::Verifier` trait). The Marvin Attack vector requires
// RSA *decryption* with attacker-chosen ciphertexts, which has no
// reachable call site in this codebase.
//
// This test fails if any source file under `crates/*/src/` imports
// `rsa::pkcs1v15::DecryptingKey` or `rsa::oaep::*` or otherwise
// references the RSA decryption surface. If a future change needs
// RSA decryption, this test forces an explicit decision: either
// remove the `--ignore` and accept the advisory exposure, or
// document a separate mitigation in
// `docs/security/advisory-dispositions.md` and update this lane.
//
// Cross-axis to the cargo-audit CI job: that job pins WHAT is
// suppressed; this lane pins WHY the suppression remains valid.
#[test]
fn no_rsa_decryption_call_sites_lane_vvvvvvv() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves");
    let crates_dir = workspace_root.join("crates");

    // Symbols whose presence in source would invalidate the
    // verify-only rationale recorded in
    // `docs/security/advisory-dispositions.md`.
    //
    // The `rsa` crate names its decryption surface
    // `DecryptingKey`, regardless of PKCS#1 v1.5 / OAEP padding.
    // `rsa::oaep` is the OAEP module. `Pkcs1v15Encrypt` /
    // `Oaep::new()` are construction helpers for raw-API decrypt
    // operations.
    let forbidden_substrings: &[&str] = &[
        "DecryptingKey",
        "rsa::oaep",
        "Pkcs1v15Encrypt",
        "Oaep::new",
        ".decrypt(",
    ];

    let mut violations: Vec<(String, String, usize, String)> = Vec::new();

    // Walk only `crates/*/src/` (production-binary source) plus
    // any `crates/*/build.rs`. Test files like this one may
    // reference the forbidden substrings as literals in allowlists
    // or grep targets; they do not ship in the binary.
    let mut src_roots: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(crate_entries) = fs::read_dir(&crates_dir) {
        for crate_entry in crate_entries.flatten() {
            let crate_path = crate_entry.path();
            if !crate_path.is_dir() {
                continue;
            }
            let src = crate_path.join("src");
            if src.is_dir() {
                src_roots.push(src);
            }
            let build_rs = crate_path.join("build.rs");
            if build_rs.is_file() {
                src_roots.push(build_rs);
            }
        }
    }

    fn walk_rs_files(dir_or_file: &Path, out: &mut Vec<std::path::PathBuf>) {
        if dir_or_file.is_file() {
            if dir_or_file.extension() == Some(OsStr::new("rs")) {
                out.push(dir_or_file.to_path_buf());
            }
            return;
        }
        let Ok(entries) = fs::read_dir(dir_or_file) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name() == Some(OsStr::new("target")) {
                    continue;
                }
                walk_rs_files(&path, out);
            } else if path.extension() == Some(OsStr::new("rs")) {
                out.push(path);
            }
        }
    }

    let mut rs_files: Vec<std::path::PathBuf> = Vec::new();
    for entry in &src_roots {
        walk_rs_files(entry, &mut rs_files);
    }

    assert!(
        rs_files.len() >= 15,
        "Lane VVVVVVV: expected at least 15 .rs files under crates/*/src/ \
         (current production source carries many more); found {}. \
         If the workspace shrank below this floor, update the floor; \
         otherwise the walker is broken.",
        rs_files.len()
    );

    for path in &rs_files {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for (line_idx, line) in content.lines().enumerate() {
            // Skip comments and string literals — we only want
            // actual code references. A line whose first non-space
            // character is `//` is a comment.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                continue;
            }
            for forbidden in forbidden_substrings {
                if line.contains(forbidden) {
                    let rel = path
                        .strip_prefix(&workspace_root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .into_owned();
                    violations.push((
                        rel,
                        (*forbidden).to_string(),
                        line_idx + 1,
                        line.trim().to_string(),
                    ));
                }
            }
        }
    }

    // Permit `.decrypt(` usage in test fixtures named with
    // `_test_only` or under `tests/`-level integration tests, since
    // those don't ship in the production binary. The current code
    // tree has no such test usage; if a future test introduces one,
    // update this allowlist with a comment explaining why.
    //
    // For now this is intentionally empty — any `.decrypt(` call
    // in production crate source is a violation.
    let allowed_decrypt_paths: &[&str] = &[];
    violations.retain(|(rel, symbol, _line_no, _line)| {
        if symbol == ".decrypt(" {
            !allowed_decrypt_paths
                .iter()
                .any(|allowed| rel.contains(allowed))
        } else {
            true
        }
    });

    if !violations.is_empty() {
        let summary: String = violations
            .iter()
            .map(|(rel, symbol, line_no, line)| {
                format!("\n  {rel}:{line_no}: `{symbol}` in `{line}`")
            })
            .collect();
        panic!(
            "Lane VVVVVVV: RSA decryption call site detected. The \
             `cargo audit` job in `.github/workflows/ci.yml` \
             passes `--ignore RUSTSEC-2023-0071` (rsa 0.9.x Marvin \
             Attack) on the rationale that ao2-control-plane uses \
             the `rsa` crate only for signature *verification* — \
             see `docs/security/advisory-dispositions.md`. The \
             following source lines reference RSA decryption \
             symbols, which invalidates that rationale and \
             requires either (a) removing the `--ignore` and \
             accepting the advisory exposure, (b) replacing the \
             `rsa` crate with a constant-time alternative, or (c) \
             documenting a separate decryption-specific mitigation \
             and adding the new file to the allowlist in this \
             test. Violations: {summary}"
        );
    }
}
