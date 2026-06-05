use std::process::Command;

/// Probe for `pwsh` (PowerShell 7+) and decide whether a cross-OS PowerShell
/// verifier check should run.
///
/// Returns `true` when `pwsh` is on PATH and a version probe succeeds — the
/// caller should then execute its `pwsh -File ...` assertions.
///
/// Returns `false` when `pwsh` is absent or the probe fails. By default the
/// helper logs an `eprintln!` skip notice so the missing coverage is visible
/// in `cargo test` output; the caller continues with the rest of its test.
///
/// When the environment variable `AO2_CP_REQUIRE_PWSH=1` is set, a missing
/// or broken `pwsh` panics instead of skipping. Use this at the release
/// gate (and on any host that's *expected* to have PowerShell installed —
/// CI Windows runners, dedicated cross-OS smoke hosts) so silent skips do
/// not hide regressions in `Verify-ReleaseSupportBundle.ps1` parity. The PS
/// 5.1 quirks discovered in May 2026 on `win-hp255-direct` (empty
/// `PSCustomObject` phantom property; `ConvertTo-Json` HTML-escaping
/// `<>&'`; `[AllowNull()]` missing on the canonical-JSON entry point) all
/// lived undetected because every existing pwsh probe skipped silently on
/// Mac/Ubuntu dev hosts.
pub fn pwsh_available_or_skip(context: &str) -> bool {
    let probe = Command::new("pwsh")
        .arg("-NoProfile")
        .arg("-Command")
        .arg("$PSVersionTable.PSVersion.Major")
        .output();
    let required = std::env::var("AO2_CP_REQUIRE_PWSH")
        .map(|v| v == "1")
        .unwrap_or(false);
    match probe {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            if required {
                panic!(
                    "AO2_CP_REQUIRE_PWSH=1 but pwsh probe failed (status {:?}) for {context}",
                    out.status
                );
            }
            eprintln!(
                "skipping {context}: pwsh probe failed (status {:?}); set AO2_CP_REQUIRE_PWSH=1 to fail loudly",
                out.status
            );
            false
        }
        Err(e) => {
            if required {
                panic!("AO2_CP_REQUIRE_PWSH=1 but pwsh not on PATH for {context}: {e}");
            }
            eprintln!(
                "skipping {context}: pwsh not on PATH ({e}); set AO2_CP_REQUIRE_PWSH=1 to fail loudly"
            );
            false
        }
    }
}
