$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location -LiteralPath $Root

$Archive = if ($env:AO2_CP_ARCHIVE) { $env:AO2_CP_ARCHIVE } else { "dist/ao2-control-plane-0.1.14-windows-x86_64.tar.gz" }
$SmokeRoot = if ($env:AO2_CP_SMOKE_ROOT) { $env:AO2_CP_SMOKE_ROOT } else { Join-Path $Root ("target/release-smoke/" + (Get-Date -Format "yyyyMMddHHmmss")) }
$SmokeJson = if ($env:AO2_CP_SMOKE_JSON) { $env:AO2_CP_SMOKE_JSON } else { $null }
$ReleasePublication = if ($env:AO2_CP_RELEASE_PUBLICATION) { $env:AO2_CP_RELEASE_PUBLICATION } else { Join-Path $Root "tests/fixtures/ao2-release-publication-v0.4.79.json" }
$ApiToken = if ($env:AO2_CP_API_TOKEN) { $env:AO2_CP_API_TOKEN } else { "smoke-token-" + ([guid]::NewGuid().ToString("N").Substring(0, 32)) }
function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), 0)
    try {
        $listener.Start()
        return $listener.LocalEndpoint.Port
    } finally {
        $listener.Stop()
    }
}
$Port = if ($env:AO2_CP_PORT) { [int]$env:AO2_CP_PORT } else { Get-FreeTcpPort }
$EXPECTED_MANIFEST_SCHEMA = "ao2.cp-release-support-bundle-manifest.v1"

if (!(Test-Path -LiteralPath $Archive)) {
    throw "missing ao2-control-plane release archive: $Archive"
}
if (!(Test-Path -LiteralPath $ReleasePublication)) {
    throw "missing AO2 release-publication fixture: $ReleasePublication"
}

$Extract = Join-Path $SmokeRoot "extract"
$InstallDir = Join-Path $SmokeRoot "bin"
$DataDir = Join-Path $SmokeRoot "data"
New-Item -ItemType Directory -Force -Path $Extract, $InstallDir, $DataDir | Out-Null

tar -xzf $Archive -C $Extract
if ($LASTEXITCODE -ne 0) { throw "tar extraction failed for $Archive" }

$ManifestPath = Join-Path $Extract "RELEASE-MANIFEST.json"
$Manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
if ($Manifest.schema_version -ne "ao2-control-plane.release-manifest.v1") { throw "unexpected manifest schema: $($Manifest.schema_version)" }
if ($Manifest.binary -ne "ao2-cp-server.exe") { throw "expected Windows binary ao2-cp-server.exe, got $($Manifest.binary)" }
if ($Manifest.binary_path -ne "bin/ao2-cp-server.exe") { throw "unexpected binary path $($Manifest.binary_path)" }

$env:AO2_CP_INSTALL_DIR = $InstallDir
& (Join-Path $Extract "install.ps1") | Out-Null
$ServerExe = Join-Path $InstallDir "ao2-cp-server.exe"
& $ServerExe --help | Out-Null
if ($LASTEXITCODE -ne 0) { throw "installed server --help failed" }

$oldOpenAi = $env:OPENAI_API_KEY
$oldAnthropic = $env:ANTHROPIC_API_KEY
$oldToken = $env:AO2_CP_API_TOKEN
$oldBind = $env:AO2_CP_BIND
$oldData = $env:AO2_CP_DATA_DIR
$proc = $null
try {
    Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:ANTHROPIC_API_KEY -ErrorAction SilentlyContinue
    $env:AO2_CP_API_TOKEN = $ApiToken
    $env:AO2_CP_BIND = "127.0.0.1:$Port"
    $env:AO2_CP_DATA_DIR = $DataDir
    $proc = Start-Process -FilePath $ServerExe -PassThru -WindowStyle Hidden

    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        try {
            Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -Method Get -TimeoutSec 2 | Out-Null
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (!$ready) { throw "server did not become healthy on port $Port" }

    $headers = @{ Authorization = "Bearer $ApiToken" }
    $jsonHeaders = @{ Authorization = "Bearer $ApiToken"; "Content-Type" = "application/json" }
    $CodexFixture = Join-Path $Root "tests/fixtures/codex-acceptance-v0.4.66.json"
    $ClaudeFixture = Join-Path $Root "tests/fixtures/claude-acceptance-v0.4.66.json"

    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/acceptance" -Method Post -Headers $jsonHeaders -InFile $CodexFixture -OutFile (Join-Path $SmokeRoot "codex-receipt.json") | Out-Null
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/acceptance" -Method Post -Headers $jsonHeaders -InFile $ClaudeFixture -OutFile (Join-Path $SmokeRoot "claude-receipt.json") | Out-Null
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/publication" -Method Post -Headers $jsonHeaders -InFile $ReleasePublication -OutFile (Join-Path $SmokeRoot "release-publication-receipt.json") | Out-Null

    $DashboardPath = Join-Path $SmokeRoot "acceptance-dashboard.json"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/acceptance/dashboard.json" -Method Get -Headers $headers -OutFile $DashboardPath | Out-Null
    $Dashboard = Get-Content -Raw -LiteralPath $DashboardPath | ConvertFrom-Json
    if ($Dashboard.schema_version -ne "ao2.cp-acceptance-dashboard.v1") { throw "unexpected dashboard schema: $($Dashboard.schema_version)" }
    if ($Dashboard.total_count -ne 2) { throw "expected total_count=2, got $($Dashboard.total_count)" }
    if ($Dashboard.source_class_counts.fixture -ne 2) { throw "expected fixture count=2, got $($Dashboard.source_class_counts.fixture)" }
    if ($Dashboard.source_class_counts.live -ne 0) { throw "expected live count=0, got $($Dashboard.source_class_counts.live)" }

    $SupportBundlePath = Join-Path $SmokeRoot "support-bundle.json"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/storage/support-bundle.json" -Method Get -Headers $headers -OutFile $SupportBundlePath | Out-Null
    $SupportBundle = Get-Content -Raw -LiteralPath $SupportBundlePath | ConvertFrom-Json
    if ($SupportBundle.schema_version -ne "ao2.cp-support-bundle.v1") { throw "unexpected support bundle schema: $($SupportBundle.schema_version)" }
    if ($SupportBundle.trust_boundary.role -ne "read_only_observer") { throw "unexpected support bundle role: $($SupportBundle.trust_boundary.role)" }
    if ($SupportBundle.trust_boundary.mutates_ao_artifacts -ne $false) { throw "support bundle must be read-only" }
    if ($SupportBundle.latest_index_entries.Count -ne 3) { throw "expected support bundle latest_index_entries=3, got $($SupportBundle.latest_index_entries.Count)" }
    if ($SupportBundle.operator_handoff.relative_endpoints.release_handoff -ne "/api/v1/release/handoff") { throw "support bundle missing release handoff link" }
    if ($SupportBundle.operator_handoff.relative_endpoints.release_readiness_json -ne "/api/v1/release/readiness.json") { throw "support bundle missing release readiness JSON link" }
    if ($SupportBundle.phase1_release_readiness.operator_links.release_handoff_json -ne "/api/v1/release/handoff.json") { throw "phase1 readiness missing release handoff JSON link" }
    if ($SupportBundle.phase1_release_readiness.operator_links.release_readiness -ne "/api/v1/release/readiness") { throw "phase1 readiness missing release readiness link" }
    if ($SupportBundle.phase1_release_readiness.observed_artifacts.release_publication.status -ne "published_verified") { throw "release publication not observed in support bundle" }

    $Phase1GapReportPath = Join-Path $SmokeRoot "phase1-gap-report.json"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/phase1/promotion/gap-report.json" -Method Get -Headers $headers -OutFile $Phase1GapReportPath | Out-Null
    $Phase1GapReport = Get-Content -Raw -LiteralPath $Phase1GapReportPath | ConvertFrom-Json
    if ($Phase1GapReport.schema_version -ne "ao2.cp-phase1-gap-report.v1") { throw "unexpected Phase 1 gap report schema: $($Phase1GapReport.schema_version)" }
    if ($Phase1GapReport.trust_boundary.role -ne "read_only_observer") { throw "unexpected Phase 1 gap report role: $($Phase1GapReport.trust_boundary.role)" }
    if ($Phase1GapReport.trust_boundary.mutates_ao_artifacts -ne $false) { throw "Phase 1 gap report must be read-only" }

    $ReleasePublicationDashboardPath = Join-Path $SmokeRoot "release-publication-dashboard.json"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/publication/dashboard.json" -Method Get -Headers $headers -OutFile $ReleasePublicationDashboardPath | Out-Null
    $ReleasePublicationDashboard = Get-Content -Raw -LiteralPath $ReleasePublicationDashboardPath | ConvertFrom-Json
    if ($ReleasePublicationDashboard.schema_version -ne "ao2.cp-release-publication-dashboard.v1") { throw "unexpected release publication dashboard schema: $($ReleasePublicationDashboard.schema_version)" }
    if ($ReleasePublicationDashboard.state -ne "release_published_verified") { throw "unexpected release publication state: $($ReleasePublicationDashboard.state)" }
    if ($ReleasePublicationDashboard.latest.release_tag -ne "v0.4.79") { throw "unexpected release publication tag: $($ReleasePublicationDashboard.latest.release_tag)" }
    if ($ReleasePublicationDashboard.trust_boundary.role -ne "read_only_observer") { throw "release publication dashboard must be read-only" }
    $PublicationCorrelationStatus = [string]$ReleasePublicationDashboard.candidate_correlation.status
    if (-not @("matched","mismatched","missing") -contains $PublicationCorrelationStatus) { throw "release publication dashboard candidate_correlation.status unexpected: $PublicationCorrelationStatus" }
    if ($null -eq $ReleasePublicationDashboard.candidate_correlation.blockers) { throw "release publication dashboard candidate_correlation missing blockers" }
    $ReleasePublicationDashboardHtmlPath = Join-Path $SmokeRoot "release-publication-dashboard.html"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/publication/dashboard" -Method Get -Headers $headers -OutFile $ReleasePublicationDashboardHtmlPath | Out-Null
    $ReleasePublicationDashboardHtml = Get-Content -Raw -LiteralPath $ReleasePublicationDashboardHtmlPath
    if (-not $ReleasePublicationDashboardHtml.Contains("AO2 Release Publication")) { throw "release publication dashboard HTML missing title" }

    $ReleaseCockpitPath = Join-Path $SmokeRoot "release-cockpit.json"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/cockpit.json" -Method Get -Headers $headers -OutFile $ReleaseCockpitPath | Out-Null
    $ReleaseCockpit = Get-Content -Raw -LiteralPath $ReleaseCockpitPath | ConvertFrom-Json
    if ($ReleaseCockpit.schema_version -ne "ao2.cp-release-cockpit.v1") { throw "unexpected release cockpit schema: $($ReleaseCockpit.schema_version)" }
    if ($ReleaseCockpit.surfaces.release_publication.state -ne "release_published_verified") { throw "unexpected release cockpit publication state: $($ReleaseCockpit.surfaces.release_publication.state)" }
    if ($ReleaseCockpit.surfaces.release_publication.release_tag -ne "v0.4.79") { throw "unexpected release cockpit tag: $($ReleaseCockpit.surfaces.release_publication.release_tag)" }
    if ($ReleaseCockpit.trust_boundary.role -ne "read_only_observer") { throw "release cockpit must be read-only" }
    $CockpitCorrelationStatus = [string]$ReleaseCockpit.candidate_correlation.status
    if (-not @("matched","mismatched","missing") -contains $CockpitCorrelationStatus) { throw "release cockpit candidate_correlation.status unexpected: $CockpitCorrelationStatus" }
    if ($null -eq $ReleaseCockpit.candidate_correlation.blockers) { throw "release cockpit candidate_correlation missing blockers" }
    $ReleaseCockpitHtmlPath = Join-Path $SmokeRoot "release-cockpit.html"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/cockpit" -Method Get -Headers $headers -OutFile $ReleaseCockpitHtmlPath | Out-Null
    $ReleaseCockpitHtml = Get-Content -Raw -LiteralPath $ReleaseCockpitHtmlPath
    if (-not $ReleaseCockpitHtml.Contains("AO2 Release Cockpit")) { throw "release cockpit HTML missing title" }

    $ReleaseHandoffPath = Join-Path $SmokeRoot "release-handoff.json"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/handoff.json" -Method Get -Headers $headers -OutFile $ReleaseHandoffPath | Out-Null
    $ReleaseHandoff = Get-Content -Raw -LiteralPath $ReleaseHandoffPath | ConvertFrom-Json
    if ($ReleaseHandoff.schema_version -ne "ao2.cp-release-candidate-handoff.v1") { throw "unexpected release handoff schema: $($ReleaseHandoff.schema_version)" }
    if ($ReleaseHandoff.operator_handoff.control_plane_role -ne "read_only_observer") { throw "unexpected release handoff role: $($ReleaseHandoff.operator_handoff.control_plane_role)" }
    if ($ReleaseHandoff.operator_handoff.mutates_ao_artifacts -ne $false) { throw "release handoff must be read-only" }
    if ($ReleaseHandoff.links.release_candidate_handoff -ne "/api/v1/release/handoff") { throw "release handoff missing HTML link" }
    if ($ReleaseHandoff.links.release_readiness_json -ne "/api/v1/release/readiness.json") { throw "release handoff missing release readiness JSON link" }
    $HandoffCorrelationStatus = [string]$ReleaseHandoff.candidate_correlation.status
    if (-not @("matched","mismatched","missing") -contains $HandoffCorrelationStatus) { throw "release handoff candidate_correlation.status unexpected: $HandoffCorrelationStatus" }
    if ($null -eq $ReleaseHandoff.candidate_correlation.blockers) { throw "release handoff candidate_correlation missing blockers" }

    $ReleaseHandoffHtmlPath = Join-Path $SmokeRoot "release-handoff.html"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/handoff" -Method Get -Headers $headers -OutFile $ReleaseHandoffHtmlPath | Out-Null
    $ReleaseHandoffHtml = Get-Content -Raw -LiteralPath $ReleaseHandoffHtmlPath
    if (-not $ReleaseHandoffHtml.Contains("AO2 Release Candidate Handoff")) { throw "release handoff HTML missing title" }

    $ReleaseReadinessPath = Join-Path $SmokeRoot "release-readiness.json"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/readiness.json" -Method Get -Headers $headers -OutFile $ReleaseReadinessPath | Out-Null
    $ReleaseReadiness = Get-Content -Raw -LiteralPath $ReleaseReadinessPath | ConvertFrom-Json
    if ($ReleaseReadiness.schema_version -ne "ao2.cp-release-readiness.v1") { throw "unexpected release readiness schema: $($ReleaseReadiness.schema_version)" }
    if ($ReleaseReadiness.operator_decision.factory_v3_evaluator_closer_required -ne $true) { throw "release readiness must require evaluator-closer" }
    if ($ReleaseReadiness.operator_decision.control_plane_approves_release -ne $false) { throw "control plane must not approve release" }
    if ($ReleaseReadiness.install_verification.schema_version -ne "ao2.install-verification-evidence.v1") { throw "release readiness missing install verification schema" }
    if ($ReleaseReadiness.install_verification.status -ne "verified") { throw "release readiness install verification must be verified" }
    if ($ReleaseReadiness.install_verification.offline_verification_status -ne "verified") { throw "release readiness install offline verification must be verified" }
    if ($ReleaseReadiness.install_verification.provider_api_keys_required -ne $false) { throw "release readiness install verification must not require provider API keys" }
    if ($ReleaseReadiness.install_verification.control_plane_approves_release -ne $false) { throw "release readiness install verification must not approve release" }
    if ($ReleaseReadiness.install_verification.mutates_ao_artifacts -ne $false) { throw "release readiness install verification must not mutate AO artifacts" }
    $ReadinessCorrelationStatus = [string]$ReleaseReadiness.candidate_correlation.status
    if (-not @("matched","mismatched","missing") -contains $ReadinessCorrelationStatus) { throw "release readiness candidate_correlation.status unexpected: $ReadinessCorrelationStatus" }
    if ($null -eq $ReleaseReadiness.candidate_correlation.blockers) { throw "release readiness candidate_correlation missing blockers" }

    $ReleaseReadinessHtmlPath = Join-Path $SmokeRoot "release-readiness.html"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/readiness" -Method Get -Headers $headers -OutFile $ReleaseReadinessHtmlPath | Out-Null
    $ReleaseReadinessHtml = Get-Content -Raw -LiteralPath $ReleaseReadinessHtmlPath
    if (-not $ReleaseReadinessHtml.Contains("AO2 Release Readiness")) { throw "release readiness HTML missing title" }

    $ReleaseSupportBundlePath = Join-Path $SmokeRoot "release-support-bundle.json"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/support-bundle.json" -Method Get -Headers $headers -OutFile $ReleaseSupportBundlePath | Out-Null
    $ReleaseSupportBundle = Get-Content -Raw -LiteralPath $ReleaseSupportBundlePath | ConvertFrom-Json
    if ($ReleaseSupportBundle.schema_version -ne "ao2.cp-release-support-bundle.v1") { throw "unexpected release support bundle schema: $($ReleaseSupportBundle.schema_version)" }
    if ($ReleaseSupportBundle.bundle_kind -ne "portable_release_operator_handoff") { throw "unexpected release support bundle kind: $($ReleaseSupportBundle.bundle_kind)" }
    if ($ReleaseSupportBundle.trust_boundary.role -ne "read_only_observer") { throw "release support bundle must be read-only" }
    if ($ReleaseSupportBundle.trust_boundary.mutates_ao_artifacts -ne $false) { throw "release support bundle must not mutate AO artifacts" }
    if ($ReleaseSupportBundle.operator_handoff.release_acceptance_owner -ne "factory-v3 evaluator-closer") { throw "release support bundle must defer acceptance to evaluator-closer" }
    if ($ReleaseSupportBundle.release_assembly.schema_version -ne "ao2.cp-release-assembly.v1") { throw "release support bundle missing release assembly schema" }
    if ($ReleaseSupportBundle.release_assembly.control_plane_approves_release -ne $false) { throw "release support bundle assembly must not approve release" }
    if ($ReleaseSupportBundle.install_verification.schema_version -ne "ao2.install-verification-evidence.v1") { throw "release support bundle missing install verification schema" }
    if ($ReleaseSupportBundle.install_verification.status -ne "verified") { throw "release support bundle install verification must be verified" }
    if ($ReleaseSupportBundle.install_verification.offline_verification_status -ne "verified") { throw "release support bundle install offline verification must be verified" }
    $AssemblyCorrelationStatus = [string]$ReleaseSupportBundle.release_assembly.candidate_correlation_detail.status
    if (-not @("matched","mismatched","missing") -contains $AssemblyCorrelationStatus) { throw "release assembly candidate_correlation_detail.status unexpected: $AssemblyCorrelationStatus" }
    if ($null -eq $ReleaseSupportBundle.release_assembly.candidate_correlation_detail.blockers) { throw "release assembly candidate_correlation_detail missing blockers" }
    if ($ReleaseSupportBundle.portable_bundle_manifest.schema_version -ne $EXPECTED_MANIFEST_SCHEMA) { throw "release support bundle portable_bundle_manifest.schema_version expected $EXPECTED_MANIFEST_SCHEMA, got $($ReleaseSupportBundle.portable_bundle_manifest.schema_version)" }
    if (-not ($ReleaseSupportBundle.portable_bundle_manifest.included_surfaces | Where-Object { $_.id -eq "release_readiness" })) { throw "release support bundle missing readiness surface" }
    if (-not ($ReleaseSupportBundle.portable_bundle_manifest.included_surfaces | Where-Object { $_.id -eq "install_verification" -and $_.path -eq '$.install_verification' -and $_.schema_version -eq "ao2.install-verification-evidence.v1" })) { throw "release support bundle missing install verification surface" }
    if ($ReleaseSupportBundle.portable_bundle_manifest.integrity.algorithm -ne "sha256-ao2-cp-canonical-json-v1") { throw "release support bundle missing canonical digest algorithm" }
    if ($ReleaseSupportBundle.portable_bundle_manifest.integrity.scope -ne "embedded_support_bundle_surfaces") { throw "release support bundle integrity scope mismatch" }
    foreach ($SurfaceName in @("release_assembly", "release_readiness", "release_candidate_handoff", "release_cockpit", "install_verification", "storage_support_bundle")) {
        $Digest = $ReleaseSupportBundle.portable_bundle_manifest.integrity.surface_sha256.$SurfaceName
        if ($Digest -notmatch '^[0-9a-f]{64}$') { throw "release support bundle digest for $SurfaceName is not sha256 hex" }
    }

    $ReleaseSupportBundleDownloadPath = Join-Path $SmokeRoot "release-support-bundle-download.json"
    $ReleaseSupportBundleChecksumsPath = Join-Path $SmokeRoot "release-support-bundle-SHA256SUMS"
    $ReleaseSupportBundleOfflineVerifyPath = Join-Path $SmokeRoot "release-support-bundle-offline-verify.json"
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/support-bundle/download" -Method Get -Headers $headers -OutFile $ReleaseSupportBundleDownloadPath | Out-Null
    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/release/support-bundle/SHA256SUMS" -Method Get -Headers $headers -OutFile $ReleaseSupportBundleChecksumsPath | Out-Null
    & (Join-Path $Extract "Verify-ReleaseSupportBundle.ps1") -Path $ReleaseSupportBundleDownloadPath | Set-Content -Encoding UTF8 -LiteralPath $ReleaseSupportBundleOfflineVerifyPath
    if ($LASTEXITCODE -ne 0) { throw "offline release support bundle verifier failed" }
    $ReleaseSupportBundleOfflineVerify = Get-Content -Raw -LiteralPath $ReleaseSupportBundleOfflineVerifyPath | ConvertFrom-Json
    $ReleaseSupportBundleDownloadSha256 = [string]$ReleaseSupportBundleOfflineVerify.bundle_sha256
    $ReleaseSupportBundleChecksumsSha256 = $null
    foreach ($Line in Get-Content -LiteralPath $ReleaseSupportBundleChecksumsPath) {
        if ($Line.StartsWith("#") -or [string]::IsNullOrWhiteSpace($Line)) { continue }
        $Parts = $Line -split '\s+'
        if ($Parts.Count -ge 2 -and $Parts[1].StartsWith("ao2-release-support-bundle-")) {
            $ReleaseSupportBundleChecksumsSha256 = $Parts[0]
            break
        }
    }
    if ($ReleaseSupportBundleDownloadSha256 -ne $ReleaseSupportBundleChecksumsSha256) {
        throw "release support bundle checksum mismatch: verifier=$ReleaseSupportBundleDownloadSha256 checksums=$ReleaseSupportBundleChecksumsSha256"
    }

    # Lane OO: read the .source-commit record embedded in the source tarball
    # (or this checkout) so the per-target smoke JSON pins the source commit
    # the target actually built against. The orchestrator writes this file
    # before packaging; on a non-three-OS local run the file may not exist,
    # in which case the per-target fields stay empty. Future server-side
    # validation can then cross-check top-level == every per-target.
    $SourceCommitPath = Join-Path $Root ".source-commit"
    $SourceCommitAtTarget = ""
    $SourceDirtyAtTarget = ""
    $SourceCommitSchemaAtTarget = ""
    if (Test-Path -LiteralPath $SourceCommitPath -PathType Leaf) {
        try {
            $SourceCommitRecord = Get-Content -Raw -LiteralPath $SourceCommitPath | ConvertFrom-Json
            if ($null -ne $SourceCommitRecord.PSObject.Properties['source_commit']) {
                $SourceCommitAtTarget = [string]$SourceCommitRecord.source_commit
            }
            if ($null -ne $SourceCommitRecord.PSObject.Properties['source_dirty']) {
                $SourceDirtyAtTarget = if ($SourceCommitRecord.source_dirty) { "true" } else { "false" }
            }
            if ($null -ne $SourceCommitRecord.PSObject.Properties['schema']) {
                $SourceCommitSchemaAtTarget = [string]$SourceCommitRecord.schema
            }
        } catch {
            # Malformed .source-commit is non-fatal for the per-target smoke;
            # the field stays empty and any future server-side validation can
            # diagnose the missing value.
        }
    }

    $CandidateCorrelationStatus = $PublicationCorrelationStatus
    $SurfaceStatuses = @{
        release_cockpit = $CockpitCorrelationStatus
        release_candidate_handoff = $HandoffCorrelationStatus
        release_readiness = $ReadinessCorrelationStatus
        release_assembly = $AssemblyCorrelationStatus
    }
    foreach ($SurfaceName in $SurfaceStatuses.Keys) {
        $SurfaceStatus = $SurfaceStatuses[$SurfaceName]
        if ($SurfaceStatus -ne $CandidateCorrelationStatus) {
            throw "candidate_correlation status drift: dashboard=$CandidateCorrelationStatus $SurfaceName=$SurfaceStatus"
        }
    }

    # Lane II: emission-time internal-consistency guard. Re-derive the
    # trailer values from the source JSON files RIGHT BEFORE emission
    # so any in-process drift of $CandidateCorrelationStatus between
    # the initial computation/cross-surface check and the actual
    # trailer/JSON emission is caught. A corrupted run-state could
    # only fool the downstream aggregator if the source files
    # themselves disagreed, which the initial check already gates.
    # Lane II tightens that gate by re-fetching at the moment of
    # emission rather than trusting that the variable was not
    # clobbered between the two events.
    $CandidateCorrelationStatusEmission = [string](Get-Content -Raw -LiteralPath $ReleasePublicationDashboardPath | ConvertFrom-Json).candidate_correlation.status
    if ($CandidateCorrelationStatusEmission -ne $CandidateCorrelationStatus) {
        throw "candidate_correlation_status emission_time_drift: initial=$CandidateCorrelationStatus emission=$CandidateCorrelationStatusEmission"
    }
    $EmissionTimeSurfaces = @(
        [pscustomobject]@{ Path = $ReleaseCockpitPath; Field = 'candidate_correlation' },
        [pscustomobject]@{ Path = $ReleaseHandoffPath; Field = 'candidate_correlation' },
        [pscustomobject]@{ Path = $ReleaseReadinessPath; Field = 'candidate_correlation' },
        [pscustomobject]@{ Path = $ReleaseSupportBundlePath; Field = 'release_assembly_detail' }
    )
    foreach ($entry in $EmissionTimeSurfaces) {
        $emissionJson = Get-Content -Raw -LiteralPath $entry.Path | ConvertFrom-Json
        $emissionStatus = $null
        if ($entry.Field -eq 'release_assembly_detail') {
            $emissionStatus = [string]$emissionJson.release_assembly.candidate_correlation_detail.status
        } else {
            $emissionStatus = [string]$emissionJson.candidate_correlation.status
        }
        if ($emissionStatus -ne $CandidateCorrelationStatus) {
            throw "candidate_correlation_status emission_time_drift: initial=$CandidateCorrelationStatus $($entry.Path)=$emissionStatus"
        }
    }

    if ($SmokeJson) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $SmokeJson) | Out-Null
        [ordered]@{
            schema = "ao2-control-plane.release-smoke.v1"
            status = "passed"
            archive = $Archive
            smoke_root = $SmokeRoot
            smoke_port = $Port
            acceptance_dashboard = $DashboardPath
            dashboard_source_counts = $Dashboard.source_class_counts
            support_bundle = $SupportBundlePath
            support_bundle_schema = $SupportBundle.schema_version
            phase1_gap_report = $Phase1GapReportPath
            phase1_gap_report_schema = $Phase1GapReport.schema_version
            release_publication_fixture = $ReleasePublication
            release_publication_dashboard = $ReleasePublicationDashboardPath
            release_publication_dashboard_html = $ReleasePublicationDashboardHtmlPath
            release_publication_schema = $ReleasePublicationDashboard.schema_version
            release_publication_state = $ReleasePublicationDashboard.state
            release_publication_tag = $ReleasePublicationDashboard.latest.release_tag
            release_cockpit = $ReleaseCockpitPath
            release_cockpit_html = $ReleaseCockpitHtmlPath
            release_cockpit_schema = $ReleaseCockpit.schema_version
            release_cockpit_publication_state = $ReleaseCockpit.surfaces.release_publication.state
            release_handoff = $ReleaseHandoffPath
            release_handoff_html = $ReleaseHandoffHtmlPath
            release_handoff_schema = $ReleaseHandoff.schema_version
            release_readiness = $ReleaseReadinessPath
            release_readiness_html = $ReleaseReadinessHtmlPath
            release_readiness_schema = $ReleaseReadiness.schema_version
            release_readiness_status = $ReleaseReadiness.status
            release_support_bundle = $ReleaseSupportBundlePath
            release_support_bundle_download = $ReleaseSupportBundleDownloadPath
            release_support_bundle_checksums = $ReleaseSupportBundleChecksumsPath
            release_support_bundle_offline_verify = $ReleaseSupportBundleOfflineVerifyPath
            release_support_bundle_download_sha256 = $ReleaseSupportBundleDownloadSha256
            release_support_bundle_schema = $ReleaseSupportBundle.schema_version
            release_support_bundle_kind = $ReleaseSupportBundle.bundle_kind
            release_support_bundle_integrity_algorithm = $ReleaseSupportBundle.portable_bundle_manifest.integrity.algorithm
            release_assembly_status = $ReleaseSupportBundle.release_assembly.status
            release_assembly_candidate_correlation = $ReleaseSupportBundle.release_assembly.candidate_correlation
            candidate_correlation_status = $CandidateCorrelationStatus
            source_commit_at_target = $SourceCommitAtTarget
            source_dirty_at_target = $SourceDirtyAtTarget
            source_commit_schema_at_target = $SourceCommitSchemaAtTarget
        } | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -LiteralPath $SmokeJson
    }

    Write-Output "ao2_control_plane_release_smoke=passed"
    Write-Output "smoke_root=$SmokeRoot"
    Write-Output "smoke_port=$Port"
    Write-Output "acceptance_dashboard=$DashboardPath"
    Write-Output "support_bundle=$SupportBundlePath"
    Write-Output "phase1_gap_report=$Phase1GapReportPath"
    Write-Output "release_publication_dashboard=$ReleasePublicationDashboardPath"
    Write-Output "release_cockpit=$ReleaseCockpitPath"
    Write-Output "release_handoff=$ReleaseHandoffPath"
    Write-Output "release_readiness=$ReleaseReadinessPath"
    Write-Output "release_support_bundle=$ReleaseSupportBundlePath"
    Write-Output "release_support_bundle_download=$ReleaseSupportBundleDownloadPath"
    Write-Output "release_support_bundle_checksums=$ReleaseSupportBundleChecksumsPath"
    Write-Output "release_support_bundle_offline_verify=$ReleaseSupportBundleOfflineVerifyPath"
    Write-Output "release_support_bundle_download_sha256=$ReleaseSupportBundleDownloadSha256"
    Write-Output "candidate_correlation_status=$CandidateCorrelationStatus"
    Write-Output "source_commit_at_target=$SourceCommitAtTarget"
    Write-Output "source_dirty_at_target=$SourceDirtyAtTarget"
} finally {
    if ($proc -and !$proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        $proc.WaitForExit()
    }
    if ($null -ne $oldOpenAi) { $env:OPENAI_API_KEY = $oldOpenAi } else { Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue }
    if ($null -ne $oldAnthropic) { $env:ANTHROPIC_API_KEY = $oldAnthropic } else { Remove-Item Env:ANTHROPIC_API_KEY -ErrorAction SilentlyContinue }
    if ($null -ne $oldToken) { $env:AO2_CP_API_TOKEN = $oldToken } else { Remove-Item Env:AO2_CP_API_TOKEN -ErrorAction SilentlyContinue }
    if ($null -ne $oldBind) { $env:AO2_CP_BIND = $oldBind } else { Remove-Item Env:AO2_CP_BIND -ErrorAction SilentlyContinue }
    if ($null -ne $oldData) { $env:AO2_CP_DATA_DIR = $oldData } else { Remove-Item Env:AO2_CP_DATA_DIR -ErrorAction SilentlyContinue }
}
