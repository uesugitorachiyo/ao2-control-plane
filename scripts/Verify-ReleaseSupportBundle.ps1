param(
    [switch]$Json,
    [string]$Checksums,
    [string]$CompareAgainst,
    [Parameter(Mandatory=$true)]
    [string]$Path
)

# Offline, read-only verifier for AO2 Control Plane release support bundles.
# It never contacts the control plane and never mutates AO2/factory-v3 artifacts.
# Windows note: compatible with Windows PowerShell 5.1 and PowerShell 7+.
#
# Lane NN: -CompareAgainst diffs aggregate verdicts and per-surface
# candidate_correlation status across two release-candidate bundles so
# operators can surface verdict drift between candidates without
# re-navigating each bundle's HTML surfaces.

$ErrorActionPreference = "Stop"

$SurfacePaths = @{
    ci_evidence_index = @("ci_evidence_index")
    release_assembly = @("release_assembly")
    release_readiness = @("readiness")
    release_candidate_handoff = @("handoff")
    release_cockpit = @("cockpit")
    release_evaluator_decision = @("evaluator_decision")
    install_verification = @("install_verification")
    hosted_release_smoke = @("hosted_release_smoke")
    storage_support_bundle = @("storage_support")
}

$ExpectedJsonPaths = @{
    ci_evidence_index = '$.ci_evidence_index'
    release_assembly = '$.release_assembly'
    release_readiness = '$.readiness'
    release_candidate_handoff = '$.handoff'
    release_cockpit = '$.cockpit'
    release_evaluator_decision = '$.evaluator_decision'
    install_verification = '$.install_verification'
    hosted_release_smoke = '$.hosted_release_smoke'
    storage_support_bundle = '$.storage_support'
}

$RequiredSurfaceIds = @(
    'ci_evidence_index',
    'release_assembly',
    'release_readiness',
    'release_candidate_handoff',
    'release_cockpit',
    'release_evaluator_decision',
    'install_verification',
    'hosted_release_smoke',
    'storage_support_bundle'
)
$EXPECTED_MANIFEST_SCHEMA = 'ao2.cp-release-support-bundle-manifest.v1'
$RequiredCiEvidenceFamilyIds = @(
    'risky-pr-golden-bridge-smoke',
    'release-train-bridge-smoke',
    'ingest-smoke',
    'release-archive-smoke',
    'backup-restore-drill'
)
# Operator-visible candidate-correlation field MUST be present at the top of
# every embedded surface that exposes cross-evidence triage to the operator.
# A downgraded server dropping the field would silently mask release/three_os/
# evaluator/codex/claude divergence, so the offline verifier hard-fails the
# bundle here as a defense-in-depth gate.
#
# Each entry maps surface_id -> field name on that surface that holds the full
# candidate_correlation object. release_assembly uses candidate_correlation_detail
# because its top-level candidate_correlation is the status string consumed by
# the cross-OS smoke scripts (changing that would break operator contracts).
$CandidateCorrelationRequiredSurfaces = @(
    @{ id = 'release_cockpit';             field = 'candidate_correlation' },
    @{ id = 'release_candidate_handoff';   field = 'candidate_correlation' },
    @{ id = 'release_readiness';           field = 'candidate_correlation' },
    @{ id = 'release_assembly';            field = 'candidate_correlation_detail' }
)

# Lane NN: cross-bundle byte-identity comparison.
# Operators compare two release-candidate bundles to surface verdict drift
# between candidates. The compare-against flow extracts the verdicts and
# correlation-status fields from both bundles and emits a structural diff
# WITHOUT contacting either control plane. Verdict drift on any of these
# fields is operator-actionable and fails the primary bundle's exit code so
# automation pipelines surface the drift without parsing the JSON summary.
$ComparisonParityVerdicts = @(
    'candidate_correlation_parity',
    'surface_content_hash_parity'
)
$ComparisonParitySurfaces = @(
    'release_cockpit',
    'release_candidate_handoff',
    'release_readiness'
)
$ComparisonCorrelationStatusSurfaces = @(
    @{ id = 'release_cockpit';           field = 'candidate_correlation' },
    @{ id = 'release_candidate_handoff'; field = 'candidate_correlation' },
    @{ id = 'release_readiness';         field = 'candidate_correlation' },
    @{ id = 'release_assembly';          field = 'candidate_correlation_detail' }
)
# Lane ZZ: rejected_smoke_audit is rendered identically on cockpit, handoff,
# and readiness JSON by construction (the same rejected_smoke_audit_summary
# reader is embedded by all three handlers). A tampered offline bundle could
# alter one surface's audit object without touching the others — Lane XX's
# server-side pass-through proves the property holds at render time; the
# offline verifier audits it at bundle-acceptance time. Cross-bundle drift
# in the rotation-budget fields is also operator-actionable: two bundles
# collected at different rotation states will show different size/count
# even when verdicts agree, so the comparison view surfaces it as a
# distinct drift signal that is NOT a verdict failure.
$RejectedSmokeAuditSurfaces = @(
    'release_cockpit',
    'release_candidate_handoff',
    'release_readiness'
)
$RejectedSmokeAuditBudgetFields = @(
    'count',
    'audit_log_size_bytes',
    'audit_log_cap_bytes'
)

$SecretMarkerPatterns = @{
    authorization_bearer_header = 'authorization\s*[:=]\s*bearer\s+[^\s"'']+'
    ao2_cp_api_token_assignment = 'AO2_CP_API_TOKEN\s*='
    openai_api_key_assignment = 'OPENAI_API_KEY\s*='
    anthropic_api_key_assignment = 'ANTHROPIC_API_KEY\s*='
    json_api_token_field = '"(?:api_token|access_token|refresh_token)"\s*:\s*"[^"]+"'
}

function ConvertTo-CanonicalJsonString {
    # Mirrors serde_json's default string serialization exactly so canonical-JSON
    # hashes match the Rust server. Windows PowerShell 5.1's ConvertTo-Json also
    # HTML-escapes <>&' as <>&', which breaks byte-identity
    # with Rust/Python; this function never HTML-escapes.
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$Value)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('"')
    foreach ($c in $Value.ToCharArray()) {
        $code = [int]$c
        if ($c -ceq '"') { [void]$sb.Append('\"') }
        elseif ($c -ceq '\') { [void]$sb.Append('\\') }
        elseif ($code -eq 0x08) { [void]$sb.Append('\b') }
        elseif ($code -eq 0x09) { [void]$sb.Append('\t') }
        elseif ($code -eq 0x0A) { [void]$sb.Append('\n') }
        elseif ($code -eq 0x0C) { [void]$sb.Append('\f') }
        elseif ($code -eq 0x0D) { [void]$sb.Append('\r') }
        elseif ($code -lt 0x20) {
            [void]$sb.AppendFormat([System.Globalization.CultureInfo]::InvariantCulture, '\u{0:x4}', $code)
        }
        else { [void]$sb.Append($c) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-CanonicalJson {
    param([Parameter(Mandatory=$true)][AllowNull()] $Value)
    if ($null -eq $Value) { return "null" }
    if ($Value -is [bool]) { if ($Value) { return "true" } else { return "false" } }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int] -or $Value -is [uint32] -or $Value -is [long] -or $Value -is [uint64]) {
        return ([System.Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture)).ToLowerInvariant()
    }
    if ($Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        return ([System.Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture)).ToLowerInvariant()
    }
    if ($Value -is [datetime]) {
        $timestamp = $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
        return ConvertTo-CanonicalJsonString -Value $timestamp
    }
    if ($Value -is [datetimeoffset]) {
        $timestamp = $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
        return ConvertTo-CanonicalJsonString -Value $timestamp
    }
    if ($Value -is [string]) { return ConvertTo-CanonicalJsonString -Value $Value }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [System.Collections.IDictionary]) -and -not ($Value -is [pscustomobject])) {
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Value) {
            $items.Add((ConvertTo-CanonicalJson $item))
        }
        return "[" + ($items -join ",") + "]"
    }
    if (($Value -isnot [System.Collections.IDictionary]) -and ($Value -isnot [pscustomobject])) {
        return ConvertTo-CanonicalJsonString -Value ([System.Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture))
    }
    $props = @()
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = @($Value.Keys | ForEach-Object { [string]$_ })
        [array]::Sort($keys, [System.StringComparer]::Ordinal)
        foreach ($key in $keys) {
            $props += @{ Name = $key; Value = $Value[$key] }
        }
    } else {
        # PS 5.1 quirk: $obj.PSObject.Properties.Name on an empty PSMemberInfoCollection
        # unwraps to a single $null, manufacturing a phantom "" property. Iterate the
        # Properties collection directly so empty objects stay empty.
        $keys = @($Value.PSObject.Properties | ForEach-Object { [string]$_.Name })
        [array]::Sort($keys, [System.StringComparer]::Ordinal)
        foreach ($key in $keys) {
            $props += @{ Name = $key; Value = $Value.PSObject.Properties[$key].Value }
        }
    }
    $pairs = New-Object System.Collections.Generic.List[string]
    foreach ($prop in $props) {
        $pairs.Add((ConvertTo-CanonicalJson $prop.Name) + ":" + (ConvertTo-CanonicalJson $prop.Value))
    }
    return "{" + ($pairs -join ",") + "}"
}

function Get-Sha256Canonical {
    param([Parameter(Mandatory=$true)] $Value)
    $json = ConvertTo-CanonicalJson $Value
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
    } finally {
        $sha.Dispose()
    }
    return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Get-Sha256File {
    param([Parameter(Mandatory=$true)][string]$FilePath)
    $stream = [System.IO.File]::OpenRead($FilePath)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($stream)
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
    return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Get-ChecksumFailures {
    param(
        [Parameter(Mandatory=$true)][string]$ChecksumsPath,
        [Parameter(Mandatory=$true)][string]$BundleFilename,
        [Parameter(Mandatory=$true)][string]$BundleSha256
    )
    $checksumFailures = New-Object System.Collections.Generic.List[string]
    if (!(Test-Path -LiteralPath $ChecksumsPath -PathType Leaf)) {
        $checksumFailures.Add("checksums unable to read $ChecksumsPath")
        return $checksumFailures
    }
    $matchingPaths = New-Object System.Collections.Generic.List[string]
    foreach ($rawLine in (Get-Content -LiteralPath $ChecksumsPath)) {
        $line = $rawLine.Trim()
        if (($line.Length -eq 0) -or $line.StartsWith('#')) { continue }
        $parts = @($line -split '\s+')
        if ($parts.Count -lt 2) {
            $checksumFailures.Add("checksums malformed line $rawLine")
            continue
        }
        $digest = $parts[0].ToLowerInvariant()
        $checksumPath = $parts[1].TrimStart('*')
        if ($digest -notmatch '^[0-9a-f]{64}$') {
            $checksumFailures.Add("checksums malformed sha256 digest for $checksumPath")
            continue
        }
        if ($digest -eq $BundleSha256) {
            $matchingPaths.Add($checksumPath)
        }
    }
    if ($matchingPaths.Count -eq 0) {
        $checksumFailures.Add("checksums canonical bundle digest not present in SHA256SUMS; expected $BundleSha256 for $BundleFilename")
    } elseif (!(@($matchingPaths | Where-Object { ($_ -eq $BundleFilename) -or ($_.EndsWith("/$BundleFilename")) -or (($_.StartsWith("ao2-release-support-bundle-")) -and ($_.EndsWith(".json"))) }).Count -gt 0)) {
        $checksumFailures.Add("checksums canonical bundle digest present but not associated with $BundleFilename; matched $($matchingPaths -join ',')")
    }
    return $checksumFailures
}

function Get-Surface {
    param($Bundle, [string]$SurfaceId)
    $value = $Bundle
    foreach ($part in $SurfacePaths[$SurfaceId]) {
        if ($null -eq $value.PSObject.Properties[$part]) { throw "missing surface $SurfaceId" }
        $value = $value.$part
    }
    return $value
}

function Get-ComparisonView {
    param($Bundle)
    $view = [ordered]@{
        schema_version = $null
        release_candidate_version = $null
        verdicts = [ordered]@{}
        correlation_status = [ordered]@{}
        rejected_smoke_audit = [ordered]@{}
    }
    if ($null -ne $Bundle) {
        if ($null -ne $Bundle.PSObject.Properties['schema_version']) {
            $view.schema_version = [string]$Bundle.schema_version
        }
        if ($null -ne $Bundle.PSObject.Properties['release_candidate_version']) {
            $view.release_candidate_version = [string]$Bundle.release_candidate_version
        }
    }
    foreach ($surfaceId in $ComparisonParitySurfaces) {
        try {
            $surface = Get-Surface $Bundle $surfaceId
        } catch {
            continue
        }
        if ($null -eq $surface -or $surface -isnot [pscustomobject]) { continue }
        foreach ($verdictField in $ComparisonParityVerdicts) {
            if ($null -eq $surface.PSObject.Properties[$verdictField]) { continue }
            $value = $surface.$verdictField
            if ($value -is [string]) {
                if (-not $view.verdicts.Contains($verdictField)) {
                    $view.verdicts[$verdictField] = [ordered]@{}
                }
                $view.verdicts[$verdictField][$surfaceId] = [string]$value
            }
        }
    }
    foreach ($entry in $ComparisonCorrelationStatusSurfaces) {
        $surfaceId = [string]$entry.id
        $fieldName = [string]$entry.field
        try {
            $surface = Get-Surface $Bundle $surfaceId
        } catch {
            continue
        }
        if ($null -eq $surface -or $surface -isnot [pscustomobject]) { continue }
        if ($null -eq $surface.PSObject.Properties[$fieldName]) { continue }
        $correlation = $surface.$fieldName
        if ($null -ne $correlation -and $correlation -is [pscustomobject] -and $null -ne $correlation.PSObject.Properties['status']) {
            $status = $correlation.status
            if ($status -is [string]) {
                $view.correlation_status[$surfaceId] = [string]$status
            }
        }
    }
    # Lane ZZ: collect rejected_smoke_audit rotation-budget fields from each
    # operator-triage surface so the cross-bundle diff can surface drift.
    # Two bundles captured at different rotation states will show different
    # size/count even when verdicts match — that's still operator-actionable
    # because it signals one of: (a) bundles were captured across rotation,
    # (b) a tampering burst between captures, or (c) tampering of the audit
    # log itself. The drift is surfaced as a distinct signal, never folded
    # into the verdict-parity boolean.
    foreach ($surfaceId in $RejectedSmokeAuditSurfaces) {
        try {
            $surface = Get-Surface $Bundle $surfaceId
        } catch {
            continue
        }
        if ($null -eq $surface -or $surface -isnot [pscustomobject]) { continue }
        if ($null -eq $surface.PSObject.Properties['rejected_smoke_audit']) { continue }
        $audit = $surface.rejected_smoke_audit
        if ($null -eq $audit -or $audit -isnot [pscustomobject]) { continue }
        $captured = [ordered]@{}
        foreach ($fieldName in $RejectedSmokeAuditBudgetFields) {
            if ($null -eq $audit.PSObject.Properties[$fieldName]) { continue }
            $value = $audit.$fieldName
            if ($value -is [int] -or $value -is [int64] -or $value -is [uint32] -or $value -is [uint64] -or $value -is [long]) {
                $captured[$fieldName] = [int64]$value
            }
        }
        if ($captured.Count -gt 0) {
            $view.rejected_smoke_audit[$surfaceId] = $captured
        }
    }
    return $view
}

function Get-ComparisonDiff {
    param(
        $PrimaryView,
        $CompareView,
        [string]$PrimarySha256,
        [string]$CompareSha256
    )
    $diffFailures = New-Object System.Collections.Generic.List[string]
    $verdictDiffs = New-Object System.Collections.Generic.List[object]
    foreach ($verdictField in $ComparisonParityVerdicts) {
        $primaryMap = if ($PrimaryView.verdicts.Contains($verdictField)) { $PrimaryView.verdicts[$verdictField] } else { [ordered]@{} }
        $compareMap = if ($CompareView.verdicts.Contains($verdictField)) { $CompareView.verdicts[$verdictField] } else { [ordered]@{} }
        foreach ($surfaceId in $ComparisonParitySurfaces) {
            $primaryValue = if ($primaryMap.Contains($surfaceId)) { $primaryMap[$surfaceId] } else { $null }
            $compareValue = if ($compareMap.Contains($surfaceId)) { $compareMap[$surfaceId] } else { $null }
            if ($primaryValue -ne $compareValue) {
                $verdictDiffs.Add([pscustomobject]@{
                    surface = $surfaceId
                    field = $verdictField
                    primary = $primaryValue
                    compare = $compareValue
                })
                $diffFailures.Add("comparison_verdict_drift: $surfaceId.$verdictField differs across bundles (primary='$primaryValue', compare='$compareValue')")
            }
        }
    }
    $correlationStatusDiffs = New-Object System.Collections.Generic.List[object]
    foreach ($entry in $ComparisonCorrelationStatusSurfaces) {
        $surfaceId = [string]$entry.id
        $primaryValue = if ($PrimaryView.correlation_status.Contains($surfaceId)) { $PrimaryView.correlation_status[$surfaceId] } else { $null }
        $compareValue = if ($CompareView.correlation_status.Contains($surfaceId)) { $CompareView.correlation_status[$surfaceId] } else { $null }
        if ($primaryValue -ne $compareValue) {
            $correlationStatusDiffs.Add([pscustomobject]@{
                surface = $surfaceId
                primary = $primaryValue
                compare = $compareValue
            })
            $diffFailures.Add("comparison_correlation_status_drift: $surfaceId candidate_correlation.status differs across bundles (primary='$primaryValue', compare='$compareValue')")
        }
    }
    # Lane ZZ: cross-bundle rotation-budget drift. The audit-budget signal is
    # explicitly NOT folded into verdict_parity — two bundles captured at
    # different times legitimately have different rotation states. The diff
    # surfaces the drift so operators can decide whether it's expected
    # (between-captures activity) or suspicious (audit-log tampering, or
    # rotation cap drift indicating a server-side cap change).
    $auditBudgetDiffs = New-Object System.Collections.Generic.List[object]
    $primaryAudit = $PrimaryView.rejected_smoke_audit
    $compareAudit = $CompareView.rejected_smoke_audit
    foreach ($surfaceId in $RejectedSmokeAuditSurfaces) {
        $primaryEntry = if ($null -ne $primaryAudit -and $primaryAudit.Contains($surfaceId)) { $primaryAudit[$surfaceId] } else { $null }
        $compareEntry = if ($null -ne $compareAudit -and $compareAudit.Contains($surfaceId)) { $compareAudit[$surfaceId] } else { $null }
        foreach ($fieldName in $RejectedSmokeAuditBudgetFields) {
            $primaryValue = if ($null -ne $primaryEntry -and $primaryEntry.Contains($fieldName)) { $primaryEntry[$fieldName] } else { $null }
            $compareValue = if ($null -ne $compareEntry -and $compareEntry.Contains($fieldName)) { $compareEntry[$fieldName] } else { $null }
            if ($primaryValue -ne $compareValue) {
                $auditBudgetDiffs.Add([pscustomobject]@{
                    surface = $surfaceId
                    field = $fieldName
                    primary = $primaryValue
                    compare = $compareValue
                })
                $diffFailures.Add("comparison_audit_log_rotation_budget_drift: $surfaceId.rejected_smoke_audit.$fieldName differs across bundles (primary='$primaryValue', compare='$compareValue')")
            }
        }
    }
    $schemaMatch = ($PrimaryView.schema_version -eq $CompareView.schema_version)
    if (-not $schemaMatch) {
        $diffFailures.Add("comparison_schema_version_drift: primary='$($PrimaryView.schema_version)' vs compare='$($CompareView.schema_version)'; bundles are not the same schema generation")
    }
    $verdictDiffArray = @($verdictDiffs | ForEach-Object { $_ })
    $correlationStatusDiffArray = @($correlationStatusDiffs | ForEach-Object { $_ })
    $auditBudgetDiffArray = @($auditBudgetDiffs | ForEach-Object { $_ })
    $report = [pscustomobject]@{
        primary_bundle_sha256 = $PrimarySha256
        compare_bundle_sha256 = $CompareSha256
        bundle_sha256_match = ($PrimarySha256 -eq $CompareSha256)
        schema_version_match = $schemaMatch
        primary_schema_version = $PrimaryView.schema_version
        compare_schema_version = $CompareView.schema_version
        primary_release_candidate_version = $PrimaryView.release_candidate_version
        compare_release_candidate_version = $CompareView.release_candidate_version
        verdict_diffs = $verdictDiffArray
        correlation_status_diffs = $correlationStatusDiffArray
        audit_budget_diffs = $auditBudgetDiffArray
        verdict_parity = (($verdictDiffs.Count -eq 0) -and ($correlationStatusDiffs.Count -eq 0))
    }
    return @{ report = $report; failures = $diffFailures }
}

function Get-CiEvidenceIndexSemanticFailures {
    param($Surface)
    $semanticFailures = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Surface -or $Surface -isnot [pscustomobject]) {
        $semanticFailures.Add("ci_evidence_index expected object")
        return $semanticFailures
    }
    if ([string]$Surface.schema_version -ne 'ao2.cp-ci-evidence-index.v1') {
        $semanticFailures.Add("ci_evidence_index.schema_version expected ao2.cp-ci-evidence-index.v1")
    }
    if ([string]$Surface.control_plane_role -ne 'read-only-observer') {
        $semanticFailures.Add("ci_evidence_index.control_plane_role expected read-only-observer")
    }
    foreach ($fieldName in @('mutates_ao_artifacts', 'mutates_observer_storage', 'control_plane_approves_release')) {
        if ($Surface.$fieldName -ne $false) {
            $semanticFailures.Add("ci_evidence_index.$fieldName expected false")
        }
    }
    $auth = $Surface.auth
    if ($null -eq $auth -or $auth -isnot [pscustomobject]) {
        $semanticFailures.Add("ci_evidence_index.auth expected object")
    } else {
        if ($auth.required -ne $true) {
            $semanticFailures.Add("ci_evidence_index.auth.required expected true")
        }
        if ([string]$auth.scheme -ne 'bearer') {
            $semanticFailures.Add("ci_evidence_index.auth.scheme expected bearer")
        }
        foreach ($fieldName in @('credential_material_included', 'credential_material_in_urls')) {
            if ($auth.$fieldName -ne $false) {
                $semanticFailures.Add("ci_evidence_index.auth.$fieldName expected false")
            }
        }
    }
    $endpoints = $Surface.endpoints
    if ($null -eq $endpoints -or $endpoints -isnot [pscustomobject]) {
        $semanticFailures.Add("ci_evidence_index.endpoints expected object")
    } else {
        if ([string]$endpoints.html -ne '/api/v1/ci/evidence-index') {
            $semanticFailures.Add("ci_evidence_index.endpoints.html unexpected path")
        }
        if ([string]$endpoints.json -ne '/api/v1/ci/evidence-index.json') {
            $semanticFailures.Add("ci_evidence_index.endpoints.json unexpected path")
        }
    }
    $families = @()
    if ($null -eq $Surface.PSObject.Properties['evidence_families']) {
        $semanticFailures.Add("ci_evidence_index.evidence_families expected array")
        return $semanticFailures
    } else {
        $families = @($Surface.evidence_families)
    }
    foreach ($familyId in $RequiredCiEvidenceFamilyIds) {
        $familyMatches = @($families | Where-Object { ($null -ne $_) -and ([string]$_.id -eq $familyId) })
        if ($familyMatches.Count -eq 0) {
            $semanticFailures.Add("ci_evidence_index.evidence_families missing $familyId")
            continue
        }
        $family = $familyMatches[0]
        if ([string]$family.operator_action -ne 'download-ci-artifact') {
            $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.operator_action expected download-ci-artifact")
        }
        $schemaVersions = @()
        if ($null -ne $family.PSObject.Properties['schema_versions']) {
            $schemaVersions = @($family.schema_versions)
        }
        if ($schemaVersions.Count -eq 0) {
            $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.schema_versions expected non-empty array")
        }
        if (([string]$family.artifact_name_pattern) -notlike '*ao2-control-plane*') {
            $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.artifact_name_pattern expected ao2-control-plane artifact pattern")
        }
        $provenance = $family.ci_artifact_provenance
        if ($null -eq $provenance -or $provenance -isnot [pscustomobject]) {
            $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance expected object")
        } else {
            if ([string]$provenance.provider -ne 'github-actions') {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance.provider expected github-actions")
            }
            if ([string]$provenance.workflow_file -ne '.github/workflows/ci.yml') {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance.workflow_file expected .github/workflows/ci.yml")
            }
            if ([string]$provenance.workflow_name -ne 'CI') {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance.workflow_name expected CI")
            }
            if ([string]$provenance.run_id_source -ne 'github_actions_run_id') {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance.run_id_source expected github_actions_run_id")
            }
            if ($provenance.token_free -ne $true) {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance.token_free expected true")
            }
            $jobNames = @()
            if ($null -ne $provenance.PSObject.Properties['job_names']) {
                $jobNames = @($provenance.job_names)
            }
            if ($jobNames.Count -eq 0) {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance.job_names expected non-empty array")
            }
            $artifactNames = @()
            if ($null -ne $provenance.PSObject.Properties['artifact_names']) {
                $artifactNames = @($provenance.artifact_names)
            }
            if ($artifactNames.Count -eq 0) {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance.artifact_names expected non-empty array")
            } elseif (($artifactNames | Where-Object { ([string]$_) -notlike '*ao2-control-plane*' }).Count -gt 0) {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance.artifact_names expected ao2-control-plane artifact names")
            }
            if (([string]$provenance.run_url_template) -notlike '*/actions/runs/<run_id>*') {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance.run_url_template expected GitHub Actions run template")
            }
            if (([string]$provenance.artifact_download_url_template) -notlike '*/actions/runs/<run_id>/artifacts*') {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance.artifact_download_url_template expected GitHub Actions artifact template")
            }
            if (([string]$provenance.digest_reference) -notlike '*summary*') {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.ci_artifact_provenance.digest_reference expected summary digest reference")
            }
        }
        $trust = $family.trust_boundary
        if ($null -eq $trust -or $trust -isnot [pscustomobject]) {
            $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.trust_boundary expected object")
            continue
        }
        if ($trust.read_only -ne $true) {
            $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.trust_boundary.read_only expected true")
        }
        foreach ($fieldName in @('approves_release', 'mutates_ao_artifacts')) {
            if ($trust.$fieldName -ne $false) {
                $semanticFailures.Add("ci_evidence_index.evidence_families.$familyId.trust_boundary.$fieldName expected false")
            }
        }
    }
    return $semanticFailures
}

function Get-HostedReleaseSmokeSemanticFailures {
    param($Surface)
    $semanticFailures = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Surface -or $Surface -isnot [pscustomobject]) {
        $semanticFailures.Add("hosted_release_smoke expected object")
        return $semanticFailures
    }
    if ([string]$Surface.schema_version -ne 'ao2.release-archive-hosted-smoke.v1') {
        $semanticFailures.Add("hosted_release_smoke.schema_version expected ao2.release-archive-hosted-smoke.v1")
    }
    if ([string]$Surface.status -ne 'passed') {
        $semanticFailures.Add("hosted_release_smoke.status expected passed")
    }
    if ([string]$Surface.install_verification_schema -ne 'ao2.install-verification-evidence.v1') {
        $semanticFailures.Add("hosted_release_smoke.install_verification_schema expected ao2.install-verification-evidence.v1")
    }
    if ([string]::IsNullOrWhiteSpace([string]$Surface.install_verification_evidence)) {
        $semanticFailures.Add("hosted_release_smoke.install_verification_evidence expected non-empty string")
    }
    foreach ($fieldName in @('provider_api_keys_required', 'control_plane_approves_release', 'mutates_ao_artifacts')) {
        if ($Surface.$fieldName -ne $false) {
            $semanticFailures.Add("hosted_release_smoke.$fieldName expected false")
        }
    }
    if ([string]$Surface.release_acceptance_owner -ne 'factory-v3 evaluator-closer') {
        $semanticFailures.Add("hosted_release_smoke.release_acceptance_owner expected factory-v3 evaluator-closer")
    }
    return $semanticFailures
}

$rawBundle = Get-Content -Raw -LiteralPath $Path
$bundle = $rawBundle | ConvertFrom-Json
$bundleSha256 = Get-Sha256Canonical $bundle
$checksumVerified = $null
$manifest = $bundle.portable_bundle_manifest
$integrity = $manifest.integrity
$surfaceSha256 = $integrity.surface_sha256
$verificationPlan = $integrity.verification_plan
$failures = New-Object System.Collections.Generic.List[string]
if (![string]::IsNullOrEmpty($Checksums)) {
    $checksumFailures = Get-ChecksumFailures -ChecksumsPath $Checksums -BundleFilename ([System.IO.Path]::GetFileName($Path)) -BundleSha256 $bundleSha256
    foreach ($failure in $checksumFailures) { $failures.Add($failure) }
    $checksumVerified = ($checksumFailures.Count -eq 0)
}
foreach ($marker in $SecretMarkerPatterns.Keys) {
    if ($rawBundle -match $SecretMarkerPatterns[$marker]) {
        $failures.Add("secret hygiene forbidden marker $marker present in support bundle")
    }
}
if ($bundle.schema_version -ne 'ao2.cp-release-support-bundle.v1') {
    $failures.Add("schema_version expected ao2.cp-release-support-bundle.v1, found $($bundle.schema_version)")
}
$surfaces = @()
if ($null -eq $manifest -or $null -eq $manifest.PSObject.Properties['included_surfaces']) {
    $failures.Add("portable_bundle_manifest.included_surfaces expected array")
} else {
    $surfaces = @($manifest.included_surfaces)
}
if ($null -eq $surfaceSha256 -or $surfaceSha256 -isnot [pscustomobject]) {
    $failures.Add("integrity.surface_sha256 expected object")
    $surfaceSha256 = [pscustomobject]@{}
}
$surfaceIds = @($surfaces | ForEach-Object {
    if ($null -ne $_ -and $null -ne $_.PSObject.Properties['id']) {
        [string]$_.id
    } else {
        "missing"
    }
})

if ($surfaces.Count -ne $RequiredSurfaceIds.Count) {
    $failures.Add("portable_bundle_manifest.included_surfaces expected $($RequiredSurfaceIds.Count) surfaces, found $($surfaces.Count)")
}
$manifestSchema = if ($null -ne $manifest -and $null -ne $manifest.PSObject.Properties['schema_version']) {
    [string]$manifest.schema_version
} else {
    "missing"
}
if ($manifestSchema -ne $EXPECTED_MANIFEST_SCHEMA) {
    $failures.Add("portable_bundle_manifest.schema_version expected $EXPECTED_MANIFEST_SCHEMA, found $manifestSchema")
}
foreach ($requiredId in $RequiredSurfaceIds) {
    if ($surfaceIds -notcontains $requiredId) {
        $failures.Add("$requiredId missing required support-bundle surface")
    }
    if ($null -eq $surfaceSha256.PSObject.Properties[$requiredId]) {
        $failures.Add("$requiredId missing required integrity.surface_sha256 entry")
    }
}
foreach ($id in $surfaceIds) {
    if ($RequiredSurfaceIds -notcontains $id) {
        $failures.Add("$id unknown support-bundle surface id")
    }
    if ((@($surfaceIds | Where-Object { $_ -eq $id })).Count -gt 1) {
        $failures.Add("$id duplicate support-bundle surface id")
    }
}
$planSurfaceCount = if ($null -ne $verificationPlan -and $null -ne $verificationPlan.PSObject.Properties['surface_count']) {
    $verificationPlan.surface_count
} else {
    "missing"
}
if ($planSurfaceCount -ne $RequiredSurfaceIds.Count) {
    $failures.Add("verification_plan.surface_count expected $($RequiredSurfaceIds.Count), found $planSurfaceCount")
}

$earlyCandidateCorrelationFailures = New-Object System.Collections.Generic.List[string]
foreach ($entry in $CandidateCorrelationRequiredSurfaces) {
    $surfaceId = [string]$entry.id
    $fieldName = [string]$entry.field
    try {
        $embedded = Get-Surface $bundle $surfaceId
    } catch {
        continue
    }
    if ($null -eq $embedded -or $null -eq $embedded.PSObject.Properties[$fieldName]) {
        $earlyCandidateCorrelationFailures.Add("$surfaceId $fieldName missing or not an object; operator triage requires this field on cockpit, handoff, readiness, and assembly surfaces")
        continue
    }
    $correlation = $embedded.$fieldName
    if ($null -eq $correlation -or $correlation -isnot [pscustomobject]) {
        $earlyCandidateCorrelationFailures.Add("$surfaceId $fieldName missing or not an object; operator triage requires this field on cockpit, handoff, readiness, and assembly surfaces")
    }
}
if ($earlyCandidateCorrelationFailures.Count -gt 0) {
    foreach ($failure in $earlyCandidateCorrelationFailures) { $failures.Add($failure) }
    $uniqueFailures = @($failures | Select-Object -Unique)
    if ($Json) {
        [pscustomobject]@{
            status = "failed"
            surface_count = $surfaces.Count
            bundle_sha256 = $bundleSha256
            checksum_verified = $checksumVerified
            trust_boundary = "read_only_observer"
            control_plane_role = "read_only_observer"
            release_acceptance_owner = "factory-v3 evaluator-closer"
            verification_scope = "embedded support-bundle digest verification only; no AO2 artifact mutation and no release approval"
            failures = $uniqueFailures
            comparison_against = $null
        } | ConvertTo-Json -Compress -Depth 8
    } else {
        Write-Output "FAILED release support-bundle verification"
        foreach ($failure in $uniqueFailures) { Write-Output "- $failure" }
    }
    exit 1
}

$surfacesForDigestVerification = New-Object System.Collections.Generic.List[object]
foreach ($surface in $surfaces) {
    if ([string]$surface.id -eq "storage_support_bundle") {
        $surfacesForDigestVerification.Add($surface)
    }
}
foreach ($surface in $surfaces) {
    if ([string]$surface.id -ne "storage_support_bundle") {
        $surfacesForDigestVerification.Add($surface)
    }
}

foreach ($surface in $surfacesForDigestVerification) {
    $id = [string]$surface.id
    $declaredPath = [string]$surface.path
    $expectedPath = [string]$ExpectedJsonPaths[$id]
    $manifestSha = [string]$surface.sha256
    $integritySha = if ($null -ne $surfaceSha256.PSObject.Properties[$id]) {
        [string]$surfaceSha256.$id
    } else {
        "missing"
    }
    try {
        $embedded = Get-Surface $bundle $id
        $recomputedSha = Get-Sha256Canonical $embedded
        $embeddedSchema = [string]$embedded.schema_version
    } catch {
        $recomputedSha = "error:$($_.Exception.Message)"
        $embeddedSchema = "missing"
    }
    $declaredSchema = [string]$surface.schema_version
    if (!(($declaredPath -eq $expectedPath) -and ($manifestSha -ne "missing") -and ($integritySha -ne "missing") -and ($manifestSha -eq $integritySha) -and ($manifestSha -eq $recomputedSha) -and ($declaredSchema -eq $embeddedSchema))) {
        $failures.Add("$id path=$declaredPath/$expectedPath manifest=$manifestSha integrity=$integritySha recomputed=$recomputedSha schema=$declaredSchema/$embeddedSchema")
    }
    if ($id -eq "ci_evidence_index") {
        try {
            $ciEvidenceSemanticFailures = Get-CiEvidenceIndexSemanticFailures -Surface (Get-Surface $bundle $id)
            foreach ($failure in $ciEvidenceSemanticFailures) { $failures.Add($failure) }
        } catch {
            $failures.Add("ci_evidence_index.semantic_validation error $($_.Exception.Message)")
        }
    }
    if ($id -eq "hosted_release_smoke") {
        try {
            $hostedReleaseSmokeSemanticFailures = Get-HostedReleaseSmokeSemanticFailures -Surface (Get-Surface $bundle $id)
            foreach ($failure in $hostedReleaseSmokeSemanticFailures) { $failures.Add($failure) }
        } catch {
            $failures.Add("hosted_release_smoke.semantic_validation error $($_.Exception.Message)")
        }
    }
}

if (($bundle.trust_boundary.role -ne "read_only_observer") -or ($bundle.trust_boundary.mutates_ao_artifacts -ne $false)) {
    $failures.Add("trust_boundary expected read_only_observer and mutates_ao_artifacts=false")
}

$correlationHashes = [ordered]@{}
foreach ($entry in $CandidateCorrelationRequiredSurfaces) {
    $surfaceId = [string]$entry.id
    $fieldName = [string]$entry.field
    try {
        $embedded = Get-Surface $bundle $surfaceId
    } catch {
        continue
    }
    if ($null -eq $embedded -or $null -eq $embedded.PSObject.Properties[$fieldName]) {
        $failures.Add("$surfaceId $fieldName missing or not an object; operator triage requires this field on cockpit, handoff, readiness, and assembly surfaces")
        continue
    }
    $correlation = $embedded.$fieldName
    if ($null -eq $correlation -or $correlation -isnot [pscustomobject]) {
        $failures.Add("$surfaceId $fieldName missing or not an object; operator triage requires this field on cockpit, handoff, readiness, and assembly surfaces")
        continue
    }
    $status = [string]$correlation.status
    if (($status -ne 'matched') -and ($status -ne 'mismatched')) {
        $failures.Add("$surfaceId.$fieldName.status expected matched|mismatched, found '$status'")
    }
    if ($null -eq $correlation.PSObject.Properties['blockers'] -or -not ($correlation.blockers -is [array] -or $correlation.blockers -is [System.Collections.IEnumerable])) {
        $failures.Add("$surfaceId.$fieldName.blockers expected array")
    }
    $correlationHashes[$surfaceId] = Get-Sha256Canonical $correlation
}

# Lane FF: cross-surface candidate_correlation byte-identity audit.
# All four operator-triage surfaces (cockpit, handoff, readiness,
# assembly_detail) embed the SAME candidate_correlation object by
# construction - every render path calls candidate_correlation_value()
# with the same underlying artifact evidence. A tampered offline bundle
# could embed inconsistent objects across surfaces (e.g., cockpit shows
# status=matched, readiness shows status=mismatched). The legacy per-
# surface validation passes both individually because each is "valid"
# in shape. The byte-identity check catches the cross-surface drift.
if ($correlationHashes.Count -ge 2) {
    $distinctHashes = @($correlationHashes.Values | Sort-Object -Unique)
    if ($distinctHashes.Count -gt 1) {
        $sortedSurfaceIds = @($correlationHashes.Keys | Sort-Object)
        $bucketEntries = @($sortedSurfaceIds | ForEach-Object {
            $shortSha = $correlationHashes[$_].Substring(0, 12)
            "$($_)=$shortSha"
        })
        $buckets = $bucketEntries -join ", "
        $failures.Add("candidate_correlation_cross_surface_byte_identity: the four operator-triage surfaces (cockpit, handoff, readiness, assembly_detail) MUST embed byte-identical candidate_correlation objects; found $($distinctHashes.Count) distinct canonical hashes ($buckets)")
    }
}

# Lane HH: cross-surface byte-identity audit for the aggregate parity
# verdicts. The control plane recomputes candidate_correlation_parity
# (Lane W) and aggregates surface_content_hash_parity (Lane CC) from
# the same underlying three-OS smoke evidence and then surfaces both
# verdicts on cockpit, handoff, and readiness by construction. A
# tampered offline bundle could expose "matched" on cockpit while
# readiness/handoff still show "drift", visually misleading the
# operator. The legacy per-surface validation passes individually
# because each verdict is a valid enum string in isolation. The
# cross-surface verdict audit catches the drift. Markers are listed
# literally so the cross-script parity test can grep them.
$ParityVerdictAudits = @(
    [pscustomobject]@{
        field = 'candidate_correlation_parity'
        marker = 'candidate_correlation_parity_cross_surface_byte_identity'
    },
    [pscustomobject]@{
        field = 'surface_content_hash_parity'
        marker = 'surface_content_hash_parity_cross_surface_byte_identity'
    }
)
foreach ($audit in $ParityVerdictAudits) {
    $verdictField = [string]$audit.field
    $marker = [string]$audit.marker
    $verdicts = [ordered]@{}
    foreach ($surfaceId in @("release_cockpit", "release_candidate_handoff", "release_readiness")) {
        try {
            $surface = Get-Surface $bundle $surfaceId
        } catch {
            continue
        }
        if ($null -eq $surface -or $surface -isnot [pscustomobject]) {
            continue
        }
        if ($null -eq $surface.PSObject.Properties[$verdictField]) {
            continue
        }
        $value = $surface.$verdictField
        if ($value -is [string]) {
            $verdicts[$surfaceId] = [string]$value
        }
    }
    if ($verdicts.Count -ge 2) {
        $distinctVerdicts = @($verdicts.Values | Sort-Object -Unique)
        if ($distinctVerdicts.Count -gt 1) {
            $sortedVerdictKeys = @($verdicts.Keys | Sort-Object)
            $verdictBucketEntries = @($sortedVerdictKeys | ForEach-Object {
                "$($_)='$($verdicts[$_])'"
            })
            $verdictBuckets = $verdictBucketEntries -join ", "
            $failures.Add("$($marker): the three operator-triage surfaces (cockpit, handoff, readiness) MUST agree on the aggregate $verdictField verdict; found $($distinctVerdicts.Count) distinct values ($verdictBuckets)")
        }
    }
}

# Lane ZZ: cross-surface rejected_smoke_audit byte-identity audit.
# cockpit/handoff/readiness JSON each embed the same audit summary by
# construction (the rejected_smoke_audit_summary reader is invoked once
# per render and serialized into all three surfaces). A tampered offline
# bundle could alter one surface's audit object — for instance bumping
# cockpit's count to mask rejected tampering attempts on operator
# surfaces while leaving readiness untouched. The per-surface shape
# check would still pass (each is a valid object). The byte-identity
# hash catches the cross-surface drift, paralleling Lane FF/HH for the
# rotation-budget surface introduced in Lane XX.
$auditHashes = [ordered]@{}
foreach ($surfaceId in $RejectedSmokeAuditSurfaces) {
    try {
        $surface = Get-Surface $bundle $surfaceId
    } catch {
        continue
    }
    if ($null -eq $surface -or $surface -isnot [pscustomobject]) { continue }
    if ($null -eq $surface.PSObject.Properties['rejected_smoke_audit']) { continue }
    $audit = $surface.rejected_smoke_audit
    if ($null -eq $audit -or $audit -isnot [pscustomobject]) { continue }
    $auditHashes[$surfaceId] = Get-Sha256Canonical $audit
}
if ($auditHashes.Count -ge 2) {
    $distinctAuditHashes = @($auditHashes.Values | Sort-Object -Unique)
    if ($distinctAuditHashes.Count -gt 1) {
        $sortedAuditSurfaceIds = @($auditHashes.Keys | Sort-Object)
        $auditBucketEntries = @($sortedAuditSurfaceIds | ForEach-Object {
            $shortSha = $auditHashes[$_].Substring(0, 12)
            "$($_)=$shortSha"
        })
        $auditBuckets = $auditBucketEntries -join ", "
        $failures.Add("rejected_smoke_audit_cross_surface_byte_identity: the three operator-triage surfaces (cockpit, handoff, readiness) MUST embed byte-identical rejected_smoke_audit objects; found $($distinctAuditHashes.Count) distinct canonical hashes ($auditBuckets)")
    }
}

$comparisonAgainst = $null
if (-not [string]::IsNullOrEmpty($CompareAgainst)) {
    $loadError = $null
    $compareBundle = $null
    $compareRaw = $null
    try {
        $compareRaw = Get-Content -Raw -LiteralPath $CompareAgainst
        $compareBundle = $compareRaw | ConvertFrom-Json
    } catch {
        $loadError = $_.Exception.Message
    }
    if ($null -ne $loadError) {
        $comparisonAgainst = [pscustomobject]@{
            bundle_path = $CompareAgainst
            load_error = "failed to load compare-against bundle: $loadError"
            verdict_parity = $false
        }
        $failures.Add("comparison_against: failed to load ${CompareAgainst}: $loadError")
    } else {
        foreach ($marker in $SecretMarkerPatterns.Keys) {
            if ($compareRaw -match $SecretMarkerPatterns[$marker]) {
                $failures.Add("comparison_against: secret hygiene forbidden marker $marker present in support bundle")
            }
        }
        $primaryView = Get-ComparisonView $bundle
        $compareView = Get-ComparisonView $compareBundle
        $compareSha256 = Get-Sha256Canonical $compareBundle
        $diffResult = Get-ComparisonDiff $primaryView $compareView $bundleSha256 $compareSha256
        $report = $diffResult.report
        $report | Add-Member -NotePropertyName bundle_path -NotePropertyValue $CompareAgainst -Force
        $comparisonAgainst = $report
        foreach ($f in $diffResult.failures) { $failures.Add($f) }
    }
}

if ($failures.Count -gt 0) {
    $uniqueFailures = @($failures | Select-Object -Unique)
    if ($Json) {
        [pscustomobject]@{
            status = "failed"
            surface_count = $surfaces.Count
            bundle_sha256 = $bundleSha256
            checksum_verified = $checksumVerified
            trust_boundary = "read_only_observer"
            control_plane_role = "read_only_observer"
            release_acceptance_owner = "factory-v3 evaluator-closer"
            verification_scope = "embedded support-bundle digest verification only; no AO2 artifact mutation and no release approval"
            failures = $uniqueFailures
            comparison_against = $comparisonAgainst
        } | ConvertTo-Json -Compress -Depth 8
    } else {
        Write-Output "FAILED release support-bundle verification"
        foreach ($failure in $uniqueFailures) { Write-Output "- $failure" }
    }
    exit 1
}

if ($Json) {
    [pscustomobject]@{
        status = "passed"
        surface_count = $surfaces.Count
        bundle_sha256 = $bundleSha256
        checksum_verified = $checksumVerified
        trust_boundary = "read_only_observer"
        control_plane_role = "read_only_observer"
        release_acceptance_owner = "factory-v3 evaluator-closer"
        verification_scope = "embedded support-bundle digest verification only; no AO2 artifact mutation and no release approval"
        failures = @()
        comparison_against = $comparisonAgainst
    } | ConvertTo-Json -Compress -Depth 8
} else {
    $passedSummary = [ordered]@{
        status = "passed"
        surface_count = $surfaces.Count
        bundle_sha256 = $bundleSha256
        checksum_verified = $checksumVerified
        trust_boundary = "read_only_observer"
    }
    if ($null -ne $comparisonAgainst) {
        $passedSummary.comparison_against = $comparisonAgainst
    }
    [pscustomobject]$passedSummary | ConvertTo-Json -Compress -Depth 8
}
