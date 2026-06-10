param(
    [Parameter(Mandatory = $true)]
    [string]$BaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$OutDir,

    [string]$AuthEnv = "AO2_CP_AUTH_VALUE",
    [int]$KeepLatest = -1,
    [int]$TimeoutSec = 30,
    [switch]$IncludePhase1Portable
)

$ErrorActionPreference = "Stop"

# Fetch token-safe AO2 Control Plane release support handoff artifacts on Windows.
# The bearer value is read from an environment variable, sent only as an HTTP
# header, and never written to disk or echoed in summaries.

$ReleaseEndpoints = [ordered]@{
    "release-support-verifier-handoff.json" = "/api/v1/release/support-bundle/handoff.json"
    "release-support-bundle.json" = "/api/v1/release/support-bundle/download"
    "SHA256SUMS" = "/api/v1/release/support-bundle/SHA256SUMS"
    "release-support-bundle-verify.json" = "/api/v1/release/support-bundle/verify.json"
    "release-support-bundle-manifest.json" = "/api/v1/release/support-bundle/manifest.json"
}

$Phase1Endpoints = [ordered]@{
    "phase1-portable-manifest.json" = "/api/v1/phase1/promotion/portable-manifest/download"
    "ao2-phase1-operator-support-bundle.json" = "/api/v1/phase1/promotion/operator-support-bundle/download"
    "ao2-phase1-gap-report.json" = "/api/v1/phase1/promotion/gap-report/download"
    "phase1-SHA256SUMS" = "/api/v1/phase1/promotion/portable-manifest/SHA256SUMS"
}

$Phase1VerifyEndpoint = "/api/v1/phase1/promotion/portable-manifest/verify.json"

$RequiredCiEvidenceFamilyIds = @(
    "risky-pr-golden-bridge-smoke",
    "release-train-bridge-smoke",
    "ingest-smoke",
    "release-archive-smoke",
    "backup-restore-drill"
)

$SecretMarkerPatterns = [ordered]@{
    authorization_bearer_header = '(?i)authorization\s*[:=]\s*bearer\s+[^\s"'']+'
    ao2_cp_api_token_assignment = '(?i)AO2_CP_API_TOKEN\s*='
    openai_api_key_assignment = '(?i)OPENAI_API_KEY\s*='
    anthropic_api_key_assignment = '(?i)ANTHROPIC_API_KEY\s*='
    json_api_token_field = '(?i)"(?:api_token|access_token|refresh_token|token)"\s*:\s*"[^"]+"'
}

function Get-AuthorizationValue {
    param([string]$Name)
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "missing authorization value in `$env:$Name; expected full header value like 'Bearer ...'"
    }
    if (!$value.StartsWith("Bearer ", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "`$env:$Name must contain a bearer-style authorization header value"
    }
    return $value
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
        return ([System.BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Build-Url {
    param([string]$Base, [string]$Path, [int]$KeepLatestValue)
    $url = $Base.TrimEnd('/') + $Path
    if ($KeepLatestValue -ge 0) {
        $url = $url + "?keep_latest=$KeepLatestValue"
    }
    return $url
}

function Get-HeaderValue {
    param($Headers, [string[]]$Names)
    foreach ($name in $Names) {
        if ($Headers.ContainsKey($name)) {
            return [string]$Headers[$name]
        }
        $match = $Headers.Keys | Where-Object { $_ -ieq $name } | Select-Object -First 1
        if ($match) {
            return [string]$Headers[$match]
        }
    }
    return $null
}

function Invoke-Fetch {
    param(
        [string]$Url,
        [string]$Authorization,
        [int]$TimeoutSeconds,
        [byte[]]$Body = $null
    )
    $headers = @{ Authorization = $Authorization; Accept = "application/json" }
    $params = @{
        Uri = $Url
        Headers = $headers
        TimeoutSec = $TimeoutSeconds
        UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $params["Method"] = "POST"
        $params["Body"] = $Body
        $params["ContentType"] = "application/json"
    } else {
        $params["Method"] = "GET"
    }
    return Invoke-WebRequest @params
}

function Write-ResponseBytes {
    param($Response, [string]$Path)
    if ($null -ne $Response.RawContentStream) {
        $stream = $Response.RawContentStream
        if ($stream.CanSeek) { $stream.Position = 0 }
        $memory = New-Object System.IO.MemoryStream
        $stream.CopyTo($memory)
        $bytes = $memory.ToArray()
    } else {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Response.Content)
    }
    [System.IO.File]::WriteAllBytes($Path, $bytes)
    return $bytes
}

function Fetch-EndpointSet {
    param(
        [hashtable]$Endpoints,
        [string]$Base,
        [string]$OutPath,
        [string]$Authorization,
        [int]$KeepLatestValue,
        [int]$TimeoutSeconds,
        [string[]]$DigestHeaders
    )
    $items = @()
    foreach ($entry in $Endpoints.GetEnumerator()) {
        $filename = [string]$entry.Key
        $endpoint = [string]$entry.Value
        $url = Build-Url -Base $Base -Path $endpoint -KeepLatestValue $KeepLatestValue
        $response = Invoke-Fetch -Url $url -Authorization $Authorization -TimeoutSeconds $TimeoutSeconds
        $path = Join-Path $OutPath $filename
        $bytes = Write-ResponseBytes -Response $response -Path $path
        $items += [ordered]@{
            filename = $filename
            endpoint = $endpoint
            bytes = $bytes.Length
            sha256 = Get-Sha256Hex -Bytes $bytes
            content_type = Get-HeaderValue -Headers $response.Headers -Names @("Content-Type", "content-type")
            digest_header = Get-HeaderValue -Headers $response.Headers -Names $DigestHeaders
        }
    }
    return $items
}

function Read-JsonFile {
    param([string]$Path)
    return (Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -Depth 100)
}

function ConvertTo-JsonBytes {
    param($Value)
    $json = $Value | ConvertTo-Json -Depth 100
    return [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
}

function Write-Phase1PortableHandoff {
    param(
        [string]$Base,
        [string]$OutPath,
        [string]$Authorization,
        [int]$KeepLatestValue,
        [int]$TimeoutSeconds
    )
    $fetched = @(Fetch-EndpointSet -Endpoints $Phase1Endpoints -Base $Base -OutPath $OutPath -Authorization $Authorization -KeepLatestValue $KeepLatestValue -TimeoutSeconds $TimeoutSeconds -DigestHeaders @("x-ao2-cp-portable-manifest-sha256", "x-ao2-cp-support-bundle-sha256", "x-ao2-cp-gap-report-sha256"))

    $manifestPath = Join-Path $OutPath "phase1-portable-manifest.json"
    $manifest = Read-JsonFile -Path $manifestPath
    $artifacts = [ordered]@{}
    foreach ($artifact in @($manifest.artifacts)) {
        $name = [string]$artifact.name
        $filename = [string]$artifact.filename
        if (![string]::IsNullOrWhiteSpace($name) -and ![string]::IsNullOrWhiteSpace($filename)) {
            $artifactPath = Join-Path $OutPath $filename
            if (Test-Path -LiteralPath $artifactPath) {
                $artifacts[$name] = Read-JsonFile -Path $artifactPath
            }
        }
    }

    $upload = [ordered]@{
        schema_version = "ao2.cp-phase1-portable-manifest-verification-upload.v1"
        manifest = $manifest
        artifacts = $artifacts
        trust_boundary = [ordered]@{
            role = "read_only_observer"
            mutates_ao_artifacts = $false
            release_acceptance_owner = "factory-v3 evaluator-closer"
        }
    }
    $uploadPath = Join-Path $OutPath "phase1-portable-manifest-verify-upload.json"
    $uploadBytes = ConvertTo-JsonBytes -Value $upload
    [System.IO.File]::WriteAllBytes($uploadPath, $uploadBytes)

    $verifyUrl = Build-Url -Base $Base -Path $Phase1VerifyEndpoint -KeepLatestValue $KeepLatestValue
    $verifyResponse = Invoke-Fetch -Url $verifyUrl -Authorization $Authorization -TimeoutSeconds $TimeoutSeconds -Body $uploadBytes
    $verifyPath = Join-Path $OutPath "phase1-portable-manifest-verification.json"
    $verifyBytes = Write-ResponseBytes -Response $verifyResponse -Path $verifyPath
    $verification = Read-JsonFile -Path $verifyPath

    $fetched += [ordered]@{
        filename = "phase1-portable-manifest-verify-upload.json"
        endpoint = "local-generated-upload"
        bytes = $uploadBytes.Length
        sha256 = Get-Sha256Hex -Bytes $uploadBytes
        content_type = "application/json; charset=utf-8"
        digest_header = $null
    }
    $fetched += [ordered]@{
        filename = "phase1-portable-manifest-verification.json"
        endpoint = $Phase1VerifyEndpoint
        bytes = $verifyBytes.Length
        sha256 = Get-Sha256Hex -Bytes $verifyBytes
        content_type = Get-HeaderValue -Headers $verifyResponse.Headers -Names @("Content-Type", "content-type")
        digest_header = $null
    }

    return [ordered]@{
        status = if ($verification.status -eq "verified") { "passed" } else { "failed" }
        fetched = $fetched
        verification_status = $verification.status
        verification_upload = "phase1-portable-manifest-verify-upload.json"
        verification_result = "phase1-portable-manifest-verification.json"
        trust_boundary = "read-only observer; does not mutate AO artifacts or approve releases"
    }
}

function Test-HandoffArtifacts {
    param([string]$OutPath)
    $failures = @()
    $handoffPath = Join-Path $OutPath "release-support-verifier-handoff.json"
    if (Test-Path -LiteralPath $handoffPath) {
        $handoff = Read-JsonFile -Path $handoffPath
        if ($handoff.schema_version -ne "ao2.cp-release-support-verifier-handoff.v1") { $failures += "handoff schema_version is not ao2.cp-release-support-verifier-handoff.v1" }
        if ($handoff.control_plane_role -ne "read_only_observer") { $failures += "handoff control_plane_role must remain read_only_observer" }
        if ($handoff.release_acceptance_owner -ne "factory-v3 evaluator-closer") { $failures += "handoff release_acceptance_owner must remain factory-v3 evaluator-closer" }
        if ($handoff.control_plane_approves_release -ne $false) { $failures += "handoff must not approve releases" }
        if ($handoff.mutates_ao_artifacts -ne $false) { $failures += "handoff must not mutate AO artifacts" }
        if ($handoff.contains_bearer_token -ne $false) { $failures += "handoff must declare contains_bearer_token=false" }
    }
    foreach ($file in Get-ChildItem -LiteralPath $OutPath -File) {
        if ($file.Name -eq "fetch-summary.json") { continue }
        $raw = Get-Content -Raw -LiteralPath $file.FullName -ErrorAction SilentlyContinue
        foreach ($marker in $SecretMarkerPatterns.GetEnumerator()) {
            if ($raw -match $marker.Value) {
                $failures += "$($file.Name): forbidden marker $($marker.Key)"
            }
        }
    }
    return $failures
}

function Test-SecretMarkersInFile {
    param([string]$Path)
    $failures = @()
    if (!(Test-Path -LiteralPath $Path)) {
        return $failures
    }
    $raw = Get-Content -Raw -LiteralPath $Path -ErrorAction SilentlyContinue
    foreach ($marker in $SecretMarkerPatterns.GetEnumerator()) {
        if ($raw -match $marker.Value) {
            $failures += "$(Split-Path -Leaf $Path): forbidden marker $($marker.Key)"
        }
    }
    return $failures
}

function Get-CiEvidenceIndexFetchSummary {
    param([string]$OutPath)

    $bundlePath = Join-Path $OutPath "release-support-bundle.json"
    if (!(Test-Path -LiteralPath $bundlePath)) {
        return [pscustomobject][ordered]@{
            verified = $false
            status = "missing_bundle"
            surface_count = 0
            family_count = 0
            required_family_count = $RequiredCiEvidenceFamilyIds.Count
            required_families_present = $false
            missing_families = $RequiredCiEvidenceFamilyIds
            token_hygiene_status = "failed"
            failures = @("release-support-bundle.json not found")
        }
    }

    $failures = @()
    $bundle = Read-JsonFile -Path $bundlePath
    $surfaces = @()
    if ($null -ne $bundle.portable_bundle_manifest -and $null -ne $bundle.portable_bundle_manifest.included_surfaces) {
        $surfaces = @($bundle.portable_bundle_manifest.included_surfaces)
    }
    $surfaceCount = $surfaces.Count
    $hasCiSurface = $false
    foreach ($surface in $surfaces) {
        if ($null -ne $surface -and $surface.id -eq "ci_evidence_index") {
            $hasCiSurface = $true
            break
        }
    }
    if (!$hasCiSurface) {
        $failures += "portable_bundle_manifest.included_surfaces missing ci_evidence_index"
    }

    $ciIndex = $bundle.ci_evidence_index
    if ($null -eq $ciIndex) {
        return [pscustomobject][ordered]@{
            verified = $false
            status = "missing_ci_evidence_index"
            surface_count = $surfaceCount
            family_count = 0
            required_family_count = $RequiredCiEvidenceFamilyIds.Count
            required_families_present = $false
            missing_families = $RequiredCiEvidenceFamilyIds
            token_hygiene_status = "failed"
            failures = @("ci_evidence_index missing from release support bundle")
        }
    }

    if ($ciIndex.schema_version -ne "ao2.cp-ci-evidence-index.v1") {
        $failures += "ci_evidence_index schema_version is not ao2.cp-ci-evidence-index.v1"
    }
    if ($ciIndex.control_plane_role -ne "read-only-observer") {
        $failures += "ci_evidence_index control_plane_role is not read-only-observer"
    }
    if ($ciIndex.mutates_ao_artifacts -ne $false) {
        $failures += "ci_evidence_index mutates_ao_artifacts must remain false"
    }
    if ($ciIndex.control_plane_approves_release -ne $false) {
        $failures += "ci_evidence_index control_plane_approves_release must remain false"
    }

    $families = @()
    if ($null -ne $ciIndex.evidence_families) {
        $families = @($ciIndex.evidence_families)
    }
    $familyIds = @{}
    foreach ($family in $families) {
        if ($null -ne $family -and ![string]::IsNullOrWhiteSpace([string]$family.id)) {
            $familyIds[[string]$family.id] = $true
        }
    }
    $missingFamilies = @()
    foreach ($familyId in $RequiredCiEvidenceFamilyIds) {
        if (!$familyIds.ContainsKey($familyId)) {
            $missingFamilies += $familyId
        }
    }
    if ($missingFamilies.Count -gt 0) {
        $failures += "ci_evidence_index missing required families: $($missingFamilies -join ', ')"
    }

    $auth = $ciIndex.auth
    $tokenHygieneOk = (
        $null -ne $auth -and
        $auth.credential_material_included -eq $false -and
        $auth.credential_material_in_urls -eq $false -and
        @(Test-SecretMarkersInFile -Path $bundlePath).Count -eq 0
    )
    if (!$tokenHygieneOk) {
        $failures += "ci_evidence_index token hygiene check failed"
    }

    $verified = $failures.Count -eq 0
    return [pscustomobject][ordered]@{
        verified = $verified
        status = if ($verified) { "passed" } else { "failed" }
        schema_version = $ciIndex.schema_version
        surface_count = $surfaceCount
        family_count = $families.Count
        required_family_count = $RequiredCiEvidenceFamilyIds.Count
        required_families_present = $missingFamilies.Count -eq 0
        missing_families = $missingFamilies
        token_hygiene_status = if ($tokenHygieneOk) { "passed" } else { "failed" }
        auth_credential_material_included = if ($null -ne $auth) { $auth.credential_material_included } else { $null }
        auth_credential_material_in_urls = if ($null -ne $auth) { $auth.credential_material_in_urls } else { $null }
        control_plane_role = $ciIndex.control_plane_role
        mutates_ao_artifacts = $ciIndex.mutates_ao_artifacts
        control_plane_approves_release = $ciIndex.control_plane_approves_release
        failures = $failures
    }
}

$summary = [pscustomobject][ordered]@{
    schema_version = "ao2.cp-release-support-fetch-summary.v1"
    base_url = $BaseUrl.TrimEnd('/')
    keep_latest = if ($KeepLatest -ge 0) { $KeepLatest } else { $null }
    auth_source_env = $AuthEnv
    auth_value_stored = $false
    control_plane_role = "read_only_observer"
    release_acceptance_owner = "factory-v3 evaluator-closer"
    mutates_ao_artifacts = $false
    control_plane_approves_release = $false
    status = "failed"
    fetched = @()
    offline_verifier = [pscustomobject][ordered]@{ status = "not_run"; reason = "PowerShell fetcher only captures handoff artifacts; run Verify-ReleaseSupportBundle.ps1 separately for offline bundle verification" }
    ci_evidence_index_verified = $false
    ci_evidence_index_surface_count = 0
    ci_evidence_index_family_count = 0
    ci_evidence_index_token_hygiene_status = "not_run"
    ci_evidence_index = [pscustomobject][ordered]@{
        verified = $false
        status = "not_run"
        surface_count = 0
        family_count = 0
        required_family_count = $RequiredCiEvidenceFamilyIds.Count
        required_families_present = $false
        token_hygiene_status = "not_run"
    }
    phase1_portable_handoff = [pscustomobject][ordered]@{ status = "not_requested" }
    failures = @()
}

try {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $authorization = Get-AuthorizationValue -Name $AuthEnv
    $summary.fetched = @(Fetch-EndpointSet -Endpoints $ReleaseEndpoints -Base $BaseUrl -OutPath $OutDir -Authorization $authorization -KeepLatestValue $KeepLatest -TimeoutSeconds $TimeoutSec -DigestHeaders @("x-ao2-cp-support-bundle-sha256", "x-ao2-cp-sha256"))
    $summary.ci_evidence_index = Get-CiEvidenceIndexFetchSummary -OutPath $OutDir
    $summary.ci_evidence_index_verified = $summary.ci_evidence_index.verified
    $summary.ci_evidence_index_surface_count = $summary.ci_evidence_index.surface_count
    $summary.ci_evidence_index_family_count = $summary.ci_evidence_index.family_count
    $summary.ci_evidence_index_token_hygiene_status = $summary.ci_evidence_index.token_hygiene_status
    if ($IncludePhase1Portable) {
        $summary.phase1_portable_handoff = Write-Phase1PortableHandoff -Base $BaseUrl -OutPath $OutDir -Authorization $authorization -KeepLatestValue $KeepLatest -TimeoutSeconds $TimeoutSec
    }
    $failures = @(Test-HandoffArtifacts -OutPath $OutDir)
    if ($summary.ci_evidence_index.status -eq "failed") {
        $failures += "CI evidence index verification failed"
    }
    if ($summary.phase1_portable_handoff.status -eq "failed") {
        $failures += "phase1 portable manifest verification failed"
    }
    $summary.failures = $failures
    $summary.status = if ($failures.Count -eq 0) { "passed" } else { "failed" }
} catch {
    $summary.failures = @("fetch failed: $($_.Exception.GetType().Name): $($_.Exception.Message)")
} finally {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $summaryJson = $summary | ConvertTo-Json -Depth 100
    Set-Content -LiteralPath (Join-Path $OutDir "fetch-summary.json") -Value ($summaryJson + "`n") -Encoding UTF8
}

$printable = [ordered]@{
    status = $summary.status
    out_dir = $OutDir
    fetched_files = @($summary.fetched | ForEach-Object { $_.filename })
    offline_verifier_status = $summary.offline_verifier.status
    ci_evidence_index_verified = $summary.ci_evidence_index_verified
    phase1_portable_handoff_status = $summary.phase1_portable_handoff.status
    failures = $summary.failures
}
Write-Output (($printable | ConvertTo-Json -Depth 20 -Compress))
if ($summary.status -eq "passed") { exit 0 } else { exit 1 }
