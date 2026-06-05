# End-to-end smoke for ao2-cp-server on Windows. Acceptance bar for v0.1.
# Windows note: compatible with Windows PowerShell 5.1 and PowerShell 7+.

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location -LiteralPath $Root

function New-SmokeToken {
    $bytes = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return "smoke-" + ([System.BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant())
}

$Token = New-SmokeToken
$Port = if ($env:AO2_CP_PORT) { [int]$env:AO2_CP_PORT } else { 18744 }
$DataDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ao2-cp-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$ServerProcess = $null

function Stop-Server {
    if ($null -ne $script:ServerProcess) {
        try {
            if (!$script:ServerProcess.HasExited) {
                $script:ServerProcess.Kill($true)
            }
        } catch {}
        try { $script:ServerProcess.WaitForExit(5000) | Out-Null } catch {}
        $script:ServerProcess = $null
    }
    if (Test-Path -LiteralPath $DataDir) {
        try { Remove-Item -LiteralPath $DataDir -Recurse -Force -ErrorAction Stop } catch {}
    }
}

try {
    Write-Host "=== build ==="
    & cargo build --release -p ao2-cp-server
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    Write-Host "=== start server ==="
    $serverBinary = Join-Path $Root "target/release/ao2-cp-server.exe"
    if (!(Test-Path -LiteralPath $serverBinary)) {
        $serverBinary = Join-Path $Root "target/release/ao2-cp-server"
    }
    if (!(Test-Path -LiteralPath $serverBinary)) {
        throw "missing ao2-cp-server release binary"
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $serverBinary
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $Root
    # Inherit current environment, then scrub provider API keys and inject smoke config.
    foreach ($entry in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        if ($null -ne $entry.Key) {
            $psi.EnvironmentVariables[$entry.Key] = [string]$entry.Value
        }
    }
    foreach ($key in @("OPENAI_API_KEY", "ANTHROPIC_API_KEY")) {
        if ($psi.EnvironmentVariables.ContainsKey($key)) {
            $psi.EnvironmentVariables.Remove($key) | Out-Null
        }
    }
    $psi.EnvironmentVariables["AO2_CP_API_TOKEN"] = $Token
    $psi.EnvironmentVariables["AO2_CP_BIND"] = "127.0.0.1:$Port"
    $psi.EnvironmentVariables["AO2_CP_DATA_DIR"] = $DataDir

    $script:ServerProcess = [System.Diagnostics.Process]::Start($psi)

    Write-Host "=== wait for healthz ==="
    $ready = $false
    for ($i = 1; $i -le 30; $i++) {
        if ($script:ServerProcess.HasExited) {
            $stdout = $script:ServerProcess.StandardOutput.ReadToEnd()
            $stderr = $script:ServerProcess.StandardError.ReadToEnd()
            if ($stdout) { Write-Host "server stdout:`n$stdout" }
            if ($stderr) { Write-Host "server stderr:`n$stderr" }
            throw "server exited before healthz with code $($script:ServerProcess.ExitCode)"
        }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/healthz" -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                Write-Host "  ready"
                $ready = $true
                break
            }
        } catch {}
        Start-Sleep -Milliseconds 200
    }
    if (-not $ready) {
        throw "server did not become healthy on port $Port"
    }

    $CodexFixture = Join-Path $Root "tests/fixtures/codex-acceptance-v0.4.66.json"
    $ClaudeFixture = Join-Path $Root "tests/fixtures/claude-acceptance-v0.4.66.json"
    $BundleFixture = Join-Path $Root "tests/fixtures/control-plane-bundle-sample.json"
    $BadFixture = Join-Path $Root "tests/fixtures/bad-schema-version.json"

    function Invoke-Post {
        param([string]$Path, [string]$BodyPath)
        $body = [System.IO.File]::ReadAllBytes($BodyPath)
        $headers = @{ "Authorization" = "Bearer $Token" }
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port$Path" `
            -Method Post -Headers $headers -ContentType "application/json" -Body $body
        return ($response.Content | ConvertFrom-Json)
    }

    function Invoke-Get {
        param([string]$Path)
        $headers = @{ "Authorization" = "Bearer $Token" }
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port$Path" -Headers $headers
        return ($response.Content | ConvertFrom-Json)
    }

    function Invoke-Get-Raw {
        param([string]$Path, [string]$OutPath)
        $headers = @{ "Authorization" = "Bearer $Token" }
        Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port$Path" -Headers $headers -OutFile $OutPath | Out-Null
    }

    function Invoke-Post-Expect-Fail {
        param([string]$Path, [string]$BodyPath, [int]$ExpectedStatus)
        $body = [System.IO.File]::ReadAllBytes($BodyPath)
        $headers = @{ "Authorization" = "Bearer $Token" }
        $actual = 0
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port$Path" `
                -Method Post -Headers $headers -ContentType "application/json" -Body $body
            $actual = [int]$response.StatusCode
        } catch [System.Net.WebException] {
            if ($_.Exception.Response) {
                $actual = [int]$_.Exception.Response.StatusCode
            } else {
                throw
            }
        } catch {
            if ($_.Exception.Response) {
                $actual = [int]$_.Exception.Response.StatusCode
            } else {
                throw
            }
        }
        if ($actual -ne $ExpectedStatus) {
            throw "expected $ExpectedStatus, got $actual"
        }
    }

    function Invoke-Get-StatusCode {
        param([string]$Path)
        $headers = @{ "Authorization" = "Bearer $Token" }
        $actual = 0
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port$Path" -Headers $headers
            $actual = [int]$response.StatusCode
        } catch [System.Net.WebException] {
            if ($_.Exception.Response) {
                $actual = [int]$_.Exception.Response.StatusCode
            } else {
                throw
            }
        } catch {
            if ($_.Exception.Response) {
                $actual = [int]$_.Exception.Response.StatusCode
            } else {
                throw
            }
        }
        return $actual
    }

    Write-Host "=== POST codex acceptance ==="
    $codexReceipt = Invoke-Post "/api/v1/acceptance" $CodexFixture
    $codexSha = $codexReceipt.sha256
    Write-Host "  sha=$codexSha"

    Write-Host "=== POST claude acceptance ==="
    $claudeReceipt = Invoke-Post "/api/v1/acceptance" $ClaudeFixture
    $claudeSha = $claudeReceipt.sha256
    Write-Host "  sha=$claudeSha"

    Write-Host "=== POST control-plane bundle ==="
    $bundleReceipt = Invoke-Post "/api/v1/control-plane/bundle" $BundleFixture
    $bundleSha = $bundleReceipt.sha256
    Write-Host "  sha=$bundleSha"

    Write-Host "=== GET /api/v1/acceptance -- expect 2 entries ==="
    $list = Invoke-Get "/api/v1/acceptance"
    $count = $list.total_count
    if ($count -ne 2) { throw "expected 2, got $count" }

    Write-Host "=== GET /api/v1/acceptance/<sha> -- byte-identical ==="
    $fetched = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString("N") + ".json")
    try {
        Invoke-Get-Raw "/api/v1/acceptance/$codexSha" $fetched
        $expectedBytes = [System.IO.File]::ReadAllBytes($CodexFixture)
        $actualBytes = [System.IO.File]::ReadAllBytes($fetched)
        if ($expectedBytes.Length -ne $actualBytes.Length) {
            throw ("byte length mismatch: expected {0}, got {1}" -f $expectedBytes.Length, $actualBytes.Length)
        }
        for ($i = 0; $i -lt $expectedBytes.Length; $i++) {
            if ($expectedBytes[$i] -ne $actualBytes[$i]) {
                throw "byte mismatch at offset $i"
            }
        }
    } finally {
        if (Test-Path -LiteralPath $fetched) { Remove-Item -LiteralPath $fetched -Force }
    }

    Write-Host "=== POST same codex again -- idempotent ==="
    $codexReceipt2 = Invoke-Post "/api/v1/acceptance" $CodexFixture
    if ($codexReceipt2.sha256 -ne $codexSha) {
        throw "sha changed across idempotent posts"
    }
    $listAfter = Invoke-Get "/api/v1/acceptance"
    if ($listAfter.total_count -ne 2) {
        throw "count changed: $($listAfter.total_count)"
    }

    Write-Host "=== POST bad-schema-version -- expect 422 ==="
    Invoke-Post-Expect-Fail "/api/v1/acceptance" $BadFixture 422

    Write-Host "=== tamper test -- modify stored bundle, GET should fail ==="
    $storedFile = Join-Path $DataDir ("acceptance/codex/$codexSha.json")
    [System.IO.File]::WriteAllText($storedFile, '{"tampered":true}')
    $httpCode = Invoke-Get-StatusCode "/api/v1/acceptance/$codexSha"
    if ($httpCode -ne 500) {
        throw "expected 500 on tamper, got $httpCode"
    }

    Write-Host "=== shutdown ==="
    Stop-Server

    Write-Host "=== smoke OK ==="
} finally {
    Stop-Server
}
