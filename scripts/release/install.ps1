$ErrorActionPreference = "Stop"

Set-Location -LiteralPath $PSScriptRoot
$InstallDir = if ($env:AO2_CP_INSTALL_DIR) { $env:AO2_CP_INSTALL_DIR } elseif ($env:AO2_INSTALL_DIR) { $env:AO2_INSTALL_DIR } else { Join-Path $env:USERPROFILE ".local\bin" }
$Names = @("ao2-cp-server.exe", "ao2-cp-gc.exe")
$ReceiptName = "ao2-control-plane.install-receipt.json"

function Get-ExpectedHash([string]$RelativePath) {
    $row = Get-Content -LiteralPath "SHA256SUMS" | Where-Object { $_ -match "  $([regex]::Escape($RelativePath))$" } | Select-Object -First 1
    if (!$row) { throw "missing checksum for $RelativePath" }
    return ($row -split "\s+")[0].ToLowerInvariant()
}

foreach ($Name in $Names) {
    $Source = Join-Path "bin" $Name
    if (!(Test-Path -LiteralPath $Source -PathType Leaf)) { throw "missing packaged binary: $Source" }
    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Source).Hash.ToLowerInvariant()
    if ($Actual -ne (Get-ExpectedHash "bin/$Name")) { throw "checksum mismatch for bin/$Name" }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Stage = Join-Path $InstallDir (".ao2-control-plane.stage." + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Stage | Out-Null
$Moved = @()
$Installed = @()
try {
    $rows = @()
    foreach ($Name in $Names) {
        $Source = Join-Path "bin" $Name
        $Staged = Join-Path $Stage $Name
        Copy-Item -LiteralPath $Source -Destination $Staged
        $Expected = Get-ExpectedHash "bin/$Name"
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Staged).Hash.ToLowerInvariant() -ne $Expected) { throw "checksum mismatch for staged $Name" }
        $Destination = Join-Path $InstallDir $Name
        $Backup = Join-Path $InstallDir ".$Name.ao2-previous"
        $PriorPresent = Test-Path -LiteralPath $Destination -PathType Leaf
        $PriorHash = if ($PriorPresent) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant() } else { $null }
        $rows += [ordered]@{ name=$Name; path=$Destination; sha256=$Expected; prior_present=$PriorPresent; prior_sha256=$PriorHash; backup_path=$Backup }
    }
    $Version = (Get-Content -Raw -LiteralPath "RELEASE-MANIFEST.json" | ConvertFrom-Json).version
    $Receipt = [ordered]@{ schema_version="ao2-control-plane.install-receipt.v1"; operation="install"; version=$Version; install_dir=$InstallDir; binaries=$rows; preserves_data_and_config=$true }
    $Receipt | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $Stage $ReceiptName)

    foreach ($row in $rows) {
        Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $row.backup_path
        if ($row.prior_present) { Move-Item -LiteralPath $row.path -Destination $row.backup_path; $Moved += $row }
    }
    foreach ($Name in $Names) {
        Move-Item -LiteralPath (Join-Path $Stage $Name) -Destination (Join-Path $InstallDir $Name)
        $Installed += $Name
    }
    Move-Item -Force -LiteralPath (Join-Path $Stage $ReceiptName) -Destination (Join-Path $InstallDir $ReceiptName)
} catch {
    foreach ($Name in $Installed) { Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath (Join-Path $InstallDir $Name) }
    foreach ($row in $Moved) { if (Test-Path -LiteralPath $row.backup_path) { Move-Item -LiteralPath $row.backup_path -Destination $row.path } }
    throw
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $Stage
}
Write-Output "ao2_control_plane_installed=$(Join-Path $InstallDir $($Names[0]))"
Write-Output "ao2_control_plane_gc_installed=$(Join-Path $InstallDir $($Names[1]))"
Write-Output "ao2_control_plane_install_receipt=$(Join-Path $InstallDir $ReceiptName)"
