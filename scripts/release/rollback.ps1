$ErrorActionPreference = "Stop"

$InstallDir = if ($env:AO2_CP_INSTALL_DIR) { $env:AO2_CP_INSTALL_DIR } elseif ($env:AO2_INSTALL_DIR) { $env:AO2_INSTALL_DIR } else { Join-Path $env:USERPROFILE ".local\bin" }
$ReceiptPath = Join-Path $InstallDir "ao2-control-plane.install-receipt.json"
if (!(Test-Path -LiteralPath $ReceiptPath -PathType Leaf)) { throw "missing install receipt: $ReceiptPath" }
$Receipt = Get-Content -Raw -LiteralPath $ReceiptPath | ConvertFrom-Json
if ($Receipt.schema_version -ne "ao2-control-plane.install-receipt.v1") { throw "unsupported install receipt schema" }

$Stage = Join-Path $InstallDir (".ao2-control-plane.rollback." + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Stage | Out-Null
$Moved = @()
try {
    foreach ($row in $Receipt.binaries) {
        if ($row.prior_present) {
            if (!(Test-Path -LiteralPath $row.backup_path -PathType Leaf)) { throw "missing rollback backup: $($row.backup_path)" }
            if ((Get-FileHash -Algorithm SHA256 -LiteralPath $row.backup_path).Hash.ToLowerInvariant() -ne $row.prior_sha256) { throw "checksum mismatch for $($row.backup_path)" }
            Copy-Item -LiteralPath $row.backup_path -Destination (Join-Path $Stage $row.name)
        }
    }
    foreach ($row in $Receipt.binaries) {
        $CurrentBackup = Join-Path $InstallDir ".$($row.name).ao2-rollback-current"
        Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $CurrentBackup
        if (Test-Path -LiteralPath $row.path) { Move-Item -LiteralPath $row.path -Destination $CurrentBackup; $Moved += [ordered]@{ row=$row; current=$CurrentBackup } }
        if ($row.prior_present) { Move-Item -LiteralPath (Join-Path $Stage $row.name) -Destination $row.path }
    }
    $Receipt.operation = "rollback"
    $Receipt | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -LiteralPath $ReceiptPath
} catch {
    foreach ($item in $Moved) {
        Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $item.row.path
        if (Test-Path -LiteralPath $item.current) { Move-Item -LiteralPath $item.current -Destination $item.row.path }
    }
    throw
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $Stage
}
Write-Output "ao2_control_plane_rollback=passed"
Write-Output "ao2_control_plane_install_receipt=$ReceiptPath"
