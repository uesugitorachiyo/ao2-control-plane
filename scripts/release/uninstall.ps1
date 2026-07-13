$ErrorActionPreference = "Stop"

$InstallDir = if ($env:AO2_CP_INSTALL_DIR) { $env:AO2_CP_INSTALL_DIR } elseif ($env:AO2_INSTALL_DIR) { $env:AO2_INSTALL_DIR } else { Join-Path $env:USERPROFILE ".local\bin" }
$Owned = @(
    "ao2-cp-server.exe", "ao2-cp-gc.exe", "ao2-control-plane.install-receipt.json",
    ".ao2-control-plane.install-receipt.previous.json",
    ".ao2-cp-server.exe.ao2-previous", ".ao2-cp-gc.exe.ao2-previous",
    ".ao2-cp-server.exe.ao2-rollback-current", ".ao2-cp-gc.exe.ao2-rollback-current"
)
foreach ($Name in $Owned) { Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath (Join-Path $InstallDir $Name) }
Write-Output "ao2_control_plane_uninstall=passed"
Write-Output "ao2_control_plane_data_config_preserved=true"
