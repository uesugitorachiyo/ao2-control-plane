#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install ao2-control-plane as a Windows service via NSSM.

.DESCRIPTION
  Wraps `nssm install ao2-cp-server` with the canonical argument set:
    - binds 127.0.0.1:8744
    - data dir under %ProgramData%\ao2-control-plane\data (or -DataDir)
    - reads AO2_CP_API_TOKEN from a file (or -Token), never from command line
    - rotates stdout/stderr logs under %ProgramData%\ao2-control-plane\logs
    - restarts on crash with a 5-second throttle
    - raises file-descriptor headroom (NSSM AppEnvironmentExtra)

  Requires NSSM 2.24+ on PATH or supplied via -NssmPath.
  Download: https://nssm.cc/download

.PARAMETER BinaryPath
  Absolute path to ao2-cp-server.exe (installed from release archive's bin\ dir).

.PARAMETER DataDir
  Absolute path for the data directory. Created if missing. Defaults to
  $env:ProgramData\ao2-control-plane\data.

.PARAMETER TokenFile
  Path to a file whose first line is the AO2_CP_API_TOKEN value. The token
  is read at install time and written to the service environment. The file
  itself is NOT referenced at runtime; rotate by re-running this script.

.PARAMETER NssmPath
  Optional path to nssm.exe if not on PATH.

.PARAMETER ServiceName
  Service name. Defaults to "ao2-cp-server". Change for side-by-side deploys.

.EXAMPLE
  .\Install-Ao2CpServerService.ps1 `
    -BinaryPath "C:\Program Files\ao2-control-plane\bin\ao2-cp-server.exe" `
    -TokenFile "C:\ProgramData\ao2-control-plane\token.txt"
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)] [string] $BinaryPath,
  [string] $DataDir,
  [Parameter(Mandatory=$true)] [string] $TokenFile,
  [string] $NssmPath,
  [string] $ServiceName = "ao2-cp-server",
  [string] $Bind = "127.0.0.1:8744",
  [string] $LogLevel = "info"
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $BinaryPath)) {
  throw "Binary not found: $BinaryPath"
}

if (-not $DataDir) {
  $DataDir = Join-Path $env:ProgramData "ao2-control-plane\data"
}
$logDir = Join-Path $env:ProgramData "ao2-control-plane\logs"
foreach ($d in @($DataDir, $logDir)) {
  if (-not (Test-Path -LiteralPath $d)) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
  }
}

if (-not (Test-Path -LiteralPath $TokenFile)) {
  throw "Token file not found: $TokenFile (run `openssl rand -hex 32 > <path>` first, then ACL it to admins only)"
}
$token = (Get-Content -LiteralPath $TokenFile -TotalCount 1).Trim()
if ([string]::IsNullOrWhiteSpace($token)) {
  throw "Token file is empty: $TokenFile"
}

if (-not $NssmPath) {
  $cmd = Get-Command nssm -ErrorAction SilentlyContinue
  if (-not $cmd) {
    throw "nssm.exe not on PATH and -NssmPath not supplied. Download from https://nssm.cc/download"
  }
  $NssmPath = $cmd.Source
}

# Refuse to install if forbidden env vars are present in the *machine* scope.
# Service env is overlaid on top of machine env, so a global OPENAI_API_KEY
# would still leak into the process and trip the server's preflight reject.
foreach ($forbidden in @("OPENAI_API_KEY", "ANTHROPIC_API_KEY")) {
  $v = [Environment]::GetEnvironmentVariable($forbidden, "Machine")
  if ($v) {
    throw "Machine environment has $forbidden set. Server preflight will refuse to start. Remove it (setx /M $forbidden """") and re-run."
  }
}

Write-Host "Installing NSSM service '$ServiceName' for $BinaryPath ..."

if (& $NssmPath status $ServiceName 2>$null) {
  Write-Host "Service '$ServiceName' already exists. Stopping and removing first ..."
  & $NssmPath stop $ServiceName confirm | Out-Null
  & $NssmPath remove $ServiceName confirm | Out-Null
}

& $NssmPath install $ServiceName $BinaryPath `
  "--bind" $Bind `
  "--data-dir" $DataDir | Out-Null

& $NssmPath set $ServiceName AppDirectory (Split-Path -Parent $BinaryPath) | Out-Null
& $NssmPath set $ServiceName DisplayName "ao2-control-plane" | Out-Null
& $NssmPath set $ServiceName Description "ao2-control-plane: read-only observer for AO2 evidence (bind=$Bind)" | Out-Null
& $NssmPath set $ServiceName Start SERVICE_AUTO_START | Out-Null
& $NssmPath set $ServiceName AppRestartDelay 5000 | Out-Null
& $NssmPath set $ServiceName AppThrottle 5000 | Out-Null
& $NssmPath set $ServiceName AppExit Default Restart | Out-Null

# Environment — token + log level + log color disable. NSSM expects NUL-separated.
$envBlock = @(
  "AO2_CP_API_TOKEN=$token",
  "AO2_CP_LOG_LEVEL=$LogLevel"
) -join "`0"
& $NssmPath set $ServiceName AppEnvironmentExtra ":$envBlock" | Out-Null

# Stdout/stderr rotating logs (NSSM-native, 10 MB cap, keep 5).
& $NssmPath set $ServiceName AppStdout (Join-Path $logDir "ao2-cp-server.out.log") | Out-Null
& $NssmPath set $ServiceName AppStderr (Join-Path $logDir "ao2-cp-server.err.log") | Out-Null
& $NssmPath set $ServiceName AppRotateFiles 1 | Out-Null
& $NssmPath set $ServiceName AppRotateOnline 1 | Out-Null
& $NssmPath set $ServiceName AppRotateBytes 10485760 | Out-Null

# ACL: only SYSTEM + Administrators may read the data dir or logs.
$acl = Get-Acl $DataDir
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
  "BUILTIN\Administrators", "FullControl",
  "ContainerInherit,ObjectInherit", "None", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
  "NT AUTHORITY\SYSTEM", "FullControl",
  "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($adminRule)
$acl.SetAccessRule($systemRule)
Set-Acl $DataDir $acl
Set-Acl $logDir $acl

Write-Host "Starting service ..."
& $NssmPath start $ServiceName | Out-Null

Start-Sleep -Seconds 2
$state = (& $NssmPath status $ServiceName).Trim()
Write-Host "Service '$ServiceName' state: $state"

if ($state -ne "SERVICE_RUNNING") {
  Write-Warning "Service did not reach SERVICE_RUNNING. Inspect: $logDir"
  exit 1
}

Write-Host ""
Write-Host "Healthcheck:"
try {
  $r = Invoke-WebRequest -Uri "http://$Bind/healthz" -UseBasicParsing -TimeoutSec 5
  Write-Host "  /healthz HTTP $($r.StatusCode): $($r.Content)"
} catch {
  Write-Warning "/healthz probe failed: $_"
  exit 1
}

Write-Host ""
Write-Host "Done. Manage with:"
Write-Host "  nssm status   $ServiceName"
Write-Host "  nssm stop     $ServiceName"
Write-Host "  nssm restart  $ServiceName"
Write-Host "  nssm remove   $ServiceName confirm"
