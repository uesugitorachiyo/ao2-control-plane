param(
    [string]$ServerBin,
    [string]$WorkDir,
    [string]$Out,
    [int]$Port,
    [double]$TimeoutSeconds = 15,
    [int]$MaxBytes = 4096,
    [int]$Requests = 80
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = Join-Path $ScriptDir "cp_audit_log_rotation_drill.py"

$ArgsList = @(
    $PythonScript,
    "--timeout-seconds", "$TimeoutSeconds",
    "--max-bytes", "$MaxBytes",
    "--requests", "$Requests"
)

if ($ServerBin) {
    $ArgsList += @("--server-bin", $ServerBin)
}
if ($WorkDir) {
    $ArgsList += @("--work-dir", $WorkDir)
}
if ($Out) {
    $ArgsList += @("--out", $Out)
}
if ($Port) {
    $ArgsList += @("--port", "$Port")
}

& python @ArgsList
exit $LASTEXITCODE
