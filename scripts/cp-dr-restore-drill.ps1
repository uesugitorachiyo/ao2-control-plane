param(
    [string]$ServerBin,
    [string]$WorkDir,
    [string]$Out,
    [int]$Port,
    [double]$TimeoutSeconds = 15
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = Join-Path $ScriptDir "cp_dr_restore_drill.py"

$ArgsList = @($PythonScript, "--timeout-seconds", "$TimeoutSeconds")

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
