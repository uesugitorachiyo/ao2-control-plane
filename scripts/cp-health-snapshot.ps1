param(
    [string]$BaseUrl = "http://127.0.0.1:8744",
    [string]$ApiTokenEnv = "AO2_CP_API_TOKEN",
    [string]$HealthzJson,
    [string]$LogDir,
    [string]$Out,
    [double]$TimeoutSeconds = 10
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = Join-Path $ScriptDir "cp_health_snapshot.py"

$ArgsList = @(
    $PythonScript,
    "--base-url", $BaseUrl,
    "--api-token-env", $ApiTokenEnv,
    "--timeout-seconds", "$TimeoutSeconds"
)

if ($HealthzJson) {
    $ArgsList += @("--healthz-json", $HealthzJson)
}
if ($LogDir) {
    $ArgsList += @("--log-dir", $LogDir)
}
if ($Out) {
    $ArgsList += @("--out", $Out)
}

& python @ArgsList
exit $LASTEXITCODE
