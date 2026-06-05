param(
    [string]$BaseUrl = "http://127.0.0.1:8744",
    [string]$ApiTokenEnv = "AO2_CP_API_TOKEN",
    [Parameter(Mandatory=$true)]
    [string]$OutDir,
    [double]$TimeoutSeconds = 10,
    [switch]$Open
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = Join-Path $ScriptDir "cp_dashboard_snapshot.py"

$ArgsList = @(
    $PythonScript,
    "--base-url", $BaseUrl,
    "--api-token-env", $ApiTokenEnv,
    "--timeout-seconds", "$TimeoutSeconds",
    "--out-dir", $OutDir
)

if ($Open) {
    $ArgsList += "--open"
}

& python @ArgsList
exit $LASTEXITCODE
