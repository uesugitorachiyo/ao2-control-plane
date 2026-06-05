# Stream the ao2-control-plane audit-log NDJSON to stdout for
# downstream log shippers (Vector, Fluent Bit, NXLog, etc.) that
# expect newline-delimited JSON on their stdin.
#
# Usage:
#   scripts\ship-audit-log.ps1 [-BaseUrl URL] [-Token VAL] [-Path PATH]
#                              [-IncludeRotated] [-Follow]
#
# Parameters:
#   -BaseUrl <string>    Control-plane base URL.
#                        Default: http://127.0.0.1:8744
#   -Token <string>      Bearer token. If omitted, reads
#                        $env:AO2_CP_API_TOKEN. Never printed
#                        to stdout or stderr.
#   -Path <string>       Skip the /api/v1/status round-trip and
#                        use this NDJSON path directly.
#                        Default: $env:AO2_CP_AUDIT_LOG_FILE
#   -IncludeRotated      Emit the contents of <path>.1 (if it
#                        exists) before the live file.
#   -Follow              Tail the live file continuously
#                        (Get-Content -Wait). Without this flag,
#                        the live file is read once and the
#                        script exits.
#
# Exit codes:
#   0  success
#   2  missing or invalid argument
#   3  /api/v1/status round-trip failed
#   4  persistence is not enabled on the target server
#   5  live NDJSON file does not exist
#
# Trust boundary:
#   This helper is a read-only observer. It does not ingest,
#   approve, or mutate AO artifacts. It only reads NDJSON the
#   server has already written to disk and copies it to stdout.
#
# Security:
#   The bearer is only forwarded as an `Authorization` header
#   on the /api/v1/status round-trip; it is never written to
#   stdout, stderr, or any URL. The audit-log NDJSON itself
#   does not contain bearer values (the server strips them at
#   write time).
param(
    [string]$BaseUrl = 'http://127.0.0.1:8744',
    [string]$Token,
    [string]$Path,
    [switch]$IncludeRotated,
    [switch]$Follow
)

$ErrorActionPreference = 'Stop'

if (-not $Token) {
    $Token = $env:AO2_CP_API_TOKEN
}
if (-not $Path) {
    $Path = $env:AO2_CP_AUDIT_LOG_FILE
}

function Resolve-PathViaStatus {
    if (-not $Token) {
        [Console]::Error.WriteLine('ship-audit-log: bearer required (set $env:AO2_CP_API_TOKEN or pass -Token)')
        exit 2
    }
    $statusUrl = "$BaseUrl/api/v1/status"
    try {
        $response = Invoke-WebRequest -Uri $statusUrl `
            -Headers @{ 'Authorization' = "Bearer $Token" } `
            -UseBasicParsing -ErrorAction Stop
    } catch {
        [Console]::Error.WriteLine("ship-audit-log: GET $statusUrl failed")
        exit 3
    }
    try {
        $json = $response.Content | ConvertFrom-Json -ErrorAction Stop
    } catch {
        [Console]::Error.WriteLine('ship-audit-log: /api/v1/status response is not valid JSON')
        exit 3
    }
    $enabled = $json.audit_log.persistence.enabled
    if ($enabled -ne $true) {
        [Console]::Error.WriteLine("ship-audit-log: audit-log persistence is not enabled on $BaseUrl")
        exit 4
    }
    $resolved = $json.audit_log.persistence.path
    if (-not $resolved) {
        [Console]::Error.WriteLine('ship-audit-log: /api/v1/status returned persistence.enabled=true with empty path')
        exit 3
    }
    return [string]$resolved
}

if ($Path) {
    $LivePath = $Path
} else {
    $LivePath = Resolve-PathViaStatus
}

$RotatedPath = "$LivePath.1"

if ($IncludeRotated -and (Test-Path -LiteralPath $RotatedPath)) {
    Get-Content -LiteralPath $RotatedPath
}

if (-not (Test-Path -LiteralPath $LivePath)) {
    [Console]::Error.WriteLine("ship-audit-log: live NDJSON file does not exist: $LivePath")
    exit 5
}

if ($Follow) {
    # -Wait re-opens by name when the server rotates the file
    # (Windows allows rename of an open-for-read file, and
    # Get-Content tracks the file by path), so the stream keeps
    # producing across rotation events without operator action.
    Get-Content -LiteralPath $LivePath -Wait
} else {
    Get-Content -LiteralPath $LivePath
}
