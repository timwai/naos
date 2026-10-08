# Non-destructive smoke; requires Windows curl.exe and a running NAOS instance.
param(
  [string]$BaseUrl = "http://127.0.0.1:8443"
)

$ErrorActionPreference = "Stop"
$base = $BaseUrl.TrimEnd("/")
if ($base -notmatch '^https?://') {
  throw "Usage: .\\acceptance-smoke.ps1 [-BaseUrl http(s)://host:port]"
}
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
  throw "curl.exe is required"
}

function Get-Naos([string]$Route) {
  $text = & curl.exe --fail --silent --show-error --max-time 10 "$base$Route"
  if ($LASTEXITCODE -ne 0) {
    throw "GET $Route failed"
  }
  return ($text | Out-String)
}

$null = Get-Naos "/health/live"
Write-Host "OK: process liveness"
$null = Get-Naos "/health/ready"
Write-Host "OK: dependency readiness"

$root = Get-Naos "/"
if (-not $root.Contains('<div id="root"></div>')) {
  throw "embedded SPA root is absent"
}
$files = Get-Naos "/files"
if ($root -ne $files) {
  throw "SPA deep-link fallback differs from homepage"
}
Write-Host "OK: SPA homepage and deep-link"

$null = Get-Naos "/assets/app.js"
$null = Get-Naos "/assets/app.css"
Write-Host "OK: embedded assets"

$session = Get-Naos "/api/v1/auth/session"
if ($session -notmatch '"authenticated"\s*:\s*false') {
  throw "anonymous session is not explicitly unauthenticated"
}
Write-Host "OK: anonymous auth/session"

$status = & curl.exe --silent --show-error --max-time 10 --output NUL --write-out "%{http_code}" "$base/api/v1/this-route-must-not-exist"
if ($LASTEXITCODE -ne 0 -or $status -ne "404") {
  throw "reserved /api prefix returned HTTP $status rather than 404"
}
Write-Host "PASS: portable NAOS HTTP/SPA smoke; no resources were modified"
Write-Host "NOTE: this does not validate SMB/WebDAV/NFS, TLS, ACLs or recovery; see README-DEPLOY.md"
