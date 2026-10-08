#!/usr/bin/env bash
# Non-destructive, unauthenticated smoke for an already running NAOS instance.
set -euo pipefail

base="${1:-http://127.0.0.1:8443}"
base="${base%/}"
case "$base" in
  http://*|https://*) ;;
  *) echo "Usage: $0 [http(s)://host:port]" >&2; exit 2 ;;
esac

command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

check() {
  printf 'Checking %s ... ' "$1"
  shift
  "$@"
  echo "OK"
}

check 'process liveness' curl -fsS --max-time 10 "$base/health/live" -o "$tmpdir/live"
check 'dependency readiness' curl -fsS --max-time 10 "$base/health/ready" -o "$tmpdir/ready"
check 'embedded homepage' curl -fsS --max-time 10 "$base/" -o "$tmpdir/index"
grep -q '<div id="root"></div>' "$tmpdir/index" || {
  echo "embedded SPA root is absent" >&2
  exit 1
}

check 'SPA deep-link' curl -fsS --max-time 10 "$base/files" -o "$tmpdir/deep-link"
cmp -s "$tmpdir/index" "$tmpdir/deep-link" || {
  echo "BrowserRouter fallback differs from homepage" >&2
  exit 1
}
check 'embedded JavaScript' curl -fsS --max-time 10 "$base/assets/app.js" -o /dev/null
check 'embedded stylesheet' curl -fsS --max-time 10 "$base/assets/app.css" -o /dev/null
check 'unauthenticated session endpoint' curl -fsS --max-time 10 "$base/api/v1/auth/session" -o "$tmpdir/session"
grep -Eq '"authenticated"[[:space:]]*:[[:space:]]*false' "$tmpdir/session" || {
  echo "anonymous session is not explicitly unauthenticated" >&2
  exit 1
}

status="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "$base/api/v1/this-route-must-not-exist")"
if [ "$status" != "404" ]; then
  echo "reserved /api prefix returned HTTP $status rather than 404" >&2
  exit 1
fi

echo "PASS: portable NAOS HTTP/SPA smoke; no resources were modified"
echo "NOTE: this does not validate SMB/WebDAV/NFS, TLS, ACLs or recovery; see README-DEPLOY.md"
