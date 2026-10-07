#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "real NFS smoke test must run as root because it performs a kernel mount" >&2
  exit 2
fi

OS="$(uname -s)"
case "$OS" in
  Linux)
    for command in mount umount mount.nfs grep cmp mv rm mkdir rmdir sync; do
      command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 3
      }
    done
    ;;
  Darwin)
    for command in mount_nfs umount grep cmp mv rm mkdir rmdir sync; do
      command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 3
      }
    done
    ;;
  *)
    echo "unsupported NFS smoke-test host: $OS" >&2
    exit 3
    ;;
esac

SERVER="${NAOS_NFS_SMOKE_SERVER:-}"
if [[ -z "$SERVER" || ! -x "$SERVER" ]]; then
  echo "NAOS_NFS_SMOKE_SERVER must point to an executable nfs-smoke-server binary" >&2
  exit 4
fi

NFS_PORT="${NAOS_NFS_SMOKE_NFS_PORT:-32049}"
MOUNT_PORT="${NAOS_NFS_SMOKE_MOUNT_PORT:-32048}"
ROOT="$(mktemp -d)"
SHARE="$ROOT/share"
MOUNTPOINT="$ROOT/mnt"
SERVER_LOG="$ROOT/server.log"
SERVER_PID=""
MOUNTED=0

cleanup() {
  local status=$?
  set +e
  if [[ "$MOUNTED" -eq 1 ]]; then
    umount "$MOUNTPOINT"
  fi
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID"
    wait "$SERVER_PID" 2>/dev/null
  fi
  if [[ "$status" -ne 0 && -f "$SERVER_LOG" ]]; then
    echo "----- naos NFS smoke server log -----" >&2
    cat "$SERVER_LOG" >&2
  fi
  rm -rf "$ROOT"
  exit "$status"
}
trap cleanup EXIT

mkdir -p "$SHARE" "$MOUNTPOINT"

"$SERVER" "$SHARE" "$NFS_PORT" "$MOUNT_PORT" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

mount_export() {
  case "$OS" in
    Linux)
      local options="vers=3,proto=tcp,mountproto=tcp,port=$NFS_PORT,mountport=$MOUNT_PORT,nolock,soft,timeo=10,retrans=2"
      mount -t nfs -o "$options" "127.0.0.1:/ci-share" "$MOUNTPOINT"
      ;;
    Darwin)
      local options="vers=3,tcp,port=$NFS_PORT,mountport=$MOUNT_PORT,nolocks,soft,timeo=10,retrans=2"
      mount_nfs -o "$options" "127.0.0.1:/ci-share" "$MOUNTPOINT"
      ;;
  esac
}

READY=0
attempt=0
while [[ "$attempt" -lt 80 ]]; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "NFS smoke server exited before the client could mount" >&2
    exit 5
  fi
  if mount_export >/dev/null 2>&1; then
    READY=1
    MOUNTED=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done

if [[ "$READY" -ne 1 ]]; then
  echo "$OS kernel NFSv3 client could not mount the naos export" >&2
  exit 6
fi

printf 'created\n' >"$MOUNTPOINT/roundtrip.txt"
sync
printf 'created\n' >"$ROOT/expected-created.txt"
cmp "$ROOT/expected-created.txt" "$MOUNTPOINT/roundtrip.txt"
cmp "$ROOT/expected-created.txt" "$SHARE/roundtrip.txt"

printf 'truncated\n' >"$MOUNTPOINT/roundtrip.txt"
sync
printf 'truncated\n' >"$ROOT/expected-truncated.txt"
cmp "$ROOT/expected-truncated.txt" "$MOUNTPOINT/roundtrip.txt"
cmp "$ROOT/expected-truncated.txt" "$SHARE/roundtrip.txt"

mv "$MOUNTPOINT/roundtrip.txt" "$MOUNTPOINT/renamed.txt"
[[ -f "$SHARE/renamed.txt" && ! -e "$SHARE/roundtrip.txt" ]]

mkdir "$MOUNTPOINT/dir"
[[ -d "$SHARE/dir" ]]
ls -la "$MOUNTPOINT" >/dev/null
rmdir "$MOUNTPOINT/dir"
rm "$MOUNTPOINT/renamed.txt"

[[ ! -e "$SHARE/dir" && ! -e "$SHARE/renamed.txt" ]]

echo "real $OS NFSv3 mount/create/truncate/read/write/rename/delete smoke test passed"
