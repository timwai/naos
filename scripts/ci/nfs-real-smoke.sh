#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "real NFS smoke test must run as root because it performs a kernel mount" >&2
  exit 2
fi

OS="$(uname -s)"
case "$OS" in
  Linux)
    for command in mount umount mount.nfs grep cmp mv rm mkdir rmdir sync ln readlink; do
      command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 3
      }
    done
    ;;
  Darwin)
    for command in mount_nfs umount grep cmp mv rm mkdir rmdir sync ln readlink; do
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
LOCKS="${NAOS_NFS_SMOKE_LOCKS:-0}"
if [[ "$LOCKS" != "0" && "$LOCKS" != "1" ]]; then
  echo "NAOS_NFS_SMOKE_LOCKS must be 0 or 1" >&2
  exit 4
fi
if [[ "$LOCKS" -eq 1 ]]; then
  for command in python3 rpcinfo; do
    command -v "$command" >/dev/null || {
      echo "missing required lock-smoke command: $command" >&2
      exit 4
    }
  done
  if [[ -z "${NAOS_NFS_SMOKE_RPCBIND:-}" ]]; then
    echo "lock smoke requires NAOS_NFS_SMOKE_RPCBIND so the client can discover NLMv4" >&2
    exit 4
  fi
fi
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
      local options="vers=3,proto=tcp,mountproto=tcp,port=$NFS_PORT,mountport=$MOUNT_PORT,soft,timeo=10,retrans=2"
      if [[ "$LOCKS" -eq 0 ]]; then
        options="$options,nolock"
      fi
      mount -t nfs -o "$options" "127.0.0.1:/ci-share" "$MOUNTPOINT"
      ;;
    Darwin)
      local options="vers=3,tcp,port=$NFS_PORT,mountport=$MOUNT_PORT,soft,timeo=10,retrans=2"
      if [[ "$LOCKS" -eq 0 ]]; then
        options="$options,nolocks"
      fi
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
  if [[ "$LOCKS" -eq 1 ]]; then
    echo "----- rpcbind registrations -----" >&2
    rpcinfo -p 127.0.0.1 >&2 || true
  fi
  echo "----- final mount attempt -----" >&2
  mount_export >&2 || true
  exit 6
fi

if [[ "$LOCKS" -eq 1 ]]; then
  registrations="$(rpcinfo -p 127.0.0.1)"
  grep -Eq "^[[:space:]]*100021[[:space:]]+4[[:space:]]+tcp[[:space:]]+" <<<"$registrations" || {
    echo "NLMv4 TCP registration was not visible through rpcbind" >&2
    exit 7
  }

  printf 'lock-test\n' >"$MOUNTPOINT/lock-test.txt"
  python3 - "$MOUNTPOINT/lock-test.txt" <<'PY'
import errno
import fcntl
import subprocess
import sys

path = sys.argv[1]
holder_code = r"""
import fcntl
import sys

with open(sys.argv[1], "r+") as handle:
    fcntl.lockf(handle, fcntl.LOCK_EX)
    print("locked", flush=True)
    sys.stdin.readline()
    fcntl.lockf(handle, fcntl.LOCK_UN)
"""

holder = subprocess.Popen(
    [sys.executable, "-c", holder_code, path],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
try:
    first_line = holder.stdout.readline().strip()
    if first_line != "locked":
        return_code = holder.poll()
        stderr = holder.stderr.read() if return_code is not None else ""
        raise RuntimeError(
            "first process did not acquire the NFS record lock "
            f"(returncode={return_code}, stdout={first_line!r}, stderr={stderr!r})"
        )

    with open(path, "r+") as contender:
        try:
            fcntl.lockf(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EAGAIN):
                raise
        else:
            fcntl.lockf(contender, fcntl.LOCK_UN)
            raise RuntimeError("second process unexpectedly acquired a conflicting NFS lock")

    holder.stdin.write("\n")
    holder.stdin.flush()
    if holder.wait(timeout=10) != 0:
        raise RuntimeError(holder.stderr.read())

    with open(path, "r+") as contender:
        fcntl.lockf(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.lockf(contender, fcntl.LOCK_UN)
finally:
    if holder.poll() is None:
        holder.kill()
        holder.wait()
PY
  rm "$MOUNTPOINT/lock-test.txt"
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

printf 'linked\n' >"$MOUNTPOINT/link-target.txt"
ln -s link-target.txt "$MOUNTPOINT/symlink.txt"
[[ "$(readlink "$MOUNTPOINT/symlink.txt")" == "link-target.txt" ]]
[[ "$(readlink "$SHARE/symlink.txt")" == "link-target.txt" ]]
cmp "$MOUNTPOINT/link-target.txt" "$MOUNTPOINT/symlink.txt"

ln "$MOUNTPOINT/link-target.txt" "$MOUNTPOINT/hardlink.txt"
cmp "$MOUNTPOINT/link-target.txt" "$MOUNTPOINT/hardlink.txt"
cmp "$SHARE/link-target.txt" "$SHARE/hardlink.txt"

rm "$MOUNTPOINT/symlink.txt" "$MOUNTPOINT/hardlink.txt" "$MOUNTPOINT/link-target.txt"
[[ ! -e "$SHARE/symlink.txt" && ! -e "$SHARE/hardlink.txt" && ! -e "$SHARE/link-target.txt" ]]

mv "$MOUNTPOINT/roundtrip.txt" "$MOUNTPOINT/renamed.txt"
[[ -f "$SHARE/renamed.txt" && ! -e "$SHARE/roundtrip.txt" ]]

mkdir "$MOUNTPOINT/dir"
[[ -d "$SHARE/dir" ]]
ls -la "$MOUNTPOINT" >/dev/null
rmdir "$MOUNTPOINT/dir"
rm "$MOUNTPOINT/renamed.txt"

[[ ! -e "$SHARE/dir" && ! -e "$SHARE/renamed.txt" ]]

if [[ "$LOCKS" -eq 1 ]]; then
  echo "real $OS NFSv3 mount + NLMv4 record-lock smoke test passed"
else
  echo "real $OS NFSv3 mount/create/truncate/read/write/symlink/hardlink/rename/delete smoke test passed (locks disabled)"
fi
