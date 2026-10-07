#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "remote NLM smoke test must run as root because it performs a kernel mount" >&2
  exit 2
fi

OS="$(uname -s)"
case "$OS" in
  Linux)
    for command in mount umount mount.nfs rpcinfo python3 rm; do
      command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 3
      }
    done
    ;;
  Darwin)
    for command in mount_nfs umount rpcinfo python3 rm; do
      command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 3
      }
    done
    ;;
  *)
    echo "unsupported NLM smoke-test host: $OS" >&2
    exit 3
    ;;
esac

HOST="${NAOS_NFS_REMOTE_HOST:-}"
EXPORT="${NAOS_NFS_REMOTE_EXPORT:-/ci-share}"
NFS_PORT="${NAOS_NFS_REMOTE_NFS_PORT:-2049}"
MOUNT_PORT="${NAOS_NFS_REMOTE_MOUNT_PORT:-20048}"

if [[ -z "$HOST" ]]; then
  echo "NAOS_NFS_REMOTE_HOST is required" >&2
  exit 4
fi
case "$HOST" in
  localhost|127.0.0.1|::1)
    echo "remote NLM smoke requires a separate server host; loopback is not a valid topology" >&2
    exit 4
    ;;
esac
if [[ ! "$EXPORT" =~ ^/ ]]; then
  echo "NAOS_NFS_REMOTE_EXPORT must be an absolute export path" >&2
  exit 4
fi
for port in "$NFS_PORT" "$MOUNT_PORT"; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo "invalid NFS smoke port: $port" >&2
    exit 4
  fi
done

registrations="$(rpcinfo -p "$HOST")"
grep -Eq "^[[:space:]]*100021[[:space:]]+4[[:space:]]+udp[[:space:]]+" <<<"$registrations" || {
  echo "remote server does not advertise NLMv4 over UDP" >&2
  echo "$registrations" >&2
  exit 5
}
grep -Eq "^[[:space:]]*100024[[:space:]]+1[[:space:]]+udp[[:space:]]+" <<<"$registrations" || {
  echo "remote server does not advertise NSMv1 over UDP" >&2
  echo "$registrations" >&2
  exit 5
}

ROOT="$(mktemp -d)"
MOUNTPOINT="$ROOT/mnt"
MOUNTED=0

cleanup() {
  local status=$?
  set +e
  if [[ "$MOUNTED" -eq 1 ]]; then
    umount "$MOUNTPOINT"
  fi
  rm -rf "$ROOT"
  exit "$status"
}
trap cleanup EXIT
mkdir -p "$MOUNTPOINT"

case "$OS" in
  Linux)
    options="vers=3,proto=tcp,mountproto=tcp,port=$NFS_PORT,mountport=$MOUNT_PORT,soft,timeo=10,retrans=2"
    mount -t nfs -o "$options" "$HOST:$EXPORT" "$MOUNTPOINT"
    ;;
  Darwin)
    options="vers=3,tcp,port=$NFS_PORT,mountport=$MOUNT_PORT,soft,timeo=10,retrans=2"
    mount_nfs -o "$options" "$HOST:$EXPORT" "$MOUNTPOINT"
    ;;
esac
MOUNTED=1

LOCK_PATH="$MOUNTPOINT/naos-nlm-smoke-$$.txt"
printf 'remote-lock-smoke\n' >"$LOCK_PATH"

python3 - "$LOCK_PATH" <<'PY'
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
            "first process did not acquire the remote NFS record lock "
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
            raise RuntimeError("second process unexpectedly acquired a conflicting remote NFS lock")

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

rm "$LOCK_PATH"
echo "real $OS NFSv3 remote NLMv4 record-lock smoke test passed against $HOST"
