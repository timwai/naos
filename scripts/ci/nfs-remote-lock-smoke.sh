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
RESTART_TARGET="${NAOS_NFS_REMOTE_RESTART_TARGET:-}"
RESTART_SERVICE="${NAOS_NFS_REMOTE_RESTART_SERVICE:-naosd}"
RESTART_GRACE_WAIT="${NAOS_NFS_REMOTE_RESTART_GRACE_WAIT:-35}"
RESTART_RPC_TIMEOUT="${NAOS_NFS_REMOTE_RESTART_RPC_TIMEOUT:-60}"

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

if [[ -n "$RESTART_TARGET" ]]; then
  command -v ssh >/dev/null || {
    echo "missing required command: ssh" >&2
    exit 3
  }
  if [[ ! "$RESTART_TARGET" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$ ]]; then
    echo "NAOS_NFS_REMOTE_RESTART_TARGET must be a simple user@host SSH target" >&2
    exit 4
  fi
  if [[ ! "$RESTART_SERVICE" =~ ^[A-Za-z0-9_.@-]+$ ]]; then
    echo "invalid NAOS_NFS_REMOTE_RESTART_SERVICE" >&2
    exit 4
  fi
  if [[ ! "$RESTART_GRACE_WAIT" =~ ^[0-9]+$ ]] || (( RESTART_GRACE_WAIT < 31 || RESTART_GRACE_WAIT > 300 )); then
    echo "NAOS_NFS_REMOTE_RESTART_GRACE_WAIT must be between 31 and 300 seconds" >&2
    exit 4
  fi
  if [[ ! "$RESTART_RPC_TIMEOUT" =~ ^[0-9]+$ ]] || (( RESTART_RPC_TIMEOUT < 5 || RESTART_RPC_TIMEOUT > 300 )); then
    echo "NAOS_NFS_REMOTE_RESTART_RPC_TIMEOUT must be between 5 and 300 seconds" >&2
    exit 4
  fi
fi

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

python3 - \
  "$LOCK_PATH" \
  "$HOST" \
  "$RESTART_TARGET" \
  "$RESTART_SERVICE" \
  "$RESTART_GRACE_WAIT" \
  "$RESTART_RPC_TIMEOUT" <<'PY'
import errno
import fcntl
import subprocess
import sys
import time

path = sys.argv[1]
host = sys.argv[2]
restart_target = sys.argv[3]
restart_service = sys.argv[4]
grace_wait = int(sys.argv[5])
rpc_timeout = int(sys.argv[6])

holder_code = r"""
import fcntl
import sys

with open(sys.argv[1], "r+") as handle:
    fcntl.lockf(handle, fcntl.LOCK_EX)
    print("locked", flush=True)
    sys.stdin.readline()
    fcntl.lockf(handle, fcntl.LOCK_UN)
"""


def conflicting_lock_is_denied():
    with open(path, "r+") as contender:
        try:
            fcntl.lockf(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            return True
        else:
            fcntl.lockf(contender, fcntl.LOCK_UN)
            return False


def remote_rpc_services_ready():
    probe = subprocess.run(
        ["rpcinfo", "-p", host],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        return False

    services = set()
    for line in probe.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            services.add(tuple(fields[:3]))
    return ("100021", "4", "udp") in services and ("100024", "1", "udp") in services


def wait_for_remote_rpc_services():
    deadline = time.monotonic() + rpc_timeout
    while time.monotonic() < deadline:
        if remote_rpc_services_ready():
            return
        time.sleep(1)
    raise RuntimeError(
        f"remote NLMv4/NSMv1 RPC registrations did not recover within {rpc_timeout}s"
    )


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

    if not conflicting_lock_is_denied():
        raise RuntimeError("second process unexpectedly acquired a conflicting remote NFS lock")

    if restart_target:
        subprocess.run(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "--",
                restart_target,
                "sudo",
                "systemctl",
                "restart",
                restart_service,
            ],
            check=True,
        )
        wait_for_remote_rpc_services()

        if holder.poll() is not None:
            raise RuntimeError(
                f"lock holder exited during server restart: {holder.stderr.read()!r}"
            )

        # naos currently uses a 30-second NLM grace period after restart.
        # Check after grace has elapsed so DENIED cannot be explained by grace alone:
        # a conflicting lock must still be denied because the holder reclaimed it.
        time.sleep(grace_wait)
        if not conflicting_lock_is_denied():
            raise RuntimeError(
                "conflicting lock succeeded after server restart and grace period; "
                "the original client lock was not reclaimed"
            )

    holder.stdin.write("\n")
    holder.stdin.flush()
    if holder.wait(timeout=10) != 0:
        raise RuntimeError(holder.stderr.read())

    if conflicting_lock_is_denied():
        raise RuntimeError("lock remained unavailable after the original holder released it")
finally:
    if holder.poll() is None:
        holder.kill()
        holder.wait()
PY

rm "$LOCK_PATH"
if [[ -n "$RESTART_TARGET" ]]; then
  echo "real $OS NFSv3 remote NLMv4 restart/reclaim smoke test passed against $HOST"
else
  echo "real $OS NFSv3 remote NLMv4 record-lock smoke test passed against $HOST"
fi
