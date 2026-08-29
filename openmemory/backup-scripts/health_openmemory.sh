#!/usr/bin/env bash
set -euo pipefail

umask 077
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
unset DOCKER_HOST DOCKER_CONTEXT COMPOSE_FILE COMPOSE_PROFILES COMPOSE_PROJECT_NAME COMPOSE_PATH_SEPARATOR
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
source "$SCRIPT_DIR/keychain_contract.sh"

ROOT="${OPENMEMORY_BACKUP_ROOT:-$HOME/.local/share/openmemory-backups}"
STATE_FILE="${OPENMEMORY_HEALTH_STATE:-$ROOT/health.state}"
STATE_DIR="$ROOT/.state"
AUTH_DIR="$ROOT/.manifest-auth"
LOG_DIR="${OPENMEMORY_LOG_DIR:-$HOME/.local/share/openmemory-logs}"
API_URL="${OPENMEMORY_API_URL:-http://127.0.0.1:8765}"
QDRANT_URL="${OPENMEMORY_QDRANT_URL:-http://127.0.0.1:6333}"
PROTECTED_ROOT="${OPENMEMORY_PROTECTED_ROOT:-$HOME/Library/CloudStorage/GoogleDrive-ntu.theanh1@gmail.com/My Drive/Backup/Mem0}"
MAX_AGE="${OPENMEMORY_HEALTH_MAX_AGE_SECONDS:-93600}"
MIN_FREE_KB="${OPENMEMORY_HEALTH_MIN_FREE_KB:-1048576}"
LOG="$LOG_DIR/health.log"
HMAC_SERVICE="com.ultimatesup.openmemory.backup.manifest-v1"
HMAC_ACCOUNT="openmemory-backup-manifest-v1"
HMAC_KEY_ID="v1"
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"

mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"

atomic_write() {
  local target="$1" value="$2" temporary="$1.tmp.$$"
  mkdir -p "$(dirname "$target")"
  printf '%s\n' "$value" > "$temporary"
  /usr/bin/python3 - "$temporary" "$target" <<'PY'
import os
import sys
temporary, target = sys.argv[1:]
with open(temporary, "rb") as handle:
    os.fsync(handle.fileno())
os.replace(temporary, target)
directory = os.open(os.path.dirname(target) or ".", os.O_RDONLY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
  chmod 600 "$target"
}

fail() {
  atomic_write "$STATE_FILE" "status=red
code=$1
checked_at=$(date -u '+%FT%TZ')"
  printf '%s FAIL %s\n' "$(date -u '+%FT%TZ')" "$1" >> "$LOG"
  exit 1
}

pass() {
  atomic_write "$STATE_FILE" "status=green
code=OK
checked_at=$(date -u '+%FT%TZ')"
  printf '%s PASS\n' "$(date -u '+%FT%TZ')" >> "$LOG"
}

bounded() {
  local seconds="$1"
  shift
  /usr/bin/python3 - "$seconds" "$@" <<'PY'
import os
import signal
import subprocess
import sys
process = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    process.wait(timeout=float(sys.argv[1]))
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    raise SystemExit(124)
raise SystemExit(process.returncode)
PY
}

[ -d "$ROOT" ] && [ ! -L "$ROOT" ] || fail E_ROOT_MISSING
[ "$(stat -f %Lp "$ROOT")" = 700 ] || fail E_ROOT_MODE
[ "$(stat -f %u "$ROOT")" = "$(id -u)" ] || fail E_ROOT_OWNER
[ ! -e "$ROOT/.backup.lock" ] || fail E_BACKUP_LOCK

latest="$(find "$ROOT" -mindepth 2 -maxdepth 2 -type f -name state -print 2>/dev/null | while IFS= read -r state; do
  run_id="$(basename "$(dirname "$state")")"
  [[ "$run_id" =~ ^[0-9]{8}-[0-9]{6}-[0-9]+$ ]] && printf '%s\n' "$state"
done | sort | tail -n 1)"
[ -n "$latest" ] || fail E_BACKUP_STATE_MISSING
run_dir="$(dirname "$latest")"
run_id="$(basename "$run_dir")"
[ "$(cat "$latest")" = complete ] || fail E_BACKUP_STATE_INCOMPLETE
[ -f "$run_dir/restore-verified" ] || fail E_RESTORE_UNVERIFIED
[ $(( $(date +%s) - $(stat -f %m "$latest") )) -le "$MAX_AGE" ] || fail E_BACKUP_STATE_STALE
[ "$(stat -f %Lp "$latest")" = 600 ] || fail E_STATE_MODE
[ ! -L "$run_dir" ] && [ "$(stat -f %u "$run_dir")" = "$(id -u)" ] || fail E_RUN_ROOT

[ -f "$run_dir/SHA256SUMS" ] || fail E_CHECKSUMS_MISSING
[ -f "$run_dir/data/runtime.manifest" ] || fail E_RUNTIME_MANIFEST_MISSING
[ -f "$run_dir/data/source/SOURCE-SHA256SUMS" ] || fail E_SOURCE_CHECKSUMS_MISSING
[ -f "$run_dir/data/source/SOURCE-MODES" ] || fail E_SOURCE_MODES_MISSING
(cd "$run_dir/data" && bounded 30 shasum -a 256 -c ../SHA256SUMS >/dev/null 2>&1) || fail E_CHECKSUM_MISMATCH
(cd "$run_dir/data/source" && bounded 30 shasum -a 256 -c SOURCE-SHA256SUMS >/dev/null 2>&1) || fail E_SOURCE_CHECKSUM_MISMATCH
/usr/bin/python3 - "$run_dir/data/source" <<'PY' || fail E_SOURCE_MODE_MISMATCH
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
expected = {}
for line in (root / "SOURCE-MODES").read_text(encoding="utf-8").splitlines():
    relative, mode = line.rsplit("|mode=", 1)
    expected[relative] = int(mode, 8)
actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file() and path.name not in {"SOURCE-MODES", "SOURCE-SHA256SUMS"}}
if actual != set(expected) or any((root / relative).stat().st_mode & 0o777 != mode for relative, mode in expected.items()):
    raise SystemExit(1)
PY
[ -f "$AUTH_DIR/$run_id.json" ] || fail E_MANIFEST_AUTH_MISSING

exec 3< <(keychain_manifest_secret "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$KEYCHAIN")
/usr/bin/python3 "$SCRIPT_DIR/manifest_auth.py" verify "$run_dir" "$AUTH_DIR/$run_id.json" "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$HMAC_KEY_ID" 3<&3 || fail E_MANIFEST_AUTH
exec 3<&-

[ ! -f "$STATE_DIR/failure" ] || { [ -f "$STATE_DIR/success" ] && [ "$STATE_DIR/failure" -ot "$STATE_DIR/success" ]; } || fail E_FAILURE_MARKER
[ -f "$STATE_DIR/deadline" ] && grep -Fxq 'status=active' "$STATE_DIR/deadline" || fail E_DEADLINE_STATE
[ -f "$STATE_DIR/retention" ] && grep -Fxq 'status=complete' "$STATE_DIR/retention" || fail E_RETENTION_STATE
[ -f "$STATE_DIR/publication" ] && grep -Fxq 'status=protected_local_verified' "$STATE_DIR/publication" || fail E_PUBLICATION_STATE
[ ! -f "$STATE_DIR/notification" ] || grep -Eq '^status=(sent|rate_limited|disabled)$' "$STATE_DIR/notification" || fail E_NOTIFICATION_STATE

[ -f "$run_dir/protected.pointer" ] && [ ! -L "$run_dir/protected.pointer" ] && [ "$(stat -f %u "$run_dir/protected.pointer")" = "$(id -u)" ] && [ "$(stat -f %Lp "$run_dir/protected.pointer")" = 600 ] || fail E_PROTECTED_POINTER_MISSING
[ -f "$run_dir/protected.pointer.auth.json" ] && [ ! -L "$run_dir/protected.pointer.auth.json" ] && [ "$(stat -f %u "$run_dir/protected.pointer.auth.json")" = "$(id -u)" ] && [ "$(stat -f %Lp "$run_dir/protected.pointer.auth.json")" = 600 ] || fail E_PROTECTED_POINTER_AUTH_MISSING
exec 3< <(keychain_manifest_secret "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$KEYCHAIN")
/usr/bin/python3 "$SCRIPT_DIR/manifest_auth.py" pointer-verify "$run_dir" "$run_dir/protected.pointer.auth.json" "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$HMAC_KEY_ID" --artifact-root "$PROTECTED_ROOT" 3<&3 || fail E_PROTECTED_POINTER_AUTH
exec 3<&-
grep -Fxq 'state=protected_local_verified' "$run_dir/protected.pointer" || fail E_PROTECTED_STATE
grep -Fxq 'remote_sync=unconfirmed' "$run_dir/protected.pointer" || fail E_REMOTE_SYNC_UNCONFIRMED
artifact="$(sed -n 's/^artifact=//p' "$run_dir/protected.pointer")"
artifact_sha="$(sed -n 's/^sha256=//p' "$run_dir/protected.pointer")"
[ -n "$artifact" ] && [ "$(basename "$artifact")" = "$artifact" ] || fail E_PROTECTED_POINTER_MALFORMED
[ -d "$PROTECTED_ROOT" ] && [ ! -L "$PROTECTED_ROOT" ] && [ "$(stat -f %u "$PROTECTED_ROOT")" = "$(id -u)" ] || fail E_PROTECTED_ROOT
[ -f "$PROTECTED_ROOT/.protected.pointer" ] && [ ! -L "$PROTECTED_ROOT/.protected.pointer" ] && [ "$(stat -f %u "$PROTECTED_ROOT/.protected.pointer")" = "$(id -u)" ] && [ "$(stat -f %Lp "$PROTECTED_ROOT/.protected.pointer")" = 600 ] || fail E_PROTECTED_POINTER_MISSING
[ -f "$PROTECTED_ROOT/.protected.pointer.auth.json" ] && [ ! -L "$PROTECTED_ROOT/.protected.pointer.auth.json" ] && [ "$(stat -f %u "$PROTECTED_ROOT/.protected.pointer.auth.json")" = "$(id -u)" ] && [ "$(stat -f %Lp "$PROTECTED_ROOT/.protected.pointer.auth.json")" = 600 ] || fail E_PROTECTED_POINTER_AUTH_MISSING
cmp -s "$run_dir/protected.pointer" "$PROTECTED_ROOT/.protected.pointer" || fail E_PROTECTED_POINTER_MISMATCH
exec 3< <(keychain_manifest_secret "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$KEYCHAIN")
/usr/bin/python3 "$SCRIPT_DIR/manifest_auth.py" pointer-verify "$run_dir" "$PROTECTED_ROOT/.protected.pointer.auth.json" "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$HMAC_KEY_ID" --artifact-root "$PROTECTED_ROOT" --pointer-path "$PROTECTED_ROOT/.protected.pointer" 3<&3 || fail E_PROTECTED_POINTER_AUTH
exec 3<&-
[ -f "$PROTECTED_ROOT/$artifact" ] || fail E_PROTECTED_ARTIFACT_MISSING
[ "$(shasum -a 256 "$PROTECTED_ROOT/$artifact" | awk '{print $1}')" = "$artifact_sha" ] || fail E_PROTECTED_ARTIFACT_MISMATCH

free_kb="$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')"
[ "${free_kb:-0}" -ge "$MIN_FREE_KB" ] || fail E_DISK_HEADROOM

docker_context="$(sed -n 's/^docker_context=//p' "$run_dir/data/runtime.manifest")"
[ -n "$docker_context" ] || fail E_DOCKER_CONTEXT
docker_endpoint_sha="$(sed -n 's/^docker_endpoint_sha256=//p' "$run_dir/data/runtime.manifest")"
[ -n "$docker_endpoint_sha" ] || fail E_DOCKER_ENDPOINT
current_endpoint="$(bounded 10 docker --context "$docker_context" context inspect "$docker_context" -f '{{(index .Endpoints "docker").Host}}')" || fail E_DOCKER_ENDPOINT
current_endpoint_sha="$(printf '%s' "$current_endpoint" | shasum -a 256 | awk '{print $1}')"
[ "$current_endpoint_sha" = "$docker_endpoint_sha" ] || fail E_DOCKER_ENDPOINT
ports="$(bounded 15 docker --context "$docker_context" ps --format '{{.Names}}|{{.Ports}}')" || fail E_DOCKER_UNAVAILABLE
printf '%s\n' "$ports" | grep -Eq 'mem0_store[^|]*\|[^|]*127\.0\.0\.1:6333->6333/tcp' || fail E_QDRANT_BINDING
printf '%s\n' "$ports" | grep -Eq 'openmemory-ui[^|]*\|[^|]*127\.0\.0\.1:3000->3000/tcp' || fail E_UI_BINDING
printf '%s\n' "$ports" | grep -Eq 'openmemory-mcp[^|]*\|[^|]*127\.0\.0\.1:8765->8765/tcp' || fail E_API_BINDING

api_container="$(bounded 15 docker --context "$docker_context" ps --format '{{.ID}} {{.Names}}' | awk '$2 ~ /openmemory-mcp/ {print $1; exit}')"
[ -n "$api_container" ] || fail E_API_CONTAINER
[ "$(bounded 15 docker --context "$docker_context" exec "$api_container" sqlite3 /var/lib/openmemory/openmemory.db 'PRAGMA quick_check;')" = ok ] || fail E_LIVE_DB_INTEGRITY
live_memory_count="$(bounded 15 docker --context "$docker_context" exec "$api_container" sqlite3 /var/lib/openmemory/openmemory.db 'select count(*) from memories;')" || fail E_LIVE_DB_READ
[[ "$live_memory_count" =~ ^[1-9][0-9]*$ ]] || fail E_LIVE_DB_EMPTY

bounded 10 curl --fail --silent --show-error "$API_URL/healthz" >/dev/null || fail E_API_HEALTHZ
code="$(bounded 10 curl --silent --show-error -o /dev/null -w '%{http_code}' "$API_URL/api/v1/apps/?page=1&page_size=1")" || fail E_API_PROBE
[ "$code" = 401 ] || fail E_API_MIDDLEWARE
bounded 10 curl --fail --silent --show-error "$QDRANT_URL/collections" >/dev/null || fail E_QDRANT_READINESS
pass
