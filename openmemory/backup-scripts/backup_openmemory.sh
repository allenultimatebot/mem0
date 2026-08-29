#!/usr/bin/env bash
set -euo pipefail

umask 077
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
source "$SCRIPT_DIR/keychain_contract.sh"
PROJECT="${OPENMEMORY_PROJECT_DIR:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)}"
BACKUP_ROOT="${OPENMEMORY_BACKUP_ROOT:-$HOME/.local/share/openmemory-backups}"
PROTECTED_ROOT="${OPENMEMORY_PROTECTED_ROOT:-$HOME/Library/CloudStorage/GoogleDrive-ntu.theanh1@gmail.com/My Drive/Backup/Mem0}"
COMPOSE_PROJECT="${OPENMEMORY_COMPOSE_PROJECT:-openmemory}"
API_URL="${OPENMEMORY_API_URL:-http://127.0.0.1:8765}"
QDRANT_URL="${OPENMEMORY_QDRANT_URL:-http://127.0.0.1:6333}"
WINDOW_START="${OPENMEMORY_WINDOW_START:-00:05}"
WINDOW_END="${OPENMEMORY_WINDOW_END:-00:15}"
MIN_FREE_KB="${OPENMEMORY_BACKUP_MIN_FREE_KB:-1048576}"
KEEP_VERIFIED=2
RUN_ID="$(date -u '+%Y%m%d-%H%M%S')-$$"
RUN_DIR="$BACKUP_ROOT/$RUN_ID"
STAGE_DIR="$BACKUP_ROOT/.stage-$RUN_ID"
LOCK_DIR="$BACKUP_ROOT/.backup.lock"
JOURNAL="$RUN_DIR/coordinator.journal"
STATE="$RUN_DIR/state"
POLICY_FILE="$RUN_DIR/restart-policies"
ACTIVE_CHILD_FILE="$RUN_DIR/active-child"
STATE_DIR="$BACKUP_ROOT/.state"
AUTH_DIR="$BACKUP_ROOT/.manifest-auth"
WATCHDOG_PID=""
DEADLINE_NS=""
ONE_SHOT_DIGEST=""
PRIOR_RUNNING=""
STOPPED=0
POLICIES_MUTATED=0
HISTORY_VOLUME=""
STORAGE_VOLUME=""
DATABASE_VOLUME=""
API_IMAGE=""
DOCKER_CONTEXT_NAME=""
DOCKER_ENDPOINT=""
FAILURE_CODE=E_BACKUP_FAILED
HMAC_SERVICE="com.ultimatesup.openmemory.backup.manifest-v1"
HMAC_ACCOUNT="openmemory-backup-manifest-v1"
HMAC_KEY_ID="v1"
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"

die() { printf 'openmemory backup: %s\n' "$1" >&2; exit 1; }
log() {
  printf '%s %s\n' "$(date -u '+%FT%TZ')" "$1" >> "$JOURNAL"
  /usr/bin/python3 - "$JOURNAL" <<'PY'
import os
import sys

with open(sys.argv[1], "rb") as handle:
    os.fsync(handle.fileno())
PY
}

atomic_write() {
  local target="$1" value="$2" temporary="$1.tmp.$$"
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
}

set_state() { atomic_write "$STATE" "$1"; log "state=$1"; }
mono_ns() { /usr/bin/python3 -c 'import time; print(time.monotonic_ns())'; }
remaining() { echo $(( (DEADLINE_NS - $(mono_ns)) / 1000000000 )); }
marker() {
  local name="$1" status="$2" detail="${3:-}"
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  atomic_write "$STATE_DIR/$name" "status=$status
run_id=$RUN_ID
at=$(date -u '+%FT%TZ')
${detail:+detail=$detail}"
}
check_deadline() {
  [ "$(remaining)" -gt "${1:-0}" ] || { FAILURE_CODE=E_DEADLINE_EXPIRED; marker deadline expired; set_state window_expired; die 'maintenance deadline expired'; }
}

bounded() {
  local seconds="$1"
  shift
  if [ "${1:-}" = docker_cmd ]; then
    shift
    set -- docker --context "$DOCKER_CONTEXT_NAME" "$@"
  fi
  if [ -n "$DEADLINE_NS" ]; then
    [ "$(remaining)" -gt 0 ] || return 124
    [ "$seconds" -le "$(remaining)" ] || seconds="$(remaining)"
  fi
  OPENMEMORY_ACTIVE_CHILD_FILE="${ACTIVE_CHILD_FILE:-}" /usr/bin/python3 "$SCRIPT_DIR/run_bounded.py" "$seconds" "$@"
}

notify_failure() {
  local code="$1" now last interval="${OPENMEMORY_NOTIFICATION_INTERVAL_SECONDS:-3600}" stamp="$STATE_DIR/notification.last"
  [ "${OPENMEMORY_NOTIFICATION_DISABLED:-0}" = 1 ] && { marker notification disabled "$code"; return 0; }
  now="$(date +%s)"; last="$(cat "$stamp" 2>/dev/null || echo 0)"
  if [ $((now - last)) -lt "$interval" ]; then marker notification rate_limited "$code"; return 0; fi
  atomic_write "$stamp" "$now"
  if command -v osascript >/dev/null && bounded 5 osascript -e 'display notification "OpenMemory backup failed" with title "OpenMemory"' >/dev/null 2>&1; then
    marker notification sent "$code"
  else
    marker notification failed E_NOTIFICATION_FAILED
  fi
}

record_docker_context() {
  [ -z "${DOCKER_HOST:-}" ] && [ -z "${DOCKER_CONTEXT:-}" ] && [ -z "${COMPOSE_FILE:-}" ] && [ -z "${COMPOSE_PROFILES:-}" ] && [ -z "${COMPOSE_PROJECT_NAME:-}" ] || die 'ambient Docker or Compose override is rejected'
  unset DOCKER_HOST DOCKER_CONTEXT COMPOSE_FILE COMPOSE_PROFILES COMPOSE_PROJECT_NAME COMPOSE_PATH_SEPARATOR
  DOCKER_CONTEXT_NAME="$(bounded 10 docker context show)" || die 'docker context cannot be recorded'
  DOCKER_ENDPOINT="$(bounded 10 docker context inspect "$DOCKER_CONTEXT_NAME" -f '{{(index .Endpoints "docker").Host}}')" || die 'docker endpoint cannot be recorded'
  [ -n "$DOCKER_CONTEXT_NAME" ] && [ -n "$DOCKER_ENDPOINT" ] || die 'docker context or endpoint is empty'
}
docker_cmd() { docker --context "$DOCKER_CONTEXT_NAME" "$@"; }
compose() {
  local seconds=120
  if [[ "${1:-}" =~ ^[0-9]+$ ]]; then seconds="$1"; shift; fi
  bounded "$seconds" docker --context "$DOCKER_CONTEXT_NAME" compose --project-directory "$PROJECT" --file "$PROJECT/docker-compose.yml" -p "$COMPOSE_PROJECT" "$@"
}

owner_root() {
  local path="$1"
  [ -e "$path" ] || mkdir -p "$path"
  [ ! -L "$path" ] || die 'symlinked root rejected'
  [ "$(stat -f %u "$path")" = "$(id -u)" ] || die 'root is not owner-controlled'
  chmod 700 "$path"
}

validate_roots() {
  /usr/bin/python3 - "$HOME" "$PROJECT" "$BACKUP_ROOT" "$PROTECTED_ROOT" <<'PY'
import pathlib
import sys

home, project, backup, protected = map(lambda value: pathlib.Path(value).expanduser().resolve(), sys.argv[1:])
for name, root in {"backup": backup, "protected": protected}.items():
    if root in {pathlib.Path("/"), home, project}:
        raise SystemExit(f"{name} root is unsafe")
    if root.is_relative_to(project) or project.is_relative_to(root):
        raise SystemExit(f"{name} root overlaps project")
if backup == protected or backup.is_relative_to(protected) or protected.is_relative_to(backup):
    raise SystemExit("backup and protected roots overlap")
PY
}

is_scheduled_minute() {
  local now="$1" start="$2" hour minute now_minute start_minute
  hour="${now%%:*}"; minute="${now#*:}"; minute="${minute%%:*}"
  now_minute=$((10#$hour * 60 + 10#$minute))
  start_minute=$((10#${start%%:*} * 60 + 10#${start##*:}))
  [ "$now_minute" -eq "$start_minute" ]
}

admit_window() {
  local now="${OPENMEMORY_TEST_NOW:-$(date '+%H:%M:%S')}"
  if [ "${1:-0}" = 1 ]; then
    local token_file="${OPENMEMORY_ONE_SHOT_TOKEN_FILE:-}" token_digest
    [ -n "$token_file" ] && [ -n "${OPENMEMORY_ONE_SHOT_TOKEN_SHA256:-}" ] || die 'one-shot token contract is incomplete'
    [ -f "$token_file" ] && [ ! -L "$token_file" ] || die 'one-shot token file is invalid'
    [ "$(stat -f %u "$token_file")" = "$(id -u)" ] || die 'one-shot token owner mismatch'
    [ "$(stat -f %Lp "$token_file")" = 600 ] || die 'one-shot token mode mismatch'
    token_digest="$(shasum -a 256 "$token_file" | awk '{print $1}')"
    [ "$token_digest" = "$OPENMEMORY_ONE_SHOT_TOKEN_SHA256" ] || die 'one-shot token verification failed'
    ONE_SHOT_DIGEST="$token_digest"
    return 0
  fi
  if ! is_scheduled_minute "$now" "$WINDOW_START"; then
    mkdir -p "$BACKUP_ROOT/.admission"
    atomic_write "$BACKUP_ROOT/.admission/state" skipped_outside_window
    exit 0
  fi
}

set_deadline() {
  local one_shot="${1:-0}" now="${OPENMEMORY_TEST_NOW:-$(date '+%H:%M:%S')}" hour minute second now_seconds end_seconds seconds_left
  if [ "$one_shot" = 1 ]; then
    seconds_left="${OPENMEMORY_ONE_SHOT_WINDOW_SECONDS:-600}"
    [[ "$seconds_left" =~ ^[1-9][0-9]*$ ]] || { FAILURE_CODE=E_DEADLINE_EXPIRED; marker deadline expired; die 'one-shot deadline is invalid'; }
    DEADLINE_NS=$(( $(mono_ns) + seconds_left * 1000000000 ))
    marker deadline active "seconds=$seconds_left"
    return 0
  fi
  hour="${now%%:*}"; minute="${now#*:}"; minute="${minute%%:*}"; second="${now##*:}"
  now_seconds=$((10#$hour * 3600 + 10#$minute * 60 + 10#$second))
  end_seconds=$((10#${WINDOW_END%%:*} * 3600 + 10#${WINDOW_END##*:} * 60))
  seconds_left=$((end_seconds - now_seconds))
  [ "$seconds_left" -gt 0 ] || { FAILURE_CODE=E_DEADLINE_EXPIRED; marker deadline expired; die 'maintenance window already expired'; }
  DEADLINE_NS=$(( $(mono_ns) + seconds_left * 1000000000 ))
  marker deadline active "seconds=$seconds_left"
}

capture_source() {
  local destination="$1"
  /usr/bin/python3 - "$PROJECT" "$destination" <<'PY'
import os
import pathlib
import shutil
import sys

source, destination = map(pathlib.Path, sys.argv[1:])
excluded_dirs = {".git", "node_modules", ".next", ".pytest_cache", "__pycache__"}
excluded_files = {".env", "ui.env", "openmemory.db", "SOURCE-SHA256SUMS", "SOURCE-MODES"}
destination.mkdir(parents=True, exist_ok=True)
for root, directories, files in os.walk(source, topdown=True, followlinks=False):
    root_path = pathlib.Path(root)
    directories[:] = [name for name in directories if name not in excluded_dirs and not (root_path / name).is_symlink()]
    relative_root = root_path.relative_to(source)
    target_root = destination / relative_root
    target_root.mkdir(parents=True, exist_ok=True)
    for name in files:
        source_path = root_path / name
        if name in excluded_files or name.startswith(".env.") or source_path.is_symlink():
            continue
        target_path = destination / source_path.relative_to(source)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target_path)
PY
  /usr/bin/python3 - "$destination" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
entries = []
mode_entries = []
for path in sorted(item for item in root.rglob("*") if item.is_file()):
    if any(part in {".git", "node_modules", ".next", ".pytest_cache", "__pycache__"} for part in path.parts):
        continue
    relative = path.relative_to(root)
    entries.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}")
    mode_entries.append(f"{relative}|mode={path.stat().st_mode & 0o777:o}")
(root / "SOURCE-SHA256SUMS").write_text("\n".join(entries) + "\n")
(root / "SOURCE-MODES").write_text("\n".join(mode_entries) + "\n")
PY
}

verify_source() {
  local source="$1"
  /usr/bin/python3 - "$source" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
expected = {}
for line in (root / "SOURCE-MODES").read_text().splitlines():
    relative, mode = line.rsplit("|mode=", 1)
    expected[relative] = int(mode, 8)
actual = {
    str(path.relative_to(root))
    for path in root.rglob("*")
    if path.is_file() and path.name not in {"SOURCE-SHA256SUMS", "SOURCE-MODES"}
}

if actual != set(expected):
    raise SystemExit("source file set mismatch")
for relative, mode in expected.items():
    if (root / relative).stat().st_mode & 0o777 != mode:
        raise SystemExit("source mode mismatch")
PY
  (cd "$source" && shasum -a 256 -c SOURCE-SHA256SUMS >/dev/null)
}

verify_source_baseline() {
  bounded 60 /usr/bin/python3 - "$PROJECT" "$STAGE_DIR/source" <<'PY'
import hashlib
import os
import pathlib
import subprocess
import sys
project, snapshot = map(pathlib.Path, sys.argv[1:])
excluded_dirs = {"node_modules", "." + "git", "." + "next", ".pytest_cache", "__pycache__"}
excluded_files = {".env", "ui.env", "openmemory.db", "SOURCE-SHA256SUMS", "SOURCE-MODES"}
def entries(root):
    result = {}
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        base = pathlib.Path(directory)
        directories[:] = [name for name in directories if name not in excluded_dirs and not (base / name).is_symlink()]
        for name in files:
            path = base / name
            if name in excluded_files or name.startswith(".env.") or path.is_symlink():
                continue
            relative = str(path.relative_to(root))
            result[relative] = (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode & 0o777)
    return result
if entries(project) != entries(snapshot):
    raise SystemExit("source baseline changed during capture")
PY
}

record_fingerprint() {
  local destination="$1" ports launch_state
  ports="$(bounded 15 docker_cmd ps --format '{{.Names}}|{{.Ports}}')" || die 'production port baseline unavailable'
  launch_state="$(bounded 10 launchctl print-disabled "gui/$(id -u)" | shasum -a 256 | awk '{print $1}')" || die 'LaunchAgent baseline unavailable'
  {
    printf 'project_head=%s\n' "$(bounded 10 git -C "$PROJECT" rev-parse HEAD)"
    printf 'source_manifest_sha256=%s\nsource_modes_sha256=%s\n' "$(shasum -a 256 "$STAGE_DIR/source/SOURCE-SHA256SUMS" | awk '{print $1}')" "$(shasum -a 256 "$STAGE_DIR/source/SOURCE-MODES" | awk '{print $1}')"
    printf 'database_volume=%s\n' "$DATABASE_VOLUME"
    printf 'database_live_fingerprint=%s\n' "$(compose 15 exec -T openmemory-mcp sqlite3 /var/lib/openmemory/openmemory.db 'select count(*) || ":" || coalesce(max(updated_at), "") from memories;' | shasum -a 256 | awk '{print $1}')"
    printf 'history_volume=%s\nstorage_volume=%s\n' "$HISTORY_VOLUME" "$STORAGE_VOLUME"
    printf 'docker_context=%s\ndocker_endpoint_sha256=%s\n' "$DOCKER_CONTEXT_NAME" "$(printf '%s' "$DOCKER_ENDPOINT" | shasum -a 256 | awk '{print $1}')"
    printf 'ports_sha256=%s\nlaunchagent_disabled_sha256=%s\n' "$(printf '%s' "$ports" | shasum -a 256 | awk '{print $1}')" "$launch_state"
  } > "$destination"
  chmod 600 "$destination"
}

consume_one_shot() {
  [ -n "$ONE_SHOT_DIGEST" ] || return 0
  mkdir -p "$BACKUP_ROOT/.one-shot-used"
  mkdir "$BACKUP_ROOT/.one-shot-used/$ONE_SHOT_DIGEST" 2>/dev/null || die 'one-shot token was already used'
  chmod 700 "$BACKUP_ROOT/.one-shot-used/$ONE_SHOT_DIGEST"
}

record_runtime() {
  local manifest="$1"
  printf 'project=%s\nhead=%s\ncompose_file=%s\ndocker_context=%s\ndocker_endpoint_sha256=%s\n' \
    "$COMPOSE_PROJECT" "$(bounded 10 git -C "$PROJECT" rev-parse HEAD)" "$PROJECT/docker-compose.yml" "$DOCKER_CONTEXT_NAME" "$(printf '%s' "$DOCKER_ENDPOINT" | shasum -a 256 | awk '{print $1}')" > "$manifest"
  bounded 15 docker_cmd version --format 'docker_server={{.Server.Version}}' >> "$manifest"
  bounded 15 docker_cmd info --format 'docker_root={{.DockerRootDir}}' >> "$manifest"
  for service in mem0_store openmemory-mcp openmemory-ui; do
    local container
    container="$(compose 15 ps -q "$service")"
    [ -n "$container" ] || die "missing container for $service"
    printf 'service=%s|container=%s|image=%s|image_id=%s|restart=%s|mounts=%s|ports=%s\n' \
      "$service" "$container" "$(bounded 15 docker_cmd inspect -f '{{.Config.Image}}' "$container")" "$(bounded 15 docker_cmd inspect -f '{{.Image}}' "$container")" \
      "$(bounded 15 docker_cmd inspect -f '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$container")" \
      "$(bounded 15 docker_cmd inspect -f '{{range .Mounts}}{{.Name}}:{{.Destination}}:{{.RW}};{{end}}' "$container")" \
      "$(bounded 15 docker_cmd inspect -f '{{json .NetworkSettings.Ports}}' "$container" | shasum -a 256 | awk '{print $1}')" >> "$manifest"
  done
  HISTORY_VOLUME="$(bounded 15 docker_cmd inspect -f '{{range .Mounts}}{{if eq .Destination "/root/.mem0"}}{{.Name}}{{end}}{{end}}' "$(compose 15 ps -q openmemory-mcp)")"
  STORAGE_VOLUME="$(bounded 15 docker_cmd inspect -f '{{range .Mounts}}{{if eq .Destination "/qdrant/storage"}}{{.Name}}{{end}}{{end}}' "$(compose 15 ps -q mem0_store)")"
  DATABASE_VOLUME="$(bounded 15 docker_cmd inspect -f '{{range .Mounts}}{{if eq .Destination "/var/lib/openmemory"}}{{.Name}}{{end}}{{end}}' "$(compose 15 ps -q openmemory-mcp)")"
  API_IMAGE="$(bounded 15 docker_cmd inspect -f '{{.Config.Image}}' "$(compose 15 ps -q openmemory-mcp)")"
  [ "$HISTORY_VOLUME" = openmemory_mem0_history ] && [ "$STORAGE_VOLUME" = openmemory_mem0_storage ] && [ "$DATABASE_VOLUME" = openmemory_openmemory_db ] || die 'required volume identity mismatch'
  [ -n "$API_IMAGE" ] || die 'API image identity missing'
  printf 'history_volume=%s\nstorage_volume=%s\ndatabase_volume=%s\napi_image=%s\n' "$HISTORY_VOLUME" "$STORAGE_VOLUME" "$DATABASE_VOLUME" "$API_IMAGE" >> "$manifest"
}

record_policies() {
  : > "$POLICY_FILE"
  POLICIES_MUTATED=1
  for service in mem0_store openmemory-mcp openmemory-ui; do
    local container policy running
    container="$(compose 15 ps -q "$service")"
    policy="$(bounded 15 docker_cmd inspect -f '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$container")"
    running="$(bounded 15 docker_cmd inspect -f '{{.State.Running}}' "$container")"
    printf '%s|%s|%s\n' "$service" "$policy" "$running" >> "$POLICY_FILE"
    [ "$running" = true ] && PRIOR_RUNNING="${PRIOR_RUNNING:+$PRIOR_RUNNING }$service"
    bounded 15 docker_cmd update --restart=no "$container"
  done
}

restore_policies() {
  [ -f "$POLICY_FILE" ] || return 0
  while IFS='|' read -r service policy _; do
    local container restart_name restart_count
    container="$(compose 15 ps -q "$service")"
    [ -n "$container" ] || continue
    restart_name="${policy%%:*}"; restart_count="${policy#*:}"
    if [ "$restart_name" = on-failure ]; then bounded 15 docker_cmd update --restart="on-failure:$restart_count" "$container"; else bounded 15 docker_cmd update --restart="$restart_name" "$container"; fi
  done < "$POLICY_FILE"
}

retention() {
  [ -d "$LOCK_DIR" ] || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_LOCK_MISSING; return 1; }
  local verified="" local_verified="" planned_local="" protected_artifacts="" kept_verified="" expected_protected actual_protected expected_local actual_local keep=0 count=0 plan="$STATE_DIR/retention.dry-run" plan_sha candidate id dev ino real artifact sha entry name state
  : > "$plan"
  while IFS= read -r entry; do
    name="$(basename "$entry")"
    case "$name" in
      .protected.pointer)
        [ -f "$entry" ] && [ ! -L "$entry" ] && [ "$(stat -f %u "$entry")" = "$(id -u)" ] && [ "$(stat -f %Lp "$entry")" = 600 ] || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_PROTECTED_ENUMERATION; return 1; }
        ;;
      .protected.pointer.auth.json)
        [ -f "$entry" ] && [ ! -L "$entry" ] && [ "$(stat -f %u "$entry")" = "$(id -u)" ] && [ "$(stat -f %Lp "$entry")" = 600 ] || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_PROTECTED_ENUMERATION; return 1; }
        ;;
      openmemory-*.tar.gpg)
        [[ "$name" =~ ^openmemory-[0-9]{8}-[0-9]{6}-[0-9]+\.tar\.gpg$ ]] && [ -f "$entry" ] && [ ! -L "$entry" ] && [ "$(stat -f %u "$entry")" = "$(id -u)" ] && [ "$(stat -f %Lp "$entry")" = 600 ] || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_PROTECTED_ENUMERATION; return 1; }
        protected_artifacts="$protected_artifacts $name"
        ;;
      *)
        FAILURE_CODE=E_RETENTION_FAILED
        marker retention blocked E_PROTECTED_ENUMERATION
        return 1
        ;;
    esac
  done < <(find "$PROTECTED_ROOT" -mindepth 1 -maxdepth 1 -print | sort)
  [ -f "$PROTECTED_ROOT/.protected.pointer" ] || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_PROTECTED_ENUMERATION; return 1; }
  while IFS= read -r candidate; do
    id="$(basename "$candidate")"
    [[ "$id" =~ ^[0-9]{8}-[0-9]{6}-[0-9]+$ ]] || continue
    [ ! -L "$candidate" ] && [ "$(stat -f %u "$candidate")" = "$(id -u)" ] && [ "$(stat -f %Lp "$candidate")" = 700 ] || continue
    state="$(cat "$candidate/state" 2>/dev/null || true)"
    [ "$state" = complete ] || [ "$state" = restart_verified ] || continue
    [ -f "$candidate/restore-verified" ] && [ -f "$AUTH_DIR/$id.json" ] && [ "$(stat -f %u "$AUTH_DIR/$id.json")" = "$(id -u)" ] && [ "$(stat -f %Lp "$AUTH_DIR/$id.json")" = 600 ] || continue
    manifest_auth verify "$candidate" >/dev/null 2>&1 || continue
    pointer_auth verify "$candidate" "$PROTECTED_ROOT" >/dev/null 2>&1 || continue
    artifact="$(sed -n 's/^artifact=//p' "$candidate/protected.pointer")"
    sha="$(sed -n 's/^sha256=//p' "$candidate/protected.pointer")"
    [ "$artifact" = "openmemory-$id.tar.gpg" ] && [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { [ "$id" = "$RUN_ID" ] && { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_PROTECTED_MISSING; return 1; }; continue; }
    local_verified="$local_verified $id"
    if [ -f "$PROTECTED_ROOT/$artifact" ] && [ "$(shasum -a 256 "$PROTECTED_ROOT/$artifact" | awk '{print $1}')" = "$sha" ]; then
      verified="$verified $id"
    elif [ "$id" = "$RUN_ID" ]; then
      FAILURE_CODE=E_RETENTION_FAILED
      marker retention blocked E_PROTECTED_MISSING
      return 1
    fi
  done < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -print | sort -r)
  for artifact in $protected_artifacts; do
    id="${artifact#openmemory-}"; id="${id%.tar.gpg}"
    case " $verified " in *" $id "*) ;; *) FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_PROTECTED_UNOWNED; return 1;; esac
  done
  for id in $verified; do
    keep=$((keep + 1))
    if [ "$keep" -le "$KEEP_VERIFIED" ]; then
      kept_verified="$kept_verified $id"
      continue
    fi
    candidate="$BACKUP_ROOT/$id"
    local_dev="$(stat -f %d "$candidate")"; local_ino="$(stat -f %i "$candidate")"; local_real="$(CDPATH= cd -- "$candidate" && pwd -P)"
    artifact="openmemory-$id.tar.gpg"
    dev="$(stat -f %d "$PROTECTED_ROOT/$artifact")"; ino="$(stat -f %i "$PROTECTED_ROOT/$artifact")"; real="$PROTECTED_ROOT/$artifact"
    printf 'scope=protected|candidate=%s|device=%s|inode=%s|realpath=%s\n' "$artifact" "$dev" "$ino" "$real" >> "$plan"
    printf 'scope=local|candidate=%s|device=%s|inode=%s|realpath=%s\n' "$id" "$local_dev" "$local_ino" "$local_real" >> "$plan"
    planned_local="$planned_local $id"
    count=$((count + 1))
  done
  for id in $local_verified; do
    case " $kept_verified $planned_local " in *" $id "*) continue;; esac
    candidate="$BACKUP_ROOT/$id"
    local_dev="$(stat -f %d "$candidate")"; local_ino="$(stat -f %i "$candidate")"; local_real="$(CDPATH= cd -- "$candidate" && pwd -P)"
    printf 'scope=local|candidate=%s|device=%s|inode=%s|realpath=%s\n' "$id" "$local_dev" "$local_ino" "$local_real" >> "$plan"
    planned_local="$planned_local $id"
    count=$((count + 1))
  done
  chmod 600 "$plan"
  plan_sha="$(shasum -a 256 "$plan" | awk '{print $1}')"
  atomic_write "$STATE_DIR/retention.plan" "sha256=$plan_sha
candidates=$count"
  [ "$(shasum -a 256 "$plan" | awk '{print $1}')" = "$plan_sha" ] || { marker retention blocked E_PLAN_CHANGED; return 1; }
  while IFS='|' read -r scope_field candidate_field device_field inode_field realpath_field; do
    [ -n "$candidate_field" ] || continue
    scope="${scope_field#scope=}"
    candidate="${candidate_field#candidate=}"
    if [ "$scope" = local ]; then
      id="$candidate"
      state="$(cat "$BACKUP_ROOT/$id/state" 2>/dev/null || true)"
      { [ "$state" = complete ] || [ "$state" = restart_verified ]; } || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_CANDIDATE_CHANGED; return 1; }
      [ -f "$BACKUP_ROOT/$id/restore-verified" ] && manifest_auth verify "$BACKUP_ROOT/$id" >/dev/null 2>&1 && pointer_auth verify "$BACKUP_ROOT/$id" "$PROTECTED_ROOT" >/dev/null 2>&1 || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_CANDIDATE_CHANGED; return 1; }
      bounded 30 /usr/bin/python3 - "$scope" "$BACKUP_ROOT" "$BACKUP_ROOT/$id" "${device_field#device=}" "${inode_field#inode=}" "${realpath_field#realpath=}" <<'PY'
import os
import pathlib
import shutil
import sys
scope, root, candidate, expected_device, expected_inode, expected_real = sys.argv[1:]
root_path = pathlib.Path(root).resolve()
candidate_path = pathlib.Path(candidate)
stat = candidate_path.lstat()
if scope != "local" or candidate_path.is_symlink() or not candidate_path.is_dir() or str(candidate_path.resolve()) != expected_real:
    raise SystemExit("candidate changed")
if str(stat.st_dev) != expected_device or str(stat.st_ino) != expected_inode or stat.st_uid != os.getuid():
    raise SystemExit("candidate ownership changed")
if candidate_path.parent.resolve() != root_path:
    raise SystemExit("candidate root changed")
quarantine = root_path / (".retention-delete-" + candidate_path.name + "-" + str(os.getpid()))
os.rename(candidate_path, quarantine)
after = quarantine.lstat()
if after.st_dev != stat.st_dev or after.st_ino != stat.st_ino or quarantine.is_symlink():
    raise SystemExit("candidate changed during rename")
shutil.rmtree(quarantine)
PY
    else
      [ "$scope" = protected ] || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_PLAN_CHANGED; return 1; }
      artifact="$candidate"
      id="${artifact#openmemory-}"; id="${id%.tar.gpg}"
      pointer_auth verify "$BACKUP_ROOT/$id" "$PROTECTED_ROOT" >/dev/null 2>&1 || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_CANDIDATE_CHANGED; return 1; }
      sha="$(sed -n 's/^sha256=//p' "$BACKUP_ROOT/$id/protected.pointer")"
      [ "$(shasum -a 256 "$PROTECTED_ROOT/$artifact" | awk '{print $1}')" = "$sha" ] || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_CANDIDATE_CHANGED; return 1; }
      bounded 30 /usr/bin/python3 - "$scope" "$PROTECTED_ROOT" "$PROTECTED_ROOT/$artifact" "${device_field#device=}" "${inode_field#inode=}" "${realpath_field#realpath=}" <<'PY'
import os
import pathlib
import subprocess
import sys
scope, root, candidate, expected_device, expected_inode, expected_real = sys.argv[1:]
root_path = pathlib.Path(root).resolve()
candidate_path = pathlib.Path(candidate)
stat = candidate_path.lstat()
if scope != "protected" or candidate_path.is_symlink() or not candidate_path.is_file() or str(candidate_path.resolve()) != expected_real:
    raise SystemExit("candidate changed")
if str(stat.st_dev) != expected_device or str(stat.st_ino) != expected_inode or stat.st_uid != os.getuid() or stat.st_mode & 0o777 != 0o600:
    raise SystemExit("candidate ownership changed")
if candidate_path.parent.resolve() != root_path:
    raise SystemExit("candidate root changed")
os.execv("/bin/rm", ["/bin/rm", "--", str(candidate_path)])
PY
      [ ! -e "$PROTECTED_ROOT/$artifact" ] && [ ! -L "$PROTECTED_ROOT/$artifact" ] || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_PROTECTED_POSTCONDITION; return 1; }
    fi
  done < "$plan"
  expected_protected="$(for id in $kept_verified; do printf 'openmemory-%s.tar.gpg\n' "$id"; done | sort)"
  actual_protected="$(find "$PROTECTED_ROOT" -mindepth 1 -maxdepth 1 -type f -name 'openmemory-*.tar.gpg' -exec basename {} \; | sort)"
  [ "$actual_protected" = "$expected_protected" ] || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_PROTECTED_POSTCONDITION; return 1; }
  expected_local="$(for id in $kept_verified; do printf '%s\n' "$id"; done | sort)"
  actual_local=""
  while IFS= read -r candidate; do
    id="$(basename "$candidate")"
    [[ "$id" =~ ^[0-9]{8}-[0-9]{6}-[0-9]+$ ]] || continue
    state="$(cat "$candidate/state" 2>/dev/null || true)"
    [ "$state" = complete ] || [ "$state" = restart_verified ] || continue
    [ -f "$candidate/restore-verified" ] && manifest_auth verify "$candidate" >/dev/null 2>&1 && pointer_auth verify "$candidate" "$PROTECTED_ROOT" >/dev/null 2>&1 || continue
    actual_local="$actual_local $id"
  done < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -print | sort -r)
  actual_local="$(for id in $actual_local; do printf '%s\n' "$id"; done | sort)"
  [ "$actual_local" = "$expected_local" ] || { FAILURE_CODE=E_RETENTION_FAILED; marker retention blocked E_LOCAL_POSTCONDITION; return 1; }
  marker retention complete "deleted=$count verified_generations local_and_protected_exact=1"
}

writer_barrier() {
  [ -z "$(compose 15 ps -q --status running)" ] || die 'an OpenMemory container is still running'
  [ -z "$(bounded 15 docker_cmd ps --filter volume="$HISTORY_VOLUME" -q)" ] || die 'history volume has a running consumer'
  [ -z "$(bounded 15 docker_cmd ps --filter volume="$STORAGE_VOLUME" -q)" ] || die 'storage volume has a running consumer'
  [ -z "$(bounded 15 docker_cmd ps --filter volume="$DATABASE_VOLUME" -q)" ] || die 'database volume has a running consumer'
  log writer_barrier=held
}

backup_database() {
  local target="$1"
  mkdir -p "$(dirname "$target")"
  bounded 60 docker_cmd run --rm --network none \
    -v "$DATABASE_VOLUME:/var/lib/openmemory:ro" \
    -v "$(dirname "$target"):/backup" \
    "$API_IMAGE" sqlite3 /var/lib/openmemory/openmemory.db ".backup '/backup/$(basename "$target")'"
  [ -s "$target" ] || die 'database backup is empty'
}

copy_volume() {
  local volume="$1" target="$2"
  mkdir -p "$target"
  bounded 15 docker_cmd image inspect alpine:3.20 >/dev/null 2>&1 || die 'offline helper image is unavailable'
  bounded 120 docker_cmd run --rm --network none -v "$volume":/source:ro -v "$target":/backup alpine:3.20 tar -cpf /backup/volume.tar -C /source .
  [ -s "$target/volume.tar" ] || die "empty archive for $volume"
}

verify_db() {
  local db="$1"
  bounded 30 /usr/bin/sqlite3 "$db" 'PRAGMA integrity_check;' | grep -Fxq ok || die 'sqlite integrity failed'
  [ -n "$(bounded 30 /usr/bin/sqlite3 "$db" '.schema')" ] || die 'sqlite schema is empty'
}

manifest_auth() {
  local mode="$1" run="$2"
  local auth="$AUTH_DIR/$(basename "$run").json"
  mkdir -p "$AUTH_DIR"
  chmod 700 "$AUTH_DIR"
  exec 3< <(keychain_manifest_secret "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$KEYCHAIN")
  bounded 120 /usr/bin/python3 "$SCRIPT_DIR/manifest_auth.py" "$mode" "$run" "$auth" "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$HMAC_KEY_ID" 3<&3
  exec 3<&-
}

pointer_auth() {
  local mode="$1" run="$2" artifact_root="${3:-}"
  local auth="$run/protected.pointer.auth.json"
  exec 3< <(keychain_manifest_secret "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$KEYCHAIN")
  if [ -n "$artifact_root" ]; then
    bounded 120 /usr/bin/python3 "$SCRIPT_DIR/manifest_auth.py" "pointer-$mode" "$run" "$auth" "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$HMAC_KEY_ID" --artifact-root "$artifact_root" 3<&3
  else
    bounded 120 /usr/bin/python3 "$SCRIPT_DIR/manifest_auth.py" "pointer-$mode" "$run" "$auth" "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$HMAC_KEY_ID" 3<&3
  fi
  exec 3<&-
}

create_package() {
  local package="$STAGE_DIR/openmemory-$RUN_ID.tar"
  bounded 60 tar -cpf "$package" -C "$STAGE_DIR" source sqlite volumes runtime.manifest SHA256SUMS production.fingerprint manifest.canonical.json
  printf '%s\n' "$package"
}

encrypt_and_publish() {
  local package="$1" cipher="$STAGE_DIR/openmemory-$RUN_ID.tar.gpg" pointer pointer_auth_file
  local encryption_service="com.ultimatesup.openmemory.backup-key" encryption_account="allen_bot"
  command -v gpg >/dev/null || die 'gpg is required'
  exec 3< <(keychain_secret "$encryption_service" "$encryption_account" "$KEYCHAIN")
  bounded 60 gpg --symmetric --force-aead --aead-algo OCB --cipher-algo AES256 --compress-algo none --batch --pinentry-mode loopback --passphrase-fd 3 --output "$cipher" "$package" 3<&3
  exec 3<&-
  exec 3< <(keychain_secret "$encryption_service" "$encryption_account" "$KEYCHAIN")
  bounded 30 gpg --batch --pinentry-mode loopback --passphrase-fd 3 --decrypt "$cipher" > /dev/null 3<&3
  exec 3<&-
  bounded 30 cp "$cipher" "$STAGE_DIR/tamper.gpg"
  /usr/bin/python3 - "$STAGE_DIR/tamper.gpg" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = bytearray(path.read_bytes())
data[-1] ^= 1
path.write_bytes(data)
PY
  exec 3< <(keychain_secret "$encryption_service" "$encryption_account" "$KEYCHAIN")
  if bounded 30 gpg --batch --pinentry-mode loopback --passphrase-fd 3 --decrypt "$STAGE_DIR/tamper.gpg" > /dev/null 2>/dev/null 3<&3; then
    exec 3<&-
    die 'ciphertext tamper test unexpectedly passed'
  fi
  exec 3<&-
  owner_root "$PROTECTED_ROOT"
  [ "$(df -Pk "$BACKUP_ROOT" | awk 'NR==2 {print $4}')" -ge "$MIN_FREE_KB" ] || die 'backup root lacks free space'
  [ "$(df -Pk "$PROTECTED_ROOT" | awk 'NR==2 {print $4}')" -ge "$MIN_FREE_KB" ] || die 'protected root lacks free space'
  pointer="$RUN_DIR/protected.pointer"
  atomic_write "$pointer" "state=protected_local_verified
artifact=$(basename "$cipher")
sha256=$(shasum -a 256 "$cipher" | awk '{print $1}')
remote_sync=unconfirmed"
  bounded 30 cp "$cipher" "$PROTECTED_ROOT/.$(basename "$cipher").tmp.$$"
  bounded 30 mv "$PROTECTED_ROOT/.$(basename "$cipher").tmp.$$" "$PROTECTED_ROOT/$(basename "$cipher")"
  bounded 30 cp "$pointer" "$PROTECTED_ROOT/.$(basename "$pointer").tmp.$$"
  bounded 30 mv "$PROTECTED_ROOT/.$(basename "$pointer").tmp.$$" "$PROTECTED_ROOT/.$(basename "$pointer")"
  [ "$(shasum -a 256 "$PROTECTED_ROOT/$(basename "$cipher")" | awk '{print $1}')" = "$(shasum -a 256 "$cipher" | awk '{print $1}')" ] || die 'protected publication verification failed'
  pointer_auth create "$RUN_DIR" "$PROTECTED_ROOT"
  pointer_auth_file="$RUN_DIR/protected.pointer.auth.json"
  bounded 30 cp "$pointer_auth_file" "$PROTECTED_ROOT/.$(basename "$pointer_auth_file").tmp.$$"
  bounded 30 mv "$PROTECTED_ROOT/.$(basename "$pointer_auth_file").tmp.$$" "$PROTECTED_ROOT/.$(basename "$pointer_auth_file")"
  [ "$(shasum -a 256 "$PROTECTED_ROOT/.$(basename "$pointer_auth_file")" | awk '{print $1}')" = "$(shasum -a 256 "$pointer_auth_file" | awk '{print $1}')" ] || die 'protected pointer authentication publication failed'
  cmp -s "$pointer" "$PROTECTED_ROOT/.$(basename "$pointer")" || die 'protected pointer publication failed'
  marker publication protected_local_verified
  set_state protected_local_verified
}

restart_stack() {
  local service ready=0
  check_deadline 60
  set_state restarting
  for service in $PRIOR_RUNNING; do compose 30 start "$service"; done
  if [ -z "$PRIOR_RUNNING" ]; then
    restore_policies
    STOPPED=0
    POLICIES_MUTATED=0
    set_state restart_verified
    return
  fi
  for service in $PRIOR_RUNNING; do
    local container
    container="$(compose 15 ps -q "$service")" || die "unable to find restarted service: $service"
    [ "$(bounded 15 docker_cmd inspect -f '{{.State.Running}}' "$container")" = true ] || die "service did not restart: $service"
  done
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    ready=1
    case " $PRIOR_RUNNING " in *' openmemory-mcp '*) bounded 5 curl --fail --silent --show-error "$API_URL/healthz" >/dev/null 2>&1 || ready=0;; esac
    case " $PRIOR_RUNNING " in *' mem0_store '*) bounded 5 curl --fail --silent --show-error "$QDRANT_URL/collections" >/dev/null 2>&1 || ready=0;; esac
    [ "$ready" = 1 ] && break
    bounded 3 sleep 2
  done
  [ "$ready" = 1 ] || die 'runtime readiness failed after restart'
  ports="$(bounded 15 docker_cmd ps --format '{{.Names}}|{{.Ports}}')"
  case " $PRIOR_RUNNING " in *' mem0_store '*) printf '%s\n' "$ports" | grep -Eq 'mem0_store[^|]*\|[^|]*127\.0\.0\.1:6333->6333/tcp' || die 'Qdrant port assertion failed';; esac
  case " $PRIOR_RUNNING " in *' openmemory-mcp '*) printf '%s\n' "$ports" | grep -Eq 'openmemory-mcp[^|]*\|[^|]*(0\.0\.0\.0|127\.0\.0\.1):8765->8765/tcp' || die 'API port assertion failed';; esac
  case " $PRIOR_RUNNING " in *' openmemory-ui '*) printf '%s\n' "$ports" | grep -Eq 'openmemory-ui[^|]*\|[^|]*127\.0\.0\.1:3000->3000/tcp' || die 'UI port assertion failed';; esac
  restore_policies
  STOPPED=0
  POLICIES_MUTATED=0
  set_state restart_verified
}

recover() {
  [ "$STOPPED" = 1 ] || [ "$POLICIES_MUTATED" = 1 ] || return 0
  [ "$(cat "$STATE" 2>/dev/null || true)" = deadline_exceeded ] && return 0
  if [ "$STOPPED" = 1 ]; then
    for service in $PRIOR_RUNNING; do compose 30 start "$service" >/dev/null 2>&1 || true; done
  fi
  restore_policies || true
  [ -f "$STATE" ] && set_state manual_recovery_required || true
}

watchdog_recover() {
  local project="$1" policy_file="$2" context="$3"
  DOCKER_CONTEXT_NAME="$context"
  [ -f "$policy_file" ] || return 0
  while IFS='|' read -r service policy running; do
    [ "$running" != true ] || compose 30 start "$service" >/dev/null 2>&1 || true
    container="$(compose 15 ps -q "$service" 2>/dev/null || true)"
    [ -n "$container" ] || continue
    restart_name="${policy%%:*}"
    restart_count="${policy#*:}"
    if [ "$restart_name" = on-failure ]; then
      bounded 15 docker_cmd update --restart="on-failure:$restart_count" "$container" >/dev/null 2>&1 || true
    else
      bounded 15 docker_cmd update --restart="$restart_name" "$container" >/dev/null 2>&1 || true
    fi
  done < "$policy_file"
}

watchdog() {
  local parent="$1" deadline="$2" state_file="$3" project="$4" policy_file="$5" context="$6" active_file="$7"
  ACTIVE_CHILD_FILE="$active_file"
  while kill -0 "$parent" 2>/dev/null && [ "$(mono_ns)" -lt "$deadline" ]; do sleep 2; done
  if kill -0 "$parent" 2>/dev/null; then
    atomic_write "$state_file" deadline_exceeded
    if [ -f "$ACTIVE_CHILD_FILE" ]; then
      pgid="$(sed -n 's/^pgid=//p' "$ACTIVE_CHILD_FILE")"
      if [ -n "$pgid" ]; then
        kill -TERM "-$pgid" 2>/dev/null || true
        for _ in 1 2 3; do kill -0 "-$pgid" 2>/dev/null || break; sleep 1; done
        kill -KILL "-$pgid" 2>/dev/null || true
        kill -0 "-$pgid" 2>/dev/null && return 1
      fi
    fi
    kill -TERM "$parent" 2>/dev/null || true
    sleep 3
    kill -KILL "$parent" 2>/dev/null || true
    watchdog_recover "$project" "$policy_file" "$context"
    atomic_write "$state_file" manual_recovery_required
  else
    case "$(cat "$state_file" 2>/dev/null || true)" in policies_mutating|stopping|stopped|capturing|publishing|restarting)
      if [ -f "$ACTIVE_CHILD_FILE" ]; then
        pgid="$(sed -n 's/^pgid=//p' "$ACTIVE_CHILD_FILE")"
        if [ -n "$pgid" ]; then
          kill -TERM "-$pgid" 2>/dev/null || true
          for _ in 1 2 3; do kill -0 "-$pgid" 2>/dev/null || break; sleep 1; done
          kill -KILL "-$pgid" 2>/dev/null || true
          kill -0 "-$pgid" 2>/dev/null && return 1
        fi
      fi
      watchdog_recover "$project" "$policy_file" "$context"
      atomic_write "$state_file" manual_recovery_required
      ;;
    esac
  fi
}

self_test() {
  is_scheduled_minute 05:30:05 05:30
  ! is_scheduled_minute 05:29:59 05:30
  ! is_scheduled_minute 05:31:00 05:30
  grep -Fq 'KEEP_VERIFIED=2' "$0"
  grep -Fq 'start_new_session=True' "$0"
  grep -Fq 'run_bounded.py' "$0"
  grep -Fq 'ACTIVE_CHILD_FILE' "$0"
  grep -Fq 'set -- docker --context "$DOCKER_CONTEXT_NAME"' "$0"
  grep -Fq 'local mode="$1" run="$2"' "$0"
  grep -Fq 'active}.tmp.{os.getpid()}.{process.pid}' "$0"
  ! grep -Fq '\$1' "$0"
  grep -Fq 'unset DOCKER_HOST DOCKER_CONTEXT COMPOSE_FILE COMPOSE_PROFILES' "$0"
  grep -Fq 'com.ultimatesup.openmemory.backup.manifest-v1' "$0"
  grep -Fq 'openmemory-backup-manifest-v1' "$0"
  grep -Fq 'manifest authentication failed' "$0"
  grep -Fq 'retention.dry-run' "$0"
  grep -Fq 'E_PROTECTED_ENUMERATION' "$0"
  grep -Fq 'local_and_protected=1' "$0"
  grep -Fq 'remote_sync=unconfirmed' "$0"
  grep -Fq -- '--symmetric --force-aead --aead-algo OCB --cipher-algo AES256 --compress-algo none --batch --pinentry-mode loopback --passphrase-fd 3' "$0"
  grep -Fq 'openmemory.db.pre-volume-move.stale' "$0"
  grep -Fq 'source file set mismatch' "$0"
  grep -Fq 'openmemory_mem0_history' "$0"
  grep -Fq 'mem0_storage' "$0"
  grep -Fq 'protected_local_verified' "$0"
  grep -Fq 'DATABASE_VOLUME' "$0"
  grep -Fq 'backup_database' "$0"
  local curl_method='curl .* -X '
  if grep -Eq "${curl_method}POST|${curl_method}DELETE" "$0"; then die 'self-test found a mutating HTTP call'; fi
  printf '%s\n' 'PASS backup contract self-check'
}

main() {
  [ "${1:-}" != --watchdog ] || { watchdog "$2" "$3" "$4" "$5" "$6" "$7" "$8"; exit 0; }
  [ "${1:-}" != --self-test ] || { self_test; exit 0; }
  local one_shot=0
  [ "${1:-}" = --one-shot ] && one_shot=1
  owner_root "$BACKUP_ROOT"
  validate_roots
  admit_window "$one_shot"
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    lock_pid="$(sed -n 's/^pid=//p' "$LOCK_DIR/owner" 2>/dev/null || true)"
    if [ -n "$lock_pid" ] && [[ "$lock_pid" =~ ^[0-9]+$ ]] && kill -0 "$lock_pid" 2>/dev/null; then
      printf '%s\n' 'openmemory backup: lock busy' >&2
      exit 0
    fi
    [ ! -L "$LOCK_DIR" ] && [ "$(stat -f %u "$LOCK_DIR" 2>/dev/null || echo -1)" = "$(id -u)" ] || die 'stale backup lock is not owner-controlled'
    rm -rf "$LOCK_DIR"
    mkdir "$LOCK_DIR" || { printf '%s\n' 'openmemory backup: lock busy' >&2; exit 0; }
  fi
  mkdir -p "$RUN_DIR" "$STAGE_DIR" "$STATE_DIR" "$AUTH_DIR"
  chmod 700 "$RUN_DIR" "$STAGE_DIR"
  printf 'run_id=%s\npid=%s\n' "$RUN_ID" "$$" > "$JOURNAL"
  chmod 600 "$JOURNAL"
  printf 'pid=%s\nstarted_at=%s\n' "$$" "$(date -u '+%FT%TZ')" > "$LOCK_DIR/owner"
  chmod 600 "$LOCK_DIR/owner"
  set_state admitted
  trap 'status=$?; if [ "$status" -ne 0 ] && [ -f "$JOURNAL" ]; then marker failure "$FAILURE_CODE"; notify_failure "$FAILURE_CODE"; fi; recover; rm -rf "$LOCK_DIR" 2>/dev/null || true; [ -n "$WATCHDOG_PID" ] && kill "$WATCHDOG_PID" 2>/dev/null || true; exit "$status"' EXIT
  set_deadline "$one_shot"
  marker lock held
  command -v docker >/dev/null || die 'docker is required'
  command -v curl >/dev/null || die 'curl is required'
  command -v sqlite3 >/dev/null || die 'sqlite3 is required'
  owner_root "$PROTECTED_ROOT"
  record_docker_context
  "$0" --watchdog "$$" "$DEADLINE_NS" "$STATE" "$PROJECT" "$POLICY_FILE" "$DOCKER_CONTEXT_NAME" "$ACTIVE_CHILD_FILE" & WATCHDOG_PID=$!
  record_runtime "$RUN_DIR/runtime.manifest"
  capture_source "$STAGE_DIR/source"
  verify_source "$STAGE_DIR/source"
  verify_source_baseline
  consume_one_shot
  printf 'source_manifest_sha256=%s\n' "$(shasum -a 256 "$STAGE_DIR/source/SOURCE-SHA256SUMS" | awk '{print $1}')" >> "$RUN_DIR/runtime.manifest"
  printf 'source_modes_sha256=%s\n' "$(shasum -a 256 "$STAGE_DIR/source/SOURCE-MODES" | awk '{print $1}')" >> "$RUN_DIR/runtime.manifest"
  record_fingerprint "$RUN_DIR/production.fingerprint"
  set_state policies_mutating
  record_policies
  POLICIES_MUTATED=1
  set_state stopping
  check_deadline 60
  STOPPED=1
  compose 60 stop
  writer_barrier
  set_state capturing
  mkdir -p "$STAGE_DIR/sqlite" "$STAGE_DIR/volumes/history" "$STAGE_DIR/volumes/storage"
  mkdir -p "$RUN_DIR/data/sqlite" "$RUN_DIR/data/volumes/history" "$RUN_DIR/data/volumes/storage"
  backup_database "$STAGE_DIR/sqlite/openmemory.db"
  verify_db "$STAGE_DIR/sqlite/openmemory.db"
  copy_volume "$HISTORY_VOLUME" "$STAGE_DIR/volumes/history"
  copy_volume "$STORAGE_VOLUME" "$STAGE_DIR/volumes/storage"
  bounded 30 cp "$STAGE_DIR/sqlite/openmemory.db" "$RUN_DIR/data/sqlite/openmemory.db"
  bounded 30 cp "$STAGE_DIR/volumes/history/volume.tar" "$RUN_DIR/data/volumes/history/volume.tar"
  bounded 30 cp "$STAGE_DIR/volumes/storage/volume.tar" "$RUN_DIR/data/volumes/storage/volume.tar"
  bounded 30 cp -Rp "$STAGE_DIR/source" "$RUN_DIR/data/source"
  (cd "$RUN_DIR/data" && shasum -a 256 sqlite/openmemory.db volumes/history/volume.tar volumes/storage/volume.tar > "$RUN_DIR/SHA256SUMS")
  bounded 30 cp "$RUN_DIR/runtime.manifest" "$RUN_DIR/data/runtime.manifest"
  bounded 30 cp "$STAGE_DIR/source/SOURCE-SHA256SUMS" "$RUN_DIR/data/source/SOURCE-SHA256SUMS"
  bounded 30 cp "$STAGE_DIR/source/SOURCE-MODES" "$RUN_DIR/data/source/SOURCE-MODES"
  (cd "$RUN_DIR/data" && shasum -a 256 -c ../SHA256SUMS >/dev/null)
  bounded 30 cp "$RUN_DIR/runtime.manifest" "$STAGE_DIR/runtime.manifest"
  bounded 30 cp "$RUN_DIR/SHA256SUMS" "$STAGE_DIR/SHA256SUMS"
  manifest_auth create "$RUN_DIR"
  bounded 30 cp "$RUN_DIR/production.fingerprint" "$STAGE_DIR/production.fingerprint"
  bounded 30 cp "$RUN_DIR/manifest.canonical.json" "$STAGE_DIR/manifest.canonical.json"
  set_state local_verified
  OPENMEMORY_BACKUP_ROOT="$BACKUP_ROOT" "$SCRIPT_DIR/restore_openmemory_clone.sh" "$RUN_DIR" "$STAGE_DIR/source" "$STAGE_DIR/sqlite/openmemory.db" "$STAGE_DIR/volumes/history/volume.tar" "$STAGE_DIR/volumes/storage/volume.tar"
  OPENMEMORY_BACKUP_ROOT="$BACKUP_ROOT" "$SCRIPT_DIR/verify_openmemory_restore_semantics.sh" "$RUN_DIR" | tee "$RUN_DIR/restore-semantics.log"
  atomic_write "$RUN_DIR/restore-verified" "run_id=$RUN_ID
verified_at=$(date -u '+%FT%TZ')"
  set_state publishing
  encrypt_and_publish "$(create_package)"
  restart_stack
  retention
  marker success complete
  marker lock released
  set_state complete
  kill "$WATCHDOG_PID" 2>/dev/null || true
  WATCHDOG_PID=""
}

main "$@"
