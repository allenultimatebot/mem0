#!/usr/bin/env bash
set -euo pipefail

umask 077
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
source "$SCRIPT_DIR/keychain_contract.sh"

bounded() {
  local seconds="$1"
  shift
  /usr/bin/python3 "$SCRIPT_DIR/run_bounded.py" "$seconds" "$@"
}

RUN_DIR="${1:-}"
SOURCE_DIR="${2:-}"
DB_ARCHIVE="${3:-}"
HISTORY_ARCHIVE="${4:-}"
STORAGE_ARCHIVE="${5:-}"
[ -d "$RUN_DIR" ] && [ -d "$SOURCE_DIR" ] && [ -f "$DB_ARCHIVE" ] && [ -f "$HISTORY_ARCHIVE" ] && [ -f "$STORAGE_ARCHIVE" ] || { printf '%s\n' 'restore clone: five paths are required' >&2; exit 2; }

BACKUP_ROOT="${OPENMEMORY_BACKUP_ROOT:-$HOME/.local/share/openmemory-backups}"
AUTH_DIR="$BACKUP_ROOT/.manifest-auth"
HMAC_SERVICE="com.ultimatesup.openmemory.backup.manifest-v1"
HMAC_ACCOUNT="openmemory-backup-manifest-v1"
HMAC_KEY_ID="v1"
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"
RUN_ID="$(basename "$RUN_DIR")"
[[ "$RUN_ID" =~ ^[0-9]{8}-[0-9]{6}-[0-9]+$ ]] || { printf '%s\n' 'restore clone: invalid run id' >&2; exit 1; }
RUN_PARENT="$(CDPATH= cd -- "$(dirname "$RUN_DIR")" && pwd -P)"
EXPECTED_ROOT="$(CDPATH= cd -- "$BACKUP_ROOT" && pwd -P)"
[ "$RUN_PARENT" = "$EXPECTED_ROOT" ] || { printf '%s\n' 'restore clone: run directory is outside backup root' >&2; exit 1; }
SOURCE_REAL="$(CDPATH= cd -- "$SOURCE_DIR" && pwd -P)"
EXPECTED_SOURCE="$EXPECTED_ROOT/.stage-$RUN_ID/source"
[ "$SOURCE_REAL" = "$EXPECTED_SOURCE" ] || { printf '%s\n' 'restore clone: source directory is outside run staging' >&2; exit 1; }
STAGE_ROOT="$EXPECTED_ROOT/.stage-$RUN_ID"
for archive in "$DB_ARCHIVE" "$HISTORY_ARCHIVE" "$STORAGE_ARCHIVE"; do
  [ -f "$archive" ] && [ ! -L "$archive" ] || { printf '%s\n' 'restore clone: archive path is invalid' >&2; exit 1; }
  archive_real="$(CDPATH= cd -- "$(dirname "$archive")" && pwd -P)/$(basename "$archive")"
  case "$archive_real" in "$STAGE_ROOT"/*) ;; *) printf '%s\n' 'restore clone: archive is outside run staging' >&2; exit 1;; esac
done
[ "$(CDPATH= cd -- "$(dirname "$DB_ARCHIVE")" && pwd -P)/$(basename "$DB_ARCHIVE")" = "$STAGE_ROOT/sqlite/openmemory.db" ] || { printf '%s\n' 'restore clone: unexpected database archive name' >&2; exit 1; }
[ "$(CDPATH= cd -- "$(dirname "$HISTORY_ARCHIVE")" && pwd -P)/$(basename "$HISTORY_ARCHIVE")" = "$STAGE_ROOT/volumes/history/volume.tar" ] || { printf '%s\n' 'restore clone: unexpected history archive name' >&2; exit 1; }
[ "$(CDPATH= cd -- "$(dirname "$STORAGE_ARCHIVE")" && pwd -P)/$(basename "$STORAGE_ARCHIVE")" = "$STAGE_ROOT/volumes/storage/volume.tar" ] || { printf '%s\n' 'restore clone: unexpected storage archive name' >&2; exit 1; }

verify_manifest_auth() {
  exec 3< <(keychain_manifest_secret "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$KEYCHAIN")
  bounded 30 /usr/bin/python3 "$SCRIPT_DIR/manifest_auth.py" verify "$RUN_DIR" "$AUTH_DIR/$RUN_ID.json" "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$HMAC_KEY_ID" 3<&3
  exec 3<&-
}
verify_manifest_auth

archive_safe() {
  local archive="$1" destination="$2"
  bounded 30 /usr/bin/python3 - "$archive" "$destination" <<'PY'
import pathlib
import tarfile
import sys

archive, destination = sys.argv[1:]
root = pathlib.Path(destination).resolve()
with tarfile.open(archive, "r") as handle:
    members = handle.getmembers()
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        target = (root / pathlib.Path(*path.parts)).resolve()
        if path.is_absolute() or ".." in path.parts or root not in [target, *target.parents]:
            raise SystemExit("unsafe archive path")
        if member.issym() or member.islnk() or member.isdev() or member.isfifo() or member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
            raise SystemExit("unsafe archive member")
    handle.extractall(root, members=members)
PY
}
ROOT="$RUN_DIR/clone"
PROJECT_NAME="openmemory-clone-$(printf '%s' "$RUN_DIR" | shasum -a 256 | awk '{print substr($1,1,12)}')"
[ ! -L "$RUN_DIR" ] || { printf '%s\n' 'restore clone: run directory symlink rejected' >&2; exit 1; }
if [ -e "$ROOT" ]; then
  [ ! -L "$ROOT" ] || { printf '%s\n' 'restore clone: clone directory symlink rejected' >&2; exit 1; }
  bounded 30 rm -rf -- "$ROOT"
fi
mkdir -p "$ROOT/db" "$ROOT/history" "$ROOT/storage" "$ROOT/source" "$ROOT/compose"
chmod 700 "$ROOT" "$ROOT/db" "$ROOT/history" "$ROOT/storage" "$ROOT/source"
bounded 30 cp "$DB_ARCHIVE" "$ROOT/db/openmemory.db"
archive_safe "$HISTORY_ARCHIVE" "$ROOT/history"
archive_safe "$STORAGE_ARCHIVE" "$ROOT/storage"
bounded 30 cp -Rp "$SOURCE_DIR/." "$ROOT/source/"

DOCKER_CONTEXT_NAME="$(sed -n 's/^docker_context=//p' "$RUN_DIR/data/runtime.manifest")"
[ -n "$DOCKER_CONTEXT_NAME" ] || { printf '%s\n' 'restore clone: docker context missing' >&2; exit 1; }
unset DOCKER_HOST DOCKER_CONTEXT COMPOSE_FILE COMPOSE_PROFILES COMPOSE_PROJECT_NAME COMPOSE_PATH_SEPARATOR

image() { awk -F'|' -v service="$1" '$1 == "service=" service {for (i=1;i<=NF;i++) if ($i ~ /^image=/) {sub(/^image=/,"",$i); print $i}}' "$RUN_DIR/runtime.manifest"; }
image_id() { awk -F'|' -v service="$1" '$1 == "service=" service {for (i=1;i<=NF;i++) if ($i ~ /^image_id=/) {sub(/^image_id=/,"",$i); print $i}}' "$RUN_DIR/runtime.manifest"; }
api_image="$(image openmemory-mcp)"
qdrant_image="$(image mem0_store)"
ui_image="$(image openmemory-ui)"
[ -n "$api_image" ] && [ -n "$qdrant_image" ] && [ -n "$ui_image" ] || { printf '%s\n' 'restore clone: runtime images missing' >&2; exit 1; }
for pair in "openmemory-mcp:$api_image" "mem0_store:$qdrant_image" "openmemory-ui:$ui_image"; do
  service="${pair%%:*}"; ref="${pair#*:}"
  [ "$(bounded 15 docker --context "$DOCKER_CONTEXT_NAME" image inspect -f '{{.Id}}' "$ref" 2>/dev/null)" = "$(image_id "$service")" ] || { printf '%s\n' "restore clone: image identity mismatch for $service" >&2; exit 1; }
done

cat > "$ROOT/synthetic.env" <<'EOF_ENV'
USER=clone-user
API_KEY=clone-only-invalid
OPENAI_API_KEY=clone-only-invalid
OPENMEMORY_API_TOKEN=clone-only-invalid
QDRANT_HOST=mem0_store
QDRANT_PORT=6333
DATABASE_URL=sqlite:////clone-data/openmemory.db
EOF_ENV
chmod 600 "$ROOT/synthetic.env"
cat > "$ROOT/compose/docker-compose.yml" <<EOF_COMPOSE
services:
  mem0_store:
    image: $qdrant_image
    volumes:
      - $ROOT/storage:/qdrant/storage
  openmemory-mcp:
    image: $api_image
    env_file: $ROOT/synthetic.env
    environment:
      DATABASE_URL: sqlite:////clone-data/openmemory.db
      QDRANT_HOST: mem0_store
      QDRANT_PORT: "6333"
    depends_on:
      - mem0_store
    volumes:
      - $ROOT/source:/workspace:ro
      - $ROOT/source/api:/usr/src/openmemory:ro
      - $ROOT/db:/clone-data
      - $ROOT/history:/root/.mem0
    command: sh -c "uvicorn main:app --host 0.0.0.0 --port 8765 --workers 1"
  openmemory-ui:
    image: $ui_image
    depends_on:
      - openmemory-mcp
networks:
  default:
    name: $PROJECT_NAME
    internal: true
EOF_COMPOSE

compose() { local seconds=120; if [[ "${1:-}" =~ ^[0-9]+$ ]]; then seconds="$1"; shift; fi; bounded "$seconds" docker --context "$DOCKER_CONTEXT_NAME" compose --project-directory "$ROOT/compose" --file "$ROOT/compose/docker-compose.yml" -p "$PROJECT_NAME" "$@"; }
cleanup() {
  local status=$?
  set +e
  compose 30 down --volumes --remove-orphans >/dev/null 2>&1 || status=1
  [ -z "$(docker --context "$DOCKER_CONTEXT_NAME" ps -aq --filter "label=com.docker.compose.project=$PROJECT_NAME")" ] || status=1
  [ -z "$(docker --context "$DOCKER_CONTEXT_NAME" network ls -q --filter "name=^${PROJECT_NAME}$")" ] || status=1
  [ -z "$(docker --context "$DOCKER_CONTEXT_NAME" volume ls -q --filter "name=^${PROJECT_NAME}_")" ] || status=1
  set -e
  return "$status"
}
trap 'status=$?; cleanup || status=$?; exit "$status"' EXIT
compose 120 up -d
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if compose 15 exec -T openmemory-mcp python - <<'PY' >/dev/null 2>&1
import json
import urllib.request

for url in ("http://127.0.0.1:8765/healthz", "http://mem0_store:6333/collections"):
    with urllib.request.urlopen(url, timeout=3) as response:
        if response.status != 200:
            raise SystemExit(1)
        json.load(response)
PY
  then
    bounded 15 /usr/bin/sqlite3 "$ROOT/db/openmemory.db" 'PRAGMA integrity_check;' | grep -Fxq ok
    printf '%s\n' 'PASS clone restore'
    exit 0
  fi
  bounded 3 sleep 2
done
printf '%s\n' 'restore clone: readiness failed' >&2
exit 1
