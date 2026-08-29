#!/usr/bin/env bash
set -euo pipefail

umask 077
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"

RUN_DIR="${1:-}"
BACKUP_ROOT="${OPENMEMORY_BACKUP_ROOT:-$HOME/.local/share/openmemory-backups}"
[ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ] || { printf '%s\n' 'restore semantics: run directory is required' >&2; exit 2; }
RUN_ID="$(basename "$RUN_DIR")"
[[ "$RUN_ID" =~ ^[0-9]{8}-[0-9]{6}-[0-9]+$ ]] || { printf '%s\n' 'restore semantics: invalid run id' >&2; exit 1; }
RUN_PARENT="$(CDPATH= cd -- "$(dirname "$RUN_DIR")" && pwd -P)"
EXPECTED_ROOT="$(CDPATH= cd -- "$BACKUP_ROOT" && pwd -P)"
[ "$RUN_PARENT" = "$EXPECTED_ROOT" ] || { printf '%s\n' 'restore semantics: run directory is outside backup root' >&2; exit 1; }
ROOT="$RUN_DIR/clone"
[ -d "$ROOT" ] && [ ! -L "$ROOT" ] || { printf '%s\n' 'restore semantics: clone directory is unavailable' >&2; exit 1; }
COMPOSE_FILE="$ROOT/compose/docker-compose.yml"
[ -f "$COMPOSE_FILE" ] && [ ! -L "$COMPOSE_FILE" ] || { printf '%s\n' 'restore semantics: clone compose file is unavailable' >&2; exit 1; }
grep -Fq 'internal: true' "$COMPOSE_FILE" || { printf '%s\n' 'restore semantics: clone network is not internal' >&2; exit 1; }
! grep -Eq '(^|[[:space:]])ports:|127\.0\.0\.1|localhost' "$COMPOSE_FILE" || { printf '%s\n' 'restore semantics: production endpoint exposure rejected' >&2; exit 1; }

DOCKER_CONTEXT_NAME="$(sed -n 's/^docker_context=//p' "$RUN_DIR/data/runtime.manifest")"
[ -n "$DOCKER_CONTEXT_NAME" ] || { printf '%s\n' 'restore semantics: docker context is missing' >&2; exit 1; }
PROJECT_NAME="openmemory-clone-$(printf '%s' "$RUN_DIR" | shasum -a 256 | awk '{print substr($1,1,12)}')"
compose_command=(env -i PATH="$PATH" HOME="$HOME" DOCKER_CONFIG="$HOME/.docker" docker --context "$DOCKER_CONTEXT_NAME" compose --project-directory "$ROOT/compose" --file "$COMPOSE_FILE" -p "$PROJECT_NAME")
bounded() {
  local seconds="$1"
  shift
  /usr/bin/python3 "$SCRIPT_DIR/run_bounded.py" "$seconds" "$@"
}
compose() {
  local seconds=120
  if [[ "${1:-}" =~ ^[0-9]+$ ]]; then seconds="$1"; shift; fi
  bounded "$seconds" "${compose_command[@]}" "$@"
}

cleanup() {
  local status=$?
  set +e
  compose 30 down --volumes --remove-orphans >/dev/null 2>&1 || status=1
  [ -z "$(docker --context "$DOCKER_CONTEXT_NAME" ps -aq --filter "label=com.docker.compose.project=$PROJECT_NAME")" ] || status=1
  [ -z "$(docker --context "$DOCKER_CONTEXT_NAME" network ls -q --filter "name=^${PROJECT_NAME}$")" ] || status=1
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
    break
  fi
  compose 3 exec -T openmemory-mcp sleep 2
done

compose 60 exec -T openmemory-mcp python - <<'PY'
import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from uuid import UUID

DB = "/clone-data/openmemory.db"
BASE = "http://127.0.0.1:8765"
QDRANT = "http://mem0_store:6333"
COLLECTION = "openmemory"
HEADERS = {"Authorization": "Bearer clone-only-invalid", "Accept": "application/json", "Content-Type": "application/json"}
STATES = {"active", "paused", "archived", "deleted"}


def canonical_uuid(value):
    if isinstance(value, bytes):
        value = value.hex()
    return str(UUID(str(value)))


def api(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(BASE + path, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise SystemExit(f"restore semantics: API status={response.status} path={path}")
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"restore semantics: API status={exc.code} path={path} body={body}") from exc


def page_ids(document):
    if not isinstance(document, dict) or not isinstance(document.get("items"), list):
        raise SystemExit("restore semantics: API page response is invalid")
    try:
        return {canonical_uuid(item["id"]) for item in document["items"] if isinstance(item, dict)}
    except (KeyError, TypeError, ValueError) as exc:
        raise SystemExit("restore semantics: API page item is invalid") from exc


def assert_not_listed(user_external_id, app_id, content, memory_id, label):
    listed = api(
        "GET",
        "/api/v1/memories/?" + urllib.parse.urlencode(
            {"user_id": user_external_id, "app_id": app_id, "search_query": content, "page": 1, "size": 100}
        ),
    )
    filtered = api(
        "POST",
        "/api/v1/memories/filter",
        {"user_id": user_external_id, "app_ids": [app_id], "search_query": content, "page": 1, "size": 100},
    )
    if memory_id in page_ids(listed) or memory_id in page_ids(filtered):
        raise SystemExit(f"restore semantics: {label} failed")


def assert_history(memory_id, owner_id, entries, final_state):
    if not entries:
        return
    previous_at = None
    previous_state = None
    for changed_at, old_state, new_state, changed_by in entries:
        if changed_by != owner_id:
            raise SystemExit("restore semantics: status history actor ownership failed")
        if previous_at is not None and changed_at <= previous_at:
            raise SystemExit("restore semantics: status history chronology failed")
        if previous_state is not None and old_state != previous_state:
            raise SystemExit("restore semantics: status history transition chain failed")
        previous_at = changed_at
        previous_state = new_state
    if previous_state != final_state:
        raise SystemExit("restore semantics: status history final state failed")


def qdrant(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(QDRANT + path, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=15) as response:
        document = json.loads(response.read())
    if document.get("status") not in {None, "ok"} or not isinstance(document.get("result"), dict):
        raise SystemExit("restore semantics: invalid Qdrant response")
    return document["result"]


connection = sqlite3.connect(DB)
users = {canonical_uuid(row[0]): str(row[1]) for row in connection.execute("SELECT id, user_id FROM users")}
apps = {canonical_uuid(row[0]): canonical_uuid(row[1]) for row in connection.execute("SELECT id, owner_id FROM apps")}
if len(users) < 2:
    raise SystemExit("restore semantics: cross-user fixture is missing")
memories = []
for row in connection.execute("SELECT id, user_id, app_id, content, state FROM memories ORDER BY rowid"):
    memory_id, user_id, app_id, content, state = canonical_uuid(row[0]), canonical_uuid(row[1]), canonical_uuid(row[2]), row[3], str(row[4])
    if user_id not in users or app_id not in apps or apps[app_id] != user_id or not isinstance(content, str) or state not in STATES:
        raise SystemExit("restore semantics: memory ownership or state check failed")
    memories.append((memory_id, user_id, app_id, content, state))

history = {}
for row in connection.execute("SELECT memory_id, changed_by, old_state, new_state, changed_at FROM memory_status_history ORDER BY memory_id, changed_at, rowid"):
    memory_id, changed_by, old_state, new_state, changed_at = canonical_uuid(row[0]), canonical_uuid(row[1]), str(row[2]), str(row[3]), row[4]
    if memory_id not in {item[0] for item in memories} or changed_by not in users or old_state not in STATES or new_state not in STATES or not changed_at:
        raise SystemExit("restore semantics: status history check failed")
    history.setdefault(memory_id, []).append((changed_at, old_state, new_state, changed_by))
connection.close()

memory_index = {memory_id: (user_id, app_id, content, state) for memory_id, user_id, app_id, content, state in memories}
for memory_id, (user_id, app_id, content, state) in memory_index.items():
    assert_history(memory_id, user_id, history.get(memory_id, []), state)

active_ids = {memory_id for memory_id, value in memory_index.items() if value[3] == "active"}
archived_ids = {memory_id for memory_id, value in memory_index.items() if value[3] == "archived"}
count_result = qdrant("POST", f"/collections/{urllib.parse.quote(COLLECTION, safe='')}/points/count", {"exact": True})
point_count = count_result.get("count")
if not isinstance(point_count, int) or point_count < 0 or (active_ids and point_count == 0):
    raise SystemExit("restore semantics: Qdrant point count is inconsistent")

points = []
offset = None
while True:
    payload = {"limit": 100, "with_payload": ["user_id", "state"], "with_vectors": False}
    if offset is not None:
        payload["offset"] = offset
    result = qdrant("POST", f"/collections/{urllib.parse.quote(COLLECTION, safe='')}/points/scroll", payload)
    points.extend(result.get("points", []))
    offset = result.get("next_page_offset")
    if offset is None:
        break
if len(points) != point_count:
    raise SystemExit("restore semantics: Qdrant point count/scroll mismatch")
active_point_ids = set()
archived_point_ids = set()
quarantined_point_ids = set()
for point in points:
    point_id = canonical_uuid(point.get("id"))
    if point_id in active_point_ids or point_id in quarantined_point_ids:
        raise SystemExit("restore semantics: duplicate Qdrant point id")
    payload = point.get("payload")
    if not isinstance(payload, dict):
        raise SystemExit("restore semantics: Qdrant payload is invalid")
    if payload.get("state") == "orphan-quarantined":
        if point_id in memory_index:
            raise SystemExit("restore semantics: quarantined Qdrant point has a SQLite memory")
        quarantined_point_ids.add(point_id)
        continue
    if point_id not in active_ids and point_id not in archived_ids:
        raise SystemExit("restore semantics: unquarantined Qdrant point is not an active memory")
    expected_state = "active" if point_id in active_ids else "archived"
    if payload.get("state") is not None and payload.get("state") != expected_state:
        raise SystemExit("restore semantics: Qdrant payload state failed")
    if expected_state == "active":
        active_point_ids.add(point_id)
    else:
        archived_point_ids.add(point_id)
    if str(payload.get("user_id")) != users[memory_index[point_id][0]]:
        raise SystemExit("restore semantics: Qdrant payload ownership failed")
if (len(active_point_ids) + len(archived_point_ids) + len(quarantined_point_ids) != point_count
        or active_point_ids != active_ids or archived_point_ids != archived_ids):
    raise SystemExit("restore semantics: active Qdrant correspondence failed")

checked_ids = set(active_point_ids)
for memory_id, user_id, app_id, content, state in memories:
    document = api("GET", f"/api/v1/memories/{memory_id}")
    if canonical_uuid(document.get("id")) != memory_id or canonical_uuid(document.get("app_id")) != app_id or document.get("state") != state:
        raise SystemExit("restore semantics: memory identity check failed")

if checked_ids:
    memory_id = next(iter(checked_ids))
    user_id, app_id, content, _ = next(item[1:] for item in memories if item[0] == memory_id)
    listed = api("GET", "/api/v1/memories/?" + urllib.parse.urlencode({"user_id": users[user_id], "app_id": app_id, "search_query": content, "page": 1, "size": 100}))
    listed_ids = page_ids(listed)
    if memory_id not in listed_ids or any(item.get("state") in {"archived", "deleted"} for item in listed.get("items", [])):
        raise SystemExit("restore semantics: active retrieval filtering failed")
    filtered = api("POST", "/api/v1/memories/filter", {"user_id": users[user_id], "app_ids": [app_id], "search_query": content, "page": 1, "size": 100})
    if memory_id not in page_ids(filtered):
        raise SystemExit("restore semantics: retrieval check failed")

    other_user = next(user for user in users if user != user_id)
    assert_not_listed(users[other_user], app_id, content, memory_id, "cross-user denial")
    other_app = next((candidate for candidate, owner in apps.items() if owner == user_id and candidate != app_id), None)
    if other_app is None:
        raise SystemExit("restore semantics: cross-app fixture is missing")
    assert_not_listed(users[user_id], other_app, content, memory_id, "cross-app denial")

    deleted_memory = next((item for item in memories if item[4] == "deleted"), None)
    if deleted_memory is None:
        raise SystemExit("restore semantics: deleted denial fixture is missing")
    deleted_id, deleted_user, deleted_app, deleted_content, _ = deleted_memory
    assert_not_listed(users[deleted_user], deleted_app, deleted_content, deleted_id, "deleted denial")

    archive_path = "/api/v1/memories/actions/archive?" + urllib.parse.urlencode({"user_id": user_id})
    archived = api("POST", archive_path, [memory_id])
    if not isinstance(archived, dict) or "archived" not in str(archived.get("message", "")).lower():
        raise SystemExit("restore semantics: archive transition failed")
    assert_not_listed(users[user_id], app_id, content, memory_id, "archived denial")

print(json.dumps({"schema": 1, "status": "passed", "memory_ids": len(memories), "history_ids": len(history), "qdrant_points": point_count, "active_qdrant_points": len(active_point_ids), "archived_qdrant_points": len(archived_point_ids), "orphan_quarantined_points": len(quarantined_point_ids), "retrieval": bool(checked_ids)}, sort_keys=True))
PY

printf '%s\n' 'PASS restore semantic verification'
