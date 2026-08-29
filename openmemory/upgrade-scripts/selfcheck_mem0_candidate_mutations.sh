#!/usr/bin/env bash
set -euo pipefail

umask 077
RUN_DIR="${1:-}"
PROJECT_NAME="${2:-}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
FIXTURE="${OPENMEMORY_MUTATION_FIXTURE:-}"
OUTPUT="$RUN_DIR/evidence/mutation-gate.json"

[ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ] || { printf '%s\n' 'mutation gate: run directory is required' >&2; exit 2; }
[ -n "$PROJECT_NAME" ] || { printf '%s\n' 'mutation gate: project name is required' >&2; exit 2; }
[ -n "$FIXTURE" ] && [ -f "$FIXTURE" ] && [ ! -L "$FIXTURE" ] || { printf '%s\n' 'mutation gate: private fixture is required' >&2; exit 2; }
[ "$(stat -f %Lp "$FIXTURE")" = 600 ] || { printf '%s\n' 'mutation gate: fixture must be mode 0600' >&2; exit 2; }

DOCKER_CONTEXT="${DOCKER_CONTEXT:-default}"
compose=(env -i PATH="$PATH" HOME="$HOME" DOCKER_CONTEXT="$DOCKER_CONTEXT" DOCKER_HOST="${DOCKER_HOST:-}" docker --config "$HOME/.docker" --context "$DOCKER_CONTEXT" compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME")
raw_result="$("${compose[@]}" exec -T candidate-api env OPENMEMORY_MUTATION_FIXTURE=/candidate-input/mutation-fixture.json python - <<'PY'
import json
import os
import pathlib
import sqlite3
import asyncio
import socket
import time
import urllib.parse
import urllib.error
import urllib.request
from uuid import UUID

fixture = pathlib.Path(os.environ["OPENMEMORY_MUTATION_FIXTURE"]).read_text(encoding="utf-8")
case = json.loads(fixture)
required = {"user_id", "app", "create_text", "updated_text"}
if set(case) != required or any(not isinstance(case[key], str) or not case[key] for key in required):
    raise SystemExit("mutation fixture schema mismatch")
base = "http://127.0.0.1:8765"
headers = {"Authorization": "Bearer candidate-test-key", "Content-Type": "application/json"}

def call(method, path, payload=None, timeout=15):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"mutation endpoint failed: {method} {path} status={exc.code}") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise SystemExit(f"mutation endpoint timeout: {method} {path} timeout={timeout}s") from exc
    except urllib.error.URLError as exc:
        reason = type(exc.reason).__name__
        raise SystemExit(f"mutation endpoint transport failure: {method} {path} reason={reason}") from exc

def expect(method, path, allowed, payload=None, timeout=15):
    status, body = call(method, path, payload, timeout)
    if status not in allowed:
        raise SystemExit(f"unexpected status: {method} {path} status={status}")
    return status, (json.loads(body) if body else {})

collection = os.environ.get("OPENMEMORY_QDRANT_COLLECTION", "openmemory")

def qdrant_point(memory_id):
    request = urllib.request.Request(
        "http://candidate-store:6333/collections/" + urllib.parse.quote(collection, safe="") + "/points/" + memory_id
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            document = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise SystemExit(f"mutation Qdrant lookup failed status={exc.code}") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise SystemExit(f"mutation Qdrant lookup timeout: collection={collection} point={memory_id} timeout=15s") from exc
    except urllib.error.URLError as exc:
        reason = type(exc.reason).__name__
        raise SystemExit(f"mutation Qdrant transport failure: collection={collection} point={memory_id} reason={reason}") from exc
    if not isinstance(document, dict) or document.get("status") not in {None, "ok"} or not isinstance(document.get("result"), dict):
        raise SystemExit("mutation Qdrant response schema failed")
    result = document["result"]
    if str(result.get("id")) != memory_id or not isinstance(result.get("payload"), dict):
        raise SystemExit("mutation Qdrant point schema failed")
    return result

def qdrant_point_exists(memory_id):
    point = qdrant_point(memory_id)
    payload = (point or {}).get("payload")
    if point is not None and str(payload.get("user_id")) != user_id:
        raise SystemExit("mutation Qdrant point owner mismatch")
    return point is not None

def history_snapshot(root):
    snapshot = {}
    if not root.exists():
        return snapshot
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        snapshot[str(path.relative_to(root))] = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
    return snapshot

def changed_history_contains(root, before_snapshot, needles):
    changed = []
    if not root.exists():
        return False
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        content = path.read_bytes()
        digest = __import__("hashlib").sha256(content).hexdigest()
        relative = str(path.relative_to(root))
        if digest != before_snapshot.get(relative) and any(needle.encode() in content for needle in needles):
            changed.append(path)
    return bool(changed)

history_root = pathlib.Path("/root/.mem0")
history_before = history_snapshot(history_root)
checks = {}

user_id = case["user_id"]
create_status, created = expect("POST", "/api/v1/memories/", {200}, {"user_id": user_id, "text": case["create_text"], "metadata": {"mutation_gate": True}, "infer": False, "app": case["app"]}, timeout=30)
memory_id = str(created.get("id", ""))
if not memory_id:
    raise SystemExit("mutation create did not return a memory id")
created_point = qdrant_point(memory_id)
if not qdrant_point_exists(memory_id):
    raise SystemExit("mutation Qdrant payload postcondition failed")
created_payload = created_point.get("payload") or {}
if str(created_payload.get("user_id")) != user_id or created_payload.get("mcp_client") != case["app"]:
    raise SystemExit("mutation Qdrant payload identity postcondition failed")
checks["create"] = {"status": create_status, "qdrant_payload": True, "payload_identity": True}
checks["qdrant-payload"] = {"create_payload": True}
config_connection = sqlite3.connect("/candidate-data/openmemory.db")
config_row = config_connection.execute("SELECT value FROM configs WHERE key = 'main'").fetchone()
config_connection.close()
if not config_row:
    raise SystemExit("mutation configuration lookup failed")
config = json.loads(config_row[0])
if not isinstance(config.get("openmemory"), dict) or not (config["openmemory"].get("custom_instructions") or "").strip():
    raise SystemExit("mutation configuration contract failed")
mem0_config = config.get("mem0")
if not isinstance(mem0_config, dict) or not mem0_config.get("llm") or not mem0_config.get("embedder"):
    raise SystemExit("mutation Mem0 configuration contract failed")
if mem0_config.get("vector_store") is not None and not isinstance(mem0_config["vector_store"], dict):
    raise SystemExit("mutation Mem0 vector store configuration contract failed")
checks["config"] = {"openmemory": True, "mem0": True}
from app import mcp_server
user_token = mcp_server.user_id_var.set(user_id)
app_token = mcp_server.client_name_var.set(case["app"])
try:
    mcp_result = json.loads(asyncio.run(mcp_server.search_memory(case["create_text"])))
finally:
    mcp_server.user_id_var.reset(user_token)
    mcp_server.client_name_var.reset(app_token)
if not isinstance(mcp_result, dict) or not any(str(item.get("id")) == memory_id for item in mcp_result.get("results", [])):
    raise SystemExit("mutation MCP search postcondition failed")
checks["mcp"] = {"search": True, "target_visible": True}
user_row = sqlite3.connect("/candidate-data/openmemory.db")
app_id = user_row.execute("SELECT id FROM apps WHERE owner_id = (SELECT id FROM users WHERE user_id = ?) AND name = ?", (user_id, case["app"])).fetchone()
user_row.close()
if not app_id:
    raise SystemExit("mutation app lookup failed")
app_id = str(app_id[0])
app_uuid = UUID(app_id)
memory_uuid = UUID(memory_id)
def filtered_contains(target_id):
    for page in range(1, 1001):
        status, document = expect("GET", "/api/v1/memories/?" + urllib.parse.urlencode({"user_id": user_id, "app_id": app_id, "size": 100, "page": page}), {200})
        if any(str(item.get("id")) == target_id for item in document.get("items", [])):
            return True, status
        if page >= int(document.get("pages", page)):
            return False, status
    raise SystemExit("mutation filtered retrieval pagination exceeded limit")

listed_found, list_status = filtered_contains(memory_id)
if not listed_found:
    raise SystemExit("mutation filtered retrieval allow postcondition failed")
checks["filtered-retrieval"] = {"allow": True, "allow_status": list_status}
from app.database import SessionLocal
from app.models import AccessControl, App, Memory, User
from app.utils.permissions import check_memory_access_permissions
session = SessionLocal()
user_row = session.query(User).filter(User.user_id == user_id).first()
app_row = session.query(App).filter(App.id == app_uuid).first()
memory_row = session.query(Memory).filter(Memory.id == memory_uuid).first()
if not user_row or not app_row or not memory_row:
    raise SystemExit("mutation ORM lookup failed")
actor_uuid = user_row.id
deny = AccessControl(subject_type="app", subject_id=app_row.id, object_type="memory", object_id=memory_row.id, effect="deny")
session.add(deny)
session.commit()
if check_memory_access_permissions(session, memory_row, app_row.id):
    raise SystemExit("mutation ACL deny postcondition failed")
denied_found, deny_status = filtered_contains(memory_id)
if denied_found:
    raise SystemExit("mutation ACL deny retrieval postcondition failed")
session.delete(deny)
allow = AccessControl(subject_type="app", subject_id=app_row.id, object_type="memory", object_id=memory_row.id, effect="allow")
session.add(allow)
session.commit()
if not check_memory_access_permissions(session, memory_row, app_row.id):
    raise SystemExit("mutation ACL allow postcondition failed")
allowed_found, allow_status = filtered_contains(memory_id)
if not allowed_found:
    raise SystemExit("mutation ACL allow retrieval postcondition failed")
session.delete(allow)
session.commit()
session.close()
checks["acl"] = {"allow": True, "deny": True, "deny_status": deny_status, "allow_status": allow_status}
query = urllib.parse.urlencode({"memory_ids": [memory_id], "user_id": str(actor_uuid)}, doseq=True)
update_status, _ = expect("PUT", f"/api/v1/memories/{memory_id}", {200}, {"memory_content": case["updated_text"], "user_id": user_id}, timeout=30)
_, updated = expect("GET", f"/api/v1/memories/{memory_id}", {200})
if updated.get("text") != case["updated_text"]:
    raise SystemExit("mutation update postcondition failed")
checks["update"] = {"status": update_status, "content": True}
updated_point = None
updated_payload = {}
update_payload_checks = {}
for _ in range(15):
    updated_point = qdrant_point(memory_id)
    updated_payload = (updated_point or {}).get("payload") or {}
    update_payload_checks = {
        "user_id": str(updated_payload.get("user_id")) == user_id,
        "mcp_client": updated_payload.get("mcp_client") == case["app"],
        "data": updated_payload.get("data") == case["updated_text"],
    }
    if all(update_payload_checks.values()):
        break
    time.sleep(1)
if not all(update_payload_checks.values()):
    raise SystemExit(f"mutation Qdrant update payload postcondition failed checks={update_payload_checks} keys={sorted(updated_payload)}")
checks["qdrant-payload"]["update_payload"] = True
pause_status, _ = expect("POST", "/api/v1/memories/actions/pause", {200}, {"memory_ids": [memory_id], "user_id": user_id})
_, paused = expect("GET", f"/api/v1/memories/{memory_id}", {200})
if paused.get("state") != "paused":
    raise SystemExit("mutation pause postcondition failed")
checks["pause"] = {"status": pause_status, "state": "paused"}
paused_found, _ = filtered_contains(memory_id)
if paused_found:
    raise SystemExit("mutation filtered retrieval state-deny postcondition failed")
checks["filtered-retrieval"]["state_deny"] = True
archive_status, _ = expect("POST", f"/api/v1/memories/actions/archive?{urllib.parse.urlencode({'user_id': str(actor_uuid)})}", {200}, [memory_id])
_, archived = expect("GET", f"/api/v1/memories/{memory_id}", {200})
if archived.get("state") != "archived":
    raise SystemExit("mutation archive postcondition failed")
checks["archive"] = {"status": archive_status, "state": "archived"}
delete_status, _ = expect("DELETE", "/api/v1/memories/", {200}, {"memory_ids": [memory_id], "user_id": user_id})
_, deleted = expect("GET", f"/api/v1/memories/{memory_id}", {200})
if deleted.get("state") != "deleted":
    raise SystemExit("mutation delete postcondition failed")
checks["delete"] = {"status": delete_status, "state": "deleted", "qdrant_absent": not qdrant_point_exists(memory_id)}
if not checks["delete"]["qdrant_absent"]:
    raise SystemExit("mutation Qdrant delete postcondition failed")
connection = sqlite3.connect("/candidate-data/openmemory.db")
history = connection.execute("SELECT old_state, new_state, changed_by, changed_at FROM memory_status_history WHERE memory_id = ? ORDER BY changed_at, rowid", (memory_uuid.hex,)).fetchall()
actor = connection.execute("SELECT id FROM users WHERE user_id = ?", (user_id,)).fetchone()
connection.close()
expected_states = [("deleted", "active"), ("active", "paused"), ("paused", "archived"), ("archived", "deleted")]
history_transitions = [(str(row[0]), str(row[1])) for row in history]
history_actor_match = bool(actor) and all(str(row[2]) == str(actor[0]) for row in history)
history_timestamps = all(bool(row[3]) for row in history)
if history_transitions != expected_states or not history_actor_match or not history_timestamps:
    raise SystemExit(f"mutation status history postcondition failed transitions={history_transitions} actor_match={history_actor_match} timestamps={history_timestamps}")
checks["history"] = {"status_history": True, "ordered": True, "actor_and_time": True}
history_after = history_snapshot(history_root)
if history_after == history_before:
    raise SystemExit("mutation Mem0 history postcondition failed")
if not changed_history_contains(history_root, history_before, (memory_id, case["create_text"])):
    raise SystemExit("mutation Mem0 history target-event postcondition failed")
checks["history"]["mem0_history_changed"] = True
checks["history"]["target_event"] = True
checks["qdrant-payload"]["delete_absent"] = True
operations = ["create", "update", "pause", "archive", "delete", "history", "acl", "filtered-retrieval", "qdrant-payload", "config", "mcp"]
print(json.dumps({"schema": 1, "status": "passed", "operations": operations, "postconditions": operations, "checks": checks, "fixture": "redacted"}, sort_keys=True))
PY
)"
result="$(printf '%s\n' "$raw_result" | tail -n 1)"
printf '%s\n' "$result" > "$OUTPUT"
chmod 600 "$OUTPUT"
