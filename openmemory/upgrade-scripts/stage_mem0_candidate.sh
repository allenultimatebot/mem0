#!/usr/bin/env bash
set -euo pipefail

umask 077
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
source "$SCRIPT_DIR/../backup-scripts/keychain_contract.sh"
SOURCE_PROJECT="${OPENMEMORY_PROJECT_DIR:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)}"
BACKUP_ROOT="${OPENMEMORY_BACKUP_ROOT:-$HOME/.local/share/openmemory-backups}"
CANDIDATE_ROOT="${OPENMEMORY_CANDIDATE_ROOT:-$HOME/.local/share/openmemory-upgrade-candidates}"
RUN_ID="${OPENMEMORY_RUN_ID:-$(date -u '+%Y%m%d-%H%M%S')-$$}"
RUN_DIR="${OPENMEMORY_RUN_DIR:-$CANDIDATE_ROOT/$RUN_ID}"
INPUT_DIR="$RUN_DIR/input"
RUNTIME_HISTORY_DIR="$RUN_DIR/runtime-history"
RUNTIME_STORAGE_DIR="$RUN_DIR/runtime-storage"
PROJECT_NAME="openmemory-candidate-$RUN_ID"
NETWORK_NAME="${PROJECT_NAME}-internal"
EGRESS_NETWORK_NAME="${PROJECT_NAME}-egress"
CANDIDATE_VERSION="${MEM0_CANDIDATE_VERSION:-${1:-}}"
CANDIDATE_PYTHON="${OPENMEMORY_CANDIDATE_PYTHON:-$HOME/.local/bin/python3.12}"
CANDIDATE_QDRANT_PORT="${OPENMEMORY_CANDIDATE_QDRANT_PORT:-16333}"
APPROVED_MEM0_WHEEL_SHA256="${OPENMEMORY_APPROVED_MEM0_WHEEL_SHA256:-}"
APPROVED_RELEASE_RECORD="${OPENMEMORY_APPROVED_MEM0_RELEASE_RECORD:-}"
BACKUP_RUN="${OPENMEMORY_BACKUP_RUN:-}"
MANIFEST="${OPENMEMORY_BACKUP_MANIFEST:-}"
MANIFEST_MAC="${OPENMEMORY_BACKUP_MANIFEST_MAC:-}"
EVAL_MANIFEST="${OPENMEMORY_EVAL_MANIFEST:-}"
DIRECT_BASELINE="${OPENMEMORY_DIRECT_BASELINE:-}"
HOST_NETWORK_EVIDENCE="${OPENMEMORY_HOST_NETWORK_EVIDENCE:-}"
MUTATION_GATE_SCRIPT="$SCRIPT_DIR/selfcheck_mem0_candidate_mutations.sh"
WATCHDOG_SCRIPT="$SCRIPT_DIR/candidate-watchdog.py"
NETWORK_EVIDENCE_SCRIPT="$SCRIPT_DIR/collect_host_network_evidence.py"
MUTATION_FIXTURE="${OPENMEMORY_MUTATION_FIXTURE:-}"
BASE_IMAGE="python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203"
DOCKER_CONTEXT=""
DOCKER_HOST_VALUE=""
WATCHDOG_PID=""
BOUNDED_PID=""
PENDING_OUTCOME=""
PENDING_REASON=""
TERMINAL_WRITTEN=0
QDRANT_IMAGE_DIGEST=""
NETWORK_OCTET=$((16#$(printf '%s' "$RUN_ID" | shasum -a 256 | awk '{print substr($1,1,2)}') % 200 + 20))
CANDIDATE_PROXY_PORT="${OPENMEMORY_CANDIDATE_PROXY_PORT:-$((18080 + NETWORK_OCTET))}"
INTERNAL_SUBNET="172.30.${NETWORK_OCTET}.0/24"

terminal_decision() {
  [ -d "$RUN_DIR/evidence" ] || return 0
  local outcome="${1:-BLOCKED-ENVIRONMENT}" reason="${2:-}"
  write_host_attestation "$outcome" "$reason" || return 1
  set +e
  /usr/bin/python3 - "$RUN_DIR/evidence" "$RUN_DIR/evidence/terminal-decision.json" "$RUN_ID" "$outcome" "$reason" 3<<<"$(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null || true)" <<'PY'
import hashlib
import hmac
import json
import pathlib
import sys
import uuid

def canonical_memory_id(value):
    text = str(value)
    try:
        return str(uuid.UUID(text))
    except (ValueError, AttributeError):
        return text
from datetime import datetime, timezone

evidence_dir, output, run_id, outcome, reason = sys.argv[1:]
evidence_dir = pathlib.Path(evidence_dir)
attestation = evidence_dir / "host-attestation.json"
if not attestation.is_file() or attestation.is_symlink():
    raise SystemExit("host attestation is missing")
digest = hashlib.sha256()
for path in sorted(item for item in evidence_dir.rglob("*") if item.is_file() and item.name != "terminal-decision.json"):
    digest.update(str(path.relative_to(evidence_dir)).encode())
    digest.update(path.read_bytes())
payload = {
    "schema": 1,
    "run_id": run_id,
    "outcome": outcome,
    "reason": reason,
    "evidence_sha256": digest.hexdigest(),
    "host_attestation_sha256": hashlib.sha256(attestation.read_bytes()).hexdigest(),
    "decision_source": "host",
    "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
key = pathlib.Path("/dev/fd/3").read_bytes().strip()
payload["authenticated"] = bool(key)
payload["mac"] = hmac.new(key, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest() if key else None
output = pathlib.Path(output)
output.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
output.chmod(0o600)
if not key:
    raise SystemExit(1)
PY
  local status=$?
  set -e
  return "$status"
}

verify_terminal_decision() {
  local expected_outcome="$1"
  /usr/bin/python3 - "$RUN_DIR/evidence" "$RUN_DIR/evidence/terminal-decision.json" "$RUN_ID" "$expected_outcome" 3<<<"$(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db")" <<'PY'
import hashlib
import hmac
import json
import pathlib
import sys

evidence_dir, terminal_path, run_id, expected = sys.argv[1:]
evidence_dir = pathlib.Path(evidence_dir)
terminal_path = pathlib.Path(terminal_path)
document = json.loads(terminal_path.read_text(encoding="utf-8"))
required = {"schema", "run_id", "outcome", "reason", "evidence_sha256", "host_attestation_sha256", "decision_source", "at", "authenticated", "mac"}
if set(document) != required or document["schema"] != 1 or document["run_id"] != run_id or document["outcome"] != expected or document["authenticated"] is not True:
    raise SystemExit("terminal decision schema mismatch")
attestation = evidence_dir / "host-attestation.json"
attestation_document = json.loads(attestation.read_text(encoding="utf-8"))
if attestation_document.get("source") != "host" or attestation_document.get("run_id") != run_id or attestation_document.get("outcome") != expected or document["decision_source"] != "host" or document["host_attestation_sha256"] != hashlib.sha256(attestation.read_bytes()).hexdigest():
    raise SystemExit("host decision binding mismatch")
digest = hashlib.sha256()
for path in sorted(item for item in evidence_dir.rglob("*") if item.is_file() and item.name != terminal_path.name):
    digest.update(str(path.relative_to(evidence_dir)).encode())
    digest.update(path.read_bytes())
if document["evidence_sha256"] != digest.hexdigest():
    raise SystemExit("terminal evidence digest mismatch")
key = pathlib.Path("/dev/fd/3").read_bytes().strip()
attestation_payload = {name: attestation_document[name] for name in ("schema", "source", "run_id", "candidate_version", "outcome", "reason", "decision_table_sha256", "evidence_sha256", "host_identity_sha256", "at")}
if set(attestation_document) != set(attestation_payload) | {"mac"} or not key or not hmac.compare_digest(attestation_document["mac"], hmac.new(key, json.dumps(attestation_payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()):
    raise SystemExit("host attestation MAC mismatch")
attested_digest = hashlib.sha256()
for path in sorted(item for item in evidence_dir.rglob("*") if item.is_file() and item.name not in {"host-attestation.json", "terminal-decision.json"} and not item.name.endswith(".auth.json")):
    attested_digest.update(str(path.relative_to(evidence_dir)).encode())
    attested_digest.update(path.read_bytes())
if attestation_document["evidence_sha256"] != attested_digest.hexdigest() or attestation_document["decision_table_sha256"] != hashlib.sha256((evidence_dir / "decision-table.tsv").read_bytes()).hexdigest():
    raise SystemExit("host attestation evidence binding mismatch")
payload = {name: document[name] for name in ("schema", "run_id", "outcome", "reason", "evidence_sha256", "host_attestation_sha256", "decision_source", "at", "authenticated")}
if not key or not hmac.compare_digest(document["mac"], hmac.new(key, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()):
    raise SystemExit("terminal decision MAC mismatch")
if expected == "READY-FOR-SEPARATE-PRODUCTION-PLAN":
    rows = [line.split("\t", 2) for line in (evidence_dir / "decision-table.tsv").read_text().splitlines()[1:] if line.strip()]
    expected_gates = ["docker", "production_pin", "disk", "release_provenance", "package_index", "tailscale", "gateways", "production_fingerprint", "backup_manifest", "backup", "clone", "compose", "environment", "runtime", "egress", "scoring", "authoritative_replay", "clone_pristine", "mutation", "production_fingerprint", "teardown"]
    if [row[0] for row in rows] != expected_gates or any(len(row) != 3 or row[1] != "PASS" for row in rows):
        raise SystemExit("terminal decision is not bound to all PASS gates")
PY
}
write_host_attestation() {
  local outcome="${1:-BLOCKED-ENVIRONMENT}" reason="${2:-}"
  /usr/bin/python3 - "$RUN_DIR/evidence" "$RUN_DIR/evidence/host-attestation.json" "$RUN_ID" "$CANDIDATE_VERSION" "$outcome" "$reason" 3<<<"$(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null || true)" <<'PY'
import hashlib
import hmac
import json
import pathlib
import socket
import subprocess
import sys
from datetime import datetime, timezone
from datetime import datetime, timezone

evidence_dir, output, run_id, candidate_version, outcome, reason = sys.argv[1:]
evidence_dir = pathlib.Path(evidence_dir)
digest = hashlib.sha256()
for path in sorted(item for item in evidence_dir.rglob("*") if item.is_file() and item.name not in {"host-attestation.json", "terminal-decision.json"} and not item.name.endswith(".auth.json")):
    digest.update(str(path.relative_to(evidence_dir)).encode())
    digest.update(path.read_bytes())
payload = {
    "schema": 1,
    "source": "host",
    "run_id": run_id,
    "candidate_version": candidate_version,
    "outcome": outcome,
    "reason": reason,
    "decision_table_sha256": hashlib.sha256((evidence_dir / "decision-table.tsv").read_bytes()).hexdigest() if (evidence_dir / "decision-table.tsv").is_file() else None,
    "evidence_sha256": digest.hexdigest(),
    "host_identity_sha256": hashlib.sha256(socket.gethostname().encode()).hexdigest(),
    "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
key = pathlib.Path("/dev/fd/3").read_bytes().strip()
if not key:
    raise SystemExit("host attestation key is unavailable")
payload["mac"] = hmac.new(key, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
pathlib.Path(output).write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
pathlib.Path(output).chmod(0o600)
PY
}
die() { PENDING_OUTCOME="${FAILURE_OUTCOME:-BLOCKED-ENVIRONMENT}"; PENDING_REASON="$1"; printf '%s: %s\n' "$PENDING_OUTCOME" "$1" >&2; exit 1; }
no_go() { FAILURE_OUTCOME=NO-GO; die "$1"; }
more_work() { FAILURE_OUTCOME=MORE-WORK; die "$1"; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "$1 is unavailable"; }
safe_path() { [ -n "$1" ] && [ "${1#/}" != "$1" ] && [ ! -L "$1" ]; }
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
bounded() {
  local seconds="$1"
  shift
  /usr/bin/python3 - "$seconds" "$RUN_DIR/operation.pgid" "$RUN_ID" "$@" <<'PY' &
import json
import os
import pathlib
import signal
import subprocess
import sys

seconds, marker_path, run_id = sys.argv[1:4]
command = sys.argv[4:]
marker = pathlib.Path(marker_path)
process = subprocess.Popen(command, start_new_session=True)
temporary = marker.with_name(marker.name + ".tmp-" + str(os.getpid()))
try:
    temporary.write_text(json.dumps({
        "schema": 1,
        "run_id": run_id,
        "operation": command[0] if command else "",
        "pid": process.pid,
        "pgid": os.getpgid(process.pid),
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, marker)
except OSError:
    os.killpg(process.pid, signal.SIGKILL)
    process.wait()
    raise SystemExit(125)
try:
    process.wait(timeout=float(seconds))
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    raise SystemExit(124)
finally:
    try:
        marker.unlink()
    except FileNotFoundError:
        pass
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
raise SystemExit(process.returncode)
PY
  local child=$!
  BOUNDED_PID="$child"
  set +e
  wait "$child"
  local status=$?
  set -e
  BOUNDED_PID=""
  rm -f "$RUN_DIR/operation.pgid" 2>/dev/null || true
  return "$status"
}

forward_signal() {
  if [ -f "$RUN_DIR/operation.pgid" ]; then
    /usr/bin/python3 - "$RUN_DIR/operation.pgid" <<'PY' 2>/dev/null || true
import json
import os
import pathlib
import signal
import sys
try:
    marker = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    pgid = int(marker["pgid"])
    if pgid > 0:
        os.killpg(pgid, signal.SIGTERM)
except (OSError, KeyError, TypeError, ValueError):
    pass
PY
  elif [ -n "${BOUNDED_PID:-}" ]; then
    kill -TERM "$BOUNDED_PID" 2>/dev/null || true
  fi
  PENDING_OUTCOME=BLOCKED-ENVIRONMENT
  PENDING_REASON='coordinator signal interrupted candidate operation'
  exit 143
}

start_watchdog() {
  /usr/bin/python3 "$WATCHDOG_SCRIPT" "$RUN_DIR" "$PROJECT_NAME" "$RUN_ID" "$DOCKER_CONTEXT" "$DOCKER_HOST_VALUE" "$$" "$RUN_DIR/operation.pgid" >/dev/null 2>&1 &
  WATCHDOG_PID="$!"
}

stop_watchdog() {
  if [ -n "$WATCHDOG_PID" ]; then
    kill -TERM "$WATCHDOG_PID" >/dev/null 2>&1 || true
    wait "$WATCHDOG_PID" >/dev/null 2>&1 || true
    WATCHDOG_PID=""
  fi
}

trap forward_signal INT TERM HUP

production_fingerprint_body() {
  {
    printf 'requirements='; sha256 "$SOURCE_PROJECT/api/requirements.txt"
    printf 'compose='; sha256 "$SOURCE_PROJECT/docker-compose.yml"
    printf 'sqlite='; docker_scrubbed run --rm --network none -v openmemory_openmemory_db:/var/lib/openmemory:ro alpine:3.20 sha256sum /var/lib/openmemory/openmemory.db | awk '{print $1}'
    docker_scrubbed ps -a --filter label=com.docker.compose.project=openmemory --format '{{.ID}}' | while IFS= read -r id; do
      docker_scrubbed inspect -f '{{json .}}' "$id"
    done | /usr/bin/python3 -c '
import json
import sys

records = []
for line in sys.stdin:
    item = json.loads(line)
    mounts = sorted(
        (
            {
                key: mount.get(key)
                for key in ("Type", "Name", "Source", "Destination", "Mode", "RW")
                if key in mount
            }
            for mount in item.get("Mounts") or []
        ),
        key=lambda mount: tuple(str(mount.get(key, "")) for key in ("Destination", "Source", "Name", "Type")),
    )
    ports = {
        port: sorted(bindings or [], key=lambda binding: (str(binding.get("HostIp", "")), str(binding.get("HostPort", ""))))
        for port, bindings in sorted((item.get("NetworkSettings", {}).get("Ports") or {}).items())
    }
    records.append({
        "id": item.get("Id"),
        "name": str(item.get("Name", "")).lstrip("/"),
        "image": item.get("Config", {}).get("Image"),
        "mounts": mounts,
        "ports": ports,
    })
print(json.dumps(sorted(records, key=lambda record: record["name"]), sort_keys=True, separators=(",", ":")))
'
    docker_scrubbed volume ls --filter name='^openmemory_' -q | while IFS= read -r id; do docker_scrubbed volume inspect -f '{{.Name}}|{{.Labels}}|{{.Mountpoint}}' "$id"; done
    docker_scrubbed network ls --filter name='^openmemory_' -q | while IFS= read -r id; do docker_scrubbed network inspect -f '{{.Id}}|{{.Name}}|{{.Driver}}|{{json .IPAM.Config}}' "$id"; done
    /usr/bin/python3 - "${OPENMEMORY_QDRANT_URL:-http://127.0.0.1:6333}" "${OPENMEMORY_QDRANT_COLLECTION:-openmemory}" <<'PY'
import hashlib
import json
import sys
import urllib.parse
import urllib.request

base, collection = sys.argv[1:]
def get(path, payload=None):
    data = None if payload is None else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    request = urllib.request.Request(base.rstrip("/") + path, data=data, method="GET" if data is None else "POST")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)

quoted = urllib.parse.quote(collection, safe="")
state = get("/collections/" + quoted).get("result", {})
points = []
offset = None
for page_number in range(1000):
    request = {"limit": 256, "with_payload": True, "with_vector": True}
    if offset is not None:
        request["offset"] = offset
    result = get("/collections/" + quoted + "/points/scroll", request).get("result", {})
    points.extend(result.get("points") or [])
    offset = result.get("next_page_offset")
    if offset is None:
        break
else:
    raise SystemExit("Qdrant fingerprint pagination truncated")
print(hashlib.sha256(json.dumps({"collection": state, "points": sorted(points, key=lambda item: str(item.get("id")))}, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
PY
  } | shasum -a 256 | awk '{print $1}'
}

production_fingerprint() {
  if [ "${OPENMEMORY_FINGERPRINT_CHILD:-0}" = 1 ]; then
    production_fingerprint_body
    return
  fi
  export SOURCE_PROJECT BACKUP_ROOT DOCKER_CONTEXT DOCKER_HOST_VALUE OPENMEMORY_RUN_ID="$RUN_ID" OPENMEMORY_RUN_DIR="$RUN_DIR"
  bounded 60 env OPENMEMORY_FINGERPRINT_CHILD=1 bash "$0" --production-fingerprint
}

docker_scrubbed() {
  bounded 30 env -i PATH="$PATH" HOME="$HOME" DOCKER_CONTEXT="$DOCKER_CONTEXT" DOCKER_HOST="$DOCKER_HOST_VALUE" \
    docker --config "$HOME/.docker" "$@"
}

docker_bounded() {
  local seconds="$1"
  shift
  bounded "$seconds" env -i PATH="$PATH" HOME="$HOME" DOCKER_CONTEXT="$DOCKER_CONTEXT" DOCKER_HOST="$DOCKER_HOST_VALUE" \
    docker --config "$HOME/.docker" "$@"
}

record() { printf '%s=%s\n' "$1" "$2" >> "$RUN_DIR/evidence/preflight.tsv"; }
decision() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RUN_DIR/evidence/decision-table.tsv"; }

seal_evidence_file() {
  local file="$1"
  /usr/bin/python3 - "$file" "$file.auth.json" 3<<<"$(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null || true)" <<'PY'
import hashlib
import hmac
import json
import pathlib
import sys

file_path, auth_path = map(pathlib.Path, sys.argv[1:])
digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
key = pathlib.Path("/dev/fd/3").read_bytes().strip()
if not key:
    raise SystemExit("evidence seal key is unavailable")
payload = {"schema": 1, "file": file_path.name, "sha256": digest}
payload["mac"] = hmac.new(key, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
auth_path.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
auth_path.chmod(0o600)
PY
  shasum -a 256 "$file" | awk '{print $1}' > "$file.sha256"
  chmod 600 "$file.sha256"
  return $?
}

verify_sealed_file() {
  local file="$1"
  /usr/bin/python3 - "$file" "$file.auth.json" 3<<<"$(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db")" <<'PY'
import hashlib
import hmac
import json
import pathlib
import sys

file_path, auth_path = map(pathlib.Path, sys.argv[1:])
record = json.loads(auth_path.read_text(encoding="utf-8"))
if set(record) != {"schema", "file", "sha256", "mac"} or record["schema"] != 1 or record["file"] != file_path.name:
    raise SystemExit("evidence authentication envelope mismatch")
if record["sha256"] != hashlib.sha256(file_path.read_bytes()).hexdigest():
    raise SystemExit("evidence digest mismatch")
key = pathlib.Path("/dev/fd/3").read_bytes().strip()
payload = {key: record[key] for key in ("schema", "file", "sha256")}
if not key or not hmac.compare_digest(record["mac"], hmac.new(key, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()):
    raise SystemExit("evidence MAC mismatch")
PY
}

verify_backup_manifest() {
  MANIFEST="${MANIFEST:-$BACKUP_RUN/manifest.canonical.json}"
  MANIFEST_MAC="${MANIFEST_MAC:-$BACKUP_ROOT/.manifest-auth/$(basename "$BACKUP_RUN").json}"
  [ "$MANIFEST" = "$BACKUP_RUN/manifest.canonical.json" ] || die 'manifest is not bound to selected backup'
  [ "$MANIFEST_MAC" = "$BACKUP_ROOT/.manifest-auth/$(basename "$BACKUP_RUN").json" ] || die 'manifest MAC is not bound to selected backup'
  [ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || die 'backup manifest is missing or symlinked'
  [ -f "$MANIFEST_MAC" ] && [ ! -L "$MANIFEST_MAC" ] || die 'backup manifest authentication record is missing or symlinked'
  require_command security
  /usr/bin/python3 "$SCRIPT_DIR/../backup-scripts/manifest_auth.py" verify "$BACKUP_RUN" "$MANIFEST_MAC" com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 v1 0<<<"$(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db")" || die 'manifest schema mismatch or backup manifest authentication failed'
}

verify_release_record() {
  [ -n "$APPROVED_RELEASE_RECORD" ] && [ -f "$APPROVED_RELEASE_RECORD" ] && [ ! -L "$APPROVED_RELEASE_RECORD" ] || die 'authenticated mem0ai release approval record is required'
  [ -f "$APPROVED_RELEASE_RECORD.auth.json" ] && [ ! -L "$APPROVED_RELEASE_RECORD.auth.json" ] || die 'mem0ai release approval authentication record is required'
  APPROVED_MEM0_WHEEL_SHA256="$(/usr/bin/python3 - "$APPROVED_RELEASE_RECORD" "$APPROVED_RELEASE_RECORD.auth.json" "$CANDIDATE_VERSION" "$APPROVED_MEM0_WHEEL_SHA256" 3<<<"$(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db")" <<'PY'
import hashlib
import hmac
import json
import pathlib
import sys

record_path, auth_path = map(pathlib.Path, sys.argv[1:3])
candidate_version, caller_digest = sys.argv[3:]
record = json.loads(record_path.read_text(encoding="utf-8"))
required = {"schema", "package", "version", "wheel_filename", "wheel_sha256", "source", "index_url", "approved_at", "key_id"}
if set(record) != required or record["schema"] != 1 or record["package"] != "mem0ai" or record["version"] != candidate_version or record["source"] != "pypi-json" or record["index_url"] != "https://pypi.org/simple" or record["key_id"] != "v1":
    raise SystemExit("release approval record mismatch")
if not isinstance(record["wheel_filename"], str) or not record["wheel_filename"].endswith(".whl") or not isinstance(record["wheel_sha256"], str) or len(record["wheel_sha256"]) != 64 or any(character not in "0123456789abcdef" for character in record["wheel_sha256"].lower()):
    raise SystemExit("release approval artifact identity is invalid")
if caller_digest and caller_digest.lower() != record["wheel_sha256"].lower():
    raise SystemExit("caller digest conflicts with authenticated approval record")
digest = hashlib.sha256(record_path.read_bytes()).hexdigest()
auth = json.loads(auth_path.read_text(encoding="utf-8"))
if set(auth) != {"schema", "file", "sha256", "mac"} or auth["schema"] != 1 or auth["file"] != record_path.name or auth["sha256"] != digest:
    raise SystemExit("release approval authentication envelope mismatch")
key = pathlib.Path("/dev/fd/3").read_bytes().strip()
payload = {name: auth[name] for name in ("schema", "file", "sha256")}
if not key or not hmac.compare_digest(auth["mac"], hmac.new(key, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()):
    raise SystemExit("release approval MAC mismatch")
print(record["wheel_sha256"].lower())
PY
)" || die 'mem0ai release approval verification failed'
  /usr/bin/python3 - "$APPROVED_RELEASE_RECORD" "$RUN_DIR/evidence/approved-release-record.json" <<'PY' || die 'approved release summary generation failed'
import hashlib
import json
import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:])
record = json.loads(source.read_text(encoding="utf-8"))
safe = {key: record[key] for key in ("schema", "package", "version", "wheel_filename", "wheel_sha256", "source", "index_url", "key_id")}
safe["approval_record_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
output.write_bytes(json.dumps(safe, sort_keys=True, separators=(",", ":")).encode() + b"\n")
output.chmod(0o600)
PY
  decision release_provenance PASS authenticated
}

verify_source_snapshot() {
  local source="$1"
  [ -f "$source/SOURCE-SHA256SUMS" ] && [ -f "$source/SOURCE-MODES" ] || die 'source evidence is incomplete'
  (cd "$source" && shasum -a 256 -c SOURCE-SHA256SUMS >/dev/null) || die 'source checksum mismatch'
  /usr/bin/python3 - "$source" <<'PY' || die 'source file or mode fingerprint mismatch'
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
expected = {}
for line in (root / "SOURCE-MODES").read_text().splitlines():
    relative, mode = line.rsplit("|mode=", 1)
    expected[relative] = int(mode, 8)
actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file() and path.name not in {"SOURCE-MODES", "SOURCE-SHA256SUMS"}}
if actual != set(expected):
    raise SystemExit(1)
for relative, mode in expected.items():
    if (root / relative).stat().st_mode & 0o777 != mode:
        raise SystemExit(1)
PY
}

select_backup() {
  if [ -z "$BACKUP_RUN" ]; then
    BACKUP_RUN="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -name '20??????-??????-*' -print 2>/dev/null | sort | tail -n 1)"
  fi
  [ -n "$BACKUP_RUN" ] || die 'no backup run selected'
  /usr/bin/python3 - "$BACKUP_RUN" "$BACKUP_ROOT" <<'PY' || die 'backup run is outside the approved backup root'
import pathlib
import sys
run, root = map(lambda value: pathlib.Path(value).expanduser().resolve(), sys.argv[1:])
if run.parent != root or run.is_symlink():
    raise SystemExit(1)
PY
  [ -f "$BACKUP_RUN/state" ] && grep -Fxq complete "$BACKUP_RUN/state" || die 'backup run is not complete'
  [ -f "$BACKUP_RUN/restore-verified" ] || die 'backup run restore verification is missing'
  [ -f "$BACKUP_RUN/SHA256SUMS" ] || die 'backup top-level checksums are missing'
  (cd "$BACKUP_RUN/data" && shasum -a 256 -c ../SHA256SUMS >/dev/null) || die 'backup checksum verification failed'
  [ -f "$BACKUP_RUN/data/sqlite/openmemory.db" ] || die 'SQLite backup is missing'
  [ -f "$BACKUP_RUN/data/volumes/history/volume.tar" ] || die 'history archive is missing'
  [ -f "$BACKUP_RUN/data/volumes/storage/volume.tar" ] || die 'Qdrant storage archive is missing'
  verify_source_snapshot "$BACKUP_RUN/data/source"
  verify_backup_manifest
  record keychain_manifest PASS
  decision backup_manifest PASS authenticated
  cp "$BACKUP_RUN/data/runtime.manifest" "$RUN_DIR/evidence/production-runtime.manifest"
  cp "$BACKUP_RUN/data/source/SOURCE-SHA256SUMS" "$RUN_DIR/evidence/production-source.sha256"
  cp "$BACKUP_RUN/data/source/SOURCE-MODES" "$RUN_DIR/evidence/production-source.modes"
  recorded_context="$(sed -n 's/^docker_context=//p' "$RUN_DIR/evidence/production-runtime.manifest")"
  recorded_endpoint="$(sed -n 's/^docker_endpoint_sha256=//p' "$RUN_DIR/evidence/production-runtime.manifest")"
  current_endpoint="$(printf '%s' "$DOCKER_HOST_VALUE" | shasum -a 256 | awk '{print $1}')"
  [ "$recorded_context" = "$DOCKER_CONTEXT" ] && [ "$recorded_endpoint" = "$current_endpoint" ] || die 'Docker context does not match authenticated backup context'
  decision backup PASS verified
  record backup PASS
}

preflight() {
  require_command docker
  require_command shasum
  require_command curl
  require_command tar
  [ -x "$CANDIDATE_PYTHON" ] || die 'candidate Python runtime is unavailable'
  require_command lsof
  DOCKER_CONTEXT="${OPENMEMORY_DOCKER_CONTEXT:-$(env -u DOCKER_CONTEXT -u DOCKER_HOST docker context show 2>/dev/null)}" || die 'Docker context is unavailable'
  [ -n "$DOCKER_CONTEXT" ] || die 'Docker context is empty'
  DOCKER_HOST_VALUE="$(docker_scrubbed context inspect -f '{{(index .Endpoints "docker").Host}}' "$DOCKER_CONTEXT" 2>/dev/null || true)"
  docker_scrubbed info >/dev/null 2>&1 || die 'Docker daemon is unavailable'
  record docker_context "$DOCKER_CONTEXT"
  record docker_endpoint "${DOCKER_HOST_VALUE:-context-default}"
  decision docker PASS "context=$DOCKER_CONTEXT"
  [ -f "$SOURCE_PROJECT/api/requirements.txt" ] && [ -f "$SOURCE_PROJECT/docker-compose.yml" ] || die 'production source contract is incomplete'
  docker_scrubbed volume inspect openmemory_openmemory_db >/dev/null 2>&1 || die 'production SQLite named volume is missing'
  grep -Fxq 'mem0ai==2.0.4' "$SOURCE_PROJECT/api/requirements.txt" || die 'production mem0ai pin drifted'
  record production_pin PASS
  decision production_pin PASS 'mem0ai==2.0.4'
  [ "$(df -Pk "$CANDIDATE_ROOT" 2>/dev/null | awk 'NR==2 {print $4}')" -ge "${OPENMEMORY_CANDIDATE_MIN_FREE_KB:-1048576}" ] || die 'candidate root lacks disk headroom'
  record disk PASS
  decision disk PASS headroom
  [ -n "$CANDIDATE_VERSION" ] || die 'candidate version must be supplied at execution time'
  [[ "$CANDIDATE_VERSION" =~ ^[0-9]+(\.[0-9]+){1,3}([.-][0-9A-Za-z.-]+)?$ ]] || die 'candidate version format is invalid'
  verify_release_record
  bounded 60 env -i PATH="$PATH" HOME="$HOME" PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 PIP_DEFAULT_TIMEOUT=15 \
    "$CANDIDATE_PYTHON" -m pip index versions --index-url https://pypi.org/simple --timeout 15 --retries 1 mem0ai > "$RUN_DIR/evidence/package-index.out" 2>"$RUN_DIR/evidence/package-index.err" || die 'package index verification failed'
  printf '%s\n' 'https://pypi.org/simple' > "$RUN_DIR/evidence/package-index-url.txt"
  grep -Eq "(^|[[:space:],:])$CANDIDATE_VERSION([[:space:],]|$)" "$RUN_DIR/evidence/package-index.out" || die 'candidate version is not live-verified in the package index'
record package_index PASS
  decision package_index PASS "candidate_version=$CANDIDATE_VERSION"
  record verification_timestamp "$(date -u '+%FT%TZ')"
  local tailscale_bin
  tailscale_bin="$(command -v tailscale 2>/dev/null || true)"
  [ -x "$tailscale_bin" ] || for tailscale_bin in /Applications/Tailscale.app/Contents/MacOS/tailscale /Applications/Tailscale.app/Contents/MacOS/Tailscale; do [ -x "$tailscale_bin" ] && break; done
  [ -x "$tailscale_bin" ] && "$tailscale_bin" status --json >/dev/null 2>&1 || die 'Tailscale evidence is unavailable'
  record tailscale PASS
  decision tailscale PASS reachable
  curl --fail --silent --show-error --max-time 10 http://127.0.0.1:20128/api/health >/dev/null || die 'approved API gateway preflight failed'
  curl --fail --silent --show-error --max-time 10 http://127.0.0.1:11434/api/tags >/dev/null || die 'approved embedder gateway preflight failed'
  record gateways PASS
  decision gateways PASS approved_upstreams
  production_fingerprint > "$RUN_DIR/evidence/production-before.sha256" || die 'production fingerprint capture failed'
  decision production_fingerprint PASS before
}

stage_source() {
  local source="$BACKUP_RUN/data/source"
  mkdir -p "$RUN_DIR/source" "$RUN_DIR/build" "$RUN_DIR/wheelhouse" "$RUN_DIR/evidence"
  cp -Rp "$source/." "$RUN_DIR/source/"
  verify_source_snapshot "$RUN_DIR/source"
  chmod -R a-w "$RUN_DIR/source"
  printf '%s  %s\n' "$(sha256 "$RUN_DIR/source/SOURCE-SHA256SUMS")" SOURCE-SHA256SUMS > "$RUN_DIR/evidence/source-tree.sha256"
  cp "$SOURCE_PROJECT/api/requirements.txt" "$RUN_DIR/evidence/production-requirements.txt"
  cp "$RUN_DIR/source/api/requirements.txt" "$RUN_DIR/build/production-requirements.txt"
}

stage_wheelhouse() {
  local docker_arch
  docker_arch="$(docker_scrubbed version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null || true)"
  [ "${docker_arch%%/*}" = linux ] || die "unsupported Docker platform: ${docker_arch:-unknown}"
  printf 'docker_platform=%s\nbase_image=%s\nresolver=base-image-container\n' \
    "$docker_arch" "$BASE_IMAGE" > "$RUN_DIR/evidence/wheelhouse-target.txt"
  sed "s/^mem0ai==.*/mem0ai==$CANDIDATE_VERSION/" "$RUN_DIR/build/production-requirements.txt" > "$RUN_DIR/build/candidate.in"
  grep -Fxq "mem0ai==$CANDIDATE_VERSION" "$RUN_DIR/build/candidate.in" || die 'candidate requirements replacement failed'
  bounded 300 env -i PATH="$PATH" HOME="$HOME" DOCKER_CONTEXT="$DOCKER_CONTEXT" DOCKER_HOST="$DOCKER_HOST_VALUE" \
    docker --config "$HOME/.docker" run --rm --user "$(id -u):$(id -g)" \
    --env HOME=/tmp --env PIP_DISABLE_PIP_VERSION_CHECK=1 --env PIP_NO_INPUT=1 --env PIP_DEFAULT_TIMEOUT=15 \
    --volume "$RUN_DIR/wheelhouse:/wheelhouse" --volume "$RUN_DIR/build/candidate.in:/candidate.in:ro" \
    "$BASE_IMAGE" python -m pip download --only-binary=:all: --no-cache-dir --index-url https://pypi.org/simple --timeout 15 --retries 1 \
    --dest /wheelhouse -r /candidate.in >"$RUN_DIR/evidence/pip-download.log" 2>&1 || die 'candidate wheelhouse download failed'
  find "$RUN_DIR/wheelhouse" -type f -name '*.whl' -print | grep -q . || die 'candidate wheelhouse has no wheels'
  /usr/bin/python3 - "$CANDIDATE_VERSION" "$APPROVED_MEM0_WHEEL_SHA256" "$RUN_DIR/wheelhouse" "$RUN_DIR/evidence/pypi-provenance.json" "$RUN_DIR/evidence/package-index.out" "$RUN_DIR/evidence/approved-release-record.json" <<'PY' || die 'candidate package provenance verification failed'
import hashlib
import json
import pathlib
import re
import sys
import urllib.parse
import urllib.request
import zipfile

version, approved_digest, wheelhouse, output, index_path, release_path = sys.argv[1:]
release = json.loads(pathlib.Path(release_path).read_text(encoding="utf-8"))
packages = []
for wheel in sorted(pathlib.Path(wheelhouse).glob("*.whl")):
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith("/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8", errors="replace")
    name = re.search(r"^Name: (.+)$", metadata, re.MULTILINE).group(1).strip()
    package_version = re.search(r"^Version: (.+)$", metadata, re.MULTILINE).group(1).strip()
    request = urllib.request.Request(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(package_version)}/json", headers={"User-Agent": "openmemory-candidate-verifier/1"})
    with urllib.request.urlopen(request, timeout=15) as response:
        document = json.load(response)
    expected = {item["filename"]: item["digests"]["sha256"] for item in document.get("urls", []) if item.get("filename") and item.get("digests", {}).get("sha256")}
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if expected.get(wheel.name) != digest:
        raise SystemExit(f"PyPI digest mismatch for {wheel.name}")
    packages.append({"name": name, "version": package_version, "filename": wheel.name, "sha256": digest})
if not any(item["name"].lower() == "mem0ai" and item["version"] == version for item in packages):
    raise SystemExit("downloaded mem0ai wheel was not independently verified")
mem0_wheels = [item for item in packages if item["name"].lower() == "mem0ai" and item["version"] == version]
if len(mem0_wheels) != 1 or mem0_wheels[0]["sha256"].lower() != approved_digest.lower() or mem0_wheels[0]["filename"] != release["wheel_filename"]:
    raise SystemExit("mem0ai wheel digest is not the approved digest")
index_digest = hashlib.sha256(pathlib.Path(index_path).read_bytes()).hexdigest()
pathlib.Path(output).write_bytes(json.dumps({"schema": 1, "source": "pypi-json", "approval_record_sha256": hashlib.sha256(pathlib.Path(release_path).read_bytes()).hexdigest(), "package_index_sha256": index_digest, "packages": packages}, sort_keys=True, separators=(",", ":")).encode() + b"\n")
pathlib.Path(output).chmod(0o600)
PY
  /usr/bin/python3 - "$RUN_DIR/wheelhouse" "$RUN_DIR/build/candidate-requirements.txt" <<'PY' || die 'candidate dependency freeze generation failed'
import hashlib
import pathlib
import re
import zipfile
import sys

wheelhouse, output = map(pathlib.Path, sys.argv[1:])
rows = []
for wheel in sorted(wheelhouse.glob("*.whl")):
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith("/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8")
    name = re.search(r"^Name: (.+)$", metadata, re.MULTILINE).group(1).strip()
    version = re.search(r"^Version: (.+)$", metadata, re.MULTILINE).group(1).strip()
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    rows.append((name.lower().replace("_", "-"), name, version, digest))
if not any(row[0] == "mem0ai" for row in rows):
    raise SystemExit(1)
rows.sort()
output.write_text("\n".join(f"{name}=={version} --hash=sha256:{digest}" for _, name, version, digest in rows) + "\n")
PY
  cp "$RUN_DIR/build/candidate-requirements.txt" "$RUN_DIR/evidence/dependency-freeze.txt"
  (cd "$RUN_DIR/wheelhouse" && shasum -a 256 *.whl > "$RUN_DIR/evidence/wheelhouse.sha256")
  chmod -R a-w "$RUN_DIR/wheelhouse"
}

generate_compose() {
  [[ "$CANDIDATE_PROXY_PORT" =~ ^[0-9]+$ ]] && [ "$CANDIDATE_PROXY_PORT" -ge 1024 ] && [ "$CANDIDATE_PROXY_PORT" -le 65535 ] || die 'candidate proxy port is invalid'
  [[ "$CANDIDATE_QDRANT_PORT" =~ ^[0-9]+$ ]] && [ "$CANDIDATE_QDRANT_PORT" -ge 1024 ] && [ "$CANDIDATE_QDRANT_PORT" -le 65535 ] || die 'candidate Qdrant port is invalid'
  local qdrant_image
  qdrant_image="$(sed -n 's/^service=mem0_store|.*|image=\([^|]*\).*/\1/p' "$RUN_DIR/evidence/production-runtime.manifest")"
  [ -n "$qdrant_image" ] || die 'Qdrant image evidence is incomplete'
  case "$qdrant_image" in *:latest|*latest*) die 'mutable Qdrant image reference rejected';; esac
  QDRANT_IMAGE_DIGEST="$(docker_scrubbed image inspect -f '{{index .RepoDigests 0}}' "$qdrant_image" 2>/dev/null || true)"
  [[ "$QDRANT_IMAGE_DIGEST" = *@sha256:* ]] || die 'Qdrant registry digest evidence is unavailable'
  printf 'qdrant_image=%s\n' "$QDRANT_IMAGE_DIGEST" > "$RUN_DIR/evidence/qdrant-image-pin.txt"
  cp "$SCRIPT_DIR/candidate-egress-proxy/Dockerfile" "$RUN_DIR/build/proxy.Dockerfile"
  cp "$SCRIPT_DIR/candidate-egress-proxy/proxy.py" "$RUN_DIR/build/proxy.py"
  cp "$SCRIPT_DIR/candidate-egress-proxy/allowlist.json" "$RUN_DIR/build/allowlist.json"
  cat > "$RUN_DIR/build/Dockerfile" <<EOF_DOCKERFILE
FROM $BASE_IMAGE
WORKDIR /usr/src/openmemory
COPY wheelhouse /wheelhouse
COPY candidate-requirements.txt .
RUN python -m pip install --no-index --find-links /wheelhouse --require-hashes -r candidate-requirements.txt \\
 && test "\$(python -c 'import importlib.metadata; print(importlib.metadata.version("mem0ai"))')" = "$CANDIDATE_VERSION"
COPY api/ .
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8765", "--workers", "1"]
EOF_DOCKERFILE
  cp -Rp "$RUN_DIR/source/api/." "$RUN_DIR/build/api/"
  [ -f "$SOURCE_PROJECT/api/scripts/evaluate_retrieval.py" ] || die 'current retrieval evaluator is missing'
  chmod -R u+w "$RUN_DIR/build/api/scripts"
  rm "$RUN_DIR/build/api/scripts/evaluate_retrieval.py"
  cp "$SOURCE_PROJECT/api/scripts/evaluate_retrieval.py" "$RUN_DIR/build/api/scripts/evaluate_retrieval.py"
  cp -Rp "$RUN_DIR/wheelhouse/." "$RUN_DIR/build/wheelhouse/"
  cat > "$RUN_DIR/compose.yml" <<EOF_COMPOSE
services:
  candidate-store:
    image: $QDRANT_IMAGE_DIGEST
    labels:
      com.ultimatesup.openmemory.candidate: "$RUN_ID"
    volumes:
      - $RUNTIME_STORAGE_DIR:/qdrant/storage
    ports:
      - "127.0.0.1:$CANDIDATE_QDRANT_PORT:6333"
    networks: [candidate-internal]
  candidate-egress-proxy:
    build:
      context: $RUN_DIR/build
      dockerfile: proxy.Dockerfile
      network: none
    image: $PROJECT_NAME-egress:verified
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    environment:
      PATH: /usr/local/bin:/usr/bin:/bin
      PROXY_CONFIG: /proxy/allowlist.json
      PROXY_LOG_DIR: /proxy/logs
    volumes:
      - candidate-proxy-logs:/proxy/logs
    extra_hosts:
      - host.docker.internal:host-gateway
    networks:
      candidate-internal:
        aliases:
          - host.docker.internal
      candidate-egress: {}
    ports:
      - "127.0.0.1:$CANDIDATE_PROXY_PORT:20128"
    labels:
      com.ultimatesup.openmemory.candidate: "$RUN_ID"
  candidate-api:
    build:
      context: $RUN_DIR/build
      dockerfile: Dockerfile
      network: none
    image: $PROJECT_NAME-api:verified
    command: ["sleep", "infinity"]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    environment:
      USER: candidate-test-user
      OPENMEMORY_API_TOKEN: candidate-test-key
      QDRANT_HOST: candidate-store
      QDRANT_PORT: "6333"
      DATABASE_URL: sqlite:////candidate-data/openmemory.db
      LLM_BASE_URL: http://host.docker.internal:20128/v1
      OPENAI_BASE_URL: http://host.docker.internal:20128/v1
      OLLAMA_HOST: host.docker.internal
      OLLAMA_BASE_URL: http://host.docker.internal:11434
      EMBEDDER_BASE_URL: http://host.docker.internal:11434
      MEM0_TELEMETRY: "false"
    volumes:
      - $RUN_DIR/clone/db:/candidate-data
      - $RUN_DIR/source:/usr/src/openmemory-source:ro
      - $RUNTIME_HISTORY_DIR:/root/.mem0
      - $INPUT_DIR:/candidate-input:ro
    depends_on: [candidate-store, candidate-egress-proxy]
    networks: [candidate-internal]
    labels:
      com.ultimatesup.openmemory.candidate: "$RUN_ID"
networks:
  candidate-internal:
    name: $NETWORK_NAME
    internal: true
    ipam:
      config:
        - subnet: $INTERNAL_SUBNET
    labels:
      com.ultimatesup.openmemory.candidate: "$RUN_ID"
  candidate-egress:
    name: $EGRESS_NETWORK_NAME
    labels:
      com.ultimatesup.openmemory.candidate: "$RUN_ID"
volumes:
  candidate-proxy-logs:
    name: ${PROJECT_NAME}-proxy-logs
    labels:
      com.ultimatesup.openmemory.candidate: "$RUN_ID"
EOF_COMPOSE
}

restore_clone() {
  mkdir -p "$RUN_DIR/clone/db" "$RUN_DIR/clone/history" "$RUN_DIR/clone/storage" "$RUNTIME_HISTORY_DIR" "$RUNTIME_STORAGE_DIR"
  cp "$BACKUP_RUN/data/sqlite/openmemory.db" "$RUN_DIR/clone/db/openmemory.db"
  archive_safe() {
    /usr/bin/python3 - "$1" "$2" <<'PY'
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
  archive_safe "$BACKUP_RUN/data/volumes/history/volume.tar" "$RUN_DIR/clone/history"
  archive_safe "$BACKUP_RUN/data/volumes/storage/volume.tar" "$RUN_DIR/clone/storage"
  cp -Rp "$RUN_DIR/clone/history/." "$RUNTIME_HISTORY_DIR/"
  cp -Rp "$RUN_DIR/clone/storage/." "$RUNTIME_STORAGE_DIR/"
  chmod -R u=rwX,go= "$RUN_DIR/clone"
  [ "$(/usr/bin/sqlite3 "$RUN_DIR/clone/db/openmemory.db" 'PRAGMA integrity_check;' 2>/dev/null)" = ok ] || die 'clone SQLite integrity check failed'
  printf '%s  %s\n' "$(sha256 "$BACKUP_RUN/data/volumes/storage/volume.tar")" openmemory_mem0_storage.volume.tar > "$RUN_DIR/evidence/storage-archive.sha256"
  printf '%s\n' "$(sha256 "$RUN_DIR/clone/db/openmemory.db")" > "$RUN_DIR/evidence/clone-pristine.sqlite.sha256"
  /usr/bin/python3 - "$RUN_DIR/clone" "$RUN_DIR/evidence/clone-pristine-tree.sha256" <<'PY'
import hashlib
import pathlib
import sys

root, output = map(pathlib.Path, sys.argv[1:])
digest = hashlib.sha256()
for path in sorted(item for item in root.rglob("*") if item.is_file()):
    digest.update(str(path.relative_to(root)).encode())
    digest.update(path.read_bytes())
    digest.update(str(path.stat().st_mode & 0o777).encode())
output.write_text(digest.hexdigest() + "\n")
PY
  decision clone PASS pristine_restore
}

build_and_inspect() {
  docker_scrubbed build --network none --pull=false --label "com.ultimatesup.openmemory.candidate=$RUN_ID" --file "$RUN_DIR/build/Dockerfile" --tag "$PROJECT_NAME-api:verified" "$RUN_DIR/build" >"$RUN_DIR/evidence/api-build.log" 2>&1 || die 'candidate API build failed'
  docker_scrubbed build --network none --pull=false --label "com.ultimatesup.openmemory.candidate=$RUN_ID" --file "$RUN_DIR/build/proxy.Dockerfile" --tag "$PROJECT_NAME-egress:verified" "$RUN_DIR/build" >"$RUN_DIR/evidence/proxy-build.log" 2>&1 || die 'candidate proxy build failed'
  docker_scrubbed image inspect "$PROJECT_NAME-api:verified" "$PROJECT_NAME-egress:verified" > "$RUN_DIR/evidence/image-inspect.json" || die 'candidate image inspection failed'
  docker_scrubbed image inspect -f '{{.Id}}|{{index .RepoDigests 0}}' "$PROJECT_NAME-api:verified" "$PROJECT_NAME-egress:verified" > "$RUN_DIR/evidence/candidate-image-digests.tsv" || die 'candidate image digest capture failed'
  docker_scrubbed compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" config --quiet || die 'candidate Compose validation failed'
  docker_scrubbed compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" config > "$RUN_DIR/evidence/compose.config.yml"
  ! grep -En 'external: true|127\.0\.0\.1:6333|8765:8765|3000:3000|openmemory_mem0_storage|openmemory_mem0_history|openmemory-mcp|openmemory-ui' "$RUN_DIR/evidence/compose.config.yml" >/dev/null || die 'candidate Compose references production resource'
  record compose PASS
  decision compose PASS isolated
}

assert_no_collision() {
  docker_scrubbed ps -a --filter "name=^${PROJECT_NAME}-" --format '{{.Names}}' | grep -q . && die 'candidate resource name collision' || true
  docker_scrubbed network inspect "$NETWORK_NAME" "$EGRESS_NETWORK_NAME" >/dev/null 2>&1 && die 'candidate network collision' || true
  docker_scrubbed network inspect $(docker_scrubbed network ls -q) 2>/dev/null | grep -F "$INTERNAL_SUBNET" >/dev/null && die 'candidate subnet collision' || true
  docker_scrubbed volume inspect "${PROJECT_NAME}-proxy-logs" >/dev/null 2>&1 && die 'candidate volume collision' || true
  docker_scrubbed image inspect "$PROJECT_NAME-api:verified" "$PROJECT_NAME-egress:verified" >/dev/null 2>&1 && die 'candidate image collision' || true
}

start_candidate() {
  bounded 120 env -i PATH="$PATH" HOME="$HOME" DOCKER_CONTEXT="$DOCKER_CONTEXT" DOCKER_HOST="$DOCKER_HOST_VALUE" docker --config "$HOME/.docker" compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" up -d --no-build > "$RUN_DIR/evidence/start.log" 2>&1 || die 'candidate startup failed'
  local ids
  ids="$(docker_scrubbed compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" ps -q)"
  [ -n "$ids" ] || die 'candidate containers are missing'
  docker_scrubbed inspect $ids > "$RUN_DIR/evidence/runtime-inspect.json" || die 'candidate runtime inspection failed'
  ! grep -En 'openmemory_mem0_|openmemory-mcp|openmemory-ui|127\.0\.0\.1:6333|8765:8765|3000:3000' "$RUN_DIR/evidence/runtime-inspect.json" >/dev/null || die 'candidate runtime references production resource'
  if ! CANDIDATE_PROXY_URL="http://127.0.0.1:$CANDIDATE_PROXY_PORT" "$SCRIPT_DIR/selfcheck_candidate_egress.sh" > "$RUN_DIR/evidence/egress-selfcheck.log" 2>&1; then
    docker_scrubbed compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" ps > "$RUN_DIR/evidence/egress-compose-ps.log" 2>&1 || true
    docker_scrubbed compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" logs --no-color candidate-egress-proxy > "$RUN_DIR/evidence/egress-proxy.log" 2>&1 || true
    die 'candidate egress selfcheck failed'
  fi
  decision runtime PASS inspected
  decision egress PASS allowlisted
}

evaluate_evidence() {
  [ -n "$DIRECT_BASELINE" ] && [ -f "$DIRECT_BASELINE" ] && [ ! -L "$DIRECT_BASELINE" ] || die 'sealed direct baseline is required for scoring'
  local baseline_auth="${DIRECT_BASELINE}.auth.json" baseline_digest="${DIRECT_BASELINE}.sha256"
  [ -f "$baseline_auth" ] && [ -f "$baseline_digest" ] && [ ! -L "$baseline_auth" ] && [ ! -L "$baseline_digest" ] || die 'authenticated direct baseline seal is missing'
  /usr/bin/python3 - "$DIRECT_BASELINE" "$baseline_digest" "$baseline_auth" 3<<<"$(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db")" <<'PY' || die 'authenticated direct baseline verification failed'
import hashlib
import hmac
import json
import pathlib
import sys

baseline, digest_file, auth_file = map(pathlib.Path, sys.argv[1:])
document = json.loads(baseline.read_text(encoding="utf-8"))
digest = hashlib.sha256(baseline.read_bytes()).hexdigest()
if digest_file.read_text(encoding="utf-8").strip() != digest:
    raise SystemExit("direct baseline digest mismatch")
if document.get("schema") != 1 or document.get("backend") != "direct" or document.get("decision") != "PASSED":
    raise SystemExit("direct baseline is not a sealed PASSED direct artifact")
if document.get("mem0ai") != "mem0ai==2.0.4":
    raise SystemExit("direct baseline production version mismatch")
record = json.loads(auth_file.read_text(encoding="utf-8"))
required = {"backend", "decision", "expected_label_sha256", "fixture_sha256", "mem0ai", "evidence_sha256", "key_id", "service", "account", "mac"}
if set(record) != required or record["evidence_sha256"] != digest:
    raise SystemExit("direct baseline auth envelope mismatch")
payload = {key: record[key] for key in ("backend", "decision", "expected_label_sha256", "fixture_sha256", "mem0ai", "evidence_sha256")}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
key = pathlib.Path("/dev/fd/3").read_bytes().strip()
if record["service"] != "com.ultimatesup.openmemory.backup.manifest-v1" or record["account"] != "openmemory-backup-manifest-v1" or record["key_id"] != "v1":
    raise SystemExit("direct baseline Keychain identity mismatch")
if not key or not hmac.compare_digest(record["mac"], hmac.new(key, canonical, hashlib.sha256).hexdigest()):
    raise SystemExit("direct baseline MAC mismatch")
PY
  /usr/bin/python3 - "$DIRECT_BASELINE" "$INPUT_DIR/host-network.json" <<'PY' || die 'sealed host network evidence is missing or incomplete'
import json
import pathlib
import sys

baseline, output = map(pathlib.Path, sys.argv[1:])
document = json.loads(baseline.read_text(encoding="utf-8"))
network = document.get("network")
if not isinstance(network, dict) or network.get("complete") is not True:
    raise SystemExit(1)
for label in ("lan", "ipv6"):
    probe = network.get("probe_evidence", {}).get(label, {})
    if not probe.get("address") or any(value != "unreachable" for value in probe.get("results", {}).values()):
        raise SystemExit(1)
tailnet = network.get("probe_evidence", {}).get("tailnet", {})
if not tailnet.get("address") or tailnet.get("results", {}).get("api") != "reachable" or any(
    tailnet.get("results", {}).get(service) != "unreachable" for service in ("qdrant", "ui")
):
    raise SystemExit(1)
output.write_text(json.dumps(network, sort_keys=True, separators=(",", ":")), encoding="utf-8")
output.chmod(0o600)
PY
  local evaluation
  evaluation="$(find "$RUN_DIR/evidence/evaluator" -type f -name evidence.json -print 2>/dev/null | sort | tail -n 1)"
  [ -n "$evaluation" ] || die 'sealed evaluator evidence is missing'
  set +e
  /usr/bin/python3 - "$evaluation" "$DIRECT_BASELINE" "$CANDIDATE_VERSION" <<'PY'
import json
import pathlib
import sys
import uuid

def canonical_memory_id(value):
    text = str(value)
    try:
        return str(uuid.UUID(text))
    except (ValueError, AttributeError):
        return text

document, baseline = (json.loads(pathlib.Path(value).read_text(encoding="utf-8")) for value in sys.argv[1:3])
candidate_version = sys.argv[3]
required = {
    "schema", "mem0ai", "backend", "fixture_sha256", "expected_label_sha256", "query_count",
    "top_k", "diagnostic_top_k", "thresholds", "runner_contract", "provider_embedder", "quality_passes",
    "configuration_sha256", "custom_instructions_sha256", "embedding_frozen", "metrics", "errors", "measurements", "acl_state",
    "fingerprints", "network", "decision", "paired_metrics",
}

if document.get("decision") == "BLOCKED-ENVIRONMENT":
    raise SystemExit(2)
if set(document) != required or document["schema"] != 1 or document["backend"] != "candidate":
    raise SystemExit("evaluation schema mismatch")
if document["mem0ai"] != "mem0ai==" + candidate_version:
    raise SystemExit("candidate SDK version mismatch")
if document["top_k"] != 10 or not isinstance(document["runner_contract"], dict) or document["runner_contract"].get("production_backend") != "direct-only" or document["runner_contract"].get("candidate_backend") != "Mem0 SDK Memory.search" or document["runner_contract"].get("warmups") != "excluded" or document["runner_contract"].get("normalization") != "stable score-desc then memory-id-asc; duplicate IDs collapsed; finite scores; user-bound active payloads":
    raise SystemExit("candidate runner contract mismatch")
if baseline.get("backend") != "direct" or baseline.get("decision") != "PASSED" or baseline.get("mem0ai") != "mem0ai==2.0.4":
    raise SystemExit("direct baseline is not an approved PASSED artifact")
for key in ("fixture_sha256", "expected_label_sha256", "provider_embedder", "configuration_sha256", "custom_instructions_sha256"):
    if document[key] != baseline[key]:
        raise SystemExit("sealed baseline mismatch")
if document["query_count"] < 30 or not document["embedding_frozen"] or document["errors"] or document["acl_state"].get("leakage") is True:
    raise SystemExit(2)
if document["network"].get("source") != "host-attested" or document["network"].get("remote_probe") != "verified" or document["network"].get("complete") is not True:
    raise SystemExit(2)
metrics = document["metrics"]
thresholds = document["thresholds"]
quality = bool(metrics["recall_at_5"] is not None and metrics["recall_at_10"] is not None and metrics["mrr"] is not None and metrics["latency_ms"]["p95"] is not None and metrics["recall_at_5"] >= thresholds["recall_at_5"] and metrics["recall_at_10"] >= thresholds["recall_at_10"] and metrics["mrr"] >= thresholds["mrr"] and metrics["latency_ms"]["p95"] <= thresholds["p95_latency_ms"])
if document["quality_passes"] is not quality:
    raise SystemExit("candidate quality claim is not reproducible from metrics")
if metrics["errors"] or metrics["timeouts"] or not metrics["complete"]:
    raise SystemExit(2)
if not quality:
    raise SystemExit(1)
if document["paired_metrics"].get("candidate") != document["metrics"]:
    raise SystemExit("candidate paired metrics are not the scored metrics")
direct = baseline["metrics"]
candidate = document["metrics"]
if candidate["recall_at_10"] < direct["recall_at_10"] - 0.02:
    raise SystemExit("candidate recall@10 regressed against direct baseline")
if candidate["mrr"] < direct["mrr"] - 0.05:
    raise SystemExit("candidate MRR regressed against direct baseline")
if candidate["latency_ms"]["p95"] > max(5000, direct["latency_ms"]["p95"] * 3):
    raise SystemExit("candidate p95 latency regressed against direct baseline")
if not document["fingerprints"]["unchanged"] or not document["network"]["complete"]:
    raise SystemExit(2)
if document["decision"] != "PASSED":
    raise SystemExit("candidate safety gate failed")
PY
  local evaluator_validation_status=$?
  set -e
  case "$evaluator_validation_status" in
    0) ;;
    2) die 'candidate evaluator environment or evidence collection was incomplete' ;;
    *) no_go 'host validation rejected candidate evaluator evidence' ;;
  esac
  if ! /usr/bin/python3 - "$evaluation" "$DIRECT_BASELINE" "$CANDIDATE_VERSION" "$EVAL_MANIFEST" > "$RUN_DIR/evidence/host-validation.log" 2>&1 <<'PY_CHECK'
import json
import pathlib
import sys

document, baseline = (json.loads(pathlib.Path(value).read_text(encoding="utf-8")) for value in sys.argv[1:3])
candidate_version = sys.argv[3]
manifest = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
import uuid

def canonical_memory_id(value):
    text = str(value)
    try:
        return str(uuid.UUID(text))
    except (ValueError, AttributeError):
        return text
required = {
    "schema", "mem0ai", "backend", "fixture_sha256", "expected_label_sha256", "query_count",
    "top_k", "diagnostic_top_k", "thresholds", "runner_contract", "provider_embedder", "quality_passes",
    "configuration_sha256", "custom_instructions_sha256", "embedding_frozen", "metrics", "errors", "measurements", "acl_state",
    "fingerprints", "network", "decision", "paired_metrics",
}
if document.get("decision") == "BLOCKED-ENVIRONMENT":
    raise SystemExit(2)
if set(document) != required or document["schema"] != 1 or document["backend"] != "candidate":
    raise SystemExit("schema")
if document["mem0ai"] != "mem0ai==" + candidate_version:
    raise SystemExit("version")
if document.get("runner_contract", {}).get("normalization") != "stable score-desc then memory-id-asc; duplicate IDs collapsed; finite scores; user-bound active payloads":
    raise SystemExit("runner_contract")
if baseline.get("backend") != "direct" or baseline.get("decision") != "PASSED" or baseline.get("mem0ai") != "mem0ai==2.0.4":
    raise SystemExit("baseline_identity")
for key in ("fixture_sha256", "expected_label_sha256", "provider_embedder", "configuration_sha256", "custom_instructions_sha256"):
    if document[key] != baseline[key]:
        raise SystemExit("baseline_" + key)
metrics = document["metrics"]
thresholds = document["thresholds"]
quality = bool(metrics["recall_at_5"] is not None and metrics["recall_at_10"] is not None and metrics["mrr"] is not None and metrics["latency_ms"]["p95"] is not None and metrics["recall_at_5"] >= thresholds["recall_at_5"] and metrics["recall_at_10"] >= thresholds["recall_at_10"] and metrics["mrr"] >= thresholds["mrr"] and metrics["latency_ms"]["p95"] <= thresholds["p95_latency_ms"])
measurements = document["measurements"]
if len(measurements) != document["query_count"] * int(manifest.get("repetitions", 3)):
    raise SystemExit("measurement_count")
recalls5, recalls10, mrrs, latencies = [], [], [], []
for measurement in measurements:
    index = int(measurement["query_index"])
    relevant = {canonical_memory_id(value) for value in manifest["queries"][index].get("relevant_ids", [])}
    ranked = [canonical_memory_id(value) for value in measurement["ranked_ids"]]
    recalls5.append(len(relevant & set(ranked[:5])) / len(relevant) if relevant else 1.0)
    recalls10.append(len(relevant & set(ranked[:10])) / len(relevant) if relevant else 1.0)
    if relevant:
        mrrs.append(next((1.0 / (position + 1) for position, value in enumerate(ranked) if value in relevant), 0.0))
    latencies.append(measurement["latency_ms"])
nearest = lambda values, fraction: sorted(values)[max(0, __import__("math").ceil(fraction * len(values)) - 1)]
recomputed = {"recall_at_5": sum(recalls5) / len(recalls5), "recall_at_10": sum(recalls10) / len(recalls10), "mrr": sum(mrrs) / len(mrrs), "latency_ms": {"p50": nearest(latencies, 0.50), "p95": nearest(latencies, 0.95), "sample_count": len(latencies)}}
for key in ("recall_at_5", "recall_at_10", "mrr"):
    if abs(metrics[key] - recomputed[key]) > 1e-9:
        raise SystemExit("metric_{}:{}:{}".format(key, metrics[key], recomputed[key]))
if metrics["latency_ms"] != recomputed["latency_ms"]:
    raise SystemExit("latency")
if document["quality_passes"] is not quality or metrics["errors"] or metrics["timeouts"] or not metrics["complete"] or not quality:
    raise SystemExit("quality")
if document["paired_metrics"].get("candidate") != metrics or document["decision"] != "PASSED":
    raise SystemExit("paired_metrics")
direct = baseline["metrics"]
if metrics["recall_at_10"] < direct["recall_at_10"] - 0.02 or metrics["mrr"] < direct["mrr"] - 0.05 or metrics["latency_ms"]["p95"] > max(5000, direct["latency_ms"]["p95"] * 3):
    raise SystemExit("baseline_thresholds")
if not document["fingerprints"]["unchanged"] or not document["network"]["complete"]:
    raise SystemExit("safety_fingerprint_or_network")
PY_CHECK
  then
    no_go 'host-recomputed candidate scoring or compatibility gates failed'
  fi
  cp "$evaluation" "$RUN_DIR/evidence/evaluation.json"
  decision scoring PASS thresholds
}

authoritative_replay() {
  local replay_dir="$RUN_DIR/evidence/authoritative-replay" replay status candidate_id
  rm -rf "$replay_dir"
  mkdir -p "$replay_dir"
  candidate_id="$(docker_scrubbed compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" ps -aq candidate-api)"
  [ -n "$candidate_id" ] || die 'authoritative replay candidate container id is missing'
  local network_evidence_b64
  network_evidence_b64="$(base64 < "$RUN_DIR/evidence/host-network-attested.json")"
  docker_scrubbed exec "$candidate_id" sh -c "printf '%s' '$network_evidence_b64' | base64 -d > /tmp/host-network-replay.json" || die 'authoritative replay network evidence staging failed'
  local replay_attempt=1
  set +e
  while :; do
    env -i PATH="$PATH" HOME="$HOME" DOCKER_CONTEXT="$DOCKER_CONTEXT" DOCKER_HOST="$DOCKER_HOST_VALUE" docker --config "$HOME/.docker" compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" exec -T \
      candidate-api env OPENMEMORY_AUTHORITATIVE_REPLAY=1 OPENMEMORY_EVAL_DATABASE=/candidate-data/openmemory.db \
      OPENMEMORY_EVAL_QDRANT_URL=http://candidate-store:6333 OPENMEMORY_EXPECTED_MEM0_VERSION=2.0.4 \
      OPENMEMORY_CANDIDATE_RUN_ID="$RUN_ID" OPENMEMORY_HOST_NETWORK_EVIDENCE=/tmp/host-network-replay.json \
      python /usr/src/openmemory/scripts/evaluate_retrieval.py --manifest /candidate-input/eval-manifest.json --evidence-dir /candidate-output/authoritative-replay --backend direct > "$RUN_DIR/evidence/authoritative-replay.log" 2>&1
    status=$?
    [ "$status" -eq 0 ] && break
    [ "$status" -eq 2 ] && [ "$replay_attempt" -lt 2 ] || break
    replay_attempt=$((replay_attempt + 1))
  done
  set -e
  [ "$status" -eq 0 ] || [ "$status" -eq 2 ] || die 'authoritative candidate replay failed'
  mkdir -p "$replay_dir/import"
  docker_scrubbed cp "$candidate_id:/candidate-output/authoritative-replay/." "$replay_dir/import" || die 'authoritative replay evidence export failed'
  replay="$(find "$replay_dir/import" -type f -name evidence.json -print | sort | tail -n 1)"
  [ -n "$replay" ] || die 'authoritative candidate replay evidence is missing'
  cp "$replay" "$RUN_DIR/evidence/authoritative-replay.json"
  /usr/bin/python3 - "$RUN_DIR/evidence/evaluation.json" "$RUN_DIR/evidence/authoritative-replay.json" <<'PY' || die 'host authoritative replay rejected candidate rankings'
import json
import pathlib
import sys

candidate, replay = (json.loads(pathlib.Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:])
if replay.get("backend") != "direct" or replay.get("decision") not in {"PASSED", "MORE-WORK"}:
    raise SystemExit(1)
candidate_measurements = sorted(candidate.get("measurements", []), key=lambda item: (item["query_index"], item["repetition"]))
replay_measurements = sorted(replay.get("measurements", []), key=lambda item: (item["query_index"], item["repetition"]))
if len(candidate_measurements) != len(replay_measurements):
    raise SystemExit(1)
for candidate_item, replay_item in zip(candidate_measurements, replay_measurements):
    for key in ("query_index", "repetition", "embedding_sha256", "prefilter_count", "postfilter_count", "prefilter_ids_sha256", "prefilter_scores_quantized_sha256", "postfilter_ids_sha256", "ranked_ids", "leakage"):
        if candidate_item.get(key) != replay_item.get(key):
            raise SystemExit(1)
PY
  decision authoritative_replay PASS host_qdrant_and_embedder_replay
}

verify_direct_baseline_before_start() {
  [ -n "$DIRECT_BASELINE" ] && [ -f "$DIRECT_BASELINE" ] && [ ! -L "$DIRECT_BASELINE" ] || die 'sealed direct baseline is required before candidate startup'
  local baseline_auth="${DIRECT_BASELINE}.auth.json" baseline_digest="${DIRECT_BASELINE}.sha256"
  [ -f "$baseline_auth" ] && [ -f "$baseline_digest" ] && [ ! -L "$baseline_auth" ] && [ ! -L "$baseline_digest" ] || die 'authenticated direct baseline seal is missing before candidate startup'
  /usr/bin/python3 - "$DIRECT_BASELINE" "$baseline_digest" "$baseline_auth" "$INPUT_DIR/eval-manifest.json" 3<<<"$(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db")" <<'PY' || die 'authenticated direct baseline verification failed before candidate startup'
import hashlib
import hmac
import json
import pathlib
import sys

baseline, digest_file, auth_file, current_manifest = map(pathlib.Path, sys.argv[1:])
document = json.loads(baseline.read_text(encoding="utf-8"))
digest = hashlib.sha256(baseline.read_bytes()).hexdigest()
if digest_file.read_text(encoding="utf-8").strip() != digest:
    raise SystemExit(1)
if document.get("schema") != 1 or document.get("backend") != "direct" or document.get("decision") != "PASSED" or document.get("mem0ai") != "mem0ai==2.0.4":
    raise SystemExit(1)
record = json.loads(auth_file.read_text(encoding="utf-8"))
required = {"backend", "decision", "expected_label_sha256", "fixture_sha256", "mem0ai", "evidence_sha256", "key_id", "service", "account", "mac"}
if set(record) != required or record["evidence_sha256"] != digest or record["service"] != "com.ultimatesup.openmemory.backup.manifest-v1" or record["account"] != "openmemory-backup-manifest-v1" or record["key_id"] != "v1":
    raise SystemExit(1)
payload = {key: record[key] for key in ("backend", "decision", "expected_label_sha256", "fixture_sha256", "mem0ai", "evidence_sha256")}
key = pathlib.Path("/dev/fd/3").read_bytes().strip()
if not key or not hmac.compare_digest(record["mac"], hmac.new(key, json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(), hashlib.sha256).hexdigest()):
    raise SystemExit(1)
current = json.loads(current_manifest.read_text(encoding="utf-8"))
labels = [{"category": item.get("category"), "relevant_ids": sorted({str(value) for value in item.get("relevant_ids", [])})} for item in current["queries"]]
if hashlib.sha256(current_manifest.read_bytes()).hexdigest() != record["fixture_sha256"] or hashlib.sha256(json.dumps(labels, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest() != record["expected_label_sha256"]:
    raise SystemExit(1)
PY
}

evaluate_and_teardown() {
  [ -x "$MUTATION_GATE_SCRIPT" ] || die 'clone mutation gate is unavailable'
  [ -n "$MUTATION_FIXTURE" ] && [ -f "$MUTATION_FIXTURE" ] && [ ! -L "$MUTATION_FIXTURE" ] && [ "$(stat -f %Lp "$MUTATION_FIXTURE")" = 600 ] || die 'clone mutation fixture is unavailable or unsafe'
  [ -n "$EVAL_MANIFEST" ] && [ -f "$EVAL_MANIFEST" ] && [ ! -L "$EVAL_MANIFEST" ] && [ "$(stat -f %Lp "$EVAL_MANIFEST")" = 600 ] || die 'evaluation manifest is required and must be private'
  mkdir -p "$INPUT_DIR"
  cp "$MUTATION_FIXTURE" "$INPUT_DIR/mutation-fixture.json"
  cp "$EVAL_MANIFEST" "$INPUT_DIR/eval-manifest.json"
  chmod 600 "$INPUT_DIR"/*.json
  verify_direct_baseline_before_start
  HOST_NETWORK_EVIDENCE="$RUN_DIR/evidence/host-network.json"
  "$NETWORK_EVIDENCE_SCRIPT" "$RUN_ID" "$HOST_NETWORK_EVIDENCE" "$DOCKER_CONTEXT" "$DOCKER_HOST_VALUE" || die 'host network evidence collection failed'
  seal_evidence_file "$HOST_NETWORK_EVIDENCE" || die 'host network evidence seal failed'
  [ -f "$HOST_NETWORK_EVIDENCE" ] && [ ! -L "$HOST_NETWORK_EVIDENCE" ] && [ "$(stat -f %Lp "$HOST_NETWORK_EVIDENCE")" = 600 ] || die 'independent host network evidence is required'
  [ -f "$HOST_NETWORK_EVIDENCE.sha256" ] && [ -f "$HOST_NETWORK_EVIDENCE.auth.json" ] && [ ! -L "$HOST_NETWORK_EVIDENCE.sha256" ] && [ ! -L "$HOST_NETWORK_EVIDENCE.auth.json" ] || die 'independent host network evidence seal is required'
  /usr/bin/python3 - "$DIRECT_BASELINE" "$HOST_NETWORK_EVIDENCE" "$HOST_NETWORK_EVIDENCE.sha256" "$HOST_NETWORK_EVIDENCE.auth.json" "$RUN_DIR/evidence/host-network-attested.json" "$RUN_ID" 3<<<"$(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db")" <<'PY' || die 'sealed host network evidence is missing or incomplete'
import hmac
import hashlib
import json
import pathlib
import os
import socket
import subprocess
import sys
from datetime import datetime, timezone

baseline, independent, digest_path, auth_path, output, run_id = sys.argv[1:]
baseline, independent, digest_path, auth_path, output = map(pathlib.Path, (baseline, independent, digest_path, auth_path, output))
document = json.loads(independent.read_text(encoding="utf-8"))
required = {"schema", "kind", "run_id", "source", "captured_at", "complete", "remote_probe", "remote_listener", "probe_evidence", "loopback_bindings", "tailscale", "host_identity_sha256"}
if set(document) != required or document["schema"] != 1 or document["kind"] != "openmemory.host-network-evidence" or document["run_id"] != run_id or document["source"] != "host" or document["complete"] is not True or document["remote_probe"] != "verified":
    raise SystemExit(1)
if document["host_identity_sha256"] != hashlib.sha256(__import__("socket").gethostname().encode()).hexdigest():
    raise SystemExit(1)
captured_at = datetime.fromisoformat(str(document["captured_at"]).replace("Z", "+00:00"))
if captured_at.tzinfo is None or captured_at > datetime.now(timezone.utc) or (datetime.now(timezone.utc) - captured_at).total_seconds() > 300:
    raise SystemExit(1)
listener = document["remote_listener"]
address = listener.get("address") if isinstance(listener, dict) else None
if not isinstance(listener, dict) or not isinstance(address, str) or not address or address in {"127.0.0.1", "::1", "localhost"} or listener.get("source") != "host-probe" or listener.get("method") != "tcp-listen" or listener.get("reachable") is not True or not isinstance(listener.get("port"), int) or not 1 <= listener["port"] <= 65535 or not isinstance(listener.get("pid"), int) or listener["pid"] <= 0 or not isinstance(listener.get("command_sha256"), str) or len(listener["command_sha256"]) != 64 or not isinstance(listener.get("verified_at"), str) or not listener.get("evidence_sha256"):
    raise SystemExit(1)
digest = hashlib.sha256(independent.read_bytes()).hexdigest()
if digest_path.read_text().strip() != digest:
    raise SystemExit(1)
auth = json.loads(auth_path.read_text(encoding="utf-8"))
if set(auth) != {"schema", "file", "sha256", "mac"} or auth["schema"] != 1 or auth["file"] != independent.name or auth["sha256"] != digest:
    raise SystemExit(1)
key = pathlib.Path("/dev/fd/3").read_bytes().strip()
payload = {name: auth[name] for name in ("schema", "file", "sha256")}
if not key or not hmac.compare_digest(auth["mac"], hmac.new(key, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()):
    raise SystemExit(1)
for label in ("lan", "ipv6"):
    probe = document["probe_evidence"].get(label)
    if not isinstance(probe, dict) or not isinstance(probe.get("address"), str) or not isinstance(probe.get("results"), dict) or not 1 <= len(probe["results"]) <= 8:
        raise SystemExit(1)
    ports = {"api": 8765, "qdrant": 6333, "ui": 3000}
    for service, expected in probe["results"].items():
        if service not in ports or expected != "unreachable":
            raise SystemExit(1)
        family = socket.AF_INET6 if ":" in probe["address"] else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as negative:
                negative.settimeout(2)
                negative.connect((probe["address"], ports[service]))
        except OSError:
            continue
        raise SystemExit(1)
tailnet_probe = document["probe_evidence"].get("tailnet")
if not isinstance(tailnet_probe, dict) or not isinstance(tailnet_probe.get("address"), str) or not isinstance(tailnet_probe.get("results"), dict) or tailnet_probe["results"].get("api") != "reachable" or any(tailnet_probe["results"].get(service) != "unreachable" for service in ("qdrant", "ui")):
    raise SystemExit(1)
network = json.loads(baseline.read_text(encoding="utf-8")).get("network")
if not isinstance(network, dict) or network.get("complete") is not True:
    raise SystemExit(1)
for label in ("lan", "ipv6"):
    probe = network.get("probe_evidence", {}).get(label, {})
    if not probe.get("address") or any(value != "unreachable" for value in probe.get("results", {}).values()):
        raise SystemExit(1)
tailnet_probe = network.get("probe_evidence", {}).get("tailnet", {})
if not tailnet_probe.get("address") or tailnet_probe.get("results", {}).get("api") != "reachable" or any(
    tailnet_probe.get("results", {}).get(service) != "unreachable" for service in ("qdrant", "ui")
):
    raise SystemExit(1)
network["source"] = "host-attested"
network["run_id"] = run_id
network["host_evidence_sha256"] = digest
network["host_identity_sha256"] = document["host_identity_sha256"]
network["remote_probe"] = "verified"
network["remote_listener"] = listener
network["probe_evidence"] = {label: document["probe_evidence"][label] for label in ("tailnet", "lan", "ipv6")}
output.write_text(json.dumps(network, sort_keys=True, separators=(",", ":")), encoding="utf-8")
output.chmod(0o600)
PY
  cp "$RUN_DIR/evidence/host-network-attested.json" "$INPUT_DIR/host-network.json"
  chmod 600 "$INPUT_DIR/host-network.json"
  decision environment PASS host_network_verified
  start_candidate
  local evaluation_status=0
  if bounded 120 env -i PATH="$PATH" HOME="$HOME" DOCKER_CONTEXT="$DOCKER_CONTEXT" DOCKER_HOST="$DOCKER_HOST_VALUE" docker --config "$HOME/.docker" compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" exec -T \
    -e OPENMEMORY_EVAL_DATABASE=/candidate-data/openmemory.db -e OPENMEMORY_EVAL_QDRANT_URL=http://candidate-store:6333 \
    -e OPENMEMORY_EXPECTED_MEM0_VERSION="$CANDIDATE_VERSION" \
    -e OPENMEMORY_CANDIDATE_RUN_ID="$RUN_ID" \
    -e OPENMEMORY_HOST_NETWORK_EVIDENCE=/candidate-input/host-network.json \
    candidate-api python /usr/src/openmemory/scripts/evaluate_retrieval.py --manifest /candidate-input/eval-manifest.json \
    --evidence-dir /candidate-output/evaluator --backend candidate > "$RUN_DIR/evidence/evaluation-run.log" 2>&1; then
    evaluation_status=0
  else
    evaluation_status=$?
  fi
  record evaluator_exit "$evaluation_status"
  [ "$evaluation_status" -eq 0 ] || [ "$evaluation_status" -eq 2 ] || die 'candidate evaluator operation failed before host validation'
  local candidate_id
  candidate_id="$(docker_scrubbed compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" ps -aq candidate-api)"
  [ -n "$candidate_id" ] || die 'candidate API container id is missing'
  mkdir -p "$RUN_DIR/evidence/evaluator"
  docker_scrubbed cp "$candidate_id:/candidate-output/evaluator/." "$RUN_DIR/evidence/evaluator-import" || die 'candidate evaluator evidence export failed'
  local evaluation_path
  evaluation_path="$(find "$RUN_DIR/evidence/evaluator-import" -type f -name evidence.json -print 2>/dev/null | sort | tail -n 1)"
  [ -n "$evaluation_path" ] || die 'candidate evaluator evidence file is missing'
  cp "$evaluation_path" "$RUN_DIR/evidence/evaluator/evidence.json"
  rm -rf "$RUN_DIR/evidence/evaluator-import"
  record evaluator_evidence_sha256 "$(sha256 "$RUN_DIR/evidence/evaluator/evidence.json")"
  seal_evidence_file "$RUN_DIR/evidence/evaluator/evidence.json" || die 'candidate evaluator evidence seal failed'
  verify_sealed_file "$RUN_DIR/evidence/evaluator/evidence.json" || die 'candidate evaluator evidence authentication failed'
  evaluate_evidence
  authoritative_replay
  [ -f "$RUN_DIR/evidence/clone-pristine.sqlite.sha256" ] || die 'pristine fingerprint is missing'
  /usr/bin/python3 - "$RUN_DIR/clone" "$RUN_DIR/evidence/clone-pristine-tree.sha256" <<'PY' || die 'clone changed during retrieval evaluation'
import hashlib
import pathlib
import sys
root, expected = map(pathlib.Path, sys.argv[1:])
digest = hashlib.sha256()
for path in sorted(item for item in root.rglob("*") if item.is_file()):
    digest.update(str(path.relative_to(root)).encode())
    digest.update(path.read_bytes())
    digest.update(str(path.stat().st_mode & 0o777).encode())
if digest.hexdigest() != expected.read_text().strip():
    raise SystemExit(1)
PY
  decision clone_pristine PASS verified
  docker_scrubbed compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" exec -d candidate-api uvicorn main:app --host 0.0.0.0 --port 8765 >/dev/null || die 'candidate mutation API start failed'
  local candidate_api_ready=0
  for attempt in {1..30}; do
    if docker_scrubbed compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" exec -T candidate-api python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8765/healthz", timeout=1)' >/dev/null 2>&1; then
      candidate_api_ready=1
      break
    fi
    sleep 1
  done
  [ "$candidate_api_ready" -eq 1 ] || die 'candidate mutation API did not become ready'
  local candidate_embedder_ready=0
  for _ in $(seq 1 6); do
    if docker_scrubbed compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" exec -T candidate-api python -c 'import json, urllib.request; urllib.request.urlopen(urllib.request.Request("http://host.docker.internal:11434/api/tags"), timeout=5).read(); urllib.request.urlopen(urllib.request.Request("http://host.docker.internal:11434/api/embed", data=json.dumps({"model": "nomic-embed-text", "input": "candidate readiness"}).encode(), headers={"Content-Type": "application/json"}, method="POST"), timeout=30).read()' >/dev/null 2>&1; then
      candidate_embedder_ready=1
      break
    fi
    sleep 2
  done
  [ "$candidate_embedder_ready" -eq 1 ] || die 'candidate embedder gateway did not become ready'
  OPENMEMORY_QDRANT_COLLECTION="$(sed -n 's/^collection=//p' "$RUN_DIR/evidence/production-runtime.manifest" | tail -n 1)"
  bounded 120 env -i PATH="$PATH" HOME="$HOME" DOCKER_CONTEXT="$DOCKER_CONTEXT" DOCKER_HOST="$DOCKER_HOST_VALUE" \
    OPENMEMORY_QDRANT_COLLECTION="${OPENMEMORY_QDRANT_COLLECTION:-openmemory}" OPENMEMORY_MUTATION_FIXTURE="$INPUT_DIR/mutation-fixture.json" \
    "$MUTATION_GATE_SCRIPT" "$RUN_DIR" "$PROJECT_NAME" 2> >(tee "$RUN_DIR/evidence/mutation-gate.log" >&2) || die 'clone mutation gate operation failed before host validation'
  validate_mutation_gate
  record mutation_evidence_sha256 "$(sha256 "$RUN_DIR/evidence/mutation-gate.json")"
  seal_evidence_file "$RUN_DIR/evidence/mutation-gate.json" || die 'mutation gate evidence seal failed'
  verify_sealed_file "$RUN_DIR/evidence/mutation-gate.json" || die 'mutation gate evidence authentication failed'
  decision mutation PASS contract_verified
  teardown || die 'candidate teardown failed'
  if docker_bounded 30 ps -a --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID" --format '{{.Names}}' | grep -q .; then
    die 'candidate container remains after teardown'
  fi
  production_fingerprint > "$RUN_DIR/evidence/production-after.sha256" || die 'production fingerprint capture failed after teardown'
  cmp -s "$RUN_DIR/evidence/production-before.sha256" "$RUN_DIR/evidence/production-after.sha256" || die 'production fingerprint drifted'
  decision production_fingerprint PASS after
  decision teardown PASS candidate_owned_only
  redact_evidence
  cleanup_private_inputs || die 'candidate private-input cleanup failed'
}

validate_mutation_gate() {
  /usr/bin/python3 - "$RUN_DIR/evidence/mutation-gate.json" <<'PY' || no_go 'host validation rejected mutation compatibility evidence'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = ["create", "update", "pause", "archive", "delete", "history", "acl", "filtered-retrieval", "qdrant-payload", "config", "mcp"]
if document.get("schema") != 1 or document.get("status") != "passed":
    raise SystemExit(1)
if document.get("operations") != expected or document.get("postconditions") != expected:
    raise SystemExit(1)
checks = document.get("checks")
if not isinstance(checks, dict) or set(checks) != set(expected):
    raise SystemExit(1)
required = {
    "create": {"status", "qdrant_payload", "payload_identity"},
    "update": {"status", "content"},
    "pause": {"status", "state"},
    "archive": {"status", "state"},
    "delete": {"status", "state", "qdrant_absent"},
    "history": {"status_history", "ordered", "actor_and_time", "mem0_history_changed", "target_event"},
    "acl": {"allow", "deny", "deny_status", "allow_status"},
    "filtered-retrieval": {"allow", "allow_status", "state_deny"},
    "qdrant-payload": {"create_payload", "update_payload", "delete_absent"},
    "config": {"openmemory", "mem0"},
    "mcp": {"search", "target_visible"},
}
for name, fields in required.items():
    if any(checks[name].get(field) is not True for field in fields if field in {"qdrant_payload", "payload_identity", "content", "qdrant_absent", "status_history", "ordered", "actor_and_time", "mem0_history_changed", "target_event", "allow", "deny", "state_deny", "create_payload", "update_payload", "delete_absent", "openmemory", "mem0", "search", "target_visible"}):
        raise SystemExit(1)
    if not isinstance(checks[name].get("status", 200), int) or checks[name].get("status", 200) < 200 or checks[name].get("status", 200) >= 300:
        raise SystemExit(1)
if checks["acl"].get("deny_status") != 200 or checks["acl"].get("allow_status") != 200:
    raise SystemExit(1)
if checks["filtered-retrieval"].get("allow_status") != 200:
    raise SystemExit(1)
PY
}

verify_candidate_ownership() {
  local id label ids
  ids="$(docker_bounded 30 ps -aq --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID")" || return 1
  for id in $ids; do
    label="$(docker_bounded 15 inspect -f '{{index .Config.Labels "com.ultimatesup.openmemory.candidate"}}' "$id")" || return 1
    [ "$label" = "$RUN_ID" ] || return 1
  done
  ids="$(docker_bounded 30 network ls -q --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID")" || return 1
  for id in $ids; do
    label="$(docker_bounded 15 network inspect -f '{{index .Labels "com.ultimatesup.openmemory.candidate"}}' "$id")" || return 1
    [ "$label" = "$RUN_ID" ] || return 1
  done
  ids="$(docker_bounded 30 volume ls -q --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID")" || return 1
  for id in $ids; do
    label="$(docker_bounded 15 volume inspect -f '{{index .Labels "com.ultimatesup.openmemory.candidate"}}' "$id")" || return 1
    [ "$label" = "$RUN_ID" ] || return 1
  done
  ids="$(docker_bounded 30 image ls -q --no-trunc --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID" | sort -u)" || return 1
  for id in $ids; do
    label="$(docker_bounded 15 image inspect -f '{{index .Config.Labels "com.ultimatesup.openmemory.candidate"}}' "$id")" || return 1
    [ "$label" = "$RUN_ID" ] || return 1
  done
  for resource in "$NETWORK_NAME" "$EGRESS_NETWORK_NAME"; do
    if docker_bounded 15 network inspect "$resource" >/dev/null 2>&1; then
      label="$(docker_bounded 15 network inspect -f '{{index .Labels "com.ultimatesup.openmemory.candidate"}}' "$resource")" || return 1
      [ "$label" = "$RUN_ID" ] || return 1
    fi
  done
  if docker_bounded 15 volume inspect "${PROJECT_NAME}-proxy-logs" >/dev/null 2>&1; then
    label="$(docker_bounded 15 volume inspect -f '{{index .Labels "com.ultimatesup.openmemory.candidate"}}' "${PROJECT_NAME}-proxy-logs")" || return 1
    [ "$label" = "$RUN_ID" ] || return 1
  fi
  for image in "$PROJECT_NAME-api:verified" "$PROJECT_NAME-egress:verified"; do
    if docker_bounded 15 image inspect "$image" >/dev/null 2>&1; then
      label="$(docker_bounded 15 image inspect -f '{{index .Config.Labels "com.ultimatesup.openmemory.candidate"}}' "$image")" || return 1
      [ "$label" = "$RUN_ID" ] || return 1
      label="$(docker_bounded 15 image inspect -f '{{json .RepoTags}}' "$image")" || return 1
      case "$label" in *"$PROJECT_NAME"*) ;; *) return 1 ;; esac
    fi
  done
}

redact_evidence() {
  local status=0
  rm -f "$RUN_DIR/evidence/evaluation-run.log" || status=1
  find "$RUN_DIR/evidence" -type f -exec sed -E -i '' \
    -e 's/(API_KEY|TOKEN|SECRET|PASSWORD|Authorization: Bearer)[=:][^ |]*/\1=[redacted]/Ig' \
    -e 's/(api_key|token|secret|password|authorization)[^=]*=[^,}]*/\1=[redacted]/Ig' {} + 2>/dev/null || status=1
  if [ -f "$RUN_DIR/evidence/compose.config.yml" ]; then
    sed -E -i '' 's/(API_KEY:|api_key:)[[:space:]]*.*/\1 [redacted]/' "$RUN_DIR/evidence/compose.config.yml" || status=1
  fi
  /usr/bin/python3 - "$RUN_DIR/evidence" <<'PY' || status=1
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
private = {"api_key", "authorization", "password", "secret", "token", "access_token", "refresh_token", "query", "content", "prompt", "raw", "text", "ranked_ids", "relevant_ids"}
def sanitize(key, value):
    if key and key.lower() in private:
        return "[redacted]"
    if isinstance(value, dict):
        return {name: sanitize(name, item) for name, item in value.items()}
    if isinstance(value, list):
        return [sanitize(key, item) for item in value]
    return value
for path in root.rglob("*.json"):
    if path.name in {"host-attestation.json", "terminal-decision.json"}:
        continue
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        continue
    path.write_text(json.dumps(sanitize(None, document), sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
for path in (root / "evaluator/evidence.json.auth.json", root / "mutation-gate.json.auth.json"):
    if path.exists():
        path.unlink()
PY
  return "$status"
}

cleanup_private_inputs() {
  local status=0 target
  for target in "$INPUT_DIR" "$RUN_DIR/clone" "$RUN_DIR/source" "$RUN_DIR/wheelhouse" "$RUN_DIR/build" "$RUN_DIR/compose.yml"; do
    if [ -e "$target" ] || [ -L "$target" ]; then
      if [ ! -L "$target" ]; then chmod -R u+w "$target" 2>/dev/null || status=1; fi
      rm -rf "$target" || status=1
    fi
    [ ! -e "$target" ] && [ ! -L "$target" ] || status=1
  done
  [ "$status" -eq 0 ] || printf '%s\n' 'private candidate inputs could not be fully removed' >&2
  if [ -e "$RUNTIME_HISTORY_DIR" ] || [ -L "$RUNTIME_HISTORY_DIR" ]; then
    [ -L "$RUNTIME_HISTORY_DIR" ] || chmod -R u+w "$RUNTIME_HISTORY_DIR" 2>/dev/null || status=1
    rm -rf "$RUNTIME_HISTORY_DIR" || status=1
  fi
  if [ -e "$RUNTIME_STORAGE_DIR" ] || [ -L "$RUNTIME_STORAGE_DIR" ]; then
    [ -L "$RUNTIME_STORAGE_DIR" ] || chmod -R u+w "$RUNTIME_STORAGE_DIR" 2>/dev/null || status=1
    rm -rf "$RUNTIME_STORAGE_DIR" || status=1
  fi
  return "$status"
}

teardown() {
  local status=0
  verify_candidate_ownership || { printf '%s\n' 'candidate ownership verification failed' >&2; return 1; }
  local ids id label
  ids="$(docker_bounded 30 compose --project-directory "$RUN_DIR" --file "$RUN_DIR/compose.yml" --project-name "$PROJECT_NAME" ps -aq)" || return 1
  for id in $ids; do
    label="$(docker_bounded 15 inspect -f '{{index .Config.Labels "com.ultimatesup.openmemory.candidate"}}' "$id")" || return 1
    [ "$label" = "$RUN_ID" ] || return 1
  done
  ids="$(docker_bounded 30 network ls -q --filter "name=${PROJECT_NAME}-")" || return 1
  for id in $ids; do
    label="$(docker_bounded 15 network inspect -f '{{index .Labels "com.ultimatesup.openmemory.candidate"}}' "$id")" || return 1
    [ "$label" = "$RUN_ID" ] || return 1
  done
  ids="$(docker_bounded 30 volume ls -q --filter "name=${PROJECT_NAME}-")" || return 1
  for id in $ids; do
    label="$(docker_bounded 15 volume inspect -f '{{index .Labels "com.ultimatesup.openmemory.candidate"}}' "$id")" || return 1
    [ "$label" = "$RUN_ID" ] || return 1
  done
  ids="$(docker_bounded 30 ps -aq --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID")" || status=1
  for id in $ids; do docker_bounded 60 rm -f "$id" >/dev/null || status=1; done
  ids="$(docker_bounded 30 network ls -q --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID")" || status=1
  for id in $ids; do docker_bounded 30 network rm "$id" >/dev/null || status=1; done
  ids="$(docker_bounded 30 volume ls -q --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID")" || status=1
  for id in $ids; do docker_bounded 30 volume rm "$id" >/dev/null || status=1; done
  ids="$(docker_bounded 30 image ls -q --no-trunc --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID" | sort -u)" || status=1
  for id in $ids; do docker_bounded 60 image rm "$id" >/dev/null || status=1; done
  local remaining
  if remaining="$(docker_bounded 30 ps -aq --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID")"; then [ -z "$remaining" ] || status=1; else status=1; fi
  if remaining="$(docker_bounded 30 network ls -q --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID")"; then [ -z "$remaining" ] || status=1; else status=1; fi
  if remaining="$(docker_bounded 30 volume ls -q --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID")"; then [ -z "$remaining" ] || status=1; else status=1; fi
  if remaining="$(docker_bounded 30 image ls -q --no-trunc --filter "label=com.ultimatesup.openmemory.candidate=$RUN_ID")"; then [ -z "$remaining" ] || status=1; else status=1; fi
  [ "$status" -eq 0 ] || printf '%s\n' 'candidate teardown verification failed' >&2
  return "$status"
}

on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    teardown || rc=1
  fi
  cleanup_private_inputs || rc=1
  if [ -d "$RUN_DIR/evidence" ] && [ "$TERMINAL_WRITTEN" -eq 0 ]; then
    redact_evidence || rc=1
    terminal_decision "${PENDING_OUTCOME:-BLOCKED-ENVIRONMENT}" "${PENDING_REASON:-candidate run did not complete}" || rc=1
  fi
  stop_watchdog
  exit "$rc"
}

main() {
  [ ! -e "$CANDIDATE_ROOT" ] || { [ -d "$CANDIDATE_ROOT" ] && [ ! -L "$CANDIDATE_ROOT" ] && [ "$(stat -f %u "$CANDIDATE_ROOT")" = "$(id -u)" ] && [ "$(stat -f %Lp "$CANDIDATE_ROOT")" = 700 ]; } || die 'candidate root ownership or mode is unsafe'
  mkdir -p "$CANDIDATE_ROOT"
  chmod 700 "$CANDIDATE_ROOT"
  [ ! -e "$RUN_DIR" ] || die 'candidate run directory already exists'
  mkdir "$RUN_DIR"
  [ "$(stat -f %u "$RUN_DIR")" = "$(id -u)" ] && [ "$(stat -f %Lp "$RUN_DIR")" = 700 ] || die 'candidate run directory ownership or mode is unsafe'
  mkdir "$RUN_DIR/evidence"
  chmod 700 "$CANDIDATE_ROOT" "$RUN_DIR" "$RUN_DIR/evidence"
  printf 'gate\tstatus\tevidence\n' > "$RUN_DIR/evidence/decision-table.tsv"
  mkdir "$INPUT_DIR"
  trap on_exit EXIT
  preflight
  start_watchdog
  select_backup
  stage_source
  stage_wheelhouse
  restore_clone
  generate_compose
  assert_no_collision
  build_and_inspect
  if [ "${OPENMEMORY_EVALUATE:-0}" = 1 ]; then
    evaluate_and_teardown
    terminal_decision READY-FOR-SEPARATE-PRODUCTION-PLAN 'all candidate gates passed' || die 'terminal decision authentication failed'
    verify_terminal_decision READY-FOR-SEPARATE-PRODUCTION-PLAN || die 'terminal decision verification failed'
    TERMINAL_WRITTEN=1
    printf 'READY-FOR-SEPARATE-PRODUCTION-PLAN: evidence sealed at %s; production was not changed\n' "$RUN_DIR"
  else
    teardown || die 'staged candidate cleanup failed'
    redact_evidence
    cleanup_private_inputs || die 'staged candidate private-input cleanup failed'
    terminal_decision MORE-WORK 'candidate evaluation was not enabled'
    printf 'MORE-WORK: staged candidate artifacts at %s; startup/evaluation requires a separate approved run after all preflight evidence is present\n' "$RUN_DIR"
  fi
}

if [ "${1:-}" = --production-fingerprint ]; then
  [ "${OPENMEMORY_FINGERPRINT_CHILD:-0}" = 1 ] || exit 2
  production_fingerprint_body
  exit 0
fi

main "$@"
