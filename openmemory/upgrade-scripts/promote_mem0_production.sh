#!/usr/bin/env bash
set -euo pipefail

umask 077
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
source "$SCRIPT_DIR/../backup-scripts/keychain_contract.sh"
SOURCE_PROJECT="${OPENMEMORY_PROJECT_DIR:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)}"
EVIDENCE_ROOT="${OPENMEMORY_PROMOTION_EVIDENCE_ROOT:-$HOME/.local/share/openmemory-production-upgrades}"
RUN_ID="${OPENMEMORY_PROMOTION_RUN_ID:-$(date -u '+%Y%m%d-%H%M%S')-$$}"
CANDIDATE_FREEZE="${OPENMEMORY_CANDIDATE_FREEZE:-}"
WHEELHOUSE="${OPENMEMORY_CANDIDATE_WHEELHOUSE:-}"
EXPECTED_WHEEL_SHA256="${OPENMEMORY_EXPECTED_MEM0_WHEEL_SHA256:-}"
PRIOR_IMAGE_ID="${OPENMEMORY_PRIOR_IMAGE_ID:-}"
DOCKER_CONTEXT_NAME="${OPENMEMORY_DOCKER_CONTEXT:-}"
COMPOSE_PROJECT="${OPENMEMORY_COMPOSE_PROJECT:-openmemory}"
SERVICE="${OPENMEMORY_PROMOTION_SERVICE:-openmemory-mcp}"
BACKUP_ID="${OPENMEMORY_BACKUP_ID:-}"
APPROVAL_TOKEN_FILE="${OPENMEMORY_PROMOTION_APPROVAL_TOKEN_FILE:-}"
DRAIN_TIMEOUT_SECONDS="${OPENMEMORY_WRITER_DRAIN_TIMEOUT_SECONDS:-30}"
CUTOVER=0
SELF_CHECK=0
CUTOVER_STARTED=0
ROLLBACK_ATTEMPTED=0
MAINTENANCE_LOCK=""
HMAC_SERVICE="com.ultimatesup.openmemory.backup.manifest-v1"
HMAC_ACCOUNT="openmemory-backup-manifest-v1"
HMAC_KEY_ID="v1"
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"
CANDIDATE_IMAGE_ID=""
CANDIDATE_IMAGE_REF=""
RUN_DIR=""

die() { printf '%s\n' "promotion blocked: $1" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: promote_mem0_production.sh [options]

Default mode prepares a non-production candidate image and image-only Compose
override. Production recreation requires the explicit --cutover flag.

Options:
  --candidate-freeze PATH
  --wheelhouse DIR
  --expected-mem0-wheel-sha256 HEX
  --prior-image-id sha256:HEX
  --docker-context NAME
  --compose-project NAME
  --service openmemory-mcp
  --backup-id ID
  --approval-token-file PATH
  --evidence-root DIR
  --source-project DIR
  --run-id ID
  --cutover
  --self-check
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --candidate-freeze) [ "$#" -ge 2 ] || die 'missing candidate freeze'; CANDIDATE_FREEZE="$2"; shift 2 ;;
    --wheelhouse) [ "$#" -ge 2 ] || die 'missing wheelhouse'; WHEELHOUSE="$2"; shift 2 ;;
    --expected-mem0-wheel-sha256) [ "$#" -ge 2 ] || die 'missing Mem0 wheel digest'; EXPECTED_WHEEL_SHA256="$2"; shift 2 ;;
    --prior-image-id) [ "$#" -ge 2 ] || die 'missing prior image ID'; PRIOR_IMAGE_ID="$2"; shift 2 ;;
    --docker-context) [ "$#" -ge 2 ] || die 'missing Docker context'; DOCKER_CONTEXT_NAME="$2"; shift 2 ;;
    --compose-project) [ "$#" -ge 2 ] || die 'missing Compose project'; COMPOSE_PROJECT="$2"; shift 2 ;;
    --service) [ "$#" -ge 2 ] || die 'missing service'; SERVICE="$2"; shift 2 ;;
    --backup-id) [ "$#" -ge 2 ] || die 'missing backup ID'; BACKUP_ID="$2"; shift 2 ;;
    --approval-token-file) [ "$#" -ge 2 ] || die 'missing approval token file'; APPROVAL_TOKEN_FILE="$2"; shift 2 ;;
    --evidence-root) [ "$#" -ge 2 ] || die 'missing evidence root'; EVIDENCE_ROOT="$2"; shift 2 ;;
    --source-project) [ "$#" -ge 2 ] || die 'missing source project'; SOURCE_PROJECT="$2"; shift 2 ;;
    --run-id) [ "$#" -ge 2 ] || die 'missing run ID'; RUN_ID="$2"; shift 2 ;;
    --cutover) CUTOVER=1; shift ;;
    --self-check) SELF_CHECK=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

owner_only_file() {
  local path="$1"
  [ -f "$path" ] && [ ! -L "$path" ] || die "file is missing or symlinked: $path"
  [ "$(stat -f %u "$path")" = "$(id -u)" ] || die "file is not owner-owned: $path"
  [ "$(stat -f %Lp "$path")" = 600 ] || die "file is not mode 0600: $path"
}

owner_only_dir() {
  local path="$1"
  [ -d "$path" ] && [ ! -L "$path" ] || die "directory is missing or symlinked: $path"
  [ "$(stat -f %u "$path")" = "$(id -u)" ] || die "directory is not owner-owned: $path"
  [ "$(stat -f %Lp "$path")" = 700 ] || die "directory is not mode 0700: $path"
}

valid_id() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$ ]]; }
valid_image_id() { [[ "$1" =~ ^sha256:[0-9a-fA-F]{64}$ ]]; }
valid_timeout() { [[ "$1" =~ ^[1-9][0-9]{0,2}$ ]] && [ "$1" -le 300 ]; }

prepare_run_dir() {
  if [ -e "$EVIDENCE_ROOT" ]; then
    owner_only_dir "$EVIDENCE_ROOT"
  else
    mkdir -p "$EVIDENCE_ROOT"
    chmod 700 "$EVIDENCE_ROOT"
  fi
  [ ! -e "$EVIDENCE_ROOT/$RUN_ID" ] || die 'promotion run directory already exists'
  mkdir "$EVIDENCE_ROOT/$RUN_ID"
  chmod 700 "$EVIDENCE_ROOT/$RUN_ID"
  RUN_DIR="$EVIDENCE_ROOT/$RUN_ID"
  mkdir "$RUN_DIR/context"
  chmod 700 "$RUN_DIR/context"
}

validate_approval() {
  local output="$RUN_DIR/approval-payload.json"
  owner_only_file "$APPROVAL_TOKEN_FILE"
  if [ "$SELF_CHECK" -eq 1 ]; then
    exec 3<<<'promotion-self-check-secret'
  else
    exec 3< <(keychain_manifest_secret "$HMAC_SERVICE" "$HMAC_ACCOUNT" "$KEYCHAIN")
  fi
  /usr/bin/python3 - "$APPROVAL_TOKEN_FILE" "$output" "$BACKUP_ID" "$EXPECTED_WHEEL_SHA256" "$PRIOR_IMAGE_ID" <<'PY'
import datetime
import hashlib
import hmac
import json
import pathlib
import re
import sys

token_path, output_path, backup_id, digest, prior_image_id = sys.argv[1:]
token_path, output_path = map(pathlib.Path, (token_path, output_path))
try:
    document = json.loads(token_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as exc:
    raise SystemExit("approval token is not valid JSON") from exc
required = {"schema", "token", "action", "backup_id", "candidate_digest", "prior_image_id", "expires_at", "nonce", "mac"}
if set(document) != required or document["schema"] != 1 or not isinstance(document["token"], str) or len(document["token"]) < 32:
    raise SystemExit("approval token schema mismatch")
if document["action"] != "promote-mem0-production" or document["backup_id"] != backup_id or document["candidate_digest"].lower() != digest.lower() or document["prior_image_id"] != prior_image_id:
    raise SystemExit("approval token is not bound to this action")
if not isinstance(document["nonce"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{15,127}", document["nonce"]):
    raise SystemExit("approval nonce is invalid")
try:
    expires = datetime.datetime.fromisoformat(str(document["expires_at"]).replace("Z", "+00:00"))
except ValueError as exc:
    raise SystemExit("approval expiry is invalid") from exc
if expires.tzinfo is None or expires <= datetime.datetime.now(datetime.timezone.utc):
    raise SystemExit("approval token is expired")
payload = {name: document[name] for name in ("schema", "action", "backup_id", "candidate_digest", "prior_image_id", "expires_at", "nonce")}
secret = pathlib.Path('/dev/fd/3').read_text(encoding='utf-8').strip().encode()
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
expected_mac = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
if not hmac.compare_digest(document["mac"], expected_mac):
    raise SystemExit("approval token MAC verification failed")
receipt = {
    "schema": 1,
    "payload": payload,
    "payload_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    "token_sha256": hashlib.sha256(document["token"].encode()).hexdigest(),
    "mac": document["mac"],
}
pathlib.Path(output_path).write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  exec 3<&-
  chmod 600 "$output"
}

consume_approval() {
  local consumed="$APPROVAL_TOKEN_FILE.consumed"
  [ ! -e "$consumed" ] || die 'approval token was already consumed'
  mv "$APPROVAL_TOKEN_FILE" "$consumed" || die 'approval token could not be consumed atomically'
  chmod 600 "$consumed"
  printf '%s\n' "consumed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$RUN_DIR/approval-consumed.txt"
  chmod 600 "$RUN_DIR/approval-consumed.txt"
}

validate_candidate() {
  owner_only_file "$CANDIDATE_FREEZE"
  owner_only_dir "$WHEELHOUSE"
  [[ "$EXPECTED_WHEEL_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || die 'expected Mem0 wheel digest is invalid'
  valid_image_id "$PRIOR_IMAGE_ID" || die 'prior image ID must be a sha256 image ID'
  valid_id "$COMPOSE_PROJECT" || die 'Compose project name is invalid'
  [ "$SERVICE" = openmemory-mcp ] || die 'only openmemory-mcp may be promoted'
  valid_id "$BACKUP_ID" || die 'backup ID is invalid'
  valid_id "$RUN_ID" || die 'run ID is invalid'
  [ -f "$SOURCE_PROJECT/docker-compose.yml" ] || die 'production Compose file is missing'
  local expected_digest
  expected_digest="$(printf '%s' "$EXPECTED_WHEEL_SHA256" | tr '[:upper:]' '[:lower:]')"
  /usr/bin/python3 - "$CANDIDATE_FREEZE" "$WHEELHOUSE" "$expected_digest" "$RUN_DIR/package-inventory.json" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
import zipfile

freeze_path, wheelhouse_path, expected, output_path = sys.argv[1:]
freeze_path, wheelhouse_path, output_path = map(pathlib.Path, (freeze_path, wheelhouse_path, output_path))
freeze = freeze_path.read_text(encoding="utf-8")
if len(re.findall(r"(?im)^\s*mem0ai==[^\s]+", freeze)) != 1 or f"--hash=sha256:{expected}" not in freeze.lower():
    raise SystemExit("freeze does not pin the expected Mem0 wheel hash")
wheels = sorted(wheelhouse_path.glob("*.whl"))
files = [path for path in wheelhouse_path.rglob("*") if path.is_file()]
if not wheels or len(files) != len(wheels) or any(path.is_symlink() for path in files):
    raise SystemExit("wheelhouse contains unexpected files")
packages = []
for wheel in wheels:
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith("/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8", errors="replace")
    name = re.search(r"^Name: (.+)$", metadata, re.MULTILINE).group(1).strip()
    version = re.search(r"^Version: (.+)$", metadata, re.MULTILINE).group(1).strip()
    packages.append({"name": name, "version": version, "filename": wheel.name, "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()})
mem0 = [item for item in packages if item["name"].lower() == "mem0ai"]
if len(mem0) != 1 or mem0[0]["sha256"] != expected:
    raise SystemExit("wheelhouse Mem0 identity does not match the expected digest")
output_path.write_text(json.dumps({"schema": 1, "packages": packages}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  chmod 600 "$RUN_DIR/package-inventory.json"
  cp "$CANDIDATE_FREEZE" "$RUN_DIR/context/candidate-requirements.txt"
  cp -Rp "$WHEELHOUSE" "$RUN_DIR/context/wheelhouse"
  chmod 600 "$RUN_DIR/context/candidate-requirements.txt"
  find "$RUN_DIR/context/wheelhouse" -type d -exec chmod 700 {} \;
  find "$RUN_DIR/context/wheelhouse" -type f -exec chmod 600 {} \;
}

docker_cmd() { docker --context "$DOCKER_CONTEXT_NAME" "$@"; }
compose_cmd() {
  local files=(--file "$SOURCE_PROJECT/docker-compose.yml")
  [ ! -f "$SOURCE_PROJECT/docker-compose.override.yml" ] || files+=(--file "$SOURCE_PROJECT/docker-compose.override.yml")
  docker_cmd compose --project-directory "$SOURCE_PROJECT" "${files[@]}" --project-name "$COMPOSE_PROJECT" "$@"
}
docker_image_id() { docker_cmd image inspect -f '{{.Id}}' "$1"; }

capture_prior_inventory() {
  local container_id current_id
  container_id="$(compose_cmd ps -q "$SERVICE" | tr -d '\r')" || die 'prior service lookup failed'
  [ -n "$container_id" ] || die 'prior service container is missing'
  current_id="$(docker_cmd inspect -f '{{.Image}}' "$container_id")" || die 'prior image ID capture failed'
  [ "$current_id" = "$PRIOR_IMAGE_ID" ] || die 'production image does not match the supplied prior image ID'
  printf '%s\n' "$current_id" > "$RUN_DIR/prior-image-id.txt"
  printf '%s\n' "$container_id" > "$RUN_DIR/prior-container-id.txt"
  docker_cmd image inspect -f 'id={{.Id}}\nrepo_tags={{json .RepoTags}}\nrepo_digests={{json .RepoDigests}}\ncreated={{.Created}}\nsize={{.Size}}' "$PRIOR_IMAGE_ID" > "$RUN_DIR/prior-image-inventory.txt" || die 'prior image inventory failed'
  docker_cmd inspect -f 'id={{.Id}}\nname={{.Name}}\nimage={{.Image}}\nconfig_image={{.Config.Image}}\nstate={{.State.Status}}\nnetwork_mode={{.HostConfig.NetworkMode}}' "$container_id" > "$RUN_DIR/prior-container-inventory.txt" || die 'prior container inventory failed'
  docker_cmd run --rm --network none --entrypoint python "$PRIOR_IMAGE_ID" -c 'import importlib.metadata,json; print(json.dumps(sorted((d.metadata["Name"].lower(),d.version) for d in importlib.metadata.distributions()),separators=(",",":")))' > "$RUN_DIR/prior-package-inventory.json" 2> "$RUN_DIR/prior-package-inventory.log" || die 'prior package inventory failed'
  chmod 600 "$RUN_DIR/prior-image-id.txt" "$RUN_DIR/prior-container-id.txt" "$RUN_DIR/prior-image-inventory.txt" "$RUN_DIR/prior-container-inventory.txt" "$RUN_DIR/prior-package-inventory.json" "$RUN_DIR/prior-package-inventory.log"
}

create_candidate_image() {
  local base_tag="${COMPOSE_PROJECT}-${RUN_ID}-base" candidate_tag="${COMPOSE_PROJECT}-${RUN_ID}-candidate" mem0_wheel
  local prior_actual expected_digest
  expected_digest="$(printf '%s' "$EXPECTED_WHEEL_SHA256" | tr '[:upper:]' '[:lower:]')"
  mem0_wheel="$(find "$RUN_DIR/context/wheelhouse" -maxdepth 1 -type f -name 'mem0ai-*.whl' -exec basename {} \;)"
  [ -n "$mem0_wheel" ] || die 'candidate Mem0 wheel is missing from the sealed wheelhouse'
  [ "$(printf '%s\n' "$mem0_wheel" | wc -l | tr -d ' ')" = 1 ] || die 'candidate wheelhouse contains multiple Mem0 wheels'
  prior_actual="$(docker_image_id "$PRIOR_IMAGE_ID" 2>/dev/null || true)"
  [ "$prior_actual" = "$PRIOR_IMAGE_ID" ] || die 'prior image ID is not present locally'
  docker_cmd image tag "$PRIOR_IMAGE_ID" "$base_tag" || die 'prior image could not be privately tagged'
  cat > "$RUN_DIR/context/Dockerfile" <<EOF
FROM $base_tag
COPY candidate-requirements.txt /tmp/openmemory-candidate-requirements.txt
COPY wheelhouse/ /tmp/openmemory-wheelhouse/
RUN python -m pip install --no-cache-dir --no-index --no-deps /tmp/openmemory-wheelhouse/$mem0_wheel
EOF
  docker_cmd build --network none --pull=false --label "com.ultimatesup.openmemory.mem0-promotion=$RUN_ID" --label "com.ultimatesup.openmemory.mem0-wheel-sha256=$expected_digest" -f "$RUN_DIR/context/Dockerfile" -t "$candidate_tag" "$RUN_DIR/context" > "$RUN_DIR/image-build.log" 2>&1 || die 'candidate image creation failed'
  docker_cmd image rm "$base_tag" >/dev/null 2>&1 || true
  CANDIDATE_IMAGE_ID="$(docker_image_id "$candidate_tag" 2>/dev/null || true)"
  valid_image_id "$CANDIDATE_IMAGE_ID" || die 'candidate image ID is unavailable'
  CANDIDATE_IMAGE_REF="$candidate_tag"
  docker_cmd run --rm --network none --entrypoint python "$candidate_tag" -c 'import importlib.metadata,json; print(json.dumps(sorted((d.metadata["Name"].lower(),d.version) for d in importlib.metadata.distributions()),separators=(",",":")))' > "$RUN_DIR/candidate-package-inventory.json" 2> "$RUN_DIR/candidate-package-inventory.log" || die 'candidate package inventory failed'
  chmod 600 "$RUN_DIR/candidate-package-inventory.json" "$RUN_DIR/candidate-package-inventory.log"
  /usr/bin/python3 - "$RUN_DIR/prior-package-inventory.json" "$RUN_DIR/candidate-package-inventory.json" "$RUN_DIR/package-inventory-diff.json" <<'PY'
import json
import pathlib
import sys

prior_path, candidate_path, output_path = map(pathlib.Path, sys.argv[1:])
prior = dict(json.loads(prior_path.read_text(encoding="utf-8")))
candidate = dict(json.loads(candidate_path.read_text(encoding="utf-8")))
changes = {name: {"prior": prior.get(name), "candidate": candidate.get(name)} for name in sorted(set(prior) | set(candidate)) if prior.get(name) != candidate.get(name)}
unexpected = {name: change for name, change in changes.items() if name != "mem0ai"}
if unexpected:
    raise SystemExit("candidate dependency inventory changed outside mem0ai")
if candidate.get("mem0ai") != "2.0.19":
    raise SystemExit("candidate inventory does not contain mem0ai 2.0.19")
output_path.write_text(json.dumps({"schema": 1, "changes": changes}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  chmod 600 "$RUN_DIR/package-inventory-diff.json"
  printf '%s\n' "candidate_image_id=$CANDIDATE_IMAGE_ID" "prior_image_id=$PRIOR_IMAGE_ID" > "$RUN_DIR/image-ids.txt"
  chmod 600 "$RUN_DIR/image-ids.txt"
}

create_override() {
  cat > "$RUN_DIR/compose.override.yml" <<EOF
services:
  $SERVICE:
    image: $CANDIDATE_IMAGE_REF
EOF
  chmod 600 "$RUN_DIR/compose.override.yml"
  compose_cmd --file "$RUN_DIR/compose.override.yml" config --quiet || die 'image-only Compose override is invalid'
}

acquire_maintenance_lock() {
  MAINTENANCE_LOCK="${OPENMEMORY_MAINTENANCE_LOCK:-$SOURCE_PROJECT/api/.openmemory-maintenance.lock}"
  [ ! -e "$MAINTENANCE_LOCK" ] || die 'maintenance lock already exists'
  mkdir "$MAINTENANCE_LOCK" || die 'maintenance lock could not be acquired'
  chmod 700 "$MAINTENANCE_LOCK"
  printf 'run_id=%s\npid=%s\nstate=held\n' "$RUN_ID" "$$" > "$MAINTENANCE_LOCK/owner"
  chmod 600 "$MAINTENANCE_LOCK/owner"
}

release_maintenance_lock() {
  [ -n "$MAINTENANCE_LOCK" ] || return 0
  printf '%s\n' 'state=released' > "$MAINTENANCE_LOCK/state"
  chmod 600 "$MAINTENANCE_LOCK/state"
  rm -rf "$MAINTENANCE_LOCK"
  MAINTENANCE_LOCK=""
}

maintenance_lock_held() {
  [ -n "$MAINTENANCE_LOCK" ] && [ -d "$MAINTENANCE_LOCK" ] && [ -f "$MAINTENANCE_LOCK/owner" ] && grep -q '^state=held$' "$MAINTENANCE_LOCK/owner"
}

wait_for_service_stop() {
  local deadline running now
  deadline=$(( $(date +%s) + DRAIN_TIMEOUT_SECONDS ))
  while :; do
    running="$(compose_cmd ps -q --status running "$SERVICE" | tr -d '\r')" || return 1
    [ -z "$running" ] && return 0
    now="$(date +%s)"
    [ "$now" -lt "$deadline" ] || return 1
    sleep 1
  done
}

prove_writer_admission_denied() {
  local evidence_name="$1" code
  code="$(curl --noproxy '*' --silent --connect-timeout 1 --max-time 2 -o /dev/null -w '%{http_code}' -X POST 'http://127.0.0.1:8765/api/v1/memories/' 2>/dev/null || true)"
  [ "$code" = 000 ] || return 1
  printf '%s\n' 'writer_admission_probe=http_000' > "$RUN_DIR/$evidence_name-writer-admission-negative-proof.txt"
  chmod 600 "$RUN_DIR/$evidence_name-writer-admission-negative-proof.txt"
}

prove_maintenance_admission_gate() {
  /usr/bin/python3 - "$SCRIPT_DIR/../api/app/security.py" "$MAINTENANCE_LOCK" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
lock = pathlib.Path(sys.argv[2])
assert lock.joinpath("owner").is_file()
assert "def maintenance_lock_held" in source
assert "def request_is_mutating" in source
assert "request.method not in {\"GET\", \"HEAD\", \"OPTIONS\"}" in source
PY
}

drain_writers() {
  local evidence_name="$1"
  printf 'timeout_seconds=%s\n' "$DRAIN_TIMEOUT_SECONDS" > "$RUN_DIR/$evidence_name-state.txt"
  compose_cmd stop --timeout "$DRAIN_TIMEOUT_SECONDS" "$SERVICE" > "$RUN_DIR/$evidence_name.log" 2>&1 || return 1
  wait_for_service_stop || return 1
  maintenance_lock_held || return 1
  prove_writer_admission_denied "$evidence_name" || return 1
  printf '%s\n' 'state=stopped-and-not-admitting-writers' >> "$RUN_DIR/$evidence_name-state.txt"
  chmod 600 "$RUN_DIR/$evidence_name-state.txt"
}

verify_service_health() {
  local attempt code
  for attempt in $(seq 1 30); do
    code="$(curl --silent --show-error --max-time 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8765/healthz 2>/dev/null || true)"
    if [ "$code" = 200 ] && curl --silent --show-error --max-time 3 http://127.0.0.1:6333/collections >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

rollback() {
  [ "$ROLLBACK_ATTEMPTED" -eq 0 ] || return 1
  ROLLBACK_ATTEMPTED=1
  [ -n "$RUN_DIR" ] || return 1
  [ -n "$MAINTENANCE_LOCK" ] || acquire_maintenance_lock || return 1
  cat > "$RUN_DIR/rollback.override.yml" <<EOF
services:
  $SERVICE:
    image: $PRIOR_IMAGE_ID
EOF
  chmod 600 "$RUN_DIR/rollback.override.yml"
  docker_cmd image inspect "$PRIOR_IMAGE_ID" >/dev/null 2>&1 || return 1
  drain_writers rollback-drain || return 1
  compose_cmd --file "$RUN_DIR/rollback.override.yml" up -d --no-deps --force-recreate "$SERVICE" > "$RUN_DIR/rollback.log" 2>&1 || return 1
  local container_id after_id
  container_id="$(compose_cmd --file "$RUN_DIR/rollback.override.yml" ps -q "$SERVICE" | tr -d '\r')" || return 1
  [ -n "$container_id" ] || return 1
  after_id="$(docker_cmd inspect -f '{{.Image}}' "$container_id")" || return 1
  [ "$after_id" = "$PRIOR_IMAGE_ID" ] || return 1
  printf '%s\n' 'rollback=attempted' >> "$RUN_DIR/image-ids.txt"
  release_maintenance_lock || return 1
  container_id="$(compose_cmd --file "$RUN_DIR/rollback.override.yml" ps -q "$SERVICE" | tr -d '\r')" || return 1
  after_id="$(docker_cmd inspect -f '{{.Image}}' "$container_id")" || return 1
  [ "$after_id" = "$PRIOR_IMAGE_ID" ] || return 1
  verify_service_health || return 1
  printf '%s\n' "rollback_image_id=$after_id" "rollback=verified" >> "$RUN_DIR/image-ids.txt"
  return 0
}

record_manual_recovery() {
  [ -n "$RUN_DIR" ] || return 0
  cat > "$RUN_DIR/manual-recovery.txt" <<EOF
AUTOMATED ROLLBACK FAILED.
Do not delete the preserved evidence or volumes.
Use the exact prior image ID: $PRIOR_IMAGE_ID
Use the preserved override: $RUN_DIR/rollback.override.yml
1. Stop only $SERVICE with the recorded Docker context and Compose project.
2. Recreate only $SERVICE from rollback.override.yml with --no-deps --force-recreate.
3. Inspect the recreated container image ID and require exactly $PRIOR_IMAGE_ID.
4. Start only $SERVICE, verify http://127.0.0.1:8765/healthz and Qdrant health, then retain evidence.
5. If the exact image is unavailable or health fails, restore from the approved backup and escalate to the operator.
EOF
  chmod 600 "$RUN_DIR/manual-recovery.txt"
  printf '%s\n' "promotion requires manual recovery; instructions=$RUN_DIR/manual-recovery.txt" >&2
}

write_plan() {
  /usr/bin/python3 - "$RUN_DIR/promotion-plan.json" "$RUN_ID" "$COMPOSE_PROJECT" "$SERVICE" "$BACKUP_ID" "$PRIOR_IMAGE_ID" "$CANDIDATE_IMAGE_ID" "$CANDIDATE_IMAGE_REF" "$EXPECTED_WHEEL_SHA256" "$RUN_DIR/approval-payload.json" "$CUTOVER" <<'PY'
import datetime
import hashlib
import json
import pathlib
import sys

output, run_id, project, service, backup_id, prior_id, candidate_id, candidate_ref, wheel_digest, approval_path, cutover = sys.argv[1:]
approval = json.loads(pathlib.Path(approval_path).read_text(encoding="utf-8"))
inventory = pathlib.Path(output).with_name("package-inventory.json")
document = {
    "schema": 1,
    "action": "promote-mem0-production",
    "run_id": run_id,
    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "mode": "cutover" if cutover == "1" else "prepare",
    "production_cutover_performed": False,
    "compose_project": project,
    "service": service,
    "backup_id": backup_id,
    "prior_image_id": prior_id,
    "candidate_image_id": candidate_id,
    "candidate_image_ref": candidate_ref,
    "candidate_mem0_wheel_sha256": wheel_digest.lower(),
    "approval_payload_sha256": approval["payload_sha256"],
    "package_inventory_sha256": hashlib.sha256(inventory.read_bytes()).hexdigest(),
    "compose_override": "compose.override.yml",
}
pathlib.Path(output).write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  chmod 600 "$RUN_DIR/promotion-plan.json"
}

perform_cutover() {
  local container_id current_id after_id
  container_id="$(compose_cmd ps -q "$SERVICE" | tr -d '\r')"
  [ -n "$container_id" ] || die 'production service container is missing'
  current_id="$(docker_cmd inspect -f '{{.Image}}' "$container_id")"
  [ "$current_id" = "$PRIOR_IMAGE_ID" ] || die 'production image changed after prior-image capture'
  consume_approval
  acquire_maintenance_lock
  CUTOVER_STARTED=1
  drain_writers cutover-drain || die 'bounded writer drain or admission barrier failed'
  docker_cmd exec "$container_id" sqlite3 /var/lib/openmemory/openmemory.db 'BEGIN IMMEDIATE; ROLLBACK;' >/dev/null || die 'database writer barrier failed'
  compose_cmd --file "$RUN_DIR/compose.override.yml" up -d --no-deps --force-recreate "$SERVICE" > "$RUN_DIR/cutover.log" 2>&1 || die 'production service recreation failed'
  container_id="$(compose_cmd --file "$RUN_DIR/compose.override.yml" ps -q "$SERVICE" | tr -d '\r')"
  [ -n "$container_id" ] || die 'promoted service container is missing'
  after_id="$(docker_cmd inspect -f '{{.Image}}' "$container_id")"
  [ "$after_id" = "$CANDIDATE_IMAGE_ID" ] || die 'promoted service image ID does not match candidate'
  release_maintenance_lock
  container_id="$(compose_cmd --file "$RUN_DIR/compose.override.yml" ps -q "$SERVICE" | tr -d '\r')"
  [ -n "$container_id" ] || die 'promoted service container disappeared after start'
  after_id="$(docker_cmd inspect -f '{{.Image}}' "$container_id")"
  [ "$after_id" = "$CANDIDATE_IMAGE_ID" ] || die 'started promoted service image ID does not match candidate'
  verify_service_health || die 'promoted service health check failed'
  printf '%s\n' "post_cutover_image_id=$after_id" >> "$RUN_DIR/image-ids.txt"
  /usr/bin/python3 - "$RUN_DIR/promotion-plan.json" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
document["production_cutover_performed"] = True
path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  chmod 600 "$RUN_DIR/promotion-plan.json"
}

self_check() {
  local root token freeze wheel digest prior backup
  root="$(mktemp -d "${TMPDIR:-/tmp}/openmemory-promote-selfcheck.XXXXXX")"
  chmod 700 "$root"
  token="$root/approval.json"; freeze="$root/freeze.txt"; wheel="$root/wheelhouse"; digest="$(printf self-check | shasum -a 256 | awk '{print $1}')"; prior="sha256:$(printf '%064d' 0)"; backup="backup-self-check"
  mkdir "$wheel"; chmod 700 "$wheel"
  printf 'mem0ai==2.0.19 --hash=sha256:%s\n' "$digest" > "$freeze"; chmod 600 "$freeze"
  /usr/bin/python3 - "$token" "$backup" "$digest" "$prior" <<'PY'
import hashlib
import hmac
import json
import pathlib
import sys

path, backup, digest, prior = sys.argv[1:]
payload = {"schema": 1, "action": "promote-mem0-production", "backup_id": backup, "candidate_digest": digest, "prior_image_id": prior, "expires_at": "2999-01-01T00:00:00Z", "nonce": "self-check-nonce-123456"}
payload["mac"] = hmac.new(b"promotion-self-check-secret", json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
payload["token"] = "self-check-token-self-check-token-123456"
pathlib.Path(path).write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  chmod 600 "$token"
  EVIDENCE_ROOT="$root/evidence"; mkdir "$EVIDENCE_ROOT"; chmod 700 "$EVIDENCE_ROOT"; RUN_ID=self-check; RUN_DIR="$EVIDENCE_ROOT/self-check"; mkdir "$RUN_DIR"; chmod 700 "$RUN_DIR"
  CANDIDATE_FREEZE="$freeze"; WHEELHOUSE="$wheel"; EXPECTED_WHEEL_SHA256="$digest"; PRIOR_IMAGE_ID="$prior"; BACKUP_ID="$backup"; APPROVAL_TOKEN_FILE="$token"
  DRAIN_TIMEOUT_SECONDS=3
  valid_timeout "$DRAIN_TIMEOUT_SECONDS"
  DRAIN_TIMEOUT_SECONDS=0
  if valid_timeout "$DRAIN_TIMEOUT_SECONDS"; then die 'self-check accepted an invalid drain timeout'; fi
  SOURCE_PROJECT="$root/project"; mkdir "$SOURCE_PROJECT"
  OPENMEMORY_MAINTENANCE_LOCK="$root/maintenance.lock"
  acquire_maintenance_lock
  maintenance_lock_held || die 'self-check did not hold the maintenance lock'
  prove_maintenance_admission_gate
  release_maintenance_lock
  validate_approval
  consume_approval
  [ ! -e "$token" ] && [ -e "$token.consumed" ] || die 'self-check token was not consumed once'
  if (consume_approval 2>/dev/null); then die 'self-check allowed approval replay'; fi
  rm -rf "$root"
  printf '%s\n' 'promotion self-check: ok'
}

if [ "$SELF_CHECK" -eq 1 ]; then
  [ "$CUTOVER" -eq 0 ] || die '--self-check cannot be combined with --cutover'
  self_check
  exit 0
fi

[ -n "$CANDIDATE_FREEZE" ] || die 'candidate freeze is required'
[ -n "$WHEELHOUSE" ] || die 'wheelhouse is required'
[ -n "$EXPECTED_WHEEL_SHA256" ] || die 'expected Mem0 wheel digest is required'
[ -n "$PRIOR_IMAGE_ID" ] || die 'prior image ID is required'
[ -n "$DOCKER_CONTEXT_NAME" ] || die 'Docker context is required'
[ -n "$BACKUP_ID" ] || die 'backup ID is required'
[ -n "$APPROVAL_TOKEN_FILE" ] || die 'approval token file is required'
valid_timeout "$DRAIN_TIMEOUT_SECONDS" || die 'writer drain timeout must be 1-300 seconds'
prepare_run_dir
validate_candidate
validate_approval
docker_cmd --version >/dev/null 2>&1 || die 'Docker is unavailable'
capture_prior_inventory
create_candidate_image
create_override
write_plan
if [ "$CUTOVER" -eq 1 ]; then
  trap 'status=$?; if [ "$status" -ne 0 ] && [ "$CUTOVER_STARTED" -eq 1 ]; then if ! rollback; then record_manual_recovery; fi; fi; if [ -n "$MAINTENANCE_LOCK" ]; then rm -rf "$MAINTENANCE_LOCK"; fi; exit "$status"' EXIT
  perform_cutover
  printf '%s\n' "production cutover completed; evidence=$RUN_DIR"
else
  printf '%s\n' "non-production promotion prepared; evidence=$RUN_DIR"
fi
