#!/usr/bin/env bash
set -euo pipefail

umask 077
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
STAGE="$SCRIPT_DIR/stage_mem0_candidate.sh"
PROXY="$SCRIPT_DIR/candidate-egress-proxy/proxy.py"
COMPOSE_PROXY="$SCRIPT_DIR/candidate-egress-proxy/Dockerfile"
ALLOWLIST="$SCRIPT_DIR/candidate-egress-proxy/allowlist.json"
EGRESS="$SCRIPT_DIR/selfcheck_candidate_egress.sh"
MUTATION="$SCRIPT_DIR/selfcheck_mem0_candidate_mutations.sh"
WATCHDOG="$SCRIPT_DIR/candidate-watchdog.py"

for file in "$STAGE" "$EGRESS"; do
  [ -x "$file" ] || { printf 'missing executable: %s\n' "$file" >&2; exit 1; }
  bash -n "$file"
done
[ -x "$MUTATION" ] || exit 1
bash -n "$MUTATION"
python3 -m py_compile "$PROXY"
python3 -m py_compile "$WATCHDOG"
grep -Fq 'FROM python:3.12-slim@sha256:' "$COMPOSE_PROXY"
grep -Fq 'chmod 0555 /proxy/proxy.py /proxy/allowlist.json' "$COMPOSE_PROXY"
grep -Fq 'host.docker.internal:20128' "$ALLOWLIST"
grep -Fq 'host.docker.internal:11434' "$ALLOWLIST"
grep -Fq 'frozenset(upstreams) != ALLOWED_UPSTREAMS' "$PROXY"
grep -Fq 'absolute_form_denied' "$PROXY"
grep -Fq 'connect_denied' "$PROXY"
grep -Fq 'upstream_error' "$PROXY"
grep -Fq 'for port in (20128, 11434)' "$PROXY"
grep -Fq 'read_only: true' "$STAGE"
grep -Fq 'cap_drop: [ALL]' "$STAGE"
grep -Fq 'network: none' "$STAGE"
grep -Fq 'internal: true' "$STAGE"
grep -Fq 'candidate-test-key' "$STAGE"
grep -Fq 'production-requirements.txt' "$STAGE"
grep -Fq 'candidate-requirements.txt' "$STAGE"
grep -Fq 'importlib.metadata.version("mem0ai")' "$STAGE"
grep -Fq -- '--volume "$RUN_DIR/wheelhouse:/wheelhouse"' "$STAGE"
grep -Fq -- '--dest /wheelhouse -r /candidate.in' "$STAGE"
grep -Fq 'resolver=base-image-container' "$STAGE"
grep -Fq 'wheelhouse-target.txt' "$STAGE"
grep -Fq 'manifest schema mismatch' "$STAGE"
grep -Fq 'selfcheck_mem0_candidate_mutations.sh' "$STAGE"
grep -Fq 'terminal-decision' "$STAGE"
grep -Fq 'shasum -a 256 "$file"' "$STAGE"
grep -Fq 'chmod 600 "$file.sha256"' "$STAGE"
grep -Fq 'host-network.json' "$STAGE"
grep -Fq 'mutation-gate.json' "$STAGE"
grep -Fq 'mutation-fixture.json' "$STAGE"
grep -Fq 'candidate-watchdog.py' "$STAGE"
grep -Fq 'collect_host_network_evidence.py' "$STAGE"
grep -Fq "docker_scrubbed inspect -f '{{json .}}'" "$STAGE"
grep -Fq 'DOCKER_CONTEXT' "$SCRIPT_DIR/collect_host_network_evidence.py"
grep -Fq 'DOCKER_HOST' "$SCRIPT_DIR/collect_host_network_evidence.py"
grep -Fq 'expected_gates = ["docker", "production_pin", "disk", "release_provenance"' "$STAGE"
grep -Fq '"mutation", "production_fingerprint", "teardown"' "$STAGE"
grep -Fq 'decision mutation PASS' "$STAGE"
grep -Fq 'os.replace(temporary, marker)' "$STAGE"
grep -Fq '127.0.0.1:$CANDIDATE_QDRANT_PORT:6333' "$STAGE"
grep -Fq 'authoritative_replay' "$STAGE"
grep -Fq 'current retrieval evaluator is missing' "$STAGE"
grep -Fq 'cp "$SOURCE_PROJECT/api/scripts/evaluate_retrieval.py" "$RUN_DIR/build/api/scripts/evaluate_retrieval.py"' "$STAGE"
grep -Fq 'command: ["sleep", "infinity"]' "$STAGE"
grep -Fq 'expected_gates = ["docker", "production_pin", "disk", "release_provenance", "package_index", "tailscale", "gateways", "production_fingerprint", "backup_manifest", "backup", "clone", "compose", "environment", "runtime", "egress", "scoring", "authoritative_replay"' "$STAGE"
python3 - "$SCRIPT_DIR" <<'PY'
import importlib.util
import pathlib
import sys
collector_path = pathlib.Path(sys.argv[1]) / "collect_host_network_evidence.py"
spec = importlib.util.spec_from_file_location("collector", collector_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
process, port = module.listener_process("127.0.0.1")
try:
    assert module.probe("127.0.0.1", port) == "reachable"
finally:
    process.terminate()
    process.wait(timeout=2)
PY
grep -Fq 'candidate-input:/candidate-input:ro' "$STAGE" || grep -Fq 'candidate-input:ro' "$STAGE"
! grep -Fq '$RUN_DIR/evidence:/candidate-evidence' "$STAGE"
grep -Fq 'candidate-image-digests.tsv' "$STAGE"
grep -Fq 'chmod -R a-w "$RUN_DIR/source"' "$STAGE"
grep -Fq 'chmod -R a-w "$RUN_DIR/wheelhouse"' "$STAGE"
grep -Fq 'NO-GO' "$SCRIPT_DIR/../README.md" 2>/dev/null || true

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/source/api" "$tmp/backup/data/source/api" "$tmp/backup/data/sqlite" "$tmp/backup/data/volumes/history" "$tmp/backup/data/volumes/storage"
printf 'mem0ai==2.0.4\n' > "$tmp/source/api/requirements.txt"
cp "$tmp/source/api/requirements.txt" "$tmp/backup/data/source/api/requirements.txt"
printf '%s  %s\n' "$(shasum -a 256 "$tmp/backup/data/source/api/requirements.txt" | awk '{print $1}')" api/requirements.txt > "$tmp/backup/data/source/SOURCE-SHA256SUMS"
printf 'api/requirements.txt|mode=644\n' > "$tmp/backup/data/source/SOURCE-MODES"
printf 'x' > "$tmp/backup/data/sqlite/openmemory.db"
tar -cf "$tmp/backup/data/volumes/history/volume.tar" -C "$tmp/source" .
tar -cf "$tmp/backup/data/volumes/storage/volume.tar" -C "$tmp/source" .
printf 'incomplete\n' > "$tmp/backup/state"
printf '0  data/sqlite/openmemory.db\n' > "$tmp/backup/SHA256SUMS"
if OPENMEMORY_CANDIDATE_ROOT="$tmp/candidates" OPENMEMORY_BACKUP_RUN="$tmp/backup" MEM0_CANDIDATE_VERSION=0.0.0 "$STAGE" >"$tmp/stage.out" 2>&1; then
  printf '%s\n' 'candidate selfcheck: unsafe/incomplete fixture unexpectedly passed' >&2
  exit 1
fi
grep -Fq 'BLOCKED-ENVIRONMENT:' "$tmp/stage.out" || { cat "$tmp/stage.out" >&2; exit 1; }
printf '%s\n' 'PASS candidate staging self-check'
