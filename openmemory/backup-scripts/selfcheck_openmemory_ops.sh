#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
backup="$SCRIPT_DIR/backup_openmemory.sh"
health="$SCRIPT_DIR/health_openmemory.sh"
restore="$SCRIPT_DIR/restore_openmemory_clone.sh"
semantic="$SCRIPT_DIR/verify_openmemory_restore_semantics.sh"
installer="$SCRIPT_DIR/install_launchagents.sh"
bounded_helper="$SCRIPT_DIR/run_bounded.py"

for file in "$backup" "$health" "$restore" "$semantic" "$installer"; do
  [ -x "$file" ] || { printf 'missing executable: %s\n' "$file" >&2; exit 1; }
  bash -n "$file"
done

"$backup" --self-test
grep -Fq 'DATABASE_URL=sqlite:////clone-data/openmemory.db' "$restore"
grep -Fq 'internal: true' "$restore"
grep -Fq 'compose 120 up -d' "$restore"
grep -Fq 'compose 30 down --volumes --remove-orphans' "$restore"
grep -Fq 'image identity mismatch' "$restore"
grep -Fq 'run directory is outside backup root' "$restore"
grep -Fq 'manual_recovery_required' "$backup"
grep -Fq 'Qdrant port assertion failed' "$backup"
grep -Fq 'archive_safe' "$restore"
grep -Fq 'member.issym()' "$restore"
grep -Fq 'unexpected database archive name' "$restore"
grep -Fq 'manifest_auth.py' "$restore"
grep -Fq 'restore semantics: production endpoint exposure rejected' "$semantic"
grep -Fq 'active retrieval filtering failed' "$semantic"
grep -Fq 'Qdrant point count/scroll mismatch' "$semantic"
grep -Fq 'orphan-quarantined' "$semantic"
grep -Fq 'quarantined Qdrant point has a SQLite memory' "$semantic"
grep -Fq 'unquarantined Qdrant point is not an active memory' "$semantic"
grep -Fq 'active_point_ids != active_ids' "$semantic"
grep -Fq 'orphan_quarantined_points' "$semantic"
grep -Fq 'restore-semantics.log' "$backup"
grep -Fq '"search_query": content, "page": 1, "size": 100' "$semantic"
grep -Fq 'compose_command=(' "$semantic"
grep -Fq 'local seconds=120' "$semantic"
grep -Fq 'bounded "$seconds" "${compose_command[@]}" "$@"' "$semantic"
! grep -Fq 'compose() { "${compose[@]}" "$@"; }' "$semantic"
grep -Fq 'start_new_session=True' "$bounded_helper"
grep -Fq 'signal.signal(signal.SIGTERM, terminate)' "$bounded_helper"
grep -Fq 'signal.signal(signal.SIGINT, terminate)' "$bounded_helper"
grep -Fq 'os.killpg(process.pid, signal.SIGKILL)' "$bounded_helper"
! "$semantic" >/dev/null 2>&1
grep -Fq 'KEEP_VERIFIED=2' "$backup"
grep -Fq '[ "$state" = complete ] || [ "$state" = restart_verified ] || continue' "$backup"
grep -Fq '{ [ "$state" = complete ] || [ "$state" = restart_verified ]; }' "$backup"
python3 - "$backup" <<'PY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text(encoding="utf-8")
if source.index("scope=protected|candidate=%s") > source.index("scope=local|candidate=%s"):
    raise SystemExit("retention must delete protected candidates before local candidates")
PY
grep -Fq 'retention.dry-run' "$backup"
grep -Fq 'E_PROTECTED_POSTCONDITION' "$backup"
grep -Fq 'E_LOCAL_POSTCONDITION' "$backup"
grep -Fq 'local_verified="$local_verified $id"' "$backup"
grep -Fq 'local_and_protected_exact=1' "$backup"
grep -Fq 'os.execv("/bin/rm", ["/bin/rm", "--", str(candidate_path)])' "$backup"
grep -Fq 'run_bounded.py' "$backup"
grep -Fq 'run_bounded.py' "$restore"
grep -Fq 'run_bounded.py' "$semantic"
grep -Fq 'SCRIPT_DIR=' "$semantic"
grep -Fq 'E_DEADLINE_EXPIRED' "$backup"
grep -Fq 'return 0' "$backup"
grep -Fq 'OPENMEMORY_ONE_SHOT_WINDOW_SECONDS' "$backup"
grep -Fq 'one-shot deadline is invalid' "$backup"
grep -Fq 'remote_sync=unconfirmed' "$backup"
grep -Fq 'DATABASE_VOLUME' "$backup"
grep -Fq 'backup_database' "$backup"
grep -Fq 'bounded 120 /usr/bin/python3 "$SCRIPT_DIR/manifest_auth.py"' "$backup"
grep -Fq 'E_LIVE_DB_INTEGRITY' "$health"
grep -Fq 'ambient Docker or Compose override is rejected' "$backup"
grep -Fq 'disabled-state.before' "$installer"
! grep -Fq 'exact rollback is unavailable when a target disabled override is absent' "$installer"
grep -Fq 'true|false|enabled|disabled' "$installer"
grep -Fq 'prior_state" = unknown' "$installer"
grep -Fq 'prior_state" = disabled' "$installer"
grep -Fq 'prior_state" = enabled' "$installer"
grep -Fq 'prior_loaded" = false' "$installer"
grep -Fq 'job_loaded' "$installer"
grep -Fq 'unable to determine loaded state' "$installer"
! grep -Eq 'TOKEN_FILE|MEM0_API_TOKEN|Authorization: Bearer' "$health"
grep -Fq 'status=(sent|rate_limited|disabled)' "$health"
grep -Fq 'StartInterval' "$SCRIPT_DIR/../launchd/com.ultimatesup.openmemory-health.plist.template"
grep -Fq 'StartCalendarInterval' "$SCRIPT_DIR/../launchd/com.ultimatesup.openmemory-backup.plist.template"
grep -Fq 'verified-generations-2-local-and-protected' "$SCRIPT_DIR/../launchd/com.ultimatesup.openmemory-backup.plist.template"
grep -Fq 'verified-generations-2-local-and-protected' "$SCRIPT_DIR/../launchd/com.ultimatesup.openmemory-health.plist.template"
grep -Fq 'SOURCE-SHA256SUMS' "$health"
grep -Fq 'SOURCE-MODES' "$health"
grep -Fq 'E_MANIFEST_AUTH' "$health"
grep -Fq 'E_FAILURE_MARKER' "$health"
grep -Fq 'E_DEADLINE_STATE' "$health"
grep -Fq 'dump-keychain", "-a"' "$SCRIPT_DIR/keychain_contract.sh"
grep -Fq 'manifest_auth.py" verify' "$health"
grep -Fq 'pointer-verify' "$health"
grep -Fq 'protected.pointer.auth.json' "$health"
grep -Fq 'keychain_secret "$encryption_service" "$encryption_account" "$KEYCHAIN"' "$backup"
! grep -Fq 'security find-generic-password -s com.ultimatesup.openmemory.backup-key' "$backup"
grep -Fq '.protected.pointer.auth.json' "$backup"
grep -Fq 'E_PROTECTED_POINTER_MISMATCH' "$health"
grep -Fq -- '--artifact-root "$PROTECTED_ROOT"' "$health"
grep -Fq '3<&3' "$health"
grep -Fq '3<&3' "$restore"
grep -Fq '3<&3' "$installer"
grep -Fq 'pass_fds=pass_fds' "$bounded_helper"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
OPENMEMORY_BACKUP_ROOT="$tmp/backups" OPENMEMORY_TEST_NOW=04:00:00 "$backup" >/dev/null
[ "$(cat "$tmp/backups/.admission/state")" = skipped_outside_window ]
[ ! -d "$tmp/backups/.backup.lock" ]
printf '%s\n' 'PASS operations self-check'
