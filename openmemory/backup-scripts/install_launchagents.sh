#!/usr/bin/env bash
set -euo pipefail

umask 077
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
source "$SCRIPT_DIR/keychain_contract.sh"
PROJECT="${OPENMEMORY_PROJECT_DIR:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)}"
AGENT_DIR="$HOME/Library/LaunchAgents"
LOG_DIR="${OPENMEMORY_LOG_DIR:-$HOME/.local/share/openmemory-logs}"
BACKUP_ROOT="${OPENMEMORY_BACKUP_ROOT:-$HOME/.local/share/openmemory-backups}"
PROTECTED_ROOT="${OPENMEMORY_PROTECTED_ROOT:-$HOME/Library/CloudStorage/GoogleDrive-ntu.theanh1@gmail.com/My Drive/Backup/Mem0}"
ARCHIVE="$HOME/.local/share/openmemory-launchagent-backups/$(date -u '+%Y%m%d-%H%M%S')"
UID_VALUE="$(id -u)"

mkdir -p "$AGENT_DIR" "$LOG_DIR" "$ARCHIVE"
chmod 700 "$ARCHIVE" "$LOG_DIR"
[ ! -L "$AGENT_DIR/com.ultimatesup.openmemory-health.plist" ] || { printf '%s\n' 'installer: health LaunchAgent path is symlinked' >&2; exit 1; }
[ ! -L "$AGENT_DIR/com.ultimatesup.openmemory-backup.plist" ] || { printf '%s\n' 'installer: backup LaunchAgent path is symlinked' >&2; exit 1; }
[ ! -e "$BACKUP_ROOT/.backup.lock" ] || { printf '%s\n' 'installer: backup lock is active' >&2; exit 1; }
"$SCRIPT_DIR/selfcheck_openmemory_ops.sh"
latest="$(find "$BACKUP_ROOT" -mindepth 2 -maxdepth 2 -type f -name state -print 2>/dev/null | sort | tail -n 1)"
[ -n "$latest" ] && grep -Fxq complete "$latest" || { printf '%s\n' 'installer: verified backup is required before cutover' >&2; exit 1; }
[ -f "$(dirname "$latest")/protected.pointer" ] || { printf '%s\n' 'installer: protected publication marker is missing' >&2; exit 1; }
run_dir="$(dirname "$latest")"
run_id="$(basename "$run_dir")"
[ -f "$run_dir/restore-verified" ] || { printf '%s\n' 'installer: restore verification marker is missing' >&2; exit 1; }
grep -Fxq 'state=protected_local_verified' "$run_dir/protected.pointer" || { printf '%s\n' 'installer: protected publication is not verified' >&2; exit 1; }
[ ! -L "$run_dir/protected.pointer" ] && [ "$(stat -f %u "$run_dir/protected.pointer")" = "$(id -u)" ] && [ "$(stat -f %Lp "$run_dir/protected.pointer")" = 600 ] || { printf '%s\n' 'installer: protected pointer is not a private owner file' >&2; exit 1; }
[ -f "$run_dir/protected.pointer.auth.json" ] && [ ! -L "$run_dir/protected.pointer.auth.json" ] || { printf '%s\n' 'installer: protected pointer authentication is missing' >&2; exit 1; }
[ -f "$run_dir/manifest.canonical.json" ] && [ -f "$BACKUP_ROOT/.manifest-auth/$run_id.json" ] || { printf '%s\n' 'installer: authenticated manifest is missing' >&2; exit 1; }
exec 3< <(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db")
/usr/bin/python3 "$SCRIPT_DIR/manifest_auth.py" verify "$run_dir" "$BACKUP_ROOT/.manifest-auth/$run_id.json" com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 v1 3<&3 || { printf '%s\n' 'installer: authenticated manifest verification failed' >&2; exit 1; }
exec 3<&-
exec 3< <(keychain_manifest_secret com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 "$HOME/Library/Keychains/login.keychain-db")
/usr/bin/python3 "$SCRIPT_DIR/manifest_auth.py" pointer-verify "$run_dir" "$run_dir/protected.pointer.auth.json" com.ultimatesup.openmemory.backup.manifest-v1 openmemory-backup-manifest-v1 v1 3<&3 || { printf '%s\n' 'installer: protected pointer authentication failed' >&2; exit 1; }
exec 3<&-
artifact="$(sed -n 's/^artifact=//p' "$run_dir/protected.pointer")"
artifact_sha="$(sed -n 's/^sha256=//p' "$run_dir/protected.pointer")"
[ -n "$artifact" ] && [ "$(basename "$artifact")" = "$artifact" ] || { printf '%s\n' 'installer: protected marker is malformed' >&2; exit 1; }
[ -n "$artifact_sha" ] && [ -f "$PROTECTED_ROOT/$artifact" ] || { printf '%s\n' 'installer: protected ciphertext is missing' >&2; exit 1; }
[ "$(shasum -a 256 "$PROTECTED_ROOT/$artifact" | awk '{print $1}')" = "$artifact_sha" ] || { printf '%s\n' 'installer: protected ciphertext digest mismatch' >&2; exit 1; }
if [ -f "$SCRIPT_DIR/export_openmemory.sh" ]; then
  cp -p "$SCRIPT_DIR/export_openmemory.sh" "$SCRIPT_DIR/legacy-quarantine/export_openmemory.sh"
  chmod 600 "$SCRIPT_DIR/legacy-quarantine/export_openmemory.sh" "$SCRIPT_DIR/export_openmemory.sh"
fi
launchctl print-disabled "gui/$UID_VALUE" > "$ARCHIVE/disabled-overrides.before" || {
  printf '%s\n' 'installer: unable to determine disabled LaunchAgent state' >&2
  exit 1
}

job_loaded() {
  local output
  if output="$(launchctl print "gui/$UID_VALUE/$1" 2>&1)"; then
    return 0
  fi
  printf '%s' "$output" | grep -Eiq 'could not find service|no such process|not found' && return 1
  return 2
}

for label in com.ultimatesup.openmemory-health com.ultimatesup.openmemory-backup; do
  state="$(sed -n -E "s/^\\\"$label\\\"[[:space:]]*=>[[:space:]]*(true|false|enabled|disabled)$/\\1/p" "$ARCHIVE/disabled-overrides.before")"
  if [ "$state" = true ] || [ "$state" = disabled ]; then
    printf '%s|disabled\n' "$label" >> "$ARCHIVE/disabled-state.before"
  elif [ "$state" = false ] || [ "$state" = enabled ]; then
    printf '%s|enabled\n' "$label" >> "$ARCHIVE/disabled-state.before"
  else
    printf '%s|unknown\n' "$label" >> "$ARCHIVE/disabled-state.before"
  fi
done
chmod 600 "$ARCHIVE/disabled-state.before"
: > "$ARCHIVE/loaded-state.before"
for label in com.ultimatesup.openmemory-health com.ultimatesup.openmemory-backup; do
  if job_loaded "$label"; then
    printf '%s|true\n' "$label" >> "$ARCHIVE/loaded-state.before"
  else
    loaded_status=$?
    [ "$loaded_status" -eq 1 ] || { printf '%s\n' "installer: unable to determine loaded state for $label" >&2; exit 1; }
    printf '%s|false\n' "$label" >> "$ARCHIVE/loaded-state.before"
  fi
done
chmod 600 "$ARCHIVE/loaded-state.before"

rollback() {
  local label
  for label in com.ultimatesup.openmemory-health com.ultimatesup.openmemory-backup; do
    launchctl bootout "gui/$UID_VALUE/$label" >/dev/null 2>&1 || true
    prior_state="$(sed -n "s/^$label|//p" "$ARCHIVE/disabled-state.before")"
    prior_loaded="$(sed -n "s/^$label|//p" "$ARCHIVE/loaded-state.before")"
    if [ -f "$ARCHIVE/$label.plist" ]; then
      cp -p "$ARCHIVE/$label.plist" "$AGENT_DIR/$label.plist"
    else
      rm -f -- "$AGENT_DIR/$label.plist"
    fi
    if [ "$prior_state" = disabled ]; then
      launchctl disable "gui/$UID_VALUE/$label" >/dev/null 2>&1 || true
    elif [ "$prior_state" = enabled ]; then
      launchctl enable "gui/$UID_VALUE/$label" >/dev/null 2>&1 || true
    elif [ "$prior_state" = unknown ]; then
      rollback_failed=1
    fi
    if disabled_output="$(launchctl print-disabled "gui/$UID_VALUE" 2>&1)"; then
      current_state="$(printf '%s\n' "$disabled_output" | sed -n -E "s/^\\\"$label\\\"[[:space:]]*=>[[:space:]]*(true|false|enabled|disabled)$/\1/p")"
      if [ "$current_state" = true ] || [ "$current_state" = disabled ]; then
        current_state=disabled
      elif [ "$current_state" = false ] || [ "$current_state" = enabled ]; then
        current_state=enabled
      fi
    else
      current_state="__query_failed__"
      rollback_failed=1
    fi
    if [ "$current_state" = "__query_failed__" ]; then
      :
    elif [ "$prior_state" = unknown ]; then
      rollback_failed=1
    else
      [ "$current_state" = "$prior_state" ] || rollback_failed=1
    fi
    if [ "$prior_loaded" = true ] && [ -f "$AGENT_DIR/$label.plist" ]; then
      launchctl bootstrap "gui/$UID_VALUE" "$AGENT_DIR/$label.plist" >/dev/null 2>&1 || rollback_failed=1
      launchctl print "gui/$UID_VALUE/$label" >/dev/null 2>&1 || rollback_failed=1
    elif [ "$prior_loaded" = false ]; then
      if job_loaded "$label"; then
        rollback_failed=1
      elif [ "$?" -ne 1 ]; then
        rollback_failed=1
      fi
    fi
  done
  [ "${rollback_failed:-0}" -eq 0 ]
}

trap 'status=$?; if [ "$status" -ne 0 ]; then rollback; fi; exit "$status"' EXIT

render() {
  /usr/bin/python3 - "$1" "$2" "$PROJECT" "$SCRIPT_DIR" "$LOG_DIR" "$BACKUP_ROOT" "$HOME" <<'PY'
import pathlib
import sys

template, output, project, scripts, logs, backups, home = sys.argv[1:]
text = pathlib.Path(template).read_text()
for key, value in {"__OPENMEMORY_PROJECT__": project, "__OPENMEMORY_SCRIPTS__": scripts, "__OPENMEMORY_LOGS__": logs, "__OPENMEMORY_BACKUPS__": backups, "__HOME__": home}.items():
    text = text.replace(key, value)
pathlib.Path(output).write_text(text)
PY
  chmod 600 "$2"
  plutil -lint "$2" >/dev/null
}

for label in com.ultimatesup.openmemory-health com.ultimatesup.openmemory-backup; do
  [ ! -e "$AGENT_DIR/$label.plist" ] || cp -p "$AGENT_DIR/$label.plist" "$ARCHIVE/"
done
render "$SCRIPT_DIR/../launchd/com.ultimatesup.openmemory-health.plist.template" "$ARCHIVE/com.ultimatesup.openmemory-health.new.plist"
render "$SCRIPT_DIR/../launchd/com.ultimatesup.openmemory-backup.plist.template" "$ARCHIVE/com.ultimatesup.openmemory-backup.new.plist"
cp -p "$ARCHIVE/com.ultimatesup.openmemory-health.new.plist" "$AGENT_DIR/com.ultimatesup.openmemory-health.plist"
cp -p "$ARCHIVE/com.ultimatesup.openmemory-backup.new.plist" "$AGENT_DIR/com.ultimatesup.openmemory-backup.plist"
for label in com.ultimatesup.openmemory-health com.ultimatesup.openmemory-backup; do
  launchctl bootout "gui/$UID_VALUE/$label" >/dev/null 2>&1 || true
done
launchctl enable "gui/$UID_VALUE/com.ultimatesup.openmemory-health"
launchctl bootstrap "gui/$UID_VALUE" "$AGENT_DIR/com.ultimatesup.openmemory-health.plist"
launchctl enable "gui/$UID_VALUE/com.ultimatesup.openmemory-backup"
launchctl bootstrap "gui/$UID_VALUE" "$AGENT_DIR/com.ultimatesup.openmemory-backup.plist"
launchctl print "gui/$UID_VALUE/com.ultimatesup.openmemory-health" >/dev/null
launchctl print "gui/$UID_VALUE/com.ultimatesup.openmemory-backup" >/dev/null
launchctl print "gui/$UID_VALUE/com.ultimatesup.openmemory-health" | grep -Fq "$SCRIPT_DIR/health_openmemory.sh"
launchctl print "gui/$UID_VALUE/com.ultimatesup.openmemory-backup" | grep -Fq "$SCRIPT_DIR/backup_openmemory.sh"
printf '%s\n' "installed launch agents; archive=$ARCHIVE"
