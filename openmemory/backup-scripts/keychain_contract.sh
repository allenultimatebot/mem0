#!/usr/bin/env bash

keychain_secret() {
  /usr/bin/python3 - "$1" "$2" "$3" <<'PY'
import subprocess
import sys
import re

service, account, keychain = sys.argv[1:]


def security(args, timeout=10):
    return subprocess.run(
        ["security", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )


try:
    try:
        dump = subprocess.run(
            ["security", "dump-keychain", "-a", keychain], check=True, capture_output=True, text=True, timeout=60
        ).stdout
    except subprocess.TimeoutExpired as exc:
        raise SystemExit("keychain dump timed out") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit("keychain dump failed to execute") from exc
    blocks = [block for block in dump.split("keychain:") if re.search(rf'(?m)^\s+"svce"<blob>="{re.escape(service)}"\s*$', block) and re.search(rf'(?m)^\s+"acct"<blob>="{re.escape(account)}"\s*$', block)]
    if len(blocks) != 1:
        raise SystemExit("keychain item is missing or duplicated")
    block = blocks[0]
    if not re.search(r'class(?:<[^>]+>)?\s*[:=].*genp', block, re.IGNORECASE):
        raise SystemExit("keychain item is not a generic password")
    access = block.split("access:", 1)[1] if "access:" in block else ""
    entries = [entry for entry in re.split(r'(?m)^\s+entry \d+:', access)[1:] if entry.strip()]
    applications = []
    for entry in entries:
        match = re.search(r'(?m)^\s+applications \((\d+)\):\s*$', entry)
        if match:
            applications.append((int(match.group(1)), entry))
        elif not re.search(r'(?m)^\s+applications:\s+<null>\s*$', entry):
            raise SystemExit("keychain item access policy is not owner-only")
    expected_applications = {"/usr/bin/security"}
    if service == "com.ultimatesup.openmemory.backup-key":
        expected_applications.add("/Library/Developer/CommandLineTools/usr/bin/swift-frontend")
    actual_applications = set()
    for count, entry in applications:
        actual_applications.update(re.findall(r'(?m)^\s+\d+:\s+([^\s]+) \(OK\)\s*$', entry))
    if actual_applications != expected_applications or sum(count == len(expected_applications) for count, _entry in applications) != 1:
        raise SystemExit("keychain item access policy is not the approved owner policy")
    owner_entry = next(entry for count, entry in applications if count == len(expected_applications))
    if not re.search(r'(?m)^\s+0:\s+/usr/bin/security \(OK\)\s*$', owner_entry) or not re.search(r'(?m)^\s+requirement:\s+identifier "com\.apple\.security" and anchor apple\s*$', owner_entry):
        raise SystemExit("keychain item access policy is not owner-only")
    attributes = security(["find-generic-password", "-s", service, "-a", account, keychain])
    if attributes.returncode or f'"svce"<blob>="{service}"' not in attributes.stdout or f'"acct"<blob>="{account}"' not in attributes.stdout:
        raise SystemExit("keychain item identity does not match the required service and account")
    for wrong_service, wrong_account in ((service + "-absent", account), (service, account + "-absent")):
        if not security(["find-generic-password", "-s", wrong_service, "-a", wrong_account, keychain]).returncode:
            raise SystemExit("keychain lookup is not bound to the exact service and account")
    found = security(["find-generic-password", "-s", service, "-a", account, "-w", keychain])
    if found.returncode:
        raise SystemExit("keychain item is unavailable or requires interaction")
    secret = found.stdout
except (OSError, subprocess.SubprocessError) as exc:
    raise SystemExit("keychain lookup failed to execute") from exc
if not secret.strip():
    raise SystemExit("keychain secret is empty")
sys.stdout.write(secret)
PY
}

keychain_manifest_secret() {
  keychain_secret "$@"
}
