#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
python3 - "$SCRIPT_DIR/collect_host_network_evidence.py" <<'PY'
import importlib.util
import json
import pathlib
import shlex
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

collector_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("collector", collector_path)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

valid_tcp = {"TCP": {"8765": {"TCPForward": "127.0.0.1:8765"}}}
assert collector.validate_serve_route(valid_tcp)["target"] == "127.0.0.1:8765"
for invalid in (
    {},
    {"TCP": {"8765": {"TCPForward": "100.64.0.1:8765"}}},
    {"TCP": {"8765": {"TCPForward": "127.0.0.1:6333"}}},
):
    try:
        collector.validate_serve_route(invalid)
    except RuntimeError:
        pass
    else:
        raise SystemExit("invalid Serve route unexpectedly passed")

with tempfile.TemporaryDirectory() as directory:
    input_path = pathlib.Path(directory) / "probe-input.json"
    input_path.write_text(json.dumps({"purpose": "selfcheck"}), encoding="utf-8")
    absent = collector.peer_probe(None, None, None, "100.64.0.1")
    assert absent["status"] == "unverified"

    key_path = pathlib.Path(directory) / "approved-key"
    known_hosts_path = pathlib.Path(directory) / "known_hosts"
    key_path.write_text("fixture", encoding="utf-8")
    known_hosts_path.write_text("peer.example ssh-ed25519 AAAAfixture\n", encoding="utf-8")
    key_path.chmod(0o600)
    known_hosts_path.chmod(0o600)
    collector.APPROVED_PEER_KEY_PATH = key_path
    collector.APPROVED_PEER_KNOWN_HOSTS_PATH = known_hosts_path
    ssh_path = collector.shutil.which("ssh")
    command = shlex.join(
        [
            ssh_path,
            "-i",
            str(key_path),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "UserKnownHostsFile=" + str(known_hosts_path),
            "{host}",
            "probe",
            "{target}",
        ]
    )
    ssh_result = SimpleNamespace(
        returncode=0,
        stdout=json.dumps(
            {"host": "peer.example", "target": "100.64.0.1", "reachable": True, "results": collector.PEER_RESULTS}
        ).encode(),
    )
    with patch.object(collector, "command_output", return_value="peer.example ssh-ed25519 AAAAfixture"), patch.object(
        collector.subprocess, "run", return_value=ssh_result
    ):
        verified = collector.peer_probe("peer.example", command, input_path, "100.64.0.1")
    assert verified["status"] == "verified"
    assert verified["transport"] == "ssh"
    assert verified["peer_identity"]["host"] == "peer.example"
    assert len(verified["peer_identity"]["host_key_evidence_sha256"]) == 64
    assert len(verified["command_sha256"]) == 64

    wrapper = "{} {{host}} {{target}}".format(sys.executable)
    rejected = collector.peer_probe("peer.example", wrapper, input_path, "100.64.0.1")
    assert rejected["status"] == "unverified"

status_script = pathlib.Path(tempfile.mkdtemp()) / "tailscale"
status_script.write_text("#!/bin/sh\nprintf '%s' '{not-json}'\n", encoding="utf-8")
status_script.chmod(0o700)
try:
    collector.serve_status(str(status_script))
except RuntimeError:
    pass
else:
    raise SystemExit("malformed Serve status unexpectedly passed")

print("PASS host network evidence self-check")
PY
