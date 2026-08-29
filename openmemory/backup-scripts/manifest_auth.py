#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import os
import pathlib
import re


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_key():
    try:
        key = os.read(3, 4096).strip()
    except OSError:
        key = os.read(0, 4096).strip()
    if not key:
        raise SystemExit("manifest key unavailable")
    return key


def payload_for(run, service, account, key_id):
    run_id = run.name
    if not re.fullmatch(r"[0-9]{8}-[0-9]{6}-[0-9]+", run_id):
        raise SystemExit("invalid backup run id")
    data = run / "data"
    fingerprint = run / "production.fingerprint"
    source_tree = next(
        line.split("=", 1)[1]
        for line in fingerprint.read_text(encoding="utf-8").splitlines()
        if line.startswith("source_manifest_sha256=")
    )
    return {
        "account": account,
        "archives": {
            "data/sqlite/openmemory.db": digest(data / "sqlite/openmemory.db"),
            "data/volumes/history/volume.tar": digest(data / "volumes/history/volume.tar"),
            "data/volumes/storage/volume.tar": digest(data / "volumes/storage/volume.tar"),
        },
        "key_id": key_id,
        "production_fingerprint": digest(fingerprint),
        "run_id": run_id,
        "runtime_manifest_sha256": digest(data / "runtime.manifest"),
        "service": service,
        "sha256sums_sha256": digest(run / "SHA256SUMS"),
        "source_modes_sha256": digest(data / "source/SOURCE-MODES"),
        "source_manifest_sha256": digest(data / "source/SOURCE-SHA256SUMS"),
        "source_tree_sha256": source_tree,
    }


def pointer_payload(run, service, account, key_id, pointer_path=None, artifact_root=None):
    if not re.fullmatch(r"[0-9]{8}-[0-9]{6}-[0-9]+", run.name):
        raise SystemExit("invalid backup run id")
    pointer = pathlib.Path(pointer_path) if pointer_path else run / "protected.pointer"
    if not pointer.is_file() or pointer.is_symlink() or pointer.stat().st_mode & 0o077 or pointer.stat().st_uid != os.getuid():
        raise SystemExit("protected pointer is not a private owner file")
    values = {}
    for line in pointer.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise SystemExit("protected pointer is malformed")
        values[key] = value
    if set(values) != {"state", "artifact", "sha256", "remote_sync"}:
        raise SystemExit("protected pointer is malformed")
    if values["state"] != "protected_local_verified" or values["remote_sync"] != "unconfirmed" or not re.fullmatch(r"[A-Za-z0-9._-]+", values["artifact"]) or not re.fullmatch(r"[0-9a-f]{64}", values["sha256"]):
        raise SystemExit("protected pointer is malformed")
    if artifact_root:
        artifact_path = pathlib.Path(artifact_root) / values["artifact"]
        if not artifact_path.is_file() or artifact_path.is_symlink() or digest(artifact_path) != values["sha256"]:
            raise SystemExit("protected artifact does not match pointer")
    return {
        "account": account,
        "artifact": values["artifact"],
        "artifact_sha256": values["sha256"],
        "key_id": key_id,
        "manifest_sha256": digest(run / "manifest.canonical.json"),
        "pointer_sha256": digest(pointer),
        "run_id": run.name,
        "service": service,
        "state": values["state"],
        "remote_sync": values["remote_sync"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("create", "verify", "pointer-create", "pointer-verify"))
    parser.add_argument("run")
    parser.add_argument("auth")
    parser.add_argument("service")
    parser.add_argument("account")
    parser.add_argument("key_id")
    parser.add_argument("--artifact-root")
    parser.add_argument("--pointer-path")
    args = parser.parse_args()
    run = pathlib.Path(args.run)
    auth = pathlib.Path(args.auth)
    is_pointer = args.mode.startswith("pointer-")
    payload = pointer_payload(run, args.service, args.account, args.key_id, args.pointer_path, args.artifact_root) if is_pointer else payload_for(run, args.service, args.account, args.key_id)
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    key = read_key()
    mac = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    if args.mode in {"create", "pointer-create"}:
        if is_pointer:
            record = {"kind": "protected-pointer", "payload": payload, "mac": mac}
            auth.write_bytes(json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            auth.chmod(0o600)
            return
        (run / "manifest.canonical.json").write_bytes(canonical)
        record = {
            "account": args.account,
            "key_id": args.key_id,
            "mac": mac,
            "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
            "run_id": run.name,
            "service": args.service,
        }
        auth.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        auth.chmod(0o600)
        return
    record = json.loads(auth.read_text(encoding="utf-8"))
    if is_pointer:
        expected = {"kind": "protected-pointer", "payload": payload, "mac": mac}
        if set(record) != set(expected) or record != expected:
            raise SystemExit("protected pointer authentication failed")
        return
    manifest = run / "manifest.canonical.json"
    expected = {
        "account": args.account,
        "key_id": args.key_id,
        "mac": mac,
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
        "run_id": run.name,
        "service": args.service,
    }
    if set(record) != set(expected) or record != expected or manifest.read_bytes() != canonical:
        raise SystemExit("manifest authentication failed")


if __name__ == "__main__":
    main()
