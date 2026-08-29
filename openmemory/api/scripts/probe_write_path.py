#!/usr/bin/env python3
import argparse
import glob
import importlib.util
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


HOOK = Path.home() / ".claude/hooks/mem0-autosave.py"
API = os.environ.get("OPENMEMORY_API_URL", "http://127.0.0.1:8765/api/v1/memories/")
TOKEN_FILE = Path(os.environ.get("OPENMEMORY_API_TOKEN_FILE", Path.home() / ".config/openmemory/api-token"))
COMPOSE_SERVICE = os.environ.get("OPENMEMORY_PROBE_SERVICE", "openmemory-mcp")
COMPOSE_PROJECT = Path(__file__).resolve().parents[2]

L3_SCRIPT = r'''
import json
from app.utils.memory import get_memory_client

client = get_memory_client()
capture = {"response": None, "embed_failures": 0}

original_generate = client.llm.generate_response
def generate(*args, **kwargs):
    response = original_generate(*args, **kwargs)
    capture["response"] = response
    return response
client.llm.generate_response = generate

for name in ("embed_batch", "embed"):
    model = client.embedding_model
    original = getattr(model, name)
    def wrapped(*args, _original=original, **kwargs):
        try:
            return _original(*args, **kwargs)
        except Exception:
            capture["embed_failures"] += 1
            raise
    setattr(model, name, wrapped)

try:
    result = client.add(input(), user_id="probe-scratch", infer=True)
    events = [item.get("event") for item in result.get("results", []) if isinstance(item, dict)] if isinstance(result, dict) else []
    response = capture["response"]
    parsed = None
    if isinstance(response, str) and response.strip():
        try:
            parsed = json.loads(response)
        except json.JSONDecodeError:
            parsed = None
    print(json.dumps({
        "ok": True,
        "events": events,
        "raw_type": type(response).__name__,
        "raw_keys": sorted(parsed) if isinstance(parsed, dict) else None,
        "memory_count": len(parsed.get("memory", [])) if isinstance(parsed, dict) and isinstance(parsed.get("memory"), list) else None,
        "facts_count": len(parsed.get("facts", [])) if isinstance(parsed, dict) and isinstance(parsed.get("facts"), list) else None,
        "embed_failures": capture["embed_failures"],
    }))
except Exception as error:
    print(json.dumps({
        "ok": False,
        "error_type": type(error).__name__,
        "events": [],
        "raw_type": type(capture["response"]).__name__,
        "raw_keys": None,
        "memory_count": None,
        "facts_count": None,
        "embed_failures": capture["embed_failures"],
    }))
'''


def load_hook():
    if not HOOK.exists():
        return None
    spec = importlib.util.spec_from_file_location("mem0_autosave", HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def transcripts(paths):
    if paths:
        return [Path(path).expanduser() for path in paths]
    candidates = [
        Path(path)
        for path in glob.glob(str(Path.home() / ".claude/projects/**/*.jsonl"), recursive=True)
        if "/subagents/" not in path
    ]
    return sorted(candidates, key=lambda path: path.stat().st_mtime, reverse=True)[:3]


def request(text):
    try:
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError as error:
        return 0, {"reason": "token_unavailable", "error_type": type(error).__name__}
    body = json.dumps({"user_id": "allen_bot", "text": text, "app": "probe-write-path", "infer": True}).encode()
    req = urllib.request.Request(API, data=body, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=170) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read() or b"{}")
        except (OSError, TypeError, ValueError):
            body = {"reason": "malformed_http_body", "body_type": "non_json"}
        return error.code, body
    except (OSError, ValueError) as error:
        return 0, {"reason": type(error).__name__}


def l3_verdict(report):
    if not isinstance(report, dict):
        return "wire_shape_error"
    if not report.get("ok"):
        if report.get("embed_failures"):
            return "embed_failed"
        return f"error_{report.get('error_type', 'unknown')}"
    events = report.get("events", [])
    if "ADD" in events:
        return f"accepted {events.count('ADD')}"
    if report.get("memory_count") is None:
        return "parse_failed"
    if report["memory_count"] == 0:
        return "empty_extraction"
    if report.get("embed_failures"):
        return "embed_failed"
    return "dedup_skipped"


def container_l3(text):
    try:
        completed = subprocess.run(
            ["docker", "compose", "exec", "-T", COMPOSE_SERVICE, "python", "-c", L3_SCRIPT],
            cwd=COMPOSE_PROJECT,
            input=text,
            text=True,
            capture_output=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ok": False, "error_type": type(error).__name__, "events": []}
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        return {"ok": False, "error_type": f"container_exit_{completed.returncode}", "events": []}
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError:
        return {"ok": False, "error_type": "malformed_container_report", "events": []}


def verdict(status, body):
    if status >= 400:
        reason = body.get("reason") if isinstance(body, dict) else None
        return f"error_http_{status}_{reason or 'unknown'}"
    if not isinstance(body, dict):
        return "wire-shape/parse failure"
    if body.get("id") or body.get("accepted", 0) > 0:
        return "accepted"
    reason = body.get("reason")
    return {
        "token_unavailable": "token_unavailable",
        "malformed_http_body": "wire_shape_error",
        "client_unavailable": "client_unavailable",
        "no_facts_extracted": "rejected-empty",
        "non_add_events": "dedup_skipped",
        "malformed_sdk_response": "wire-shape/parse failure",
        "extraction_error": "error_extraction",
    }.get(reason, reason or "unknown")


def safe_body(body):
    if not isinstance(body, dict):
        return {"type": type(body).__name__}
    return {
        "keys": sorted(body),
        "accepted": body.get("accepted", 0),
        "reason": body.get("reason"),
        "id_present": bool(body.get("id")),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--transcript", action="append", default=[])
    parser.add_argument("--layers", default="l1,l2,l3")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    layers = {layer.strip().lower() for layer in args.layers.split(",") if layer.strip()}
    hook = load_hook()
    paths = transcripts(args.transcript)
    if not paths:
        print("no transcripts found", file=sys.stderr)
        return 1

    for path in paths:
        print(f"transcript={path}")
        turns = hook.extract_turns(str(path)) if hook else []
        text = "\n".join(f"{role}: {content}" for role, content in turns[-20:])[-12000:]
        if "l1" in layers:
            if not hook:
                print("  l1=skipped hook-missing")
            else:
                user_turns = [(index, content) for index, (role, content) in enumerate(turns, 1) if role == "user"]
                if not user_turns:
                    print("  l1=rejected-empty no eligible user turns")
                for turn_number, content in user_turns:
                    result = "PASS" if hook._is_memory_worthy_user_text(content) else "FAIL"
                    print(f"  l1=user_turn_{turn_number}={result}")
        for layer in ("l2", "l3"):
            if layer not in layers:
                continue
            if args.dry_run and layer == "l2":
                print(f"  {layer}=skipped dry-run")
                continue
            if not text:
                print(f"  {layer}=rejected-empty no eligible turns")
                continue
            if layer == "l2":
                status, body = request(text)
                print(f"  {layer}=HTTP {status} {verdict(status, body)} body={json.dumps(safe_body(body), sort_keys=True)}")
            else:
                report = container_l3(text)
                print(f"  {layer}={l3_verdict(report)} details={json.dumps({k: report.get(k) for k in ('raw_type', 'raw_keys', 'memory_count', 'facts_count', 'embed_failures', 'events')}, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
