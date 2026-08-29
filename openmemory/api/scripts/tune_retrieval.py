#!/usr/bin/env python3
import argparse
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

PARAMS = Path(os.environ.get("OPENMEMORY_PARAMS_FILE", "api/data/retrieval-params.json"))
LOG = Path(os.environ.get("OPENMEMORY_TUNING_LOG", "api/data/tuning-log.jsonl"))


def passing_evidence(path):
    try:
        evidence = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    metrics = evidence.get("metrics") or {}
    thresholds = evidence.get("thresholds") or {}
    return (
        evidence.get("decision") == "PASSED"
        and evidence.get("quality_passes") is True
        and metrics.get("recall_at_5", 0) >= thresholds.get("recall_at_5", 1)
        and metrics.get("recall_at_10", 0) >= thresholds.get("recall_at_10", 1)
        and metrics.get("mrr", 0) >= thresholds.get("mrr", 1)
        and metrics.get("latency_ms", {}).get("p95", float("inf")) <= thresholds.get("p95_latency_ms", 0)
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=os.environ.get("OPENMEMORY_DB", "/var/lib/openmemory/openmemory.db"))
    parser.add_argument("--propose-only", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--eval-evidence")
    args = parser.parse_args()
    conn = sqlite3.connect(args.db)
    used = conn.execute("select count(*) from memory_access_logs where access_type='used'").fetchone()[0]
    conn.close()
    before = {"k": 1.0, "delta": 0.02}
    if PARAMS.is_file():
        try:
            before.update(json.loads(PARAMS.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
    after = {"k": min(3.0, max(0.5, float(before["k"]))), "delta": min(0.20, max(0.02, float(before["delta"]))) }
    result = {"usage_rows": used, "signal": "used" if used else "popularity fallback", "before": before, "after": after, "eval_before": None, "eval_after": None}
    print(json.dumps(result, indent=2))
    if args.propose_only or not args.apply:
        return 0
    if not args.eval_evidence or not passing_evidence(args.eval_evidence):
        raise SystemExit("refusing to apply retrieval parameters without passing evaluator evidence")
    PARAMS.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    PARAMS.write_text(json.dumps(after, indent=2) + "\n", encoding="utf-8")
    PARAMS.chmod(0o600)
    LOG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"ts": datetime.now(UTC).isoformat(), "param": "k,delta", **result}) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
