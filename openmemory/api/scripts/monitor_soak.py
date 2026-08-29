#!/usr/bin/env python3
import argparse
import json
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SEARCH_LOG = PROJECT_ROOT / "api/data/search-log.jsonl"
HOOK_LOG = Path.home() / ".claude/mem0-autosave/autosave.log"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def count_lines(path, contains=None):
    if not path.exists():
        return 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if contains is None or contains in line)


def runtime_stats():
    script = """
import json, sqlite3, urllib.request
db = sqlite3.connect('/var/lib/openmemory/openmemory.db')
daily = dict(db.execute("select date(created_at), count(*) from memories group by date(created_at) order by date(created_at)").fetchall())
request = urllib.request.Request('http://mem0_store:6333/collections/openmemory')
points = json.load(urllib.request.urlopen(request))['result']['points_count']
print(json.dumps({
    'db_total': db.execute('select count(*) from memories').fetchone()[0],
    'db_active': db.execute("select count(*) from memories where state = 'active'").fetchone()[0],
    'access_logs': db.execute('select count(*) from memory_access_logs').fetchone()[0],
    'daily_created': daily,
    'qdrant_points': points,
}))
"""
    output = subprocess.check_output(
        ["docker", "compose", "-f", str(PROJECT_ROOT / "docker-compose.yml"), "exec", "-T", "openmemory-mcp", "python", "-c", script],
        text=True,
    )
    return json.loads(output.strip().splitlines()[-1])


def health():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8765/healthz", timeout=10) as response:
            return json.loads(response.read())
    except Exception as error:
        return {"status": "unavailable", "error": type(error).__name__}


def search_stats(start_line):
    records = []
    if SEARCH_LOG.exists():
        with SEARCH_LOG.open(encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index < start_line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    zero_hits = sum(record.get("n_results") == 0 for record in records)
    return {
        "searches": len(records),
        "zero_hits": zero_hits,
        "zero_hit_rate": zero_hits / len(records) if records else None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--duration-days", type=float, default=7)
    parser.add_argument("--interval-seconds", type=int, default=300)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = args.output_dir / "metadata.json"
    snapshots_path = args.output_dir / "snapshots.jsonl"
    start_epoch = time.time()
    baseline = runtime_stats()
    baseline_search_lines = count_lines(SEARCH_LOG)
    baseline_timeout_lines = count_lines(HOOK_LOG, "push failed: timed out")
    metadata = {
        "start_utc": utc_now(),
        "duration_days": args.duration_days,
        "interval_seconds": args.interval_seconds,
        "project_root": str(PROJECT_ROOT),
        "search_log": str(SEARCH_LOG),
        "hook_log": str(HOOK_LOG),
        "baseline": baseline,
        "baseline_search_lines": baseline_search_lines,
        "baseline_timeout_lines": baseline_timeout_lines,
        "process_note": "tmux keeps this alive across terminal/session exit, but not across a macOS reboot",
    }
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    while True:
        try:
            runtime = runtime_stats()
        except Exception as error:
            runtime = {"runtime_error": type(error).__name__}
        snapshot = {
            "timestamp_utc": utc_now(),
            **runtime,
            **search_stats(baseline_search_lines),
            "new_timeout_lines": count_lines(HOOK_LOG, "push failed: timed out") - baseline_timeout_lines,
            "health": health(),
        }
        with snapshots_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(snapshot, sort_keys=True) + "\n")
        if args.once or time.time() - start_epoch >= args.duration_days * 86400:
            break
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    main()
