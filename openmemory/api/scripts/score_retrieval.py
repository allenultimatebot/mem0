#!/usr/bin/env python3
"""Offline-first retrieval scorer with vector baseline/candidate comparison."""

import argparse
import importlib.util
import json
import os
import math
import pathlib
import statistics
import time
import uuid
from contextlib import redirect_stderr, redirect_stdout


def memory_id(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError):
        return str(value)


def answerable(item):
    return item.get("category") != "negative" and bool(item.get("relevant_ids"))


def percentile(values, fraction):
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def load_run(path, queries):
    value = json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))
    if isinstance(value, dict) and isinstance(value.get("measurements"), list):
        output = {}
        for row in value["measurements"]:
            index = row.get("query_index")
            if isinstance(index, int) and 0 <= index < len(queries):
                output[queries[index]["query"]] = {"ids": row.get("ranked_ids", []),
                                                    "latency_ms": row.get("latency_ms", 0),
                                                    "leakage": row.get("leakage", False)}
        return output
    value = value.get("runs", value) if isinstance(value, dict) else value
    if isinstance(value, list):
        return {queries[index]["query"]: {"ids": row} for index, row in enumerate(value[:len(queries)])}
    if not isinstance(value, dict):
        raise ValueError("run must be a query map, list, or measurements object")
    return value


def metrics(manifest, run):
    recalls = {5: [], 10: [], 50: []}
    reciprocal = []
    negative_zero = []
    leakage = 0
    latencies = []
    categories = {}
    deleted_ids = {memory_id(value) for value in manifest.get("deleted_ids", [])}
    allowed_ids = {memory_id(value) for value in manifest.get("allowed_ids", [])}
    for item in manifest["queries"]:
        category = item.get("category", "unknown")
        category_metrics = categories.setdefault(category, {"queries": 0, "answerable": 0, "recall_at_5": [], "recall_at_10": [], "recall_at_50": [], "mrr": [], "negative_zero": []})
        category_metrics["queries"] += 1
        hit = run.get(item["query"], {}) if isinstance(run, dict) else {}
        ids = [memory_id(value) for value in hit.get("ids", [])] if isinstance(hit, dict) else []
        expected = {memory_id(value) for value in item.get("relevant_ids", [])} - deleted_ids
        if item.get("category") == "negative":
            negative_zero.append(not ids)
            category_metrics["negative_zero"].append(not ids)
        if answerable(item) and expected:
            category_metrics["answerable"] += 1
            for limit in recalls:
                recalls[limit].append(len(expected & set(ids[:limit])) / len(expected))
                category_metrics[f"recall_at_{limit}"].append(len(expected & set(ids[:limit])) / len(expected))
            reciprocal_rank = next((1 / (index + 1) for index, value in enumerate(ids) if value in expected), 0.0)
            reciprocal.append(reciprocal_rank)
            category_metrics["mrr"].append(reciprocal_rank)
        if isinstance(hit, dict):
            leakage += int(hit.get("leakage_count", 0) or 0)
            leakage += int(bool(hit.get("leakage")))
            if isinstance(hit.get("latency_ms"), (int, float)):
                latencies.append(float(hit["latency_ms"]))
        leakage += sum(1 for value in ids if value in deleted_ids)
        if allowed_ids:
            leakage += sum(1 for value in ids if value not in allowed_ids)
    breakdown = {}
    for category, values in categories.items():
        breakdown[category] = {
            "queries": values["queries"],
            "answerable_queries": values["answerable"],
            "recall_at_5": statistics.fmean(values["recall_at_5"]) if values["recall_at_5"] else None,
            "recall_at_10": statistics.fmean(values["recall_at_10"]) if values["recall_at_10"] else None,
            "recall_at_50": statistics.fmean(values["recall_at_50"]) if values["recall_at_50"] else None,
            "mrr": statistics.fmean(values["mrr"]) if values["mrr"] else None,
            "negatives_returning_zero": statistics.fmean(values["negative_zero"]) if values["negative_zero"] else None,
        }
    result = {"answerable_queries": len(reciprocal),
              "recall_at_5": statistics.fmean(recalls[5]) if recalls[5] else 0.0,
              "recall_at_10": statistics.fmean(recalls[10]) if recalls[10] else 0.0,
              "recall_at_50": statistics.fmean(recalls[50]) if recalls[50] else 0.0,
              "mrr": statistics.fmean(reciprocal) if reciprocal else 0.0,
              "negatives_returning_zero": statistics.fmean(negative_zero) if negative_zero else 0.0,
              "leakage": leakage, "leakage_count": leakage,
              "per_category": breakdown,
              "latency": {"p50_ms": percentile(latencies, .50), "p95_ms": percentile(latencies, .95),
                           "sample_count": len(latencies)}, "p95_latency_ms": percentile(latencies, .95)}
    return result


def self_check():
    manifest = {"queries": [{"query": "q", "category": "durable", "relevant_ids": ["a"]},
                             {"query": "n", "category": "negative", "relevant_ids": []}]}
    result = metrics(manifest, {"q": {"ids": ["a"]}, "n": {"ids": []}})
    assert result["recall_at_5"] == 1.0 and result["mrr"] == 1.0 and result["negatives_returning_zero"] == 1.0
    assert metrics({"queries": [{"query": "q", "category": "durable", "relevant_ids": ["a", "b"]}]},
                   {"q": {"ids": ["a"]}})["recall_at_5"] == 0.5
    return "score_retrieval selfcheck: ok"


def live_baseline(manifest, timeout):
    spec = importlib.util.spec_from_file_location("evaluate_retrieval", pathlib.Path(__file__).with_name("evaluate_retrieval.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    import sqlite3
    database = pathlib.Path(os.getenv("OPENMEMORY_EVAL_DATABASE", manifest.get("database", "/var/lib/openmemory/openmemory.db")))
    connection = sqlite3.connect("file:{}?mode=ro".format(database.resolve()), uri=True)
    config = json.loads(connection.execute("SELECT value FROM configs WHERE key='main'").fetchone()[0])
    embedder = ((config.get("mem0") or {}).get("embedder") or {})
    embed_config = embedder.get("config") or {}
    provider = embedder.get("provider", "ollama")
    endpoint = embed_config.get("ollama_base_url") or embed_config.get("openai_base_url")
    if endpoint and "host.docker.internal" in endpoint:
        endpoint = endpoint.replace("host.docker.internal", "127.0.0.1")
    model = embed_config.get("model") or "nomic-embed-text"
    user_id = manifest.get("user_id", "allen_bot")
    result = {}
    for item in manifest["queries"]:
        started = time.perf_counter()
        vector = module.embed_query(item["query"], provider, endpoint, model, timeout)
        points = module.qdrant_search(os.getenv("OPENMEMORY_EVAL_QDRANT_URL", manifest.get("qdrant_url", "http://127.0.0.1:6333")),
                                      manifest.get("collection", "openmemory"), user_id, vector, 50, timeout)
        result[item["query"]] = {"ids": [memory_id(point["id"]) for point in points],
                                  "latency_ms": (time.perf_counter() - started) * 1000}
    connection.close()
    return result


def live_search(manifest):
    import io
    import sys
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    from app import mcp_server

    if os.environ.get("OPENMEMORY_CUTOFF", "off").lower() not in {"on", "off"}:
        raise ValueError("OPENMEMORY_CUTOFF must be on or off")
    uid = str(manifest.get("user_id", "allen_bot"))
    client_name = str(manifest.get("app_id", "openmemory"))
    quiet = io.StringIO()
    with redirect_stdout(quiet), redirect_stderr(quiet):
        client = mcp_server.get_memory_client_safe()
    if client is None:
        raise RuntimeError("memory client unavailable")
    mcp_server.user_id_var.set(uid)
    mcp_server.client_name_var.set(client_name)
    result = {}
    for item in manifest["queries"]:
        started = time.perf_counter()
        quiet = io.StringIO()
        with redirect_stdout(quiet), redirect_stderr(quiet):
            candidates, dropped = mcp_server._search_memory_sync(item["query"], 50, [], uid, client_name, client)
        result[item["query"]] = {
            "ids": [candidate["id"] for candidate in candidates],
            "latency_ms": (time.perf_counter() - started) * 1000,
            "dropped": dropped,
        }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", default=str(pathlib.Path.home() / ".config/openmemory/retrieval-eval-dev.json"))
    parser.add_argument("--baseline", type=pathlib.Path)
    parser.add_argument("--candidate", type=pathlib.Path)
    parser.add_argument("--baseline-only", action="store_true")
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--live-search", "--hybrid-live", dest="live_search", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args(argv)
    if args.self_check:
        print(self_check())
        return
    manifest = json.loads(pathlib.Path(args.manifest).expanduser().read_text(encoding="utf-8"))
    queries = manifest.get("queries", [])
    if args.live_search:
        run = live_search(manifest)
        if args.output:
            args.output.expanduser().write_text(json.dumps({"runs": run}, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        print(json.dumps({"live_search": metrics(manifest, run)}, ensure_ascii=False, indent=2, sort_keys=True))
        return
    if args.baseline:
        baseline = load_run(args.baseline, queries)
    elif args.candidate:
        raise SystemExit("--candidate requires --baseline for offline comparison")
    else:
        baseline = live_baseline(manifest, float(manifest.get("timeout_seconds", 15)))
    output = {"baseline": metrics(manifest, baseline)}
    if args.candidate and not args.baseline_only:
        candidate = metrics(manifest, load_run(args.candidate, queries))
        output["candidate"] = candidate
        output["delta"] = {key: candidate[key] - output["baseline"][key]
                            for key in ("recall_at_5", "recall_at_10", "recall_at_50", "mrr", "negatives_returning_zero")}
    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
