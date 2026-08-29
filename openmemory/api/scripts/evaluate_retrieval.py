#!/usr/bin/env python3
"""Read-only retrieval evidence gate for the OpenMemory 2.0.4 baseline.

The production MCP search path is intentionally not imported: it creates missing
users/apps and records access-log rows. This module only reads SQLite and uses
Qdrant's HTTP read/search endpoints.
"""

import argparse
import hashlib
import hmac
import importlib.metadata
import json
import math
import os
import pathlib
import re
import socket
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid


PRODUCTION_MEM0 = "2.0.4"
REQUEST_TIMEOUT_SECONDS = 15
TOP_K = 10
DIAGNOSTIC_TOP_K = 50
MIN_QUERIES = 30
DEFAULT_MANIFEST = pathlib.Path.home() / ".config/openmemory/retrieval-eval.json"
DEFAULT_EVIDENCE = pathlib.Path.home() / ".local/share/openmemory-retrieval"
PRIVATE_IPV4 = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
TRUSTED_NETWORK_SOURCES = frozenset(("host", "host-attested", "host-produced"))
UNTRUSTED_NETWORK_SOURCES = frozenset(("candidate", "manifest", "self-attested", "untrusted"))


class GateError(RuntimeError):
    """A fail-closed environment or contract error."""


class CandidateFailure(RuntimeError):
    """A candidate-local compatibility or quality failure."""


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_json(value):
    return sha256_bytes(canonical_json(value))


def canonical_memory_id(value):
    text = str(value)
    try:
        return str(uuid.UUID(text))
    except (ValueError, AttributeError):
        return text


def private_dir(path):
    path = pathlib.Path(path).expanduser()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    if path.stat().st_mode & 0o077:
        raise GateError("private evidence directory is not mode 0700")
    return path


def require_private_file(path):
    path = pathlib.Path(path).expanduser()
    if not path.is_file() or path.is_symlink():
        raise GateError("private manifest is missing or symlinked")
    if path.stat().st_mode & 0o077:
        raise GateError("private manifest is not mode 0600")
    return path


def load_manifest(path):
    path = require_private_file(path)
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GateError("private manifest cannot be parsed") from exc
    if not isinstance(manifest, dict):
        raise GateError("private manifest must be an object")
    queries = manifest.get("queries")
    if not isinstance(queries, list) or len(queries) < MIN_QUERIES:
        raise GateError("private manifest needs at least 30 graded queries")
    category_aliases = {
        "durable-fact": "durable", "durable_facts": "durable", "acl-negative": "acl",
        "state-negative": "state", "multilingual-variant": "multilingual",
        "current-variant": "current", "stale-variant": "stale",
    }
    categories = {
        category_aliases.get(str(item.get("category", "")).lower(), str(item.get("category", "")).lower())
        for item in queries if isinstance(item, dict)
    }
    if not {"durable", "multilingual", "current", "stale", "acl", "state"}.issubset(categories):
        raise GateError("private manifest is missing required query categories")
    for item in queries:
        if not isinstance(item, dict) or not isinstance(item.get("query"), str) or not item["query"].strip():
            raise GateError("every graded query needs private query text")
        relevant = item.get("relevant_ids", [])
        if not isinstance(relevant, list) or any(not isinstance(value, (str, int)) for value in relevant):
            raise GateError("every graded query needs relevant_ids")
    thresholds = manifest.get("thresholds")
    threshold_keys = ("recall_at_5", "recall_at_10", "mrr", "p95_latency_ms")
    if not isinstance(thresholds, dict) or any(key not in thresholds for key in threshold_keys):
        raise GateError("private manifest needs explicit quality and latency thresholds")
    if any(not isinstance(thresholds[key], (int, float)) for key in threshold_keys):
        raise GateError("quality and latency thresholds must be numeric")
    if any(not math.isfinite(float(thresholds[key])) for key in threshold_keys):
        raise GateError("quality and latency thresholds must be finite")
    if any(not 0 <= float(thresholds[key]) <= 1 for key in ("recall_at_5", "recall_at_10", "mrr")):
        raise GateError("quality thresholds must be between zero and one")
    if thresholds["p95_latency_ms"] <= 0:
        raise GateError("p95 latency threshold must be positive")
    repetitions = manifest.get("repetitions", 3)
    if not isinstance(repetitions, int) or not 3 <= repetitions <= 10:
        raise GateError("manifest needs between three and ten repetitions")
    if manifest.get("timeout_seconds", REQUEST_TIMEOUT_SECONDS) != REQUEST_TIMEOUT_SECONDS:
        raise GateError("retrieval timeout must be exactly 15 seconds")
    return manifest, sha256_bytes(path.read_bytes()), path


def expected_label_hash(manifest):
    labels = [
        {"category": item.get("category"), "relevant_ids": sorted({str(value) for value in item.get("relevant_ids", [])})}
        for item in manifest["queries"]
    ]
    return sha256_json(labels)


def redacted_error(exc):
    name = type(exc).__name__
    message = str(exc).lower()
    if "timeout" in message:
        return {"type": name, "class": "timeout"}
    if "dimension" in message or "vector" in message:
        return {"type": name, "class": "vector-mismatch"}
    if "connection" in message or "urlopen" in message or "refused" in message:
        return {"type": name, "class": "provider-unavailable"}
    return {"type": name, "class": "provider-error"}


def redacted_gate_reason(exc):
    reason = str(exc).strip().lower()
    reason = re.sub(r"https?://\S+", "endpoint", reason)
    reason = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "identifier", reason)
    reason = re.sub(r"\b[0-9a-f]{32,}\b", "identifier", reason)
    reason = re.sub(r"[^a-z0-9_. -]+", "_", reason)
    return reason[:160] or "unspecified"


def open_readonly_sqlite(path):
    path = pathlib.Path(path).expanduser().resolve()
    connection = sqlite3.connect("file:{}?mode=ro".format(path), uri=True, timeout=5)
    connection.execute("PRAGMA query_only=ON")
    if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
        connection.close()
        raise GateError("SQLite query_only could not be enabled")
    return connection, path


def resolve_existing_user_app(connection, user_id, app_name):
    user = connection.execute("SELECT id FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if not user:
        raise GateError("manifest user_id does not resolve to an existing user")
    app = connection.execute(
        "SELECT id, owner_id, is_active FROM apps WHERE owner_id = ? AND name = ?", (user[0], app_name)
    ).fetchone()
    if not app:
        raise GateError("manifest app_id does not resolve to an existing app")
    if not app[2]:
        raise GateError("resolved app is inactive")
    return str(user[0]), str(app[0])


def accessible_memory_ids(connection, user_uuid, app_uuid):
    active = {
        canonical_memory_id(row[0])
        for row in connection.execute(
            "SELECT id FROM memories WHERE user_id = ? AND state = 'active'", (user_uuid,)
        )
    }
    rows = connection.execute(
        "SELECT object_id, effect FROM access_controls "
        "WHERE subject_type = 'app' AND subject_id = ? AND object_type = 'memory'",
        (app_uuid,),
    ).fetchall()
    if not rows:
        return active
    allowed = {str(row[0]) for row in rows if row[1] == "allow" and row[0] is not None}
    denied = {str(row[0]) for row in rows if row[1] == "deny" and row[0] is not None}
    if any(row[1] == "deny" and row[0] is None for row in rows):
        return set()
    if any(row[1] == "allow" and row[0] is None for row in rows):
        return active - denied
    return (active & allowed) - denied


def safe_config_tuple(connection, manifest):
    row = connection.execute("SELECT value FROM configs WHERE key = 'main'").fetchone()
    if not row:
        raise GateError("stored OpenMemory config is missing")
    try:
        raw_config = json.loads(row[0])
    except (TypeError, ValueError) as exc:
        raise GateError("stored OpenMemory config is not valid JSON") from exc
    config = stored_config(connection)
    embedder = ((config or {}).get("mem0") or {}).get("embedder") or {}
    embed_config = embedder.get("config") or {}
    provider = str(embedder.get("provider") or os.getenv("EMBEDDER_PROVIDER") or "openai").lower()
    model = str(embed_config.get("model") or os.getenv("EMBEDDER_MODEL") or "")
    endpoint = embed_config.get("ollama_base_url") or embed_config.get("openai_base_url") or os.getenv("EMBEDDER_BASE_URL")
    dimensions = manifest.get("embedder", {}).get("dimensions") or int(os.getenv("EMBEDDING_MODEL_DIMS", "768"))
    if not model or not endpoint:
        raise GateError("provider/embedder tuple is incomplete")
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise GateError("embedder endpoint is invalid")
    tuple_value = {
        "provider": provider,
        "model": model,
        "dimensions": int(dimensions),
        "endpoint_origin": "{}://{}".format(parsed.scheme, parsed.netloc),
        "config_sha256": sha256_json({"provider": provider, "model": model, "dimensions": int(dimensions), "endpoint": endpoint}),
    }
    expected = manifest.get("embedder", {}).get("expected")
    if expected:
        if not isinstance(expected, dict) or any(key not in tuple_value for key in expected):
            raise GateError("private embedder tuple is malformed")
        if any(tuple_value[key] != value for key, value in expected.items()):
            raise GateError("provider/embedder tuple drifted from private fixture")
    return tuple_value, endpoint, sha256_json(raw_config)


def stored_config(connection):
    row = connection.execute("SELECT value FROM configs WHERE key = 'main'").fetchone()
    if not row:
        raise GateError("stored OpenMemory config is missing")
    try:
        config = _resolve_env_values(json.loads(row[0]))
    except (TypeError, ValueError) as exc:
        raise GateError("stored OpenMemory config is not valid JSON") from exc
    if not isinstance(config, dict):
        raise GateError("stored OpenMemory config must be an object")
    return config


def http_json(url, payload=None, timeout=10):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise GateError("unexpected non-http endpoint")
    data = None if payload is None else canonical_json(payload)
    request = urllib.request.Request(url, data=data, method="GET" if data is None else "POST")
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def embed_query(query, provider, endpoint, model, timeout):
    if provider == "ollama":
        url = endpoint.rstrip("/") + "/api/embed"
        response = http_json(url, {"model": model, "input": query}, timeout)
        vector = response.get("embedding") or (response.get("embeddings") or [None])[0]
    else:
        url = endpoint.rstrip("/") + "/v1/embeddings"
        headers_key = os.getenv("EMBEDDER_API_KEY") or os.getenv("OPENAI_API_KEY")
        data = {"input": query, "model": model}
        request = urllib.request.Request(url, data=canonical_json(data), method="POST")
        request.add_header("Accept", "application/json")
        request.add_header("Content-Type", "application/json")
        if headers_key:
            request.add_header("Authorization", "Bearer " + headers_key)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            vector = json.loads(response.read().decode("utf-8")).get("data", [{}])[0].get("embedding")
    if not isinstance(vector, list) or not vector:
        raise GateError("embedder returned no vector")
    if any(not isinstance(value, (int, float)) or not math.isfinite(value) for value in vector):
        raise GateError("embedder returned an invalid vector")
    return vector


def runtime_embedder_endpoint(endpoint, host_runtime=None):
    if host_runtime is None:
        host_runtime = os.getenv("OPENMEMORY_EVAL_HOST_RUNTIME") == "1"
    parsed = urllib.parse.urlparse(endpoint)
    if not host_runtime or parsed.hostname != "host.docker.internal":
        return endpoint
    return parsed._replace(netloc="127.0.0.1:{}".format(parsed.port or 80)).geturl()


def qdrant_search(base_url, collection, user_id, vector, top_k, timeout):
    path = "/collections/{}/points/search".format(urllib.parse.quote(collection, safe=""))
    url = base_url.rstrip("/") + path
    request = urllib.request.Request(url, data=canonical_json({
        "vector": vector,
        "limit": int(top_k),
        "with_payload": True,
        "with_vector": False,
        "filter": {"must": [{"key": "user_id", "match": {"value": user_id}}]},
    }), method="POST")
    request.add_header("Accept", "application/json")
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response_handle:
        if response_handle.status != 200:
            raise GateError("Qdrant search returned an unexpected status")
        response = json.loads(response_handle.read().decode("utf-8"))
    if not isinstance(response, dict) or response.get("status") != "ok":
        raise GateError("Qdrant search did not report success")
    points = response.get("result")
    if not isinstance(points, list):
        raise GateError("Qdrant search response is invalid")
    return points


def normalize_hits(points, allowed_ids, user_id):
    seen = set()
    output = []
    leakage = False
    for point in points:
        if not isinstance(point, dict) or point.get("id") is None:
            raise GateError("Qdrant point is malformed")
        memory_id = canonical_memory_id(point["id"])
        if memory_id in seen:
            continue
        seen.add(memory_id)
        payload = point.get("payload")
        if not isinstance(payload, dict) or str(payload.get("user_id")) != str(user_id):
            raise GateError("Qdrant point payload identity is missing or mismatched")
        state = payload.get("state")
        if state is not None and state != "active":
            raise GateError("Qdrant point state is missing or inactive")
        score = point.get("score")
        if not isinstance(score, (int, float)) or not math.isfinite(float(score)):
            raise GateError("Qdrant point score is invalid")
        allowed = memory_id in allowed_ids
        leakage = leakage or not allowed
        output.append({"id": memory_id, "score": float(score),
                       "allowed": allowed, "state": "active" if state is None and allowed else state})
    output.sort(key=lambda item: (-item["score"], item["id"]))
    return output, leakage


def invoke_backend(backend, query, top_k, timeout):
    previous_handler = signal.signal(signal.SIGALRM, lambda _signum, _frame: (_ for _ in ()).throw(TimeoutError("backend deadline exceeded")))
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return backend(query, top_k, timeout)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def invoke_backend_with_retry(backend, query, top_k, timeout):
    for attempt in range(2):
        try:
            return invoke_backend(backend, query, top_k, timeout)
        except Exception as exc:
            retryable = type(exc).__name__ in {"ConnectTimeout", "ReadTimeout", "RemoteProtocolError"}
            if attempt == 0 and retryable:
                continue
            raise


def run_backend(backend, cases, allowed_ids, user_id, repetitions=3, warmups=1, timeout=15):
    measurements = []
    errors = []
    leakage = False
    for index, case in enumerate(cases):
        query_hash = sha256_bytes(case["query"].encode())
        for _ in range(warmups):
            try:
                invoke_backend_with_retry(backend, case["query"], TOP_K, timeout)
            except Exception:
                pass
        for repetition in range(repetitions):
            started = time.perf_counter()
            try:
                embedding, points = invoke_backend_with_retry(backend, case["query"], TOP_K, timeout)
                elapsed_ms = (time.perf_counter() - started) * 1000
                if len(embedding) != case.get("dimensions", len(embedding)):
                    raise GateError("embedding dimension mismatch")
                hits, leaked = normalize_hits(points, allowed_ids, user_id)
                leakage = leakage or leaked
                measurements.append({
                    "query_index": index,
                    "query_sha256": query_hash,
                    "repetition": repetition,
                    "embedding_sha256": sha256_json(embedding),
                    "latency_ms": round(elapsed_ms, 3),
                    "prefilter_count": len(hits),
                    "postfilter_count": sum(1 for hit in hits if hit["allowed"]),
                    "prefilter_ids_sha256": sha256_json([hit["id"] for hit in hits]),
                    "prefilter_scores_sha256": sha256_json([{"id": hit["id"], "score": hit["score"]} for hit in hits]),
                    "prefilter_scores_quantized_sha256": sha256_json([{"id": hit["id"], "score": round(hit["score"], 3)} for hit in hits]),
                    "postfilter_ids_sha256": sha256_json([hit["id"] for hit in hits if hit["allowed"]]),
                    "ranked_ids": [hit["id"] for hit in hits if hit["allowed"]],
                    "leakage": leaked,
                })
            except TimeoutError:
                errors.append({"query_index": index, "query_sha256": query_hash, "repetition": repetition, "class": "timeout"})
            except Exception as exc:
                errors.append({"query_index": index, "query_sha256": query_hash, "repetition": repetition, **redacted_error(exc)})
    return {"measurements": measurements, "errors": errors, "leakage": leakage}


def percentile(values, percentile_value):
    if not values:
        return None
    values = sorted(values)
    return values[max(0, math.ceil(percentile_value * len(values)) - 1)]


def metrics(run, cases, repetitions):
    recalls = {5: [], 10: []}
    reciprocal_ranks = []
    critical_failures = []
    for measurement in run["measurements"]:
        relevant = {str(value) for value in cases[measurement["query_index"]].get("relevant_ids", [])}
        ranked = measurement["ranked_ids"]
        denominator = len(relevant)
        for k in recalls:
            recalls[k].append(len(relevant & set(ranked[:k])) / denominator if denominator else 1.0)
        if relevant:
            reciprocal_ranks.append(next((1.0 / (position + 1) for position, value in enumerate(ranked) if value in relevant), 0.0))
        if cases[measurement["query_index"]].get("critical") and (not denominator or len(relevant & set(ranked[:5])) != denominator):
            critical_failures.append(measurement["query_index"])
    latencies = [item["latency_ms"] for item in run["measurements"]]
    return {
        "recall_at_5": sum(recalls[5]) / len(recalls[5]) if recalls[5] else None,
        "recall_at_10": sum(recalls[10]) / len(recalls[10]) if recalls[10] else None,
        "mrr": sum(reciprocal_ranks) / len(reciprocal_ranks) if reciprocal_ranks else None,
        "latency_ms": {"p50": percentile(latencies, 0.50), "p95": percentile(latencies, 0.95), "sample_count": len(latencies)},
        "errors": len(run["errors"]),
        "timeouts": sum(item.get("class") == "timeout" for item in run["errors"]),
        "critical_recall_at_5_failures": sorted(set(critical_failures)),
        "complete": len(run["measurements"]) == len(cases) * repetitions,
    }


def quality_passes(metrics_value, thresholds):
    latency = metrics_value["latency_ms"]["p95"]
    return bool(
        metrics_value["recall_at_5"] is not None
        and metrics_value["recall_at_10"] is not None
        and metrics_value["mrr"] is not None
        and latency is not None
        and metrics_value["recall_at_5"] >= thresholds["recall_at_5"]
        and metrics_value["recall_at_10"] >= thresholds["recall_at_10"]
        and metrics_value["mrr"] >= thresholds["mrr"]
        and latency <= thresholds["p95_latency_ms"]
    )


def paired_runs(direct_backend, candidate_backend, cases, allowed_ids, user_id, repetitions=3, warmups=1):
    """Run identical cases in alternating order; candidate is never production-bound."""
    results = {
        "direct": {"measurements": [], "errors": [], "leakage": False},
        "candidate": {"measurements": [], "errors": [], "leakage": False},
    }
    for repetition in range(repetitions):
        order = (("direct", direct_backend), ("candidate", candidate_backend)) if repetition % 2 == 0 else (("candidate", candidate_backend), ("direct", direct_backend))
        for name, backend in order:
            run = run_backend(
                backend, cases, allowed_ids, user_id, repetitions=1,
                warmups=warmups if repetition == 0 else 0,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            for item in run["measurements"] + run["errors"]:
                item["repetition"] = repetition
            results[name]["measurements"].extend(run["measurements"])
            results[name]["errors"].extend(run["errors"])
            results[name]["leakage"] = results[name]["leakage"] or run["leakage"]
    return results


def file_fingerprint(path):
    path = pathlib.Path(path)
    if not path.exists():
        return {"exists": False}
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    stat = path.stat()
    return {"exists": True, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "sha256": digest.hexdigest()}


def sqlite_fingerprint(path):
    return {suffix or "db": file_fingerprint(str(path) + suffix) for suffix in ("", "-wal", "-shm")}


def sqlite_content_fingerprint(connection):
    tables = {}
    table_names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
    for table in table_names:
        try:
            rows = connection.execute('SELECT * FROM "' + table.replace('"', '""') + '" ORDER BY rowid').fetchall()
            tables[table] = {"count": len(rows), "sha256": sha256_json(rows)}
        except sqlite3.Error as exc:
            tables[table] = {"error": type(exc).__name__}
    return tables


def docker_fingerprint():
    docker = shutil.which("docker")
    if not docker:
        return {"available": False}
    try:
        ids = subprocess.check_output([docker, "ps", "-q"], stderr=subprocess.DEVNULL, timeout=5).decode().splitlines()
    except (OSError, subprocess.SubprocessError):
        return {"available": False}
    services = {}
    for container_id in ids:
        try:
            name = subprocess.check_output([docker, "inspect", "--format", "{{.Name}}" , container_id],
                                           stderr=subprocess.DEVNULL, timeout=5).decode().strip().lstrip("/")
            ports = json.loads(subprocess.check_output(
                [docker, "inspect", "--format", "{{json .NetworkSettings.Ports}}", container_id],
                stderr=subprocess.DEVNULL, timeout=5,
            ).decode())
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
        service_name = next((service for service in ("mem0_store", "openmemory-mcp", "openmemory-ui")
                             if name == service or name.startswith(service + "-") or ("_" + service + "-") in name), None)
        if service_name:
            try:
                mounts = subprocess.check_output([docker, "inspect", "--format", "{{json .Mounts}}", container_id], timeout=5).decode()
                services[service_name] = {"id": container_id, "ports": ports if isinstance(ports, dict) else {}, "mounts": json.loads(mounts)}
            except (OSError, ValueError, subprocess.SubprocessError):
                continue
    try:
        volumes = subprocess.check_output([docker, "volume", "ls", "--format", "{{.Name}}|{{.Driver}}"], timeout=5).decode().splitlines()
        networks = subprocess.check_output([docker, "network", "ls", "--format", "{{.ID}}|{{.Name}}|{{.Driver}}"], timeout=5).decode().splitlines()
    except (OSError, subprocess.SubprocessError):
        return {"available": False}
    return {"available": True, "sha256": sha256_json({"services": services, "volumes": volumes, "networks": networks}),
            "service_count": len(services), "bindings": {key: value["ports"] for key, value in services.items()},
            "resources": services, "volumes": volumes, "networks": networks}


def process_fingerprint():
    try:
        output = subprocess.check_output(["ps", "-axo", "comm="], stderr=subprocess.DEVNULL, timeout=5)
        names = sorted(line.strip() for line in output.decode(errors="replace").splitlines() if line.strip())
        runtime_names = [name for name in names if any(token in name.lower() for token in ("docker", "colima", "limactl", "qemu", "tailscale"))]
        return {"sha256": sha256_json(runtime_names), "count": len(runtime_names)}
    except (OSError, subprocess.SubprocessError):
        return {"available": False}


def qdrant_fingerprint(url, collection, timeout=5):
    try:
        response = http_json(url.rstrip("/") + "/collections/" + urllib.parse.quote(collection, safe=""), timeout=timeout)
        result = response.get("result") if isinstance(response, dict) else {}
        stable = {key: result.get(key) for key in ("status", "optimizer_status", "points_count", "indexed_vectors_count",
                                                    "segments_count", "config", "payload_schema")}
        point_ids = []
        offset = None
        for page_number in range(1000):
            payload = {"limit": 256, "with_payload": True, "with_vector": True}
            if offset is not None:
                payload["offset"] = offset
            page = http_json(url.rstrip("/") + "/collections/" + urllib.parse.quote(collection, safe="") + "/points/scroll",
                             payload, timeout=timeout)
            page_result = page.get("result") if isinstance(page, dict) else {}
            points = [item for item in (page_result.get("points") or []) if item.get("id") is not None]
            point_ids.extend(points)
            offset = page_result.get("next_page_offset")
            if offset is None:
                break
        else:
            raise GateError("Qdrant fingerprint pagination truncated")
        point_ids.sort(key=lambda item: str(item["id"]))
        stable["points_sha256"] = sha256_json(point_ids)
        return {"available": True, "sha256": sha256_json(stable), "status": result.get("status"),
                "points_count": result.get("points_count"), "indexed_vectors_count": result.get("indexed_vectors_count"),
                "point_ids_count": len(point_ids)}
    except Exception as exc:
        return {"available": False, "error": redacted_error(exc)}


def _addresses():
    try:
        output = subprocess.check_output(["ifconfig"], stderr=subprocess.DEVNULL, timeout=5).decode(errors="replace")
    except (OSError, subprocess.SubprocessError):
        return []
    return re.findall(r"\binet6?\s+([0-9a-fA-F:.%]+)", output)


def _probe_service(address, port, timeout):
    address = address.split("%", 1)[0]
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((address, port))
        return "reachable"
    except OSError:
        return "unreachable"
    finally:
        sock.close()


def network_evidence(qdrant_url, timeout=5, network_manifest=None):
    network_manifest = network_manifest or {}
    manifest_source = network_manifest.get("source")
    trusted_manifest = bool(
        manifest_source in TRUSTED_NETWORK_SOURCES
        and re.fullmatch(r"[0-9a-f]{64}", str(network_manifest.get("host_evidence_sha256", "")))
        and re.fullmatch(r"[0-9a-f]{64}", str(network_manifest.get("host_identity_sha256", "")))
    )
    tailscale = shutil.which("tailscale") or next(
        (path for path in ("/Applications/Tailscale.app/Contents/MacOS/tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale") if os.access(path, os.X_OK)),
        None,
    )
    evidence = {
        "source": manifest_source if trusted_manifest else "untrusted",
        "tailscale_executable": bool(tailscale),
        "docker": docker_fingerprint(),
        "probes": {},
    }
    tailscale_ips = []
    if tailscale:
        for version in ("-4", "-6"):
            try:
                value = subprocess.check_output([tailscale, "ip", version], stderr=subprocess.DEVNULL, timeout=timeout).decode().strip()
            except (OSError, subprocess.SubprocessError):
                value = ""
            if value and "/" not in value:
                tailscale_ips.append(value)
    addresses = _addresses()
    tailnet_set = set(tailscale_ips)
    probe_addresses = {
        "localhost": "127.0.0.1",
        "ipv6": next((value for value in addresses if ":" in value and value != "::1" and value not in tailnet_set), ""),
        "tailnet": tailscale_ips[0] if tailscale_ips else "",
        "lan": next((value for value in addresses if "." in value and PRIVATE_IPV4.match(value)), ""),
    }
    ports = {"api": 8765, "qdrant": 6333, "ui": 3000}
    evidence["probe_evidence"] = {}
    for label, address in probe_addresses.items():
        results = {
            service: (_probe_service(address, port, timeout) if address else "unreachable")
            for service, port in ports.items()
        }
        evidence["probes"][label] = {
            **results,
        }
        evidence["probe_evidence"][label] = {"address": address or None, "method": "tcp-connect", "results": results}
    evidence["tailscale_ip4"] = any("." in value for value in tailscale_ips)
    evidence["tailscale_ip6"] = any(":" in value for value in tailscale_ips)
    try:
        docker_bindings = evidence["docker"].get("bindings", {})
        qdrant_binding = docker_bindings.get("mem0_store", {}).get("6333/tcp") or []
        ui_binding = docker_bindings.get("openmemory-ui", {}).get("3000/tcp") or []
        if isinstance(qdrant_binding, dict):
            qdrant_binding = [qdrant_binding]
        if isinstance(ui_binding, dict):
            ui_binding = [ui_binding]
        evidence["loopback_bindings"] = {
            "qdrant": any(item.get("HostIp") in {"127.0.0.1", "::1"} for item in qdrant_binding),
            "ui": any(item.get("HostIp") in {"127.0.0.1", "::1"} for item in ui_binding),
        }
    except AttributeError:
        evidence["loopback_bindings"] = {"qdrant": False, "ui": False}
    evidence["qdrant_url_fingerprint"] = sha256_bytes(qdrant_url.encode())
    listener = network_manifest.get("remote_listener")
    if trusted_manifest and network_manifest.get("remote_probe") == "verified" and isinstance(listener, dict) and re.fullmatch(r"[0-9a-f]{64}", str(listener.get("evidence_sha256", ""))):
        evidence["remote_probe"] = "verified"
        evidence["remote_listener"] = {"evidence_sha256": listener["evidence_sha256"], "method": listener.get("method"), "port": listener.get("port")}
    elif manifest_source in UNTRUSTED_NETWORK_SOURCES or network_manifest:
        evidence["remote_probe"] = "untrusted"
    else:
        evidence["remote_probe"] = "not-collected"
    localhost_ok = all(value == "reachable" for value in evidence["probes"].get("localhost", {}).values())
    tailnet_ok = bool(probe_addresses["tailnet"] and evidence["probes"]["tailnet"].get("api") == "reachable" and
                      all(evidence["probes"]["tailnet"].get(service) == "unreachable" for service in ("qdrant", "ui")))
    non_tailnet_ok = all(
        bool(probe_addresses[label]) and all(value == "unreachable" for value in evidence["probes"][label].values())
        for label in ("lan", "ipv6")
    )
    evidence["complete"] = bool(evidence["tailscale_executable"] and tailscale_ips and evidence["remote_probe"] == "verified" and localhost_ok and tailnet_ok and non_tailnet_ok and
                                  evidence["loopback_bindings"]["qdrant"] and evidence["loopback_bindings"]["ui"])
    return evidence


def load_host_network_evidence(path, require_attestation=True):
    try:
        document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GateError("host network evidence cannot be parsed") from exc
    source = document.get("source")
    if source in UNTRUSTED_NETWORK_SOURCES:
        document["complete"] = False
        document["remote_probe"] = "untrusted"
        return document
    expected_run_id = os.getenv("OPENMEMORY_CANDIDATE_RUN_ID")
    if source not in TRUSTED_NETWORK_SOURCES:
        raise GateError("host network evidence source is untrusted")
    if expected_run_id and document.get("run_id") != expected_run_id:
        raise GateError("host network evidence run binding is invalid: expected {} got {}".format(expected_run_id, document.get("run_id", "missing")))
    if require_attestation and not re.fullmatch(r"[0-9a-f]{64}", str(document.get("host_evidence_sha256", ""))):
        raise GateError("host network evidence attestation is missing")
    if not re.fullmatch(r"[0-9a-f]{64}", str(document.get("host_identity_sha256", ""))):
        raise GateError("host network evidence host identity is invalid")
    if "decision" in document:
        raise GateError("network evidence cannot carry a decision claim")
    if document.get("complete") is not True or document.get("remote_probe") != "verified":
        raise GateError("sealed host network evidence is incomplete")
    listener = document.get("remote_listener")
    if not isinstance(listener, dict) or listener.get("source") != "host-probe" or listener.get("method") != "tcp-listen" or listener.get("reachable") is not True or not isinstance(listener.get("port"), int) or not 1 <= listener["port"] <= 65535:
        raise GateError("sealed remote-listener evidence is incomplete")
    for label in ("lan", "ipv6"):
        probe = document.get("probe_evidence", {}).get(label, {})
        if not probe.get("address") or any(value != "unreachable" for value in probe.get("results", {}).values()):
            raise GateError("sealed host network evidence is not independently complete")
    tailnet_probe = document.get("probe_evidence", {}).get("tailnet", {})
    if not tailnet_probe.get("address") or tailnet_probe.get("results", {}).get("api") != "reachable" or any(
        tailnet_probe.get("results", {}).get(service) != "unreachable" for service in ("qdrant", "ui")
    ):
        raise GateError("sealed tailnet network evidence is not independently complete")
    return document


def compare_fingerprints(before, after):
    return before == after


def installed_mem0_version():
    try:
        return importlib.metadata.version("mem0ai")
    except importlib.metadata.PackageNotFoundError as exc:
        raise GateError("mem0ai package is not installed") from exc


def expected_mem0_version(value=None):
    version = value or os.getenv("OPENMEMORY_EXPECTED_MEM0_VERSION") or PRODUCTION_MEM0
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-.][0-9A-Za-z.-]+)?", version):
        raise GateError("expected mem0ai version is invalid")
    return version


def _resolve_env_values(value):
    if isinstance(value, dict):
        return {key: _resolve_env_values(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_env_values(item) for item in value]
    if isinstance(value, str) and value.startswith("env:"):
        return os.environ.get(value[4:], value)
    return value


def sdk_config(connection, qdrant_url, collection, tuple_value, vector_client):
    config = stored_config(connection)
    if not isinstance(config, dict) or not isinstance(config.get("mem0"), dict):
        raise GateError("stored Mem0 config is missing")
    custom_instructions = (config.get("openmemory") or {}).get("custom_instructions")
    if not isinstance(custom_instructions, str) or not custom_instructions.strip():
        raise GateError("stored OpenMemory custom_instructions is missing")
    config = json.loads(json.dumps(config["mem0"]))
    parsed = urllib.parse.urlparse(qdrant_url)
    vector_store = config.get("vector_store")
    if not isinstance(vector_store, dict):
        vector_store = {"provider": "qdrant", "config": {}}
        config["vector_store"] = vector_store
    vector_store["provider"] = "qdrant"
    vector_store["config"] = {
        **vector_store.get("config", {}),
        "client": vector_client,
        "collection_name": collection,
        "host": parsed.hostname or "candidate-store",
        "port": parsed.port or 6333,
        "embedding_model_dims": tuple_value["dimensions"],
    }
    embedder = config.get("embedder")
    if not isinstance(embedder, dict):
        embedder = {"provider": tuple_value["provider"], "config": {}}
        config["embedder"] = embedder
    embedder["provider"] = tuple_value["provider"]
    embedder_config = {
        **embedder.get("config", {}),
        "model": tuple_value["model"],
    }
    if tuple_value["provider"] == "ollama":
        embedder_config["ollama_base_url"] = os.getenv("EMBEDDER_BASE_URL", tuple_value["endpoint_origin"])
    elif tuple_value["provider"] == "openai":
        embedder_config["openai_base_url"] = os.getenv("EMBEDDER_BASE_URL", tuple_value["endpoint_origin"])
    embedder["config"] = embedder_config
    config["custom_instructions"] = custom_instructions
    return config


def custom_instructions_hash(connection):
    config = stored_config(connection)
    value = (config.get("openmemory") or {}).get("custom_instructions") if isinstance(config, dict) else None
    if not isinstance(value, str) or not value.strip():
        raise GateError("stored OpenMemory custom_instructions is missing")
    return sha256_bytes(value.encode("utf-8"))


def _config_value(config, *keys):
    current = config
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            current = getattr(current, key, None)
        if current is None:
            return None
    return current


def _timeout_is_exact(value):
    if isinstance(value, (int, float)):
        return float(value) == REQUEST_TIMEOUT_SECONDS
    components = [getattr(value, name, None) for name in ("connect", "read", "write", "pool")]
    return bool(components) and all(component == REQUEST_TIMEOUT_SECONDS for component in components)


def _client_timeout(client):
    for candidate in (client, getattr(client, "_client", None)):
        timeout = getattr(candidate, "timeout", None)
        if timeout is not None:
            return timeout
    return None


def configure_embedding_timeout(embedding_model):
    client = getattr(embedding_model, "client", None)
    if client is None:
        raise CandidateFailure("candidate embedder client is unavailable")
    if callable(getattr(client, "with_options", None)):
        client = client.with_options(timeout=REQUEST_TIMEOUT_SECONDS)
        embedding_model.client = client
    else:
        http_client = getattr(client, "_client", None)
        if http_client is None or not hasattr(http_client, "timeout"):
            raise CandidateFailure("candidate embedder timeout cannot be configured")
        current_timeout = http_client.timeout
        try:
            http_client.timeout = type(current_timeout)(REQUEST_TIMEOUT_SECONDS)
        except (TypeError, ValueError):
            http_client.timeout = REQUEST_TIMEOUT_SECONDS
    if not _timeout_is_exact(_client_timeout(embedding_model.client)):
        raise CandidateFailure("candidate effective embedder timeout is not exactly 15 seconds")


def make_qdrant_client(client_class, qdrant_url):
    return client_class(url=qdrant_url, timeout=REQUEST_TIMEOUT_SECONDS)


def verify_effective_candidate_config(memory, expected_custom_instructions, vector_client):
    effective_custom_instructions = _config_value(getattr(memory, "config", None), "custom_instructions")
    if effective_custom_instructions is None:
        effective_custom_instructions = getattr(memory, "custom_instructions", None)
    if effective_custom_instructions != expected_custom_instructions:
        raise CandidateFailure("candidate custom_instructions drifted from production")
    if getattr(getattr(memory, "vector_store", None), "client", None) is not vector_client:
        raise CandidateFailure("candidate vector-store client is not the timeout-configured client")


def self_check():
    assert REQUEST_TIMEOUT_SECONDS == 15
    assert expected_mem0_version("2.0.19") == "2.0.19"
    try:
        expected_mem0_version("not-a-version")
    except GateError:
        pass
    else:
        raise AssertionError("invalid expected mem0ai version was accepted")
    calls = {}
    fake_client = type("FakeClient", (), {"__init__": lambda self, **kwargs: calls.update(kwargs)})
    make_qdrant_client(fake_client, "http://candidate-store:6333")
    assert calls == {"url": "http://candidate-store:6333", "timeout": 15}
    assert _config_value({"custom_instructions": "exact"}, "custom_instructions") == "exact"
    hits, leakage = normalize_hits([{"id": "unauthorized", "score": 1.0, "payload": {"user_id": "user", "state": "active"}}], {"allowed"}, "user")
    assert leakage is True and hits[0]["allowed"] is False
    for malformed in (
        [{"id": "allowed", "score": 1.0}],
        [{"id": "allowed", "score": float("nan"), "payload": {"user_id": "user", "state": "active"}}],
        [{"id": "allowed", "score": 1.0, "payload": {"user_id": "other", "state": "active"}}],
    ):
        try:
            normalize_hits(malformed, {"allowed"}, "user")
        except GateError:
            pass
        else:
            raise AssertionError("malformed Qdrant point was accepted")


def candidate_backend_factory(connection, qdrant_url, collection, user_id, tuple_value):
    try:
        from mem0 import Memory
        from qdrant_client import QdrantClient
    except ImportError as exc:
        raise GateError("candidate Mem0 SDK is unavailable") from exc
    vector_client = make_qdrant_client(QdrantClient, qdrant_url)
    config = sdk_config(connection, qdrant_url, collection, tuple_value, vector_client)
    expected_custom_instructions = _config_value(stored_config(connection), "openmemory", "custom_instructions")
    if not isinstance(expected_custom_instructions, str) or not expected_custom_instructions.strip():
        raise GateError("stored OpenMemory custom_instructions is missing")
    memory = Memory.from_config(config_dict=config)
    configure_embedding_timeout(memory.embedding_model)
    verify_effective_candidate_config(memory, expected_custom_instructions, vector_client)

    captured_embedding = {}
    original_embed = memory.embedding_model.embed

    def capture_embed(text, *args, **kwargs):
        embedding = original_embed(text, *args, **kwargs)
        captured_embedding["value"] = embedding
        return embedding

    memory.embedding_model.embed = capture_embed

    def candidate_backend(query, top_k, request_timeout):
        if request_timeout != REQUEST_TIMEOUT_SECONDS:
            raise CandidateFailure("candidate request timeout is not exactly 15 seconds")
        captured_embedding.clear()
        results = memory.search(query=query, filters={"user_id": user_id}, top_k=top_k)
        embedding = captured_embedding.get("value")
        if embedding is None:
            raise GateError("candidate search did not expose its query embedding")
        if isinstance(results, dict):
            results = results.get("results", [])
        points = []
        for result in results or []:
            if not isinstance(result, dict) or result.get("id") is None:
                continue
            metadata = result.get("metadata") or {}
            points.append({"id": result["id"], "score": result.get("score", 0.0),
                           "payload": {"user_id": result.get("user_id", metadata.get("user_id")),
                                       "state": result.get("state", metadata.get("state"))}})
        return embedding, points

    return candidate_backend


def baseline_seal(output, evidence):
    service = "com.ultimatesup.openmemory.backup.manifest-v1"
    account = "openmemory-backup-manifest-v1"
    keychain = os.getenv("OPENMEMORY_MANIFEST_KEYCHAIN", str(pathlib.Path.home() / "Library/Keychains/login.keychain-db"))
    try:
        secret = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-w", keychain],
            check=True, capture_output=True, text=True, timeout=10,
        ).stdout.encode().strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError("direct baseline Keychain seal is unavailable") from exc
    digest = sha256_bytes(output.read_bytes())
    payload = {"backend": evidence["backend"], "decision": evidence["decision"],
               "expected_label_sha256": evidence["expected_label_sha256"], "fixture_sha256": evidence["fixture_sha256"],
               "mem0ai": evidence["mem0ai"], "evidence_sha256": digest}
    canonical = canonical_json(payload)
    auth = {**payload, "key_id": "v1", "service": service, "account": account,
            "mac": hmac.new(secret, canonical, hashlib.sha256).hexdigest()}
    output.with_name(output.name + ".sha256").write_text(digest + "\n", encoding="utf-8")
    output.with_name(output.name + ".auth.json").write_bytes(canonical_json(auth) + b"\n")
    output.with_name(output.name + ".sha256").chmod(0o600)
    output.with_name(output.name + ".auth.json").chmod(0o600)


def execute(manifest_path, evidence_root, backend_name="direct"):
    evidence_root = private_dir(evidence_root)
    run_dir = private_dir(evidence_root / (time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + str(os.getpid())))
    manifest = None
    database = None
    qdrant_url = ""
    collection = ""
    repetitions = 3
    timeout = 15
    evidence = {
        "schema": 1, "mem0ai": None, "backend": backend_name,
        "fixture_sha256": None, "expected_label_sha256": None, "query_count": 0,
        "custom_instructions_sha256": None,
        "top_k": TOP_K, "diagnostic_top_k": DIAGNOSTIC_TOP_K, "thresholds": None,
        "runner_contract": {
            "backends": ["direct", "candidate"], "paired_order": "direct,candidate then candidate,direct per repetition",
            "normalization": "stable score-desc then memory-id-asc; duplicate IDs collapsed; finite scores; user-bound active payloads",
            "postfilter": "active memory IDs plus current app ACL",
            "metrics": "recall@k=mean relevant-item recall; MRR=mean reciprocal rank; p50/p95=nearest-rank",
            "warmups": "excluded", "production_backend": "direct-only", "candidate_backend": "Mem0 SDK Memory.search",
        },
        "paired_metrics": {"direct": None, "candidate": None},
    }
    connection = None
    try:
        manifest, fixture_hash, manifest_path = load_manifest(manifest_path)
        expected_version = expected_mem0_version()
        installed_version = installed_mem0_version()
        if installed_version != expected_version:
            raise GateError("installed mem0ai version does not match the selected backend")
        evidence.update({"fixture_sha256": fixture_hash, "expected_label_sha256": expected_label_hash(manifest),
                         "query_count": len(manifest["queries"]), "thresholds": manifest["thresholds"],
                         "mem0ai": "mem0ai==" + installed_version})
        database = pathlib.Path(os.getenv("OPENMEMORY_EVAL_DATABASE", manifest.get("database", "/var/lib/openmemory/openmemory.db")))
        qdrant_url = str(os.getenv("OPENMEMORY_EVAL_QDRANT_URL", manifest.get("qdrant_url", "http://127.0.0.1:6333")))
        collection = str(manifest.get("collection", "openmemory"))
        user_id = str(manifest.get("user_id", ""))
        app_id = str(manifest.get("app_id", ""))
        repetitions = int(manifest.get("repetitions", 3))
        timeout = REQUEST_TIMEOUT_SECONDS
        if repetitions < 1 or repetitions > 10:
            raise GateError("repetitions outside safe bound")
        connection, database = open_readonly_sqlite(database)
        before = {"sqlite": sqlite_fingerprint(database), "sqlite_content": sqlite_content_fingerprint(connection),
                  "process": process_fingerprint(), "docker": docker_fingerprint()}
        user_uuid, app_uuid = resolve_existing_user_app(connection, user_id, app_id)
        allowed_ids = accessible_memory_ids(connection, user_uuid, app_uuid)
        tuple_value, embedder_endpoint, configuration_sha256 = safe_config_tuple(connection, manifest)
        transport_endpoint = runtime_embedder_endpoint(embedder_endpoint) if backend_name == "direct" else embedder_endpoint
        evidence["provider_embedder"] = {**tuple_value, "endpoint_sha256": sha256_bytes(embedder_endpoint.encode())}
        evidence["configuration_sha256"] = configuration_sha256
        evidence["custom_instructions_sha256"] = custom_instructions_hash(connection)
        collection_before = qdrant_fingerprint(qdrant_url, collection)
        host_network = os.getenv("OPENMEMORY_HOST_NETWORK_EVIDENCE")
        network = load_host_network_evidence(host_network, require_attestation=backend_name == "candidate") if host_network else network_evidence(
            qdrant_url, timeout=5, network_manifest=manifest.get("network")
        )
        cases = manifest["queries"]
        provider = tuple_value["provider"]
        model = tuple_value["model"]

        def direct_backend(query, top_k, request_timeout):
            vector = embed_query(query, provider, transport_endpoint, model, request_timeout)
            return vector, qdrant_search(qdrant_url, collection, user_id, vector, top_k, request_timeout)

        for case in cases:
            case["dimensions"] = tuple_value["dimensions"]
        if backend_name == "candidate":
            candidate_backend = candidate_backend_factory(connection, qdrant_url, collection, user_id, tuple_value)
            paired = paired_runs(direct_backend, candidate_backend, cases, allowed_ids, user_id, repetitions=repetitions, warmups=1)
            run = paired["candidate"]
            evidence["paired_metrics"] = {
                "direct": metrics(paired["direct"], cases, repetitions),
                "candidate": metrics(paired["candidate"], cases, repetitions),
            }
            evidence["embedding_frozen"] = all(
                (direct_hashes := {item["embedding_sha256"] for item in paired["direct"]["measurements"] if item["query_index"] == index})
                and (candidate_hashes := {item["embedding_sha256"] for item in paired["candidate"]["measurements"] if item["query_index"] == index})
                and len(direct_hashes) == 1
                and len(candidate_hashes) == 1
                and direct_hashes == candidate_hashes
                for index in range(len(cases))
            )
        else:
            run = run_backend(direct_backend, cases, allowed_ids, user_id, repetitions=repetitions, warmups=1, timeout=timeout)
            evidence["paired_metrics"]["direct"] = metrics(run, cases, repetitions)
            embedding_hashes = {}
            for item in run["measurements"]:
                embedding_hashes.setdefault(item["query_index"], set()).add(item["embedding_sha256"])
            evidence["embedding_frozen"] = len(embedding_hashes) == len(cases) and all(len(values) == 1 for values in embedding_hashes.values())
        evidence["metrics"] = metrics(run, cases, repetitions)
        evidence["quality_passes"] = quality_passes(evidence["metrics"], manifest["thresholds"])
        evidence["errors"] = run["errors"]
        evidence["measurements"] = run["measurements"]
        evidence["acl_state"] = {
            "active_memory_count": len(allowed_ids),
            "postfilter": "active memory IDs plus current app ACL",
            "leakage": bool(run.get("leakage")),
        }
        after = {"sqlite": sqlite_fingerprint(database), "sqlite_content": sqlite_content_fingerprint(connection),
                 "process": process_fingerprint(), "docker": docker_fingerprint()}
        collection_after = qdrant_fingerprint(qdrant_url, collection)
        evidence["fingerprints"] = {"before": before, "after": after, "qdrant_before": collection_before, "qdrant_after": collection_after,
                                     "unchanged": compare_fingerprints(before, after) and collection_before == collection_after}
        evidence["network"] = network
        if not evidence["fingerprints"]["unchanged"]:
            outcome = "BLOCKED-ENVIRONMENT"
        elif not network["complete"] or not collection_before.get("available"):
            outcome = "BLOCKED-ENVIRONMENT"
        elif not evidence["embedding_frozen"] or evidence["metrics"]["errors"] or not evidence["metrics"]["complete"] or evidence["acl_state"]["leakage"]:
            outcome = "BLOCKED-ENVIRONMENT"
        elif not evidence["quality_passes"] or evidence["metrics"]["critical_recall_at_5_failures"]:
            outcome = "NO-GO" if backend_name == "candidate" else "MORE-WORK"
        else:
            outcome = "PASSED"
        evidence["decision"] = outcome
    except GateError as exc:
        evidence["decision"] = "BLOCKED-ENVIRONMENT"
        evidence["errors"] = [{"class": "environment", "type": type(exc).__name__, "reason_class": redacted_error(exc)["class"], "reason_code": redacted_gate_reason(exc)}]
    except CandidateFailure as exc:
        evidence["decision"] = "NO-GO" if backend_name == "candidate" else "MORE-WORK"
        evidence["errors"] = [{"class": "candidate", "type": type(exc).__name__}]
    except Exception as exc:
        evidence["decision"] = "BLOCKED-ENVIRONMENT"
        error = redacted_error(exc)
        error["scope"] = "environment"
        evidence["errors"] = [error]
    finally:
        if connection is not None:
            connection.close()
    output = run_dir / "evidence.json"
    output.write_bytes(canonical_json(evidence))
    if backend_name == "direct" and evidence["decision"] == "PASSED" and os.getenv("OPENMEMORY_AUTHORITATIVE_REPLAY") != "1":
        try:
            baseline_seal(output, evidence)
        except GateError as exc:
            evidence["decision"] = "BLOCKED-ENVIRONMENT"
            evidence["errors"] = [{"class": "environment", "type": type(exc).__name__, "reason_code": redacted_gate_reason(exc)}]
            output.write_bytes(canonical_json(evidence))
    output.chmod(0o600)
    return evidence["decision"], output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--manifest", default=os.getenv("OPENMEMORY_RETRIEVAL_MANIFEST", str(DEFAULT_MANIFEST)))
    parser.add_argument("--evidence-dir", default=os.getenv("OPENMEMORY_RETRIEVAL_EVIDENCE_DIR", str(DEFAULT_EVIDENCE)))
    parser.add_argument("--backend", choices=("direct", "candidate"), default="direct")
    parser.add_argument("--expected-mem0-version", dest="expected_mem0_version", default=None)
    args = parser.parse_args(argv)
    if args.self_check:
        self_check()
        print("evaluate_retrieval self-check: ok")
        return 0
    if args.expected_mem0_version:
        os.environ["OPENMEMORY_EXPECTED_MEM0_VERSION"] = args.expected_mem0_version
    decision, output = execute(args.manifest, args.evidence_dir, args.backend)
    document = json.loads(output.read_text(encoding="utf-8"))
    print(json.dumps({"decision": decision, "evidence": str(output), "mem0ai": document.get("mem0ai")}, sort_keys=True))
    return 0 if decision == "PASSED" else 2


if __name__ == "__main__":
    sys.exit(main())
