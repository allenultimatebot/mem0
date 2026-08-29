#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import sqlite3
import tempfile


path = pathlib.Path(__file__).with_name("evaluate_retrieval.py")
spec = importlib.util.spec_from_file_location("evaluate_retrieval", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


assert module.percentile([3, 1, 2], 0.50) == 2
assert module.percentile([1, 2, 3, 4], 0.95) == 4
assert module.runtime_embedder_endpoint("http://host.docker.internal:11434", host_runtime=True) == "http://127.0.0.1:11434"
assert module.canonical_memory_id("3205b267735949388a0bf60339f5dccc") == "3205b267-7359-4938-8a0b-f60339f5dccc"
assert module.quality_passes(
    {"recall_at_5": 1.0, "recall_at_10": 1.0, "mrr": 1.0, "latency_ms": {"p95": 20}},
    {"recall_at_5": 0.9, "recall_at_10": 0.9, "mrr": 0.9, "p95_latency_ms": 30},
)
assert module.metrics(
    {"measurements": [{"query_index": 0, "ranked_ids": ["a"], "latency_ms": 1}], "errors": []},
    [{"relevant_ids": ["a"]}, {"relevant_ids": []}],
    1,
)["mrr"] == 1.0
normalized, leakage = module.normalize_hits(
    [{"id": "b", "score": 0.5, "payload": {"user_id": "user", "state": "active"}}, {"id": "a", "score": 0.5, "payload": {"user_id": "user", "state": "active"}}, {"id": "a", "score": 0.4, "payload": {"user_id": "user", "state": "active"}}], {"a"}, "user"
)
assert normalized == [{"id": "a", "score": 0.5, "allowed": True, "state": "active"}, {"id": "b", "score": 0.5, "allowed": False, "state": "active"}]
assert leakage is True
normalized, leakage = module.normalize_hits(
    [{"id": "a", "score": 0.5, "payload": {"user_id": "user"}}], {"a"}, "user"
)
assert normalized[0]["state"] == "active" and leakage is False

with tempfile.TemporaryDirectory() as directory:
    private = pathlib.Path(directory) / "private"
    private.mkdir(mode=0o700)
    assert module.private_dir(private) == private
    database = pathlib.Path(directory) / "fixture.db"
    connection = sqlite3.connect(database)
    connection.executescript("""
        CREATE TABLE users (id TEXT PRIMARY KEY, user_id TEXT);
        CREATE TABLE apps (id TEXT PRIMARY KEY, owner_id TEXT, name TEXT, is_active INTEGER);
        CREATE TABLE memories (id TEXT PRIMARY KEY, user_id TEXT, state TEXT);
        CREATE TABLE access_controls (subject_type TEXT, subject_id TEXT, object_type TEXT, object_id TEXT, effect TEXT);
    """)
    connection.executemany("INSERT INTO users VALUES (?, ?)", [("u", "person")])
    connection.executemany("INSERT INTO apps VALUES (?, ?, ?, ?)", [("a", "u", "app", 1)])
    connection.executemany("INSERT INTO memories VALUES (?, ?, ?)", [("m1", "u", "active"), ("m2", "u", "deleted")])
    connection.execute("INSERT INTO access_controls VALUES (?, ?, ?, ?, ?)", ("app", "a", "memory", "m1", "allow"))
    connection.commit()
    connection.close()
    read_only, _ = module.open_readonly_sqlite(database)
    assert read_only.execute("PRAGMA query_only").fetchone()[0] == 1
    try:
        read_only.execute("INSERT INTO users VALUES ('blocked', 'blocked')")
        raise AssertionError("read-only connection allowed a write")
    except sqlite3.OperationalError:
        pass
    user_uuid, app_uuid = module.resolve_existing_user_app(read_only, "person", "app")
    assert module.accessible_memory_ids(read_only, user_uuid, app_uuid) == {"m1"}
    read_only.close()

    manifest = {"queries": [{"query": "q", "category": category, "relevant_ids": []} for category in
                              ("durable", "multilingual", "current", "stale", "acl", "state")] * 5,
                "thresholds": {"recall_at_5": 0, "recall_at_10": 0, "mrr": 0, "p95_latency_ms": 1000}}
    manifest_path = pathlib.Path(directory) / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_path.chmod(0o600)
    loaded, _, _ = module.load_manifest(manifest_path)
    assert module.expected_label_hash(loaded)
    invalid = dict(manifest, timeout_seconds=30)
    invalid_path = pathlib.Path(directory) / "invalid-timeout.json"
    invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
    invalid_path.chmod(0o600)
    try:
        module.load_manifest(invalid_path)
        raise AssertionError("non-15-second timeout was accepted")
    except module.GateError:
        pass

print("evaluate_retrieval selfcheck: ok")
