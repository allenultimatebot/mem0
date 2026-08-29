#!/usr/bin/env python3
"""Build a deterministic retrieval-eval worksheet and private manifest."""

import argparse
import json
import os
import pathlib
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE = pathlib.Path.home() / ".config/openmemory/retrieval-eval.json"
DEV = pathlib.Path.home() / ".config/openmemory/retrieval-eval-dev.json"
REQUIRED = {"durable", "multilingual", "current", "stale", "acl", "state"}


def memory_id(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError):
        return str(value)


def read_json(path, default):
    try:
        value = json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else default
    except (OSError, ValueError):
        return default


def open_db(path):
    path = pathlib.Path(path).expanduser()
    if not path.is_file():
        return None
    try:
        connection = sqlite3.connect("file:{}?mode=ro".format(path.resolve()), uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        return connection
    except sqlite3.Error:
        return None


def logged_queries(connection):
    if connection is None:
        return []
    try:
        rows = connection.execute(
            "SELECT json_extract(metadata, '$.query') query, count(*) frequency, "
            "max(accessed_at) last_seen, group_concat(DISTINCT memory_id) ids "
            "FROM memory_access_logs WHERE json_extract(metadata, '$.query') IS NOT NULL "
            "GROUP BY query ORDER BY frequency DESC, query"
        )
    except sqlite3.Error:
        return []
    return [{"query": row["query"], "frequency": row["frequency"], "last_seen": row["last_seen"],
             "relevant_ids": sorted({memory_id(item) for item in (row["ids"] or "").split(",") if item})}
            for row in rows if isinstance(row["query"], str) and row["query"].strip()]


def category(query):
    lower = query.lower()
    if any(char in query for char in "áàảãạăắằẳẵặâấầẩẫậđĐéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵ"):
        return "multilingual"
    if any(word in lower for word in ("tiếng", "viet", "vietnam", "shopee", "lark", "ảnh", "mục tiêu")):
        return "multilingual"
    if any(word in lower for word in ("current", "latest", "today", "now", "status", "august", "deployed", "production", "phase", "new ")):
        return "current"
    if any(word in lower for word in ("stale", "old", "former", "previous", "retired", "interview", "candidate", "july", "recommended")):
        return "stale"
    if any(word in lower for word in ("preference", "prefer", "goal", "name", "drink", "user", "allen", "favorite", "likes")):
        return "durable"
    return "paraphrase"


def sample_strata(rows, count, strata):
    if not rows or count <= 0:
        return []
    strata = max(1, min(strata, len(rows)))
    buckets = [rows[len(rows) * index // strata:len(rows) * (index + 1) // strata]
               for index in range(strata)]
    selected = []
    while len(selected) < min(count, len(rows)):
        if not any(buckets):
            break
        for bucket in buckets:
            if bucket and len(selected) < count:
                selected.append(bucket.pop(0))
    return selected


def live_top50(query, qdrant_url, collection, user_id, embedder_url):
    try:
        def post(url, payload):
            request = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST")
            request.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(request, timeout=3) as response:
                return json.loads(response.read().decode())

        embedding = post(embedder_url.rstrip("/") + "/api/embed", {
            "model": os.getenv("EMBEDDER_MODEL", "nomic-embed-text"), "input": query,
        })
        vector = embedding.get("embedding") or (embedding.get("embeddings") or [None])[0]
        if not isinstance(vector, list):
            return []
        path = "/collections/{}/points/search".format(urllib.parse.quote(collection, safe=""))
        result = post(qdrant_url.rstrip("/") + path, {
            "vector": vector, "limit": 50, "with_payload": True, "with_vector": False,
            "filter": {"must": [{"key": "user_id", "match": {"value": user_id}}]},
        })
        return [{"id": memory_id(point["id"]), "score": point.get("score"),
                 "text": str((point.get("payload") or {}).get("data", ""))[:100]}
                for point in result.get("result", [])
                if isinstance(point, dict) and point.get("id") is not None]
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError):
        return []


def write_worksheet(rows, args):
    lines = ["query\tfrequency\tlast_seen\tcategory_suggestion\tlogged_memory_ids\ttop_50_id\ttop_50_score\ttop_50_text"]
    for row in sample_strata(rows, args.sample, args.strata):
        results = live_top50(row["query"], args.qdrant_url, args.collection, args.user_id, args.embedder_url)
        for result in results or [{"id": "", "score": "", "text": ""}]:
            values = (row["query"], row["frequency"], row["last_seen"] or "", category(row["query"]),
                      ",".join(row["relevant_ids"]), result["id"], result["score"], result["text"])
            lines.append("\t".join(str(value).replace("\t", " ").replace("\n", " ") for value in values))
    path = pathlib.Path(args.worksheet).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


def deleted_probes(connection):
    if connection is None:
        return []
    probes = []
    try:
        for text, query in (("Allen drinks oat milk lattes.", "what does Allen drink?"),
                            ("Allen's favorite color is teal.", "what is Allen's favorite color?")):
            row = connection.execute(
                "SELECT id FROM memories WHERE state = 'deleted' AND lower(content) = lower(?) LIMIT 1", (text,)
            ).fetchone()
            if row:
                probes.append({"category": "state", "critical": False, "query": query,
                               "relevant_ids": [memory_id(row[0])]})
    except sqlite3.Error:
        pass
    return probes


def active_ids(connection, user_id):
    if connection is None:
        return []
    try:
        user = connection.execute("SELECT id FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            return []
        return [memory_id(row[0]) for row in connection.execute(
            "SELECT id FROM memories WHERE user_id = ? AND state = 'active' ORDER BY id", (user[0],)
        )]
    except sqlite3.Error:
        return []


def build_manifest(fixture, rows, connection, user_id, app_id, database):
    # Carry every gate case; ACL/state objects remain byte-for-byte equivalent.
    cases = [dict(item) for item in fixture.get("queries", []) if isinstance(item, dict)]
    existing = {item.get("query") for item in cases}
    sampled = sample_strata(rows, max(50, min(60, len(rows))), 3)
    sampled_queries = {row["query"] for row in sampled}
    answerable = [row for row in sampled if row["query"] not in existing and row["relevant_ids"]]
    answerable.extend(row for row in rows if row["query"] not in existing | sampled_queries and row["relevant_ids"])
    targets = {"durable": 12, "multilingual": 10, "current": 8, "stale": 8, "paraphrase": 12}
    for kind, limit in targets.items():
        matches = [row for row in answerable if category(row["query"]) == kind]
        for row in matches[:max(0, limit - sum(item.get("category") == kind for item in cases))]:
            cases.append({"category": kind, "critical": True, "query": row["query"],
                          "relevant_ids": row["relevant_ids"]})

    cases.extend([
        {"category": "multilingual", "critical": True, "query": "athenabrain duoc thiet ke de lam gi",
         "relevant_ids": ["8276fd5b-58a4-449c-94d7-096ac6af33ea"]},
        {"category": "multilingual", "critical": True, "query": "muc tieu cua athenabrain la gi",
         "relevant_ids": ["6baf3a6b-7a79-4013-87d2-69150d6a7443"]},
        {"category": "multilingual", "critical": True, "query": "What is the rule for Vietnamese writing output?",
         "relevant_ids": ["6b0d0c2d-7a13-460a-a403-1ff1b5a7a8bc"]},
    ])

    # If a live DB is unavailable, derive labelled paraphrases from the sealed
    # fixture rather than emitting an unusable all-empty manifest.
    answerable_fixture = [item for item in cases if item.get("relevant_ids")]
    paraphrases = [
        "Please recall the memory about: {}", "What should I remember regarding {}?",
        "Give me the stored context for {}", "Which saved fact covers {}?",
    ]
    for index, item in enumerate(answerable_fixture[:12]):
        query = paraphrases[index % len(paraphrases)].format(item["query"])
        if query not in existing and not any(case["query"] == query for case in cases):
            cases.append({"category": "paraphrase", "critical": True, "query": query,
                          "relevant_ids": item["relevant_ids"]})

    cases.extend(deleted_probes(connection))
    negatives = [
        "What is the recipe for Martian soil tea?", "Which penguin won the 2099 Singapore election?",
        "Translate Neptune's quantum password into whale song.", "How many moons does an imaginary blue tiger have?",
        "Find the private memories of Nobody Example.", "What is the exchange rate of moon dust?",
        "Show source code for Empty Planet.", "Which dragon owns warehouse #00-00?",
        "Retrieve my non-existent passport number.", "What did the robot accountant decide on Pluto?",
        "List memories about Zebra Thunderclap.", "Who is CEO of Silent Comet?",
    ]
    cases.extend({"category": "negative", "critical": False, "query": query, "relevant_ids": []}
                 for query in negatives)

    deleted = []
    if connection is not None:
        try:
            deleted = [memory_id(row[0]) for row in connection.execute(
                "SELECT id FROM memories WHERE state = 'deleted' ORDER BY id")]
        except sqlite3.Error:
            pass
    output = dict(fixture)
    output.update({"queries": cases, "user_id": user_id, "app_id": app_id,
                   "database": str(pathlib.Path(database).expanduser()), "deleted_ids": deleted,
                   "allowed_ids": active_ids(connection, user_id),
                   "fixture_provenance": {"source": str(GATE), "logged_query_count": len(rows),
                                          "labeling": "access-log hits plus explicit regression probes"}})
    return output


def write_private(path, value):
    path = pathlib.Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", "--database", dest="database", default=os.getenv("OPENMEMORY_DB", "/var/lib/openmemory/openmemory.db"))
    parser.add_argument("--sample", type=int, default=60)
    parser.add_argument("--strata", type=int, default=3)
    parser.add_argument("--output", "--manifest", dest="output", default=str(DEV))
    parser.add_argument("--worksheet", default="retrieval-eval-worksheet.tsv")
    parser.add_argument("--emit-manifest", action="store_true")
    parser.add_argument("--fixture", default=str(GATE))
    parser.add_argument("--user-id", default=os.getenv("OPENMEMORY_USER_ID", "allen_bot"))
    parser.add_argument("--app-id", default=os.getenv("OPENMEMORY_APP_ID", "openmemory"))
    parser.add_argument("--qdrant-url", default=os.getenv("QDRANT_URL", "http://127.0.0.1:6333"))
    parser.add_argument("--collection", default=os.getenv("QDRANT_COLLECTION", "openmemory"))
    parser.add_argument("--embedder-url", default=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434"))
    args = parser.parse_args(argv)
    connection = open_db(args.database)
    rows = logged_queries(connection)
    if not rows:
        print("warning: no live memory_access_logs; using fixture labels", file=sys.stderr)
    write_worksheet(rows, args)
    print("wrote {}".format(pathlib.Path(args.worksheet).expanduser()))
    if args.emit_manifest:
        write_private(args.output, build_manifest(read_json(args.fixture, {"queries": []}), rows,
                                                   connection, args.user_id, args.app_id, args.database))
        print("wrote {}".format(pathlib.Path(args.output).expanduser()))
    if connection is not None:
        connection.close()


if __name__ == "__main__":
    main()
