#!/usr/bin/env python3
import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
import uuid
from pathlib import Path

from sqlalchemy import update
from sqlalchemy.orm import selectinload

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.database import SessionLocal
from app.models import Memory, MemoryAccessLog, MemoryState, MemoryStatusHistory

RUN_ROOT = Path(os.environ.get("OPENMEMORY_LINT_RUNS", "/usr/src/openmemory/data/lint-runs"))
LOCK = Path(os.environ.get("OPENMEMORY_MAINTENANCE_LOCK", "/usr/src/openmemory/.openmemory-maintenance.lock"))
QDRANT_URL = os.environ.get("OPENMEMORY_QDRANT_URL", "http://mem0_store:6333").rstrip("/")
QDRANT_COLLECTION = os.environ.get("OPENMEMORY_QDRANT_COLLECTION", "openmemory")
CHUNK_SIZE = 500
BACKUP_MARKER = os.environ.get("OPENMEMORY_BACKUP_VERIFIED_MARKER")
BACKUP_LOCK_VALUE = os.environ.get("OPENMEMORY_BACKUP_LOCK")
BACKUP_LOCK = Path(BACKUP_LOCK_VALUE) if BACKUP_LOCK_VALUE else None
BACKUP_MAX_AGE_SECONDS = int(os.environ.get("OPENMEMORY_BACKUP_MAX_AGE_SECONDS", "86400"))
DURABLE_CATEGORIES = {"preferences", "goals"}
STANDING_RULE_SIGNALS = re.compile(
    r"\b(?:decision will affect the whole staff|backbone should be goal|ai should be treated as one support lever|"
    r"distinguishes script from slide copy|first slide about meeting hygiene|publishing instructions|all team-facing|"
    r"preferred workflow|wiki conventions|planning standards|yagni, kiss, and dry|bans vague words|"
    r"gap is an authority problem|source attribution internal only|zero source attribution|singapore-market examples|"
    r"for any web task)\b",
    re.IGNORECASE,
)
EPISODIC_CATEGORY_SIGNALS = re.compile(
    r"\b(?:current|currently|remaining|pending|as of|roadmap|plan (?:is|was|includes|covers|currently|intentionally)|"
    r"approved plan|hiring plan|report describes|deck|course|curriculum|homework|buổi \d|quantified|attributed|"
    r"open work|requested the workflow|skill defines|selected phased delivery|organization redesign|interview|"
    r"on (?:january|february|march|april|may|june|july|august|september|october|november|december)|"
    r"by (?:january|february|march|april|may|june|july|august|september|october|november|december))\b",
    re.IGNORECASE,
)
ONE_OFF_JUNK_SIGNALS = re.compile(
    r"\b(?:asked to open .* and report|instructed (?:that )?(?:the )?(?:task|work).*?(?:continue|proceed)|"
    r"session outcome was not captured)\b",
    re.IGNORECASE,
)


def normalize_id(value):
    return str(value).replace("-", "").lower()


def classify(memory, retrieval_counts, duplicate_ids=frozenset()):
    content = memory.content.strip()
    lower = content.lower()
    memory_id = normalize_id(getattr(memory, "id", ""))
    category_names = {category.name.strip().lower() for category in (memory.categories or []) if category.name}
    if memory_id in duplicate_ids:
        return "transient-junk", "exact-duplicate-lower-ranked"
    if ONE_OFF_JUNK_SIGNALS.search(content):
        return "transient-junk", "one-off-session-instruction"
    age = (dt.datetime.now(dt.timezone.utc) - memory.created_at.replace(tzinfo=dt.timezone.utc)).days
    assistant_shape = lower.startswith(("assistant ", "the assistant "))
    if assistant_shape and retrieval_counts.get(str(memory.id), 0) == 0 and age > 30:
        return "transient-junk", "assistant-narration-never-retrieved-old"
    if len(content) < 40 and not re.search(r"\b[A-Z][a-z]{2,}\b", content):
        return "transient-junk", "short-no-proper-noun"
    if content.startswith("[durable]"):
        return "durable", "durable-marker"
    if STANDING_RULE_SIGNALS.search(content):
        return "durable", "standing-rule-overlay"
    if category_names & DURABLE_CATEGORIES and not EPISODIC_CATEGORY_SIGNALS.search(content):
        return "durable", "category-overlay"
    if any(word in lower for word in ("i prefer", "my preference", "my goal", "i always")):
        return "durable", "first-person-preference"
    return "episodic", "project-or-technical-default"


def rows(db):
    counts = {}
    for memory_id, count in db.query(MemoryAccessLog.memory_id, __import__('sqlalchemy').func.count(MemoryAccessLog.id)).group_by(MemoryAccessLog.memory_id).all():
        counts[str(memory_id)] = count
    memories = db.query(Memory).options(selectinload(Memory.categories)).filter(Memory.state == MemoryState.active).all()
    duplicate_ids = set()
    content_groups = {}
    for memory in memories:
        content_groups.setdefault(memory.content.strip(), []).append(memory)
    for group in content_groups.values():
        if len(group) < 2:
            continue
        canonical = max(group, key=lambda memory: (counts.get(str(memory.id), 0), memory.updated_at, str(memory.id)))
        duplicate_ids.update(normalize_id(memory.id) for memory in group if memory is not canonical)
    output = []
    for memory in memories:
        tier, reason = classify(memory, counts, duplicate_ids)
        verdict = "transient-junk" if tier == "transient-junk" else tier
        output.append((memory, tier, verdict, reason, counts.get(str(memory.id), 0)))
    return output


def acquire_lock():
    LOCK.mkdir(mode=0o700, exist_ok=True)
    owner = LOCK / "owner"
    if owner.exists() and "state=held" in owner.read_text(encoding="utf-8"):
        raise RuntimeError("maintenance lock already held")
    owner.write_text(f"state=held\npid={os.getpid()}\n", encoding="utf-8")
    return owner


def assert_mutation_prereqs(db):
    from zoneinfo import ZoneInfo

    now = dt.datetime.now(ZoneInfo("Asia/Singapore"))
    minute = now.hour * 60 + now.minute
    if 23 * 60 + 45 <= minute or minute < 30:
        raise RuntimeError("mutation window is closed from 23:45 through 00:30 SGT")
    journal_mode = db.execute(__import__("sqlalchemy").text("PRAGMA journal_mode")).scalar_one().lower()
    busy_timeout = int(db.execute(__import__("sqlalchemy").text("PRAGMA busy_timeout")).scalar_one())
    if journal_mode != "wal" or busy_timeout < 5000:
        raise RuntimeError(f"unsafe SQLite settings: journal_mode={journal_mode}, busy_timeout={busy_timeout}")
    if BACKUP_LOCK is not None and BACKUP_LOCK.exists():
        raise RuntimeError(f"backup lock is active: {BACKUP_LOCK}")
    if not BACKUP_MARKER or not Path(BACKUP_MARKER).is_file():
        raise RuntimeError("verified backup marker is missing")
    marker = Path(BACKUP_MARKER).read_text(encoding="utf-8")
    if "state=verified" not in marker:
        raise RuntimeError("verified backup marker is not verified")
    verified_at = next((line.split("=", 1)[1] for line in marker.splitlines() if line.startswith("verified_at=")), "")
    try:
        age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(verified_at)).total_seconds()
    except ValueError as exc:
        raise RuntimeError("verified backup marker timestamp is invalid") from exc
    if age < 0 or age > BACKUP_MAX_AGE_SECONDS:
        raise RuntimeError(f"verified backup marker is stale: age_seconds={age:.0f}")


def qdrant_set_state(memory_ids, state):
    if not memory_ids:
        return
    from qdrant_client import QdrantClient

    client = QdrantClient(url=QDRANT_URL, timeout=30)
    for offset in range(0, len(memory_ids), CHUNK_SIZE):
        result = client.set_payload(
            collection_name=QDRANT_COLLECTION,
            payload={"state": state},
            points=memory_ids[offset:offset + CHUNK_SIZE],
            wait=True,
        )
        if str(result.status).lower() != "completed":
            raise RuntimeError(f"Qdrant payload update did not complete: {result.status}")


def atomic_json(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_manifest(path, run_id, classified):
    data = {
        "run_id": run_id,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mutation": "p5-tier-backfill-and-quarantine",
        "chunk_size": CHUNK_SIZE,
        "touched": [
            {
                "id": str(memory.id),
                "old_state": memory.state.value,
                "old_archived_at": memory.archived_at.isoformat() if memory.archived_at else None,
                "old_metadata": memory.metadata_ or {},
                "will_archive": verdict == "transient-junk",
            }
            for memory, _, verdict, _, _ in classified
        ],
    }
    atomic_json(path, data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--classify", action="store_true")
    parser.add_argument("--report-only", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--tier-backfill", action="store_true")
    parser.add_argument("--restore")
    parser.add_argument("--report", default="lint-report.csv")
    parser.add_argument("--agreement")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    db = SessionLocal()
    try:
        if args.restore:
            manifest = json.loads((RUN_ROOT / f"{args.restore}.json").read_text(encoding="utf-8"))
            items = manifest["touched"]
            if args.dry_run:
                items = sorted(items, key=lambda item: not item["will_archive"])
            items = items[:args.limit] if args.limit else items
            if args.dry_run:
                assert_mutation_prereqs(db)
                owner = acquire_lock()
                try:
                    current = {}
                    for item in items:
                        memory = db.query(Memory).filter(Memory.id == uuid.UUID(item["id"])).first()
                        expected_state = "archived" if item["will_archive"] else item["old_state"]
                        if not memory or memory.state.value != expected_state:
                            raise RuntimeError(f"restore dry-run target is not in expected post-apply state: {item['id']}")
                        current[item["id"]] = {"state": memory.state.value, "archived_at": memory.archived_at, "metadata": memory.metadata_ or {}}
                    db.rollback()
                    for item in items:
                        archived_at = dt.datetime.fromisoformat(item["old_archived_at"]) if item["old_archived_at"] else None
                        db.execute(update(Memory).where(Memory.id == uuid.UUID(item["id"])).values({
                            Memory.metadata_: item["old_metadata"],
                            Memory.state: MemoryState(item["old_state"]),
                            Memory.archived_at: archived_at,
                        }))
                    db.flush()
                    for item in items:
                        memory = db.query(Memory).filter(Memory.id == uuid.UUID(item["id"])).first()
                        if memory.state.value != item["old_state"] or (memory.metadata_ or {}) != item["old_metadata"]:
                            raise RuntimeError(f"restore dry-run could not reconstruct pre-apply row: {item['id']}")
                    db.rollback()
                    for item in items:
                        memory = db.query(Memory).filter(Memory.id == uuid.UUID(item["id"])).first()
                        before = current[item["id"]]
                        if memory.state.value != before["state"] or (memory.metadata_ or {}) != before["metadata"]:
                            raise RuntimeError(f"restore dry-run rollback changed live row: {item['id']}")
                finally:
                    owner.write_text("state=released\n", encoding="utf-8")
                print(json.dumps({"run_id": args.restore, "dry_run": True, "checked": len(items), "reversible": True, "persisted_changes": 0}))
                return 0
            assert_mutation_prereqs(db)
            owner = acquire_lock()
            try:
                for offset in range(0, len(items), CHUNK_SIZE):
                    chunk = items[offset:offset + CHUNK_SIZE]
                    for item in chunk:
                        archived_at = dt.datetime.fromisoformat(item["old_archived_at"]) if item["old_archived_at"] else None
                        values = {
                            Memory.metadata_: item["old_metadata"],
                            Memory.state: MemoryState(item["old_state"]),
                            Memory.archived_at: archived_at,
                        }
                        db.execute(update(Memory).where(Memory.id == uuid.UUID(item["id"])).values(values))
                    db.commit()
                    qdrant_set_state([item["id"] for item in chunk if item["will_archive"]], "active")
            finally:
                owner.write_text("state=released\n", encoding="utf-8")
            print(json.dumps({"run_id": args.restore, "restored": len(items)}))
            return 0
        classified = rows(db)
        with Path(args.report).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(("id", "tier", "verdict", "reasons", "retrieval_count", "age_days", "preview"))
            for memory, tier, verdict, reason, count in classified:
                age = (dt.datetime.now(dt.timezone.utc) - memory.created_at.replace(tzinfo=dt.timezone.utc)).days
                writer.writerow((memory.id, tier, verdict, reason, count, age, memory.content[:80]))
        if args.agreement:
            allowed = {"durable", "episodic", "transient-junk"}
            labels = {}
            for row in csv.DictReader(Path(args.agreement).open(encoding="utf-8")):
                memory_id = normalize_id(row["id"])
                verdict = row["verdict"].strip()
                if not memory_id or verdict not in allowed or memory_id in labels:
                    raise ValueError(f"invalid or duplicate agreement row: {row}")
                labels[memory_id] = verdict
            predictions = {normalize_id(memory.id): verdict for memory, _, verdict, _, _ in classified}
            by_class = {}
            matches = 0
            for verdict in sorted(allowed):
                ids = [memory_id for memory_id, label in labels.items() if label == verdict]
                class_matches = sum(predictions.get(memory_id) == verdict for memory_id in ids)
                matches += class_matches
                by_class[verdict] = {
                    "agreement": class_matches / max(len(ids), 1),
                    "matched": class_matches,
                    "labelled": len(ids),
                }
            print(json.dumps({
                "agreement": matches / max(len(labels), 1),
                "matched": matches,
                "labelled": len(labels),
                "missing_ids": sum(memory_id not in predictions for memory_id in labels),
                "by_class": by_class,
            }))
        if not args.apply:
            print(f"classified {len(classified)} active memories")
            return 0
        assert_mutation_prereqs(db)
        owner = acquire_lock()
        run_id = str(uuid.uuid4())
        manifest_path = RUN_ROOT / f"{run_id}.json"
        write_manifest(manifest_path, run_id, classified)
        try:
            archived_ids = []
            for offset in range(0, len(classified), CHUNK_SIZE):
                chunk = classified[offset:offset + CHUNK_SIZE]
                for memory, tier, verdict, _, _ in chunk:
                    metadata = dict(memory.metadata_ or {})
                    if args.tier_backfill:
                        metadata["tier"] = tier
                    values = {Memory.metadata_: metadata}
                    if verdict == "transient-junk":
                        values.update({Memory.state: MemoryState.archived, Memory.archived_at: dt.datetime.now(dt.timezone.utc)})
                        db.add(MemoryStatusHistory(memory_id=memory.id, changed_by=memory.user_id, old_state=MemoryState.active, new_state=MemoryState.archived))
                        archived_ids.append(str(memory.id))
                    db.execute(update(Memory).where(Memory.id == memory.id).values(values))
                db.commit()
                qdrant_set_state([str(memory.id) for memory, _, verdict, _, _ in chunk if verdict == "transient-junk"], "archived")
            print(json.dumps({"run_id": run_id, "classified": len(classified), "archived": len(archived_ids), "manifest": str(manifest_path)}))
        finally:
            owner.write_text("state=released\n", encoding="utf-8")
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
