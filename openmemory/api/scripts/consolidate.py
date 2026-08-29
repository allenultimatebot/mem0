#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import update

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.database import SessionLocal
from app.models import Memory, MemoryState, MemoryStatusHistory
from lint_corpus import CHUNK_SIZE, acquire_lock, assert_mutation_prereqs, atomic_json, qdrant_set_state

RUN_ROOT = Path(os.environ.get("OPENMEMORY_CONSOLIDATION_RUNS", "/usr/src/openmemory/data/consolidation-runs"))
DEFAULT_CLUSTERS = Path(os.environ.get("OPENMEMORY_CONSOLIDATION_CLUSTERS", "/usr/src/openmemory/data/p6-reviewed-clusters-20260829.json"))


def exact_clusters(db):
    grouped = {}
    for memory in db.query(Memory).filter(Memory.state == MemoryState.active).all():
        key = hashlib.sha256(memory.content.strip().lower().encode()).hexdigest()
        grouped.setdefault(key, []).append(memory)
    return [{"cluster": index, "canonical_id": str(max(group, key=lambda item: (item.updated_at, str(item.id))).id), "member_ids": [str(item.id) for item in group]}
            for index, group in enumerate((group for group in grouped.values() if len(group) > 1), 1)]


def load_clusters(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    clusters = data.get("clusters") if isinstance(data, dict) else data
    if not isinstance(clusters, list) or not clusters:
        raise ValueError("cluster manifest is empty or malformed")
    return clusters


def write_manifest(path, run_id, entries, threshold, cluster_source):
    atomic_json(path, {
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "mutation": "p6-consolidation",
        "threshold": threshold,
        "cluster_source": str(cluster_source),
        "chunk_size": CHUNK_SIZE,
        "touched": entries,
    })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-only", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--threshold", type=float, default=0.93)
    parser.add_argument("--clusters", type=Path, default=DEFAULT_CLUSTERS)
    parser.add_argument("--restore")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    db = SessionLocal()
    try:
        if args.restore:
            manifest_path = RUN_ROOT / f"{args.restore}.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entries = manifest["touched"]
            if args.dry_run:
                entries = entries[:args.limit] if args.limit else entries
                assert_mutation_prereqs(db)
                for item in entries:
                    source = db.query(Memory).filter(Memory.id == uuid.UUID(item["id"])).first()
                    canonical = db.query(Memory).filter(Memory.id == uuid.UUID(item["canonical_id"])).first()
                    if not source or source.state != MemoryState.archived or not canonical:
                        raise RuntimeError(f"consolidation restore dry-run mismatch: {item['id']}")
                    if (canonical.metadata_ or {}).get("merged_from") is None:
                        raise RuntimeError(f"canonical provenance is missing: {item['canonical_id']}")
                print(json.dumps({"run_id": args.restore, "dry_run": True, "checked": len(entries), "reversible": True, "persisted_changes": 0}))
                return 0
            assert_mutation_prereqs(db)
            owner = acquire_lock()
            try:
                for offset in range(0, len(entries), CHUNK_SIZE):
                    chunk = entries[offset:offset + CHUNK_SIZE]
                    for item in chunk:
                        db.execute(update(Memory).where(Memory.id == uuid.UUID(item["id"])).values({
                            Memory.state: MemoryState(item["old_state"]),
                            Memory.archived_at: datetime.fromisoformat(item["old_archived_at"]) if item["old_archived_at"] else None,
                        }))
                        db.execute(update(Memory).where(Memory.id == uuid.UUID(item["canonical_id"])).values({Memory.metadata_: item["canonical_old_metadata"]}))
                    db.commit()
                    qdrant_set_state([item["id"] for item in chunk], "active")
            finally:
                owner.write_text("state=released\n", encoding="utf-8")
            print(json.dumps({"run_id": args.restore, "restored": len(entries)}))
            return 0

        if not args.apply:
            clusters = load_clusters(args.clusters) if args.clusters.exists() else exact_clusters(db)
            print(json.dumps({"threshold": args.threshold, "clusters": clusters}, indent=2))
            return 0

        assert_mutation_prereqs(db)
        clusters = load_clusters(args.clusters)
        all_memories = {str(memory.id): memory for memory in db.query(Memory).all()}
        memories = {memory_id: memory for memory_id, memory in all_memories.items() if memory.state == MemoryState.active}
        entries = []
        canonical_metadata = {}
        skipped_archived = []
        for cluster in clusters:
            canonical_id = str(uuid.UUID(cluster["canonical_id"]))
            if canonical_id not in memories:
                raise RuntimeError(f"approved canonical is not active: {canonical_id}")
            members = [str(uuid.UUID(value)) for value in cluster["member_ids"]]
            if canonical_id not in members:
                raise RuntimeError(f"canonical is not a member of cluster {cluster.get('cluster')}")
            canonical = memories[canonical_id]
            provenance = list((canonical.metadata_ or {}).get("merged_from", []))
            canonical_metadata[canonical_id] = {"old": canonical.metadata_ or {}, "new": provenance}
            for member_id in members:
                if member_id == canonical_id:
                    continue
                if member_id not in memories:
                    if member_id in all_memories and all_memories[member_id].state == MemoryState.archived:
                        skipped_archived.append(member_id)
                        continue
                    raise RuntimeError(f"approved cluster member is missing: {member_id}")
                memory = memories[member_id]
                entries.append({
                    "id": member_id,
                    "canonical_id": canonical_id,
                    "old_state": memory.state.value,
                    "old_archived_at": memory.archived_at.isoformat() if memory.archived_at else None,
                    "content_sha256": hashlib.sha256(memory.content.encode()).hexdigest(),
                    "canonical_old_metadata": canonical.metadata_ or {},
                })
                provenance.append({"id": member_id, "content_sha256": hashlib.sha256(memory.content.encode()).hexdigest(), "at": datetime.now(UTC).isoformat()})
            canonical_metadata[canonical_id]["new"] = provenance
        run_id = str(uuid.uuid4())
        manifest_path = RUN_ROOT / f"{run_id}.json"
        write_manifest(manifest_path, run_id, entries, args.threshold, args.clusters)
        owner = acquire_lock()
        try:
            for offset in range(0, len(entries), CHUNK_SIZE):
                chunk = entries[offset:offset + CHUNK_SIZE]
                for item in chunk:
                    db.add(MemoryStatusHistory(memory_id=uuid.UUID(item["id"]), changed_by=memories[item["id"]].user_id,
                                                old_state=MemoryState.active, new_state=MemoryState.archived))
                    db.execute(update(Memory).where(Memory.id == uuid.UUID(item["id"])).values({
                        Memory.state: MemoryState.archived,
                        Memory.archived_at: datetime.now(UTC),
                    }))
                for canonical_id, values in canonical_metadata.items():
                    if any(item["canonical_id"] == canonical_id for item in chunk):
                        db.execute(update(Memory).where(Memory.id == uuid.UUID(canonical_id)).values({
                            Memory.metadata_: {**values["old"], "merged_from": values["new"]},
                        }))
                db.commit()
                qdrant_set_state([item["id"] for item in chunk], "archived")
        finally:
            owner.write_text("state=released\n", encoding="utf-8")
        print(json.dumps({"run_id": run_id, "clusters": len(clusters), "archived": len(entries), "already_archived": len(skipped_archived), "manifest": str(manifest_path), "canonical_count": len(canonical_metadata)}))
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
