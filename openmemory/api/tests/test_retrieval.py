from datetime import UTC, datetime, timedelta

from app.utils.retrieval import apply_tier_recency, relative_cutoff, retrieval_params


def test_relative_cutoff_rejects_flat_and_keeps_peaked():
    candidates = [{"id": "a", "vector_score": 0.9}, {"id": "b", "vector_score": 0.1}]
    assert relative_cutoff(candidates, [0.5] * 10) == []
    assert relative_cutoff(candidates, [0.9, 0.1])


def test_only_episodic_memories_are_demoted_by_age():
    now = datetime.now(UTC)
    candidates = [
        {"id": "old", "tier": "episodic", "created_at": (now - timedelta(days=200)).isoformat()},
        {"id": "new", "tier": "episodic", "created_at": (now - timedelta(days=1)).isoformat()},
        {"id": "durable", "tier": "durable", "created_at": (now - timedelta(days=200)).isoformat()},
        {"id": "legacy", "tier": "unmarked", "created_at": (now - timedelta(days=200)).isoformat()},
    ]
    ranked = [item["id"] for item in apply_tier_recency(candidates, now)]
    assert ranked.index("old") > ranked.index("new")
    assert ranked.index("durable") == 2
    assert ranked.index("legacy") == 3


def test_retrieval_params_fall_back_and_honor_kill_switch(tmp_path, monkeypatch):
    path = tmp_path / "params.json"
    monkeypatch.setenv("OPENMEMORY_PARAMS_FILE", str(path))
    monkeypatch.delenv("OPENMEMORY_SELF_LEARNING", raising=False)
    assert retrieval_params() == {"k": 1.0, "delta": 0.02}
    path.write_text('{"k": 99, "delta": 0}')
    assert retrieval_params() == {"k": 3.0, "delta": 0.02}
    monkeypatch.setenv("OPENMEMORY_SELF_LEARNING", "off")
    assert retrieval_params() == {"k": 1.0, "delta": 0.02}
