import datetime as dt
from types import SimpleNamespace

import pytest

import scripts.lint_corpus as lint_corpus
from scripts.lint_corpus import classify


def memory(content, categories=(), memory_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"):
    return SimpleNamespace(
        id=memory_id,
        content=content,
        categories=[SimpleNamespace(name=name) for name in categories],
        created_at=dt.datetime.now(dt.timezone.utc),
    )


def test_category_overlay_preserves_project_facts_as_episodic():
    assert classify(memory("User prefers concise answers.", ["preferences"]), {})[0] == "durable"
    assert classify(memory("The current project plan covers Phase 1.", ["goals"]), {})[0] == "episodic"
    assert classify(memory("User's preferred workflow for future slide projects starts with NotebookLM."), {})[0] == "durable"


def test_duplicate_and_one_off_rules_override_tier_overlay():
    item = memory("User prefers concise answers.", ["preferences"])
    assert classify(item, {}, {item.id.replace("-", "")})[0] == "transient-junk"
    assert classify(memory("User asked to open example.com and report what the page displays."), {})[0] == "transient-junk"


def test_mutation_prereqs_refuse_active_backup_lock(tmp_path, monkeypatch):
    lock = tmp_path / ".backup.lock"
    lock.write_text("pid=123\n")
    monkeypatch.setattr(lint_corpus, "BACKUP_LOCK", lock)

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one(self):
            return self.value

    db = SimpleNamespace(execute=lambda statement: Result("wal" if "journal_mode" in str(statement) else 5000))
    with pytest.raises(RuntimeError, match="backup lock is active"):
        lint_corpus.assert_mutation_prereqs(db)
