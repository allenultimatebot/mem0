import json
import os
import uuid
from types import SimpleNamespace

os.environ.setdefault("OPENAI_API_KEY", "test-key")

import pytest
from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import AccessControl, App, Config as ConfigModel, Memory, MemoryState, User
from app.routers.config import get_config_from_db
from app.security import configured_api_token, maintenance_lock_held, request_has_valid_token, request_is_mutating
from app.utils.memory import DEFAULT_CUSTOM_INSTRUCTIONS
from app.utils.permissions import accessible_memory_id_set, check_memory_access_permissions


def _request(headers=None):
    raw_headers = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw_headers})


def test_api_token_supports_file_and_bearer_case(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("test-token\n", encoding="utf-8")
    monkeypatch.setenv("OPENMEMORY_API_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("OPENMEMORY_API_TOKEN", raising=False)

    assert configured_api_token() == "test-token"
    assert request_has_valid_token(_request({"Authorization": "bearer test-token"}))
    assert not request_has_valid_token(_request({"Authorization": "Bearer wrong"}))


def test_maintenance_lock_blocks_mutating_requests(monkeypatch, tmp_path):
    lock = tmp_path / "maintenance.lock"
    lock.mkdir()
    (lock / "owner").write_text("state=held\n", encoding="utf-8")
    monkeypatch.setenv("OPENMEMORY_MAINTENANCE_LOCK", str(lock))

    request = Request({"type": "http", "method": "POST", "path": "/api/v1/memories/", "headers": []})
    assert maintenance_lock_held()
    assert request_is_mutating(request)

    (lock / "owner").write_text("state=released\n", encoding="utf-8")
    assert not maintenance_lock_held()


def test_null_custom_instructions_are_migrated():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(ConfigModel(key="main", value={"openmemory": {"custom_instructions": None}, "mem0": {}}))
    session.commit()

    config = get_config_from_db(session)
    session.expire_all()

    assert config["openmemory"]["custom_instructions"] == DEFAULT_CUSTOM_INSTRUCTIONS
    assert session.query(ConfigModel).filter(ConfigModel.key == "main").one().value["openmemory"]["custom_instructions"] == DEFAULT_CUSTOM_INSTRUCTIONS


def test_memory_client_receives_custom_instructions(monkeypatch):
    from app.utils import memory as memory_utils

    captured = {}

    class Query:
        def filter(self, *_):
            return self

        def first(self):
            return SimpleNamespace(value={"openmemory": {"custom_instructions": "sentinel policy"}})

    class Session:
        def query(self, *_):
            return Query()

        def close(self):
            pass

    class FakeMemory:
        @staticmethod
        def from_config(config_dict):
            captured.update(config_dict)
            return object()

    monkeypatch.setattr(memory_utils, "SessionLocal", Session)
    monkeypatch.setattr(memory_utils, "Memory", FakeMemory)
    monkeypatch.setattr(memory_utils, "get_default_memory_config", lambda: {})
    monkeypatch.setattr(memory_utils, "_parse_environment_variables", lambda config: config)
    monkeypatch.setattr(memory_utils, "_memory_client", None)
    monkeypatch.setattr(memory_utils, "_config_hash", None)

    memory_utils.get_memory_client()

    assert captured["custom_instructions"] == "sentinel policy"


@pytest.mark.asyncio
async def test_empty_acl_does_not_return_vector_hits(monkeypatch):
    from app import mcp_server

    memory_id = uuid.uuid4()
    user_id = uuid.uuid4()
    app_id = uuid.uuid4()
    memory = SimpleNamespace(id=memory_id)
    hit = SimpleNamespace(
        id=str(memory_id),
        score=0.9,
        payload={"data": "must stay hidden", "hash": "hash"},
    )
    client = SimpleNamespace(
        embedding_model=SimpleNamespace(embed=lambda *_: [0.1]),
        vector_store=SimpleNamespace(search=lambda **_: [hit]),
    )

    class Query:
        def filter(self, *_):
            return self

        def all(self):
            return [memory]

    class Session:
        def query(self, *_):
            return Query()

        def commit(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(mcp_server, "get_memory_client_safe", lambda: client)
    monkeypatch.setattr(mcp_server, "SessionLocal", Session)
    monkeypatch.setattr(
        mcp_server,
        "get_user_and_app",
        lambda *_args, **_kwargs: (SimpleNamespace(id=user_id), SimpleNamespace(id=app_id)),
    )
    monkeypatch.setattr(mcp_server, "accessible_memory_id_set", lambda *_: set())
    logged = []
    monkeypatch.setattr(mcp_server, "log_search", lambda *args: logged.append(args))

    user_token = mcp_server.user_id_var.set("allen_bot")
    app_token = mcp_server.client_name_var.set("codex")
    try:
        result = json.loads(await mcp_server.search_memory("private query"))
    finally:
        mcp_server.user_id_var.reset(user_token)
        mcp_server.client_name_var.reset(app_token)

    assert result == {"results": []}
    assert logged and logged[0][0] == "private query" and logged[0][1] == 0


def test_batch_acl_matches_predicate_for_missing_paused_deny_all_and_archived(monkeypatch):
    from app import models

    monkeypatch.setattr(models, "get_categories_for_memory", lambda *_args: [])
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    user = User(user_id="acl-owner")
    active = App(owner=user, name="active")
    paused = App(owner=user, name="paused", is_active=False)
    session.add_all([user, active, paused])
    session.flush()
    allowed = Memory(user=user, app=active, content="allowed", state=MemoryState.active)
    archived = Memory(user=user, app=active, content="archived", state=MemoryState.archived)
    denied = Memory(user=user, app=active, content="denied", state=MemoryState.active)
    session.add_all([allowed, archived, denied])
    session.flush()
    session.add_all([
        AccessControl(
            subject_type="app", subject_id=active.id, object_type="memory", object_id=allowed.id, effect="allow"
        ),
        AccessControl(
            subject_type="app", subject_id=active.id, object_type="memory", object_id=archived.id, effect="allow"
        ),
        AccessControl(
            subject_type="app", subject_id=active.id, object_type="memory", object_id=None, effect="deny"
        ),
    ])
    session.commit()

    assert accessible_memory_id_set(session, uuid.uuid4()) == set()
    assert accessible_memory_id_set(session, paused.id) == set()
    assert accessible_memory_id_set(session, active.id) == set()

    session.query(AccessControl).filter(AccessControl.subject_id == active.id).delete()
    session.commit()
    ids = accessible_memory_id_set(session, active.id)
    assert ids == {allowed.id, denied.id}
    assert all(check_memory_access_permissions(session, memory, active.id) == (memory.id in ids)
               for memory in (allowed, archived, denied))
    session.close()


def test_write_rejection_has_stable_safe_shape():
    from app.routers.memories import _write_rejected

    assert _write_rejected("client_unavailable", RuntimeError("secret upstream detail")) == {
        "accepted": 0,
        "reason": "client_unavailable",
    }


def test_write_failure_reason_distinguishes_database_errors():
    from app.routers.memories import _write_failure_reason
    from sqlalchemy.exc import OperationalError

    database_error = OperationalError("select", {}, RuntimeError("disk I/O error"))
    assert _write_failure_reason(database_error) == "database_unavailable"
    assert _write_failure_reason(RuntimeError("provider unavailable")) == "extraction_error"


def test_search_log_is_owner_only_and_never_raises(tmp_path, monkeypatch):
    from app.utils.search_log import log_search

    path = tmp_path / "nested" / "search-log.jsonl"
    monkeypatch.setenv("OPENMEMORY_SEARCH_LOG", str(path))
    log_search("no match", 0, 12.3456, None)

    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text()) == {
        "timestamp": json.loads(path.read_text())["timestamp"],
        "query": "no match",
        "n_results": 0,
        "latency_ms": 12.346,
        "top_score": None,
        "n_dropped": 0,
    }

    monkeypatch.setenv("OPENMEMORY_SEARCH_LOG", str(tmp_path))
    log_search("must not break", 0, 0, None)


def test_autosave_gate_blocks_env_credentials_and_allows_episodic_facts():
    import importlib.util
    from pathlib import Path

    path = Path.home() / ".claude/hooks/mem0-autosave.py"
    if not path.exists():
        pytest.skip("personal autosave hook is not mounted in the API container")
    spec = importlib.util.spec_from_file_location("autosave_phase2", path)
    autosave = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(autosave)

    for value in (
        "LARK_ANNOUNCE_SECRET=abcdefgh",
        "DB_PASSWORD='abcdefgh'",
        "OPENAI_API_KEY=sk-abcdefgh",
        "AUTHORIZATION=Bearer-abcdefgh",
        "MY_ACCESS_TOKEN=abcdefgh",
    ):
        assert autosave._contains_secret(value)
    assert not autosave._contains_secret("The deployment completed successfully today.")
    assert autosave._is_memory_worthy_user_text("The deployment completed successfully today.")


def test_autosave_offsets_are_versioned(tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path

    path = Path.home() / ".claude/hooks/mem0-autosave.py"
    if not path.exists():
        pytest.skip("personal autosave hook is not mounted in the API container")
    spec = importlib.util.spec_from_file_location("autosave_offsets", path)
    autosave = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(autosave)
    monkeypatch.setattr(autosave, "STATE_DIR", str(tmp_path))
    autosave.save_offset("session", 7)
    assert autosave.load_offset("session") == 7
    (tmp_path / "session.offset").write_text('{"gate_version": 1, "offset": 7}')
    assert autosave.load_offset("session") == 0
