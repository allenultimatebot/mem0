import importlib.util
from pathlib import Path

import pytest


PROBE = Path(__file__).parents[1] / "scripts" / "probe_write_path.py"
SPEC = importlib.util.spec_from_file_location("probe_write_path", PROBE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def test_l3_verdict_distinguishes_extraction_paths():
    assert probe.l3_verdict({"ok": True, "events": ["ADD"], "memory_count": 1}) == "accepted 1"
    assert probe.l3_verdict({"ok": True, "events": [], "memory_count": None}) == "parse_failed"
    assert probe.l3_verdict({"ok": True, "events": [], "memory_count": 0}) == "empty_extraction"
    assert probe.l3_verdict({"ok": True, "events": [], "memory_count": 1}) == "dedup_skipped"
    assert probe.l3_verdict({"ok": False, "embed_failures": 1, "error_type": "EmbeddingError"}) == "embed_failed"


def test_rest_verdict_keeps_http_and_reason_distinguishable():
    assert probe.verdict(200, {"accepted": 0, "reason": "no_facts_extracted"}) == "rejected-empty"
    assert probe.verdict(503, {"reason": "database_unavailable"}) == "error_http_503_database_unavailable"


def test_probe_write_paths_require_explicit_opt_in():
    assert probe.writes_allowed(False, False) is False
    assert probe.writes_allowed(False, True) is False
    assert probe.writes_allowed(True, True) is False
    assert probe.writes_allowed(True, False) is True


def test_probe_defaults_to_scratch_user(monkeypatch):
    monkeypatch.delenv("OPENMEMORY_PROBE_USER_ID", raising=False)
    assert probe.probe_user_id() == "probe-scratch"


def test_probe_compose_target_requires_explicit_pair():
    assert probe.compose_command() == ["docker", "compose"]
    assert probe.compose_command("test-project", "test-compose.yml") == [
        "docker", "compose", "-p", "test-project", "-f", "test-compose.yml"
    ]
    with pytest.raises(ValueError):
        probe.compose_command("test-project", "")
    with pytest.raises(ValueError):
        probe.compose_command("", "test-compose.yml")
