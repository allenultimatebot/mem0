import importlib.util
from pathlib import Path


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
