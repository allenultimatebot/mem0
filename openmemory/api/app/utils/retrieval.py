import math
import json
import os
from datetime import UTC, datetime

DEFAULT_HALF_LIFE_DAYS = 90
MAX_RECENCY_DEMOTION = 5
DEFAULT_CUTOFF_K = 1.0
DEFAULT_CUTOFF_DELTA = 0.02


def apply_tier_recency(candidates, now: datetime | None = None, half_life_days: float = DEFAULT_HALF_LIFE_DAYS):
    now = now or datetime.now(UTC)
    ranked = []
    for rank, candidate in enumerate(candidates):
        tier = candidate.get("tier", "unmarked")
        demotion = 0
        if tier == "episodic":
            created_at = candidate.get("created_at")
            if isinstance(created_at, str):
                try:
                    created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                except ValueError:
                    created_at = None
            if created_at:
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=UTC)
                age_days = max(0, (now - created_at).total_seconds() / 86400)
                demotion = min(MAX_RECENCY_DEMOTION, int(age_days / half_life_days))
        ranked.append((rank + demotion, rank, candidate))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return [candidate for _, _, candidate in ranked]


def relative_cutoff(candidates, vector_scores, k: float = DEFAULT_CUTOFF_K, delta: float = DEFAULT_CUTOFF_DELTA):
    if not candidates or not vector_scores:
        return []
    top_scores = sorted(vector_scores, reverse=True)[:10]
    mean = sum(top_scores) / len(top_scores)
    variance = sum((score - mean) ** 2 for score in top_scores) / len(top_scores)
    top_score = top_scores[0]
    if variance == 0:
        return []
    if top_score < mean + k * math.sqrt(variance):
        return []
    return [candidate for candidate in candidates if candidate.get("vector_score", 0) >= top_score - delta]


_params_mtime = None
_params = None


def retrieval_params():
    global _params_mtime, _params
    defaults = {"k": DEFAULT_CUTOFF_K, "delta": DEFAULT_CUTOFF_DELTA}
    if os.environ.get("OPENMEMORY_SELF_LEARNING", "on").lower() == "off":
        return defaults
    path = os.environ.get("OPENMEMORY_PARAMS_FILE", "/usr/src/openmemory/data/retrieval-params.json")
    try:
        mtime = os.stat(path).st_mtime_ns
        if _params is not None and mtime == _params_mtime:
            return _params
        value = json.loads(open(path, encoding="utf-8").read())
        k = min(3.0, max(0.5, float(value["k"])))
        delta = min(0.20, max(0.02, float(value["delta"])))
        _params = {"k": k, "delta": delta}
        _params_mtime = mtime
        return _params
    except Exception:
        _params = defaults
        _params_mtime = None
        return defaults
