import json
import os
from datetime import UTC, datetime
from pathlib import Path


def log_search(query: str, n_results: int, latency_ms: float, top_score: float | None, n_dropped: int = 0) -> None:
    try:
        path = Path(os.environ.get("OPENMEMORY_SEARCH_LOG", "/usr/src/openmemory/data/search-log.jsonl"))
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        with path.open("a", encoding="utf-8") as handle:
            os.chmod(path, 0o600)
            handle.write(json.dumps({
                "timestamp": datetime.now(UTC).isoformat(),
                "query": query,
                "n_results": n_results,
                "latency_ms": round(latency_ms, 3),
                "top_score": top_score,
                "n_dropped": n_dropped,
            }, ensure_ascii=False) + "\n")
    except Exception:
        pass
