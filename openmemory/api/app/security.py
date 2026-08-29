import hmac
import os
from pathlib import Path

from fastapi import Request


def configured_api_token() -> str:
    token_file = os.environ.get("OPENMEMORY_API_TOKEN_FILE")
    if token_file:
        try:
            token = Path(token_file).read_text(encoding="utf-8").strip()
        except OSError:
            token = ""
        if token:
            return token
    return os.environ.get("OPENMEMORY_API_TOKEN", "").strip()


def request_has_valid_token(request: Request) -> bool:
    expected = configured_api_token()
    if not expected:
        return False

    authorization = request.headers.get("authorization", "")
    scheme, _, credential = authorization.partition(" ")
    provided = credential.strip() if scheme.lower() == "bearer" else ""
    if not provided:
        provided = request.headers.get("x-openmemory-token", "").strip()
    return bool(provided) and hmac.compare_digest(provided, expected)


def maintenance_lock_held() -> bool:
    lock = Path(os.environ.get("OPENMEMORY_MAINTENANCE_LOCK", "/usr/src/openmemory/.openmemory-maintenance.lock"))
    owner = lock / "owner"
    try:
        return lock.is_dir() and owner.is_file() and "state=held" in owner.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False


def request_is_mutating(request: Request) -> bool:
    return request.method not in {"GET", "HEAD", "OPTIONS"} and request.url.path != "/healthz"
