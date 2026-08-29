#!/usr/bin/env bash
set -euo pipefail

umask 077
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
PROXY_URL="${CANDIDATE_PROXY_URL:-${1:-}}"
ALLOWED="${CANDIDATE_ALLOWED_UPSTREAM:-host.docker.internal:20128}"
UNLISTED="${CANDIDATE_UNLISTED_UPSTREAM:-host.docker.internal:9}"
[ -n "$PROXY_URL" ] || { printf '%s\n' 'egress selfcheck: proxy URL is required' >&2; exit 2; }
[ "$ALLOWED" = host.docker.internal:20128 ] || [ "$ALLOWED" = host.docker.internal:11434 ] || {
  printf '%s\n' 'egress selfcheck: allowed destination is outside fixed contract' >&2
  exit 2
}
[ "$UNLISTED" != host.docker.internal:20128 ] && [ "$UNLISTED" != host.docker.internal:11434 ] || {
  printf '%s\n' 'egress selfcheck: unlisted destination is allowlisted' >&2
  exit 2
}

python3 - "$PROXY_URL" "$ALLOWED" "$UNLISTED" <<'PY'
import socket
import sys
import time
from urllib.parse import urlsplit

proxy, allowed, unlisted = sys.argv[1:]
parsed = urlsplit(proxy)
if parsed.scheme != "http" or not parsed.hostname or not parsed.port:
    raise SystemExit("invalid proxy URL")

def request(request_line, host):
    last_error = None
    for attempt in range(15):
        try:
            with socket.create_connection((parsed.hostname, parsed.port), timeout=2) as connection:
                connection.sendall(f"{request_line}\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                response = connection.recv(128)
            break
        except OSError as error:
            last_error = error
            if attempt == 14:
                raise SystemExit(f"proxy connection failed for {host}: {last_error}")
            time.sleep(1)
    return response.split(None, 2)[1].decode() if response.startswith(b"HTTP/") else "0"

approved_status = request("GET /healthz HTTP/1.1", allowed)
if approved_status in {"500", "502", "503", "504", "0"}:
    raise SystemExit(f"approved upstream request failed status={approved_status}")
if request("GET /healthz HTTP/1.1", unlisted) != "403":
    raise SystemExit("unlisted destination was not denied")
if request(f"GET http://{allowed}/healthz HTTP/1.1", allowed) != "400":
    raise SystemExit("absolute-form request was not denied")
if request(f"CONNECT {allowed} HTTP/1.1", allowed) != "405":
    raise SystemExit("CONNECT request was not denied")
with socket.create_connection((parsed.hostname, parsed.port), timeout=15) as connection:
    connection.sendall(f"GET /healthz HTTP/1.1\r\nHost: {allowed}\r\nX-Forwarded-Host: host.invalid\r\nConnection: close\r\n\r\n".encode())
    if connection.recv(128).split()[1].decode() != "403":
        raise SystemExit("forwarded host override was not denied")
PY

[ -f "$SCRIPT_DIR/candidate-egress-proxy/allowlist.json" ] || exit 1
printf '%s\n' 'PASS candidate egress self-check'
