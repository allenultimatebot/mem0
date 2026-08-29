#!/usr/bin/env python3
import json
import logging
import os
import pathlib
import re
import urllib.parse
from http import HTTPStatus
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ALLOWED_UPSTREAMS = frozenset(
    {
        "host.docker.internal:20128",
        "host.docker.internal:11434",
    }
)
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+:[0-9]{1,5}$")


def load_allowlist(path):
    document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    upstreams = document.get("upstreams")
    if not isinstance(upstreams, list) or frozenset(upstreams) != ALLOWED_UPSTREAMS or len(upstreams) != 2:
        raise ValueError("allowlist must contain exactly the approved upstreams")
    if any(not isinstance(value, str) or not HOST_RE.fullmatch(value) for value in upstreams):
        raise ValueError("allowlist contains an invalid host")
    return ALLOWED_UPSTREAMS


def logger_for(log_dir):
    pathlib.Path(log_dir).mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(pathlib.Path(log_dir) / "connections.jsonl", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("candidate-egress")
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    return logger


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        return

    def _record(self, decision, status, upstream=None):
        self.server.audit.info(
            json.dumps(
                {
                    "decision": decision,
                    "method": self.command,
                    "status": status,
                    "upstream": upstream or "[redacted]",
                },
                sort_keys=True,
            )
        )

    def _deny(self, status, reason):
        self._record(reason, status)
        body = b"candidate egress denied\n"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _target(self):
        if self.command == "CONNECT":
            self._deny(HTTPStatus.METHOD_NOT_ALLOWED, "connect_denied")
            return None
        if not self.path.startswith("/") or self.path.startswith("//"):
            self._deny(HTTPStatus.BAD_REQUEST, "absolute_form_denied")
            return None
        host = self.headers.get("Host", "")
        if any(name.lower() in {"forwarded", "x-forwarded-host", "x-forwarded-proto", "proxy-authorization", "x-proxy-upstream"} for name in self.headers.keys()):
            self._deny(HTTPStatus.FORBIDDEN, "destination_override_denied")
            return None
        if len(self.headers.get_all("Host", [])) != 1 or host not in self.server.allowlist:
            self._deny(HTTPStatus.FORBIDDEN, "destination_denied")
            return None
        return host

    def _forward(self):
        host = self._target()
        if host is None:
            return
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.scheme or parsed.netloc:
            self._deny(HTTPStatus.BAD_REQUEST, "absolute_form_denied")
            return
        length = self.headers.get("Content-Length")
        if length is not None:
            try:
                length = int(length)
            except ValueError:
                self._deny(HTTPStatus.BAD_REQUEST, "invalid_content_length")
                return
            if length < 0 or length > self.server.max_body_bytes:
                self._deny(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_limit")
                return
        else:
            length = 0
        body = self.rfile.read(length) if length else None
        headers = {"Host": host, "Connection": "close"}
        for name in ("Accept", "Content-Type", "Content-Length", "User-Agent"):
            value = self.headers.get(name)
            if value is not None:
                headers[name] = value
        try:
            upstream_host, upstream_port = host.rsplit(":", 1)
            connection = HTTPConnection(upstream_host, int(upstream_port), timeout=self.server.timeout)
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(self.server.max_body_bytes + 1)
            if len(response_body) > self.server.max_body_bytes:
                self._deny(HTTPStatus.BAD_GATEWAY, "response_limit")
                return
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() in {"connection", "keep-alive", "transfer-encoding"}:
                    continue
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response_body)
            self._record("allowed", response.status, host)
        except Exception:
            self._deny(HTTPStatus.BAD_GATEWAY, "upstream_error")

    do_GET = _forward
    do_HEAD = _forward
    do_OPTIONS = _forward
    do_POST = _forward
    do_PUT = _forward
    do_PATCH = _forward
    do_DELETE = _forward

    def do_CONNECT(self):
        self._deny(HTTPStatus.METHOD_NOT_ALLOWED, "connect_denied")


def main():
    config = os.environ.get("PROXY_CONFIG", "/proxy/allowlist.json")
    log_dir = os.environ.get("PROXY_LOG_DIR", "/proxy/logs")
    allowlist = load_allowlist(config)
    servers = []
    for port in (20128, 11434):
        server = ThreadingHTTPServer(("0.0.0.0", port), ProxyHandler)
        server.allowlist = allowlist
        server.audit = logger_for(log_dir)
        server.timeout = 15
        server.max_body_bytes = 4 * 1024 * 1024
        servers.append(server)
    for server in servers:
        import threading

        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()
