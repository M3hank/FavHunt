"""Shared pytest fixtures (no network access required)."""

from __future__ import annotations

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class _QuietServer(ThreadingHTTPServer):
    """Threaded server that never prints tracebacks for aborted TLS probes."""

    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):  # noqa: D102
        pass


def _build_handler(routes):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def handle_one_request(self):  # noqa: D102
            # A plain-HTTP test server cannot answer a TLS ClientHello. Detect
            # it (first byte 0x16) and close immediately so HTTPS-first probing
            # fails fast instead of waiting for the client timeout.
            try:
                self.connection.settimeout(2)
                first = self.connection.recv(1, socket.MSG_PEEK)
                self.connection.settimeout(None)
            except OSError:
                self.close_connection = True
                return
            if first == b"\x16":
                self.close_connection = True
                return
            super().handle_one_request()

        def do_GET(self):  # noqa: D102
            path = self.path.split("?", 1)[0]
            status, content_type, body = routes.get(
                path, (404, "text/plain; charset=utf-8", b"not found")
            )
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # noqa: D102
            pass

    return Handler


@pytest.fixture
def make_server():
    """Factory fixture: ``make_server(routes)`` returns a live local server."""
    servers = []

    def _start(routes):
        server = _QuietServer(("127.0.0.1", 0), _build_handler(routes))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return server

    yield _start

    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def host_of(server) -> str:
    """Return ``host:port`` for a local test server."""
    return f"127.0.0.1:{server.server_address[1]}"
