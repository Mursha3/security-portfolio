"""Integration tests for the network layer.

A throwaway server bound to 127.0.0.1 on an ephemeral port keeps these tests
hermetic: no outbound traffic, no dependence on a third-party host.
"""

from __future__ import annotations

import http.server
import socket
import threading
from typing import Iterator

import pytest

from webaudit.checks import audit, clean_checks
from webaudit.fetch import (
    fetch,
    fetch_allowed_methods,
    fetch_text,
    normalize_url,
)


class Handler(http.server.BaseHTTPRequestHandler):
    """Deterministic fixture: redirect, HTML page, robots.txt and OPTIONS."""

    def do_GET(self) -> None:  # noqa: N802 - name required by BaseHTTPRequestHandler
        if self.path == "/":
            self.send_response(301)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        if self.path == "/final":
            body = b"<html><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Fixture", "header-check")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_OPTIONS(self) -> None:  # noqa: N802 - name required by BaseHTTPRequestHandler
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()

    def log_message(self, *args) -> None:  # noqa: D102 - silence test output
        return


@pytest.fixture()
def server() -> Iterator[str]:
    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_normalize_url_adds_https_to_a_bare_host():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_an_explicit_scheme():
    assert normalize_url("http://example.com") == "http://example.com"


def test_fetch_follows_the_redirect_chain(server: str):
    result = fetch(f"{server}/")
    assert [hop.status for hop in result.hops] == [301, 200]
    assert result.final_url.endswith("/final")
    assert result.status == 200
    assert result.error is None


def test_fetch_captures_body_and_headers(server: str):
    result = fetch(f"{server}/final")
    assert "ok" in result.body
    headers = dict((name.lower(), value) for name, value in result.headers)
    assert headers["x-fixture"] == "header-check"
    assert result.resolved_ips == ["127.0.0.1"]


def test_fetch_reports_transport_errors_without_raising():
    # Bind and immediately release a port so nothing is listening on it.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    result = fetch(f"http://127.0.0.1:{port}/", timeout=2)
    assert result.hops == []
    assert result.error
    assert result.status == 0


def test_fetch_text_reads_a_public_file(server: str):
    content = fetch_text(f"{server}/robots.txt")
    assert content is not None
    assert "Disallow: /admin" in content


def test_fetch_text_returns_none_when_absent(server: str):
    assert fetch_text(f"{server}/nope.txt") is None


def test_fetch_allowed_methods_reads_the_allow_header(server: str):
    assert fetch_allowed_methods(f"{server}/final") == "GET, POST, OPTIONS"


def test_end_to_end_audit_against_the_local_server(server: str):
    result = fetch(f"{server}/")
    findings = audit(
        result,
        security_txt=None,
        robots=fetch_text(f"{server}/robots.txt"),
        allow_header=fetch_allowed_methods(f"{server}/final"),
    )
    found = {finding.check_id for finding in findings}
    # Plaintext target with no security headers and no security.txt.
    assert {"transport-https", "csp", "nosniff"} <= found
    assert "security-txt" in found
    assert "robots-sensitive" in found
    passed = dict(clean_checks(findings))
    assert "methods-trace" in passed
