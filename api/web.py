"""Vercel serverless entrypoint for the FisherMan web UI."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler
import sys
from pathlib import Path
from urllib.parse import parse_qs

# Vercel executes Python functions from the project root. Adding src keeps this
# dependency-free package importable both on Vercel and in local smoke tests.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from fisherman.detector import PhishingDetector  # noqa: E402
from fisherman.web import render_page  # noqa: E402


class handler(BaseHTTPRequestHandler):
    """Expose FisherMan's UI as a Vercel Python Function."""

    detector = PhishingDetector()

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path not in {"/", "/analyze"}:
            self.send_error(404, "Not found")
            return
        self._send_html(render_page())

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path != "/analyze":
            self.send_error(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="ignore")
        message = parse_qs(body).get("message", [""])[0]
        self._send_html(render_page(self.detector.analyze(message), message))

    def _send_html(self, content: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)
