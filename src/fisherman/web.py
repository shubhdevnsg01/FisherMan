"""Tiny web UI for analyzing pasted emails and messages."""

from __future__ import annotations

from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
import argparse

from .detector import DetectionResult, PhishingDetector

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080


def render_page(result: DetectionResult | None = None, message: str = "") -> bytes:
    """Render the analyzer page as UTF-8 HTML."""
    result_html = ""
    if result:
        signal_rows = "".join(
            f"<tr><td>{escape(signal.name)}</td><td>+{signal.score}</td><td>{escape(signal.detail)}</td></tr>"
            for signal in result.signals
        ) or "<tr><td colspan='3'>No risk signals were detected.</td></tr>"
        url_items = "".join(f"<li>{escape(url)}</li>" for url in result.urls) or "<li>No URLs found.</li>"
        result_html = f"""
        <section class="card result {escape(result.classification)}">
          <div class="result-header">
            <div>
              <p class="eyebrow">Detection result</p>
              <h2>{escape(result.classification.title())}</h2>
            </div>
            <div class="score" aria-label="Risk score">{result.score}<span>/100</span></div>
          </div>
          <p><strong>Confidence:</strong> {result.confidence:.2f}</p>
          <p><strong>Sender:</strong> {escape(result.sender or "Not provided")}</p>
          <p><strong>Subject:</strong> {escape(result.subject or "Not provided")}</p>
          <h3>Extracted URLs</h3>
          <ul>{url_items}</ul>
          <h3>Explainable signals</h3>
          <table>
            <thead><tr><th>Signal</th><th>Score</th><th>Details</th></tr></thead>
            <tbody>{signal_rows}</tbody>
          </table>
        </section>
        """

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FisherMan Phishing Detector</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    body {{ margin: 0; background: #eef5ff; color: #14213d; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 40px 20px; }}
    .hero {{ display: grid; grid-template-columns: 1.2fr .8fr; gap: 24px; align-items: stretch; }}
    .card {{ background: #fff; border: 1px solid #d9e6f7; border-radius: 24px; box-shadow: 0 18px 50px rgba(20,33,61,.08); padding: 28px; }}
    h1 {{ font-size: clamp(2rem, 5vw, 4rem); margin: 0 0 12px; line-height: .95; }}
    h2 {{ margin: 0; font-size: 2rem; }}
    h3 {{ margin-top: 24px; }}
    .eyebrow {{ color: #1769aa; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; margin: 0 0 8px; }}
    textarea {{ box-sizing: border-box; width: 100%; min-height: 320px; resize: vertical; border-radius: 18px; border: 1px solid #b7c8de; padding: 16px; font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    button {{ margin-top: 16px; border: 0; border-radius: 999px; background: #1769aa; color: #fff; font-weight: 800; padding: 14px 24px; cursor: pointer; }}
    button:hover {{ background: #0f4f83; }}
    .tips {{ background: linear-gradient(135deg, #14213d, #1769aa); color: white; }}
    .tips ul {{ padding-left: 22px; line-height: 1.8; }}
    .result {{ margin-top: 24px; }}
    .result-header {{ display: flex; justify-content: space-between; gap: 20px; align-items: center; }}
    .score {{ display: grid; place-items: center; width: 112px; height: 112px; border-radius: 50%; background: #eef5ff; color: #14213d; font-size: 2.4rem; font-weight: 900; }}
    .score span {{ display: block; font-size: .9rem; }}
    .safe .score {{ background: #d8f5df; color: #126b2f; }}
    .suspicious .score {{ background: #fff2cc; color: #936300; }}
    .phishing .score {{ background: #ffe0e0; color: #b00020; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 14px; }}
    th, td {{ border-bottom: 1px solid #e7eef7; padding: 12px; text-align: left; vertical-align: top; }}
    th {{ background: #f5f9ff; }}
    @media (max-width: 820px) {{ .hero {{ grid-template-columns: 1fr; }} .result-header {{ align-items: flex-start; flex-direction: column; }} }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="card">
        <p class="eyebrow">FisherMan</p>
        <h1>Phishing Email Detection System</h1>
        <p>Paste a raw email, email headers, or any suspicious message below. FisherMan analyzes the content and catches phishing indicators with explainable signals.</p>
        <form method="post" action="/analyze">
          <label for="message"><strong>Email or message content</strong></label>
          <textarea id="message" name="message" placeholder="Paste the suspicious email or message here...">{escape(message)}</textarea>
          <button type="submit">Analyze message</button>
        </form>
      </div>
      <aside class="card tips">
        <p class="eyebrow">What it catches</p>
        <ul>
          <li>Urgent credential and account-verification lures</li>
          <li>Suspicious links, raw IP URLs, redirect tricks, and risky TLDs</li>
          <li>Failed SPF/DKIM/DMARC authentication headers</li>
          <li>Executable and double-extension attachments in raw emails</li>
          <li>Brand impersonation patterns</li>
        </ul>
      </aside>
    </section>
    {result_html}
  </main>
</body>
</html>"""
    return html.encode("utf-8")


class FisherManRequestHandler(BaseHTTPRequestHandler):
    detector = PhishingDetector()

    def do_GET(self) -> None:  # noqa: N802 - http.server method name
        if self.path not in {"/", "/analyze"}:
            self.send_error(404, "Not found")
            return
        self._send_html(render_page())

    def do_POST(self) -> None:  # noqa: N802 - http.server method name
        if self.path != "/analyze":
            self.send_error(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="ignore")
        message = parse_qs(body).get("message", [""])[0]
        result = self.detector.analyze(message)
        self._send_html(render_page(result, message))

    def log_message(self, format: str, *args: object) -> None:
        """Use the default server behavior but keep the type checker happy."""
        super().log_message(format, *args)

    def _send_html(self, content: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the FisherMan phishing detector web UI.")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Host to bind. Default: {DEFAULT_HOST}")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port to bind. Default: {DEFAULT_PORT}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    server = ThreadingHTTPServer((args.host, args.port), FisherManRequestHandler)
    print(f"FisherMan web UI running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down FisherMan web UI")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
