"""Vercel serverless entrypoint for the FisherMan web UI."""

from __future__ import annotations

import sys
from pathlib import Path

# Vercel executes Python functions from the project root. Adding src keeps this
# dependency-free package importable both on Vercel and in local smoke tests.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from fisherman.web import FisherManRequestHandler  # noqa: E402


class handler(FisherManRequestHandler):
    """Expose FisherMan's request handler as a Vercel Python Function."""
