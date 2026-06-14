"""Command-line interface for FisherMan."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .detector import PhishingDetector


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect phishing risk in email files or stdin.")
    parser.add_argument("email", nargs="?", help="Path to an RFC 5322 email file. Reads stdin when omitted.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--threshold", type=int, default=70, help="Exit with code 2 when score is at or above this value.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    content = Path(args.email).read_bytes() if args.email else sys.stdin.buffer.read()
    result = PhishingDetector().analyze(content)

    if args.json:
        print(result.to_json())
    else:
        print(f"Classification: {result.classification}")
        print(f"Score: {result.score}/100")
        print(f"Confidence: {result.confidence:.2f}")
        if result.sender:
            print(f"Sender: {result.sender}")
        if result.subject:
            print(f"Subject: {result.subject}")
        if result.urls:
            print("URLs:")
            for url in result.urls:
                print(f"  - {url}")
        if result.signals:
            print("Signals:")
            for signal in result.signals:
                print(f"  - {signal.name} (+{signal.score}): {signal.detail}")

    return 2 if result.score >= args.threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
