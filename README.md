# FisherMan Phishing Email Detection System

FisherMan is a transparent phishing email detection system for scanning RFC 5322 email messages or plain text. It produces a risk score, a safe/suspicious/phishing classification, extracted URLs, and explainable signals that security teams can review.

## Features

- Browser UI for pasting or writing emails/messages and instantly analyzing them.
- Parses raw `.eml` messages, MIME parts, headers, plain text, and HTML bodies.
- Scores phishing indicators such as urgent language, credential requests, failed SPF/DKIM/DMARC, dangerous attachments, suspicious TLDs, URL shorteners, IP-address links, redirect parameters, and brand impersonation.
- Provides JSON output for SIEM/SOAR automation and human-readable CLI output for analysts.
- Uses auditable heuristics that can be extended with organization-specific indicators.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
fisherman samples/phishing.eml --json
```

You can also pipe an email into the detector:

```bash
cat samples/phishing.eml | fisherman
```

## Web UI

Start the browser interface:

```bash
fisherman-web --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080`, paste or write the email/message, and click **Analyze message**. The UI displays the classification, risk score, extracted URLs, sender/subject metadata, and all explainable risk signals.

You can also run the UI without installing the package:

```bash
PYTHONPATH=src python -m fisherman.web
```

## Deploy to Vercel

Yes, FisherMan can be hosted on Vercel. This repository includes a Vercel Python Function entrypoint at `api/web.py` and a `vercel.json` rewrite that sends browser requests to that function.

Deploy with the Vercel CLI:

```bash
npm i -g vercel
vercel login
vercel
```

For production after the preview deploy succeeds:

```bash
vercel --prod
```

Vercel will run the same UI as the local `fisherman-web` command, so visitors can paste or write an email/message in the browser and submit it for phishing analysis.

If Vercel reports that a `functions` pattern does not match any Serverless Functions, remove any stale project-level or local `functions` override and deploy this version. This repository now lets Vercel auto-detect `api/web.py` instead of configuring a `functions` pattern manually.

## Python API

```python
from fisherman import PhishingDetector

result = PhishingDetector().analyze(raw_email_text)
print(result.classification, result.score)
for signal in result.signals:
    print(signal.name, signal.score, signal.detail)
```

## Classification thresholds

| Score | Classification |
| --- | --- |
| 0-34 | safe |
| 35-69 | suspicious |
| 70-100 | phishing |

The CLI exits with status code `2` when the score is greater than or equal to `--threshold` so it can block risky messages in automation.

## Development

```bash
pip install -e .
python -m pytest
```
