"""Heuristic phishing email detector with explainable risk signals.

The detector intentionally uses transparent rules instead of a black-box model so
security teams can audit why a message was classified as safe, suspicious, or
phishing.  It can be extended with organization-specific allow/block lists or
fed into a later ML pipeline as a feature extractor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from email import policy
from email.message import Message
from email.parser import BytesParser, Parser
from html import unescape
import ipaddress
import json
import re
from typing import Iterable
from urllib.parse import parse_qs, unquote, urlparse

URL_RE = re.compile(r"https?://[^\s<>'\")]+", re.IGNORECASE)
HTML_TAG_RE = re.compile(r"<[^>]+>")
SUSPICIOUS_TLDS = {"zip", "mov", "click", "country", "gq", "kim", "loan", "rest", "top", "work", "xyz"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "cutt.ly", "rebrand.ly"}
URGENT_TERMS = {
    "urgent", "immediately", "action required", "final notice", "verify", "suspend",
    "locked", "password expires", "unusual activity", "confirm your account",
}
CREDENTIAL_TERMS = {"password", "login", "sign in", "signin", "credential", "2fa", "mfa", "security code"}
FINANCIAL_TERMS = {"invoice", "payment", "wire", "payroll", "bank", "refund", "tax", "purchase order"}
EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar", ".iso", ".img"}
BRAND_DOMAINS = {
    "microsoft": "microsoft.com",
    "office 365": "microsoft.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "docusign": "docusign.com",
}


@dataclass(frozen=True)
class Signal:
    """One explainable detector signal."""

    name: str
    score: int
    detail: str


@dataclass(frozen=True)
class DetectionResult:
    """Classification result returned by :class:`PhishingDetector`."""

    classification: str
    score: int
    confidence: float
    signals: tuple[Signal, ...] = field(default_factory=tuple)
    urls: tuple[str, ...] = field(default_factory=tuple)
    sender: str = ""
    subject: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "classification": self.classification,
            "score": self.score,
            "confidence": self.confidence,
            "sender": self.sender,
            "subject": self.subject,
            "urls": list(self.urls),
            "signals": [signal.__dict__ for signal in self.signals],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


class PhishingDetector:
    """Detect phishing risk in raw RFC 5322 emails or plain message text."""

    def analyze(self, content: str | bytes) -> DetectionResult:
        message = self._parse_email(content)
        subject = str(message.get("subject", "")) if message else ""
        sender = str(message.get("from", "")) if message else ""
        text = self._extract_text(message) if message else self._coerce_text(content)
        headers = self._header_text(message) if message else ""
        urls = tuple(dict.fromkeys(URL_RE.findall(text)))

        signals: list[Signal] = []
        self._score_text(text, signals)
        self._score_urls(urls, text, signals)
        self._score_headers(headers, sender, signals)
        self._score_attachments(message, signals)
        self._score_brand_impersonation(text, sender, urls, signals)

        total = max(0, min(100, sum(signal.score for signal in signals)))
        classification = self._classify(total)
        confidence = round(min(0.99, 0.45 + abs(total - 45) / 100), 2)
        return DetectionResult(classification, total, confidence, tuple(signals), urls, sender, subject)

    def _parse_email(self, content: str | bytes) -> Message | None:
        raw = content if isinstance(content, bytes) else content.encode("utf-8", errors="ignore")
        header_lines = raw.splitlines()[:8]
        common_headers = (b"from:", b"to:", b"subject:", b"date:", b"mime-version:", b"content-type:")
        normalized_headers = [line.lower().lstrip() for line in header_lines]
        if not header_lines or not any(line.startswith(common_headers) for line in normalized_headers):
            return None
        parser = BytesParser(policy=policy.default)
        try:
            return parser.parsebytes(raw)
        except Exception:
            return Parser(policy=policy.default).parsestr(self._coerce_text(content))

    def _coerce_text(self, content: str | bytes) -> str:
        return content.decode("utf-8", errors="ignore") if isinstance(content, bytes) else content

    def _extract_text(self, message: Message) -> str:
        parts: list[str] = []
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_maintype() == "multipart" or part.get_filename():
                    continue
                if part.get_content_type() in {"text/plain", "text/html"}:
                    parts.append(self._payload_to_text(part))
        else:
            parts.append(self._payload_to_text(message))
        return "\n".join(parts)

    def _payload_to_text(self, part: Message) -> str:
        payload = part.get_payload(decode=True)
        charset = part.get_content_charset() or "utf-8"
        if payload is None:
            text = str(part.get_payload())
        else:
            text = payload.decode(charset, errors="ignore")
        if part.get_content_type() == "text/html":
            text = unescape(HTML_TAG_RE.sub(" ", text))
        return text

    def _header_text(self, message: Message) -> str:
        return "\n".join(f"{key}: {value}" for key, value in message.items())

    def _score_text(self, text: str, signals: list[Signal]) -> None:
        lowered = text.lower()
        urgent_hits = [term for term in URGENT_TERMS if term in lowered]
        credential_hits = [term for term in CREDENTIAL_TERMS if term in lowered]
        financial_hits = [term for term in FINANCIAL_TERMS if term in lowered]
        if urgent_hits:
            signals.append(Signal("urgent_language", min(18, 6 * len(urgent_hits)), ", ".join(sorted(urgent_hits))))
        if credential_hits:
            signals.append(Signal("credential_request", min(20, 7 * len(credential_hits)), ", ".join(sorted(credential_hits))))
        if financial_hits:
            signals.append(Signal("financial_lure", min(12, 4 * len(financial_hits)), ", ".join(sorted(financial_hits))))
        if re.search(r"\b(?:gift card|bitcoin|crypto|wire transfer)\b", lowered):
            signals.append(Signal("high_risk_payment_request", 18, "Message requests irreversible or unusual payment."))

    def _score_urls(self, urls: Iterable[str], text: str, signals: list[Signal]) -> None:
        for url in urls:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().strip(".")
            if not host:
                continue
            if self._is_ip_address(host):
                signals.append(Signal("ip_address_url", 18, f"URL uses raw IP address: {host}"))
            domain_parts = host.split(".")
            if domain_parts[-1] in SUSPICIOUS_TLDS:
                signals.append(Signal("suspicious_tld", 10, f".{domain_parts[-1]} domain in {host}"))
            if host in SHORTENERS:
                signals.append(Signal("url_shortener", 12, f"Shortened URL: {host}"))
            if len(domain_parts) > 4:
                signals.append(Signal("deep_subdomain", 8, f"Many subdomains in {host}"))
            if "@" in urlparse(unquote(url)).netloc:
                signals.append(Signal("userinfo_url", 15, f"URL includes userinfo trick: {url}"))
            qs = parse_qs(parsed.query)
            if any(key.lower() in {"redirect", "url", "target", "continue"} for key in qs):
                signals.append(Signal("redirect_parameter", 7, f"URL contains redirect-like parameter: {url}"))

        anchor_mismatch = re.findall(r"<a[^>]+href=['\"](https?://[^'\"]+)['\"][^>]*>(.*?)</a>", text, re.I | re.S)
        for href, label in anchor_mismatch:
            label_urls = URL_RE.findall(HTML_TAG_RE.sub("", label))
            if label_urls and urlparse(label_urls[0]).hostname != urlparse(href).hostname:
                signals.append(Signal("link_text_mismatch", 18, "Visible link destination differs from href."))

    def _score_headers(self, headers: str, sender: str, signals: list[Signal]) -> None:
        lowered = headers.lower()
        if headers and "authentication-results" not in lowered:
            signals.append(Signal("missing_authentication_results", 5, "No Authentication-Results header found."))
        if "spf=fail" in lowered or "dkim=fail" in lowered or "dmarc=fail" in lowered:
            signals.append(Signal("email_authentication_failure", 22, "SPF, DKIM, or DMARC failed."))
        if sender and re.search(r"@(.*\.)?(secure|support|account|billing)-", sender.lower()):
            signals.append(Signal("suspicious_sender", 8, f"Sender appears security-themed: {sender}"))

    def _score_attachments(self, message: Message | None, signals: list[Signal]) -> None:
        if not message:
            return
        for part in message.walk():
            filename = (part.get_filename() or "").lower()
            if any(filename.endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
                signals.append(Signal("dangerous_attachment", 25, f"Executable attachment: {filename}"))
            if re.search(r"\.(pdf|docx?|xlsx?)\.(exe|js|vbs|scr)$", filename):
                signals.append(Signal("double_extension_attachment", 20, f"Double extension attachment: {filename}"))

    def _score_brand_impersonation(self, text: str, sender: str, urls: Iterable[str], signals: list[Signal]) -> None:
        lowered = text.lower()
        sender_lower = sender.lower()
        hosts = {urlparse(url).hostname or "" for url in urls}
        for brand, domain in BRAND_DOMAINS.items():
            if brand in lowered and domain not in sender_lower and not any(host.endswith(domain) for host in hosts):
                signals.append(Signal("brand_impersonation", 14, f"Mentions {brand} without trusted {domain} sender/link."))
                break

    def _is_ip_address(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True

    def _classify(self, score: int) -> str:
        if score >= 70:
            return "phishing"
        if score >= 35:
            return "suspicious"
        return "safe"
