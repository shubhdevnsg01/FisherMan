from fisherman import PhishingDetector


def test_detects_high_risk_phishing_email():
    email = """From: Microsoft Support <support-alert@secure-login.example.xyz>
Subject: Urgent password verification required
Authentication-Results: mx.example; spf=fail dkim=fail dmarc=fail
Content-Type: text/plain; charset=utf-8

Your Office 365 password expires immediately. Verify your account at http://192.0.2.10/login?redirect=https://microsoft.com or your account will be suspended.
"""

    result = PhishingDetector().analyze(email)

    assert result.classification == "phishing"
    assert result.score >= 70
    assert {signal.name for signal in result.signals} >= {
        "email_authentication_failure",
        "ip_address_url",
        "urgent_language",
        "credential_request",
    }


def test_classifies_benign_plain_text_as_safe():
    result = PhishingDetector().analyze("Hi team, lunch is at noon in the cafe. Thanks!")

    assert result.classification == "safe"
    assert result.score < 35
    assert result.urls == ()


def test_detects_dangerous_attachment():
    email = """From: Payroll <payroll@example.com>
Subject: Invoice attached
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="abc"

--abc
Content-Type: text/plain

Please review this invoice.
--abc
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"

fake
--abc--
"""

    result = PhishingDetector().analyze(email)

    assert any(signal.name == "dangerous_attachment" for signal in result.signals)
    assert any(signal.name == "double_extension_attachment" for signal in result.signals)
