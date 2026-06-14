from fisherman.detector import PhishingDetector
from fisherman.web import render_page


def test_web_page_renders_input_form():
    html = render_page().decode("utf-8")

    assert "Phishing Email Detection System" in html
    assert "textarea" in html
    assert "Analyze message" in html


def test_web_page_renders_detection_result_for_pasted_message():
    message = "Urgent: verify your password at http://192.0.2.10/login or your account is suspended"
    result = PhishingDetector().analyze(message)

    html = render_page(result, message).decode("utf-8")

    assert "Detection result" in html
    assert result.classification.title() in html
    assert "ip_address_url" in html
    assert message in html
