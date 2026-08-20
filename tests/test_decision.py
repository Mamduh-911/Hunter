from hunter_agent.decision import decide
from hunter_agent.memory import Finding, Evidence


def test_redirect_confirmed():
    f = Finding("open_redirect", "medium", "https://example.com/?next=x", "next", "candidate", parameter="next")
    d = decide(f, [Evidence("external_redirect", "redirect", True, 45)])
    assert d.status == "confirmed"


def test_xss_reflection_not_confirmed():
    f = Finding("xss_reflected", "high", "https://example.com/?q=x", "q", "candidate", parameter="q")
    d = decide(f, [Evidence("raw_reflection", "reflection", True, 35)])
    assert d.status == "likely"
    assert d.status != "confirmed"


def test_cors_confirmed():
    f = Finding("cors_misconfiguration", "high", "https://example.com", "origin", "candidate")
    d = decide(f, [
        Evidence("evil_origin_reflection", "reflection", True, 35),
        Evidence("credentialed_cors", "credentials", True, 35),
    ])
    assert d.status == "confirmed"
