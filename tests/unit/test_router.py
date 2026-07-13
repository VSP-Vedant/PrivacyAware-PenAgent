"""Unit tests for LLM Router (Member A)."""

from src.router.llm_router import route


def test_router_low_risk() -> None:
    decision = route("Normal service summary", "SUMMARIZE")
    assert decision.route == "LOCAL"
    assert decision.model == "llama3:8b"


def test_router_high_sensitivity() -> None:
    decision = route("Session token abc123 and IP 10.129.1.100", "PRIV_ESC_REASONING")
    assert decision.route == "CLOUD"
    assert decision.model == "gpt-4o"


def test_router_high_complexity() -> None:
    decision = route("Plan multi-CVE chain", "MULTI_CVE_CHAIN")
    assert decision.route == "CLOUD"


def test_sensitivity_scoring() -> None:
    from src.router.sensitivity import classify_sensitivity

    assert classify_sensitivity("Normal text") == 0.0
    assert classify_sensitivity("10.10.10.5 password") > 0.4
