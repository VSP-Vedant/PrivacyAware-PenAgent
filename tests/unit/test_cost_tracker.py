"""Unit tests for cost tracker (Member A)."""

import pytest

from src.router.cost_tracker import cost_tracker


@pytest.fixture(autouse=True)
def reset_tracker():
    """Reset tracker before every test."""
    cost_tracker.reset()
    yield
    cost_tracker.reset()


def test_record_call():
    cost_tracker.record_call("gpt-4o", 1200, 450)
    cost_tracker.record_call("llama3:8b", 800, 320)

    entries = cost_tracker.get_detailed_log()
    assert len(entries) == 2
    assert entries[0]["model"] == "gpt-4o"
    assert entries[1]["model"] == "llama3:8b"
    assert entries[0]["cost_usd"] > 0
    assert entries[1]["cost_usd"] == 0.0


def test_get_summary():
    summary = cost_tracker.get_summary()
    assert "Cost Summary" in summary
    assert "Total Calls" in summary
    assert "Total Input Tokens" in summary
    assert "Total Output Tokens" in summary
    assert "Total Cost" in summary
    assert "Cloud Usage" in summary


def test_reset():
    cost_tracker.record_call("gpt-4o", 100, 50)
    cost_tracker.reset()
    assert len(cost_tracker.get_detailed_log()) == 0
    assert (
        cost_tracker.get_summary()
        == "Cost Summary:\n  Total Calls: 0\n  Total Input Tokens: 0\n  Total Output Tokens: 0\n  Total Cost: $0.000000\n  Cloud Usage: 0 calls\n"
    )
