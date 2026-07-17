"""Unit tests for the Cost Tracker module.

This test suite verifies token tracking, cost calculations, and budget enforcement.
"""

from __future__ import annotations

import os
from unittest.mock import patch
from src.router.cost_tracker import CostTracker


def test_initialization() -> None:
    """Test cost tracker initialization default and overrides."""
    # Test custom value passing
    tracker = CostTracker(max_cloud_tokens=1000)
    assert tracker.max_cloud_tokens == 1000
    assert tracker.total_input_tokens == 0
    assert tracker.total_output_tokens == 0
    assert tracker.total_cost_usd == 0.0

    # Test loading from env
    with patch.dict(os.environ, {"MAX_CLOUD_TOKENS_PER_RUN": "25000"}):
        tracker_env = CostTracker()
        assert tracker_env.max_cloud_tokens == 25000


def test_local_run_cost() -> None:
    """Test that local LLM invocations result in zero cost."""
    tracker = CostTracker()
    cost = tracker.add_run(
        model="llama3:8b",
        input_tokens=500,
        output_tokens=300,
        latency_ms=120.0,
    )
    assert cost == 0.0
    assert tracker.total_input_tokens == 0
    assert tracker.total_output_tokens == 0
    assert tracker.total_cost_usd == 0.0


def test_cloud_run_cost() -> None:
    """Test that cloud LLM invocations calculate and accumulate cost correctly."""
    tracker = CostTracker()

    # pricing for gpt-4o: ($2.50 input, $10.00 output) per 1M tokens
    # input: 100,000 tokens = $0.25
    # output: 50,000 tokens = $0.50
    # expected: $0.75
    cost = tracker.add_run(
        model="gpt-4o",
        input_tokens=100000,
        output_tokens=50000,
        latency_ms=2500.0,
    )
    assert cost == 0.75
    assert tracker.total_input_tokens == 100000
    assert tracker.total_output_tokens == 50000
    assert tracker.total_cost_usd == 0.75


def test_unknown_model_fallback() -> None:
    """Test pricing fallback logic for unknown models."""
    tracker = CostTracker()

    # Unknown cloud model should fallback to gpt-4o pricing
    cost = tracker.add_run(
        model="gpt-unknown-cloud",
        input_tokens=100000,
        output_tokens=50000,
    )
    assert cost == 0.75

    # Unknown local model should fallback to zero pricing
    cost_local = tracker.add_run(
        model="local-custom-llama",
        input_tokens=50000,
        output_tokens=25000,
    )
    assert cost_local == 0.0


def test_budget_enforcement() -> None:
    """Test budget limit detection."""
    tracker = CostTracker(max_cloud_tokens=10000)

    assert not tracker.is_budget_exceeded()

    # Add cloud run near limit: 5000 + 4000 = 9000
    tracker.add_run(model="gpt-4o", input_tokens=5000, output_tokens=4000)
    assert not tracker.is_budget_exceeded()

    # Add run pushing over limit: 9000 + 2000 = 11000
    tracker.add_run(model="gpt-4o-mini", input_tokens=1000, output_tokens=1000)
    assert tracker.is_budget_exceeded()


def test_reset() -> None:
    """Test resetting stats to zero."""
    tracker = CostTracker()
    tracker.add_run(model="gpt-4o", input_tokens=1000, output_tokens=1000)
    assert tracker.total_cost_usd > 0.0

    tracker.reset()
    assert tracker.total_input_tokens == 0
    assert tracker.total_output_tokens == 0
    assert tracker.total_cost_usd == 0.0
