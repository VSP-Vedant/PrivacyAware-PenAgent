"""Unit tests for the LLM Router.

This test suite verifies the decision coordination of the router under various
sensitivity, complexity, budget, and override scenarios.
"""

from __future__ import annotations

import os
from unittest.mock import patch
from src.router.complexity import TaskType
from src.router.cost_tracker import CostTracker
from src.router.llm_router import LLMRouter


def test_router_local_decision() -> None:
    """Test routing to LOCAL when sensitivity and complexity are low."""
    # Default thresholds: sensitivity 0.6, complexity 0.7
    router = LLMRouter()

    # Low sensitivity input, low complexity task
    decision = router.route(
        task_input="Format ports list: 22, 80",
        task_type=TaskType.FORMAT_OUTPUT,
    )
    assert decision.route == "LOCAL"
    assert decision.model == "llama3:8b"
    assert "Local route selected" in decision.reasoning


def test_router_cloud_sensitivity_decision() -> None:
    """Test routing to CLOUD when sensitivity exceeds threshold."""
    router = LLMRouter()

    # Contains private key info (triggers sensitivity=1.0)
    decision = router.route(
        task_input="The private key matches: -----BEGIN OPENSSH PRIVATE KEY-----",
        task_type=TaskType.FORMAT_OUTPUT,
    )
    assert decision.route == "CLOUD"
    assert decision.model == "gpt-4o"
    assert "Cloud route selected" in decision.reasoning


def test_router_cloud_complexity_decision() -> None:
    """Test routing to CLOUD when complexity exceeds threshold."""
    router = LLMRouter()

    # Complexity for PRIV_ESC_REASONING is 0.9 (>= 0.7 threshold)
    decision = router.route(
        task_input="Check path escalation option",
        task_type=TaskType.PRIV_ESC_REASONING,
    )
    assert decision.route == "CLOUD"
    assert decision.model == "gpt-4o"
    assert "Cloud route selected" in decision.reasoning


def test_router_budget_exceeded_fallback() -> None:
    """Test fallback to LOCAL when cloud budget is exceeded."""
    cost_tracker = CostTracker(max_cloud_tokens=100)
    router = LLMRouter(cost_tracker=cost_tracker)

    # Exceed budget
    cost_tracker.add_run(model="gpt-4o", input_tokens=50, output_tokens=60)
    assert cost_tracker.is_budget_exceeded()

    # Even though task is highly complex, budget forces LOCAL
    decision = router.route(
        task_input="Check path escalation option",
        task_type=TaskType.PRIV_ESC_REASONING,
    )
    assert decision.route == "LOCAL"
    assert decision.model == "llama3:8b"
    assert "Forced local" in decision.reasoning


def test_router_force_override() -> None:
    """Test routing overrides (ablation mode configurations)."""
    router = LLMRouter()

    # Highly complex, but force_route LOCAL overrides decision
    decision_local = router.route(
        task_input="Check path escalation option",
        task_type=TaskType.PRIV_ESC_REASONING,
        force_route="LOCAL",
    )
    assert decision_local.route == "LOCAL"
    assert decision_local.model == "llama3:8b"

    # Simple task, but force_route CLOUD overrides decision
    decision_cloud = router.route(
        task_input="Hello world",
        task_type=TaskType.SUMMARIZE,
        force_route="CLOUD",
    )
    assert decision_cloud.route == "CLOUD"
    assert decision_cloud.model == "gpt-4o"


def test_router_custom_thresholds_from_env() -> None:
    """Test loading custom thresholds from environment variables."""
    with patch.dict(
        os.environ,
        {
            "SENSITIVITY_THRESHOLD": "0.2",
            "COMPLEXITY_THRESHOLD": "0.1",
            "LOCAL_MODEL": "mistral:7b",
            "CLOUD_MODEL": "gpt-4o-mini",
        },
    ):
        router = LLMRouter()
        assert router.sensitivity_threshold == 0.2
        assert router.complexity_threshold == 0.1
        assert router.local_model == "mistral:7b"
        assert router.cloud_model == "gpt-4o-mini"
