"""Unit tests for the LLM Router.

This test suite verifies the decision coordination of the router under various
sensitivity, complexity, budget, and override scenarios, including task-aware
local model selection.
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

    # Low sensitivity input, low complexity task — defaults to synthesis model
    decision = router.route(
        task_input="Format ports list: 22, 80",
        task_type=TaskType.FORMAT_OUTPUT,
    )
    assert decision.route == "LOCAL"
    # Default local_task_type is "synthesis" → Foundation-Sec model
    assert "Foundation-Sec" in decision.model or "QuantFactory" in decision.model
    assert decision.local_task_type == "synthesis"
    assert "Local route selected" in decision.reasoning


def test_router_local_generation_task() -> None:
    """Test routing to LOCAL with local_task_type='generation' selects Qwen."""
    router = LLMRouter()

    decision = router.route(
        task_input="Format ports list: 22, 80",
        task_type=TaskType.FORMAT_OUTPUT,
        local_task_type="generation",
    )
    assert decision.route == "LOCAL"
    assert "qwen2.5-coder" in decision.model.lower()
    assert decision.local_task_type == "generation"
    # Config entry should have format=json
    assert decision.model_config_entry.get("format") == "json"


def test_router_local_synthesis_task() -> None:
    """Test routing to LOCAL with local_task_type='synthesis' selects Foundation-Sec."""
    router = LLMRouter()

    decision = router.route(
        task_input="Format ports list: 22, 80",
        task_type=TaskType.FORMAT_OUTPUT,
        local_task_type="synthesis",
    )
    assert decision.route == "LOCAL"
    assert "Foundation-Sec" in decision.model or "QuantFactory" in decision.model
    assert decision.local_task_type == "synthesis"


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
    # Cloud routes retain local_task_type for no-key local fallthrough
    assert decision.local_task_type == "synthesis"


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

    # Even though task is highly complex, budget forces LOCAL with generation model
    decision = router.route(
        task_input="Check path escalation option",
        task_type=TaskType.PRIV_ESC_REASONING,
        local_task_type="generation",
    )
    assert decision.route == "LOCAL"
    assert "qwen2.5-coder" in decision.model.lower()
    assert decision.local_task_type == "generation"
    assert "Forced local" in decision.reasoning


def test_router_budget_exceeded_defaults_to_synthesis() -> None:
    """Budget-forced LOCAL without explicit local_task_type defaults to synthesis."""
    cost_tracker = CostTracker(max_cloud_tokens=100)
    router = LLMRouter(cost_tracker=cost_tracker)
    cost_tracker.add_run(model="gpt-4o", input_tokens=50, output_tokens=60)

    decision = router.route(
        task_input="Check path escalation option",
        task_type=TaskType.PRIV_ESC_REASONING,
    )
    assert decision.route == "LOCAL"
    assert decision.local_task_type == "synthesis"


def test_router_force_override() -> None:
    """Test routing overrides (ablation mode configurations)."""
    router = LLMRouter()

    # Highly complex, but force_route LOCAL overrides decision
    decision_local = router.route(
        task_input="Check path escalation option",
        task_type=TaskType.PRIV_ESC_REASONING,
        force_route="LOCAL",
        local_task_type="generation",
    )
    assert decision_local.route == "LOCAL"
    assert "qwen2.5-coder" in decision_local.model.lower()
    assert decision_local.local_task_type == "generation"

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


def test_routing_decision_has_model_config_entry() -> None:
    """Test that LOCAL decisions include model_config_entry metadata."""
    router = LLMRouter()

    decision = router.route(
        task_input="test",
        task_type=TaskType.SUMMARIZE,
        local_task_type="generation",
    )
    assert decision.route == "LOCAL"
    assert decision.model_config_entry
    assert "name" in decision.model_config_entry
    assert "role" in decision.model_config_entry
