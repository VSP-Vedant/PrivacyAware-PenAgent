"""Tests for Orchestrator (Member B)."""

import pytest
from typing import Any

from src.state.schemas import PenTestState, ExploitAttempt
from src.state.attack_graph import AttackGraph
from src.agents.orchestrator import (
    has_exploitable,
    check_success,
    recon_node,
    analyze_graph_node,
    exploit_node,
    verify_node,
    replan_node,
    report_node,
    build_graph
)

@pytest.fixture
def empty_state() -> PenTestState:
    return {
        "target": "10.10.10.10",
        "attack_graph": AttackGraph(),
        "current_phase": "recon",
        "exploit_attempts": [],
        "sessions": [],
        "step_count": 0,
        "max_steps": 10,
        "cloud_tokens_used": 0,
        "findings": []
    }

def test_has_exploitable(empty_state):
    assert has_exploitable(empty_state) == "report"

def test_check_success_empty(empty_state):
    assert check_success(empty_state) == "report"

def test_check_success_with_success(empty_state):
    empty_state["exploit_attempts"].append(
        ExploitAttempt(target_service_id="svc-1", module_used="test", result="success", session_id="1")
    )
    assert check_success(empty_state) == "report"

def test_check_success_with_failure(empty_state):
    empty_state["exploit_attempts"].append(
        ExploitAttempt(target_service_id="svc-1", module_used="test", result="failure")
    )
    assert check_success(empty_state) == "replan"

def test_check_success_max_steps(empty_state):
    for i in range(10):
        empty_state["exploit_attempts"].append(
            ExploitAttempt(target_service_id="svc-1", module_used="test", result="failure")
        )
    assert check_success(empty_state) == "report"

def test_build_graph():
    graph = build_graph()
    assert graph is not None
