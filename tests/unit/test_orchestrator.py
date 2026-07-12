"""Tests for Orchestrator (Member B)."""

import pytest

from src.agents.orchestrator import build_graph, check_success, has_exploitable
from src.state.attack_graph import AttackGraph
from src.state.schemas import ExploitAttempt, PenTestState


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
        "findings": [],
    }


def test_has_exploitable(empty_state: PenTestState) -> None:
    assert has_exploitable(empty_state) == "report"


def test_check_success_empty(empty_state: PenTestState) -> None:
    assert check_success(empty_state) == "report"


def test_check_success_with_success(empty_state: PenTestState) -> None:
    empty_state["exploit_attempts"].append(
        ExploitAttempt(
            target_service_id="svc-1",
            module_used="test",
            result="success",
            session_id="1",
        )
    )
    assert check_success(empty_state) == "report"


def test_check_success_with_failure(empty_state: PenTestState) -> None:
    empty_state["exploit_attempts"].append(
        ExploitAttempt(target_service_id="svc-1", module_used="test", result="failure")
    )
    assert check_success(empty_state) == "replan"


def test_check_success_max_steps(empty_state: PenTestState) -> None:
    for i in range(10):
        empty_state["exploit_attempts"].append(
            ExploitAttempt(
                target_service_id="svc-1", module_used="test", result="failure"
            )
        )
    assert check_success(empty_state) == "report"


def test_build_graph() -> None:
    graph = build_graph()
    assert graph is not None
