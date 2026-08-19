"""Tests for Orchestrator (Member B)."""

import pytest

from src.agents.orchestrator import build_graph, check_success, has_exploitable
from src.state.attack_graph import AttackGraph
from src.state.schemas import ExploitAttempt, PenTestState


@pytest.fixture
def empty_state() -> PenTestState:
    import time

    return {
        "target": "10.10.10.10",
        "attack_graph": AttackGraph(":memory:"),
        "current_phase": "recon",
        "exploit_attempts": [],
        "sessions": [],
        "step_count": 0,
        "max_steps": 10,
        "cloud_tokens_used": 0,
        "findings": [],
        "routing_decisions": [],
        "exploit_candidates": [],
        "router_enabled": True,
        "verify_enabled": True,
        "run_start_ts": time.time(),
        "start_time": "",
        "end_time": "",
        "termination_reason": "",
        "nmap_scan_type": "quick",
        "mode": "full",
        "consecutive_empty_exploit_cycles": 0,
        "consecutive_llm_failures": 0,
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
    # Exhaust the step budget (step_count >= max_steps triggers "report")
    empty_state["step_count"] = 10  # == max_steps=10
    empty_state["exploit_attempts"].append(
        ExploitAttempt(
            target_service_id="svc-1", module_used="test", result="failure"
        )
    )
    assert check_success(empty_state) == "report"


def test_check_success_max_attempts(empty_state: PenTestState) -> None:
    # Exhaust the exploit attempts cap (_MAX_EXPLOIT_ATTEMPTS = 18)
    for _ in range(18):
        empty_state["exploit_attempts"].append(
            ExploitAttempt(
                target_service_id="svc-1", module_used="test", result="failure"
            )
        )
    assert check_success(empty_state) == "report"


def test_build_graph() -> None:
    graph = build_graph()
    assert graph is not None
