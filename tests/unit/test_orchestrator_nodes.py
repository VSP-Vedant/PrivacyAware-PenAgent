"""Tests for Orchestrator Nodes."""

from unittest.mock import MagicMock, patch

import pytest

from src.agents.orchestrator import (
    analyze_graph_node,
    exploit_node,
    recon_node,
    replan_node,
    report_node,
    verify_node,
)
from src.state.attack_graph import AttackGraph
from src.state.schemas import ExploitAttempt, PenTestState, ServiceNode


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


@patch("src.agents.orchestrator.ReconAgent")
def test_recon_node(mock_recon_agent: MagicMock, empty_state: PenTestState) -> None:
    # Setup mock
    mock_instance = MagicMock()
    mock_recon_agent.return_value = mock_instance

    # Run node
    result = recon_node(empty_state)

    # Verify
    assert result["current_phase"] == "recon"
    assert result["step_count"] == 1
    mock_instance.run.assert_called_once_with("10.10.10.10")


def test_analyze_graph_node(empty_state: PenTestState) -> None:
    result = analyze_graph_node(empty_state)
    assert result["step_count"] == 1


@patch("src.agents.orchestrator.ExploitAgent")
def test_exploit_node_no_exploitable(
    mock_exploit_agent: MagicMock, empty_state: PenTestState
) -> None:
    # Graph is empty, no exploitable services
    result = exploit_node(empty_state)

    assert result["current_phase"] == "exploit"
    assert result["step_count"] == 0  # Does not increment if returned early
    mock_exploit_agent.assert_not_called()


@patch("src.agents.orchestrator.ExploitAgent")
def test_exploit_node_with_exploitable(
    mock_exploit_agent: MagicMock, empty_state: PenTestState
) -> None:
    # Setup graph with exploitable service
    svc = ServiceNode(host_ip="10.10.10.10", port=21, protocol="tcp", name="ftp")
    empty_state["attack_graph"].get_exploitable_services = MagicMock(return_value=[svc])


    # Setup mock
    mock_instance = MagicMock()
    mock_result = MagicMock()
    mock_result.attempts = [
        ExploitAttempt(target_service_id="svc_1", module_used="test", result="success")
    ]
    mock_instance.run.return_value = mock_result
    mock_exploit_agent.return_value = mock_instance

    # Run node
    result = exploit_node(empty_state)

    assert result["current_phase"] == "exploit"
    assert result["step_count"] == 1
    assert len(result["exploit_attempts"]) == 1
    mock_instance.run.assert_called_once_with("10.10.10.10")


def test_verify_node_no_attempts(empty_state: PenTestState) -> None:
    result = verify_node(empty_state)
    assert result["current_phase"] == "verify"
    assert result["step_count"] == 0  # Returns early


@patch("src.agents.orchestrator.VerificationAgent")
def test_verify_node_with_attempts(
    mock_verification_agent: MagicMock, empty_state: PenTestState
) -> None:
    attempt = ExploitAttempt(
        target_service_id="svc_1", module_used="test", result="success"
    )
    empty_state["exploit_attempts"].append(attempt)

    # Setup mock
    mock_instance = MagicMock()
    verified_attempt = ExploitAttempt(
        target_service_id="svc_1",
        module_used="test",
        result="success",
        session_id="123",
    )
    mock_instance.verify.return_value = verified_attempt
    mock_verification_agent.return_value = mock_instance

    # Run node
    result = verify_node(empty_state)

    assert result["current_phase"] == "verify"
    assert result["step_count"] == 1
    assert result["exploit_attempts"][-1].session_id == "123"
    mock_instance.verify.assert_called_once_with(attempt)


def test_replan_node(empty_state: PenTestState) -> None:
    result = replan_node(empty_state)
    assert result["step_count"] == 1


def test_report_node(empty_state: PenTestState) -> None:
    result = report_node(empty_state)
    assert result["current_phase"] == "report"
    assert result["step_count"] == 1
