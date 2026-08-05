"""Tests for Orchestrator Nodes."""

from __future__ import annotations

from unittest.mock import ANY, MagicMock, patch

import pytest

from src.agents.exploit_agent import ExploitCandidate
from src.agents.orchestrator import (
    analyze_graph_node,
    exploit_node,
    recon_node,
    replan_node,
    report_node,
    verify_node,
)
from src.agents.verification_agent import VerificationResult
from src.state.attack_graph import AttackGraph
from src.state.schemas import ExploitAttempt, PenTestState, ServiceNode


@pytest.fixture
def empty_state() -> PenTestState:
    """Fixture providing an empty PenTestState for testing."""
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
        "verify_enabled": True,  # Week 19-22: ablation flag
        "run_start_ts": time.time(),  # Week 19-22: for TTFS metric
    }


@patch("src.agents.orchestrator.ReconAgent")
def test_recon_node(mock_recon_agent: MagicMock, empty_state: PenTestState) -> None:
    """Test the recon_node execution."""
    # Setup mock
    mock_instance = MagicMock()
    mock_recon_agent.return_value = mock_instance

    # Run node
    result = recon_node(empty_state)

    # Verify
    assert result["current_phase"] == "recon"
    assert result["step_count"] == 1
    mock_instance.run.assert_called_once_with("10.10.10.10")


@patch("src.agents.orchestrator._llm_client")
@patch("src.agents.orchestrator._router")
def test_analyze_graph_node(
    mock_router: MagicMock, mock_llm_client: MagicMock, empty_state: PenTestState
) -> None:
    """Test analyze_graph_node with router enabled."""
    svc = ServiceNode(host_ip="10.10.10.10", port=21, protocol="tcp", name="ftp")
    empty_state["attack_graph"].get_exploitable_services = MagicMock(
        return_value=[svc.to_dict()]
    )

    mock_decision = MagicMock()
    mock_decision.route = "CLOUD"
    mock_decision.model = "gpt-4o"
    mock_decision.sensitivity_score = 0.1
    mock_decision.complexity_score = 0.5
    mock_decision.reasoning = "test"
    mock_router.route.return_value = mock_decision

    mock_llm_client.generate.return_value = (
        '{"recommendations": [{"module_path": "exploit/ftp", '
        '"payload": "payload/ftp", "confidence": 0.9}]}'
    )

    result = analyze_graph_node(empty_state)

    assert result["step_count"] == 1
    assert len(result["exploit_candidates"]) == 1
    assert result["exploit_candidates"][0]["module_path"] == "exploit/ftp"
    mock_router.route.assert_called_once()
    mock_llm_client.generate.assert_called_once()


@patch("src.agents.orchestrator._llm_client")
@patch("src.agents.orchestrator._router")
def test_analyze_graph_node_router_disabled(
    mock_router: MagicMock, mock_llm_client: MagicMock, empty_state: PenTestState
) -> None:
    """Test analyze_graph_node forces LOCAL route when router disabled."""
    empty_state["router_enabled"] = False
    svc = ServiceNode(host_ip="10.10.10.10", port=21, protocol="tcp", name="ftp")
    empty_state["attack_graph"].get_exploitable_services = MagicMock(
        return_value=[svc.to_dict()]
    )

    mock_decision = MagicMock()
    mock_decision.model = "llama3.2"
    mock_router.route.return_value = mock_decision

    mock_llm_client.generate.return_value = '{"recommendations": []}'

    result = analyze_graph_node(empty_state)

    assert result["step_count"] == 1
    mock_router.route.assert_called_once_with(
        task_input=ANY,
        task_type=ANY,
        force_route="LOCAL",
    )


@patch("src.agents.orchestrator.ExploitAgent")
def test_exploit_node_no_exploitable(
    mock_exploit_agent: MagicMock, empty_state: PenTestState
) -> None:
    """Test exploit_node returns early when no exploitable services are found."""
    # Graph is empty, no exploitable services
    result = exploit_node(empty_state)

    assert result["current_phase"] == "exploit"
    assert result["step_count"] == 0  # Does not increment if returned early
    mock_exploit_agent.assert_not_called()


@patch("src.agents.orchestrator.ExploitAgent")
def test_exploit_node_with_exploitable(
    mock_exploit_agent: MagicMock, empty_state: PenTestState
) -> None:
    """Test exploit_node runs ExploitAgent against exploitable services."""
    # Setup graph with exploitable service
    svc = ServiceNode(host_ip="10.10.10.10", port=21, protocol="tcp", name="ftp")
    empty_state["attack_graph"].get_exploitable_services = MagicMock(
        return_value=[svc.to_dict()]
    )

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
    # Verify that ExploitAgent.run was called with None for candidates when empty
    mock_instance.run.assert_called_once_with("10.10.10.10", candidates=None)


@patch("src.agents.orchestrator.ExploitAgent")
def test_exploit_node_with_llm_candidates(
    mock_exploit_agent: MagicMock, empty_state: PenTestState
) -> None:
    """Test exploit_node converts LLM candidates and passes them to ExploitAgent."""
    svc = ServiceNode(host_ip="10.10.10.10", port=21, protocol="tcp", name="ftp")
    empty_state["attack_graph"].get_exploitable_services = MagicMock(
        return_value=[svc.to_dict()]
    )
    empty_state["exploit_candidates"] = [
        {"module_path": "exploit/ftp", "payload": "payload/ftp", "confidence": 0.9}
    ]

    mock_instance = MagicMock()
    mock_result = MagicMock()
    mock_result.attempts = []
    mock_instance.run.return_value = mock_result
    mock_exploit_agent.return_value = mock_instance

    result = exploit_node(empty_state)

    assert result["current_phase"] == "exploit"
    assert result["step_count"] == 1
    assert len(result["exploit_candidates"]) == 0  # Cleared after use

    # Verify the candidates passed to ExploitAgent.run
    mock_instance.run.assert_called_once()
    call_args = mock_instance.run.call_args
    assert call_args[0][0] == "10.10.10.10"
    candidates = call_args[1].get("candidates")
    assert candidates is not None
    assert len(candidates) == 1
    assert isinstance(candidates[0], ExploitCandidate)
    assert candidates[0].module_path == "exploit/ftp"


def test_verify_node_no_attempts(empty_state: PenTestState) -> None:
    """Test verify_node returns early when there are no exploit attempts."""
    result = verify_node(empty_state)
    assert result["current_phase"] == "verify"
    assert result["step_count"] == 0  # Returns early when no attempts


@patch("src.agents.orchestrator.VerificationAgent")
def test_verify_node_with_attempts(
    mock_verification_agent: MagicMock, empty_state: PenTestState
) -> None:
    """Test verify_node checks the last exploit attempt."""
    attempt = ExploitAttempt(
        target_service_id="svc_1", module_used="test", result="success"
    )
    empty_state["exploit_attempts"].append(attempt)

    verified_attempt = ExploitAttempt(
        target_service_id="svc_1",
        module_used="test",
        result="success",
        session_id="123",
    )
    mock_result = VerificationResult(
        attempt=verified_attempt,
        success=True,
        privilege="user",
        session_id=123,
        post_mortem=None,
    )
    mock_instance = MagicMock()
    mock_instance.verify_attempt.return_value = mock_result
    mock_verification_agent.return_value = mock_instance

    # Run node
    result = verify_node(empty_state)

    assert result["current_phase"] == "verify"
    assert result["step_count"] == 1
    assert result["exploit_attempts"][-1].session_id == "123"
    mock_instance.verify_attempt.assert_called_once_with(attempt)


def test_replan_node(empty_state: PenTestState) -> None:
    """Test the replan_node execution."""
    result = replan_node(empty_state)
    assert result["step_count"] == 1


@patch("src.agents.orchestrator.ReportGenerator")
@patch("src.agents.orchestrator._cost_tracker")
def test_report_node(
    mock_cost_tracker: MagicMock,
    mock_report_generator: MagicMock,
    empty_state: PenTestState,
) -> None:
    """Test the report_node execution and cost tracking logging."""
    mock_cost_tracker.get_stats.return_value = {
        "total_cloud_tokens": 100,
        "total_cost_usd": 0.05,
    }

    mock_instance = MagicMock()
    mock_instance.generate_all.return_value = {"html": "report.html"}
    mock_report_generator.return_value = mock_instance

    result = report_node(empty_state)

    assert result["current_phase"] == "report"
    assert result["step_count"] == 1

    # Week 17-18: reports and cost_summary
    # Week 19-22: evaluation_metrics added as third finding
    assert len(result["findings"]) >= 2
    assert "reports" in result["findings"][0]
    assert "cost_summary" in result["findings"][1]
    # Verify evaluation_metrics finding exists (Week 19-22)
    metric_findings = [f for f in result["findings"] if "evaluation_metrics" in f]
    assert len(metric_findings) >= 1
    assert "success" in metric_findings[0]["evaluation_metrics"]
