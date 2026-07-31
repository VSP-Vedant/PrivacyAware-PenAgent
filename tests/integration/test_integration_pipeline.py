"""Integration tests for the full LangGraph pipeline.

Tests validate the end-to-end orchestrator flow with all external
tools mocked (Nmap, Gobuster, Metasploit, LLM APIs).
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.agents.orchestrator import (
    analyze_graph_node,
    build_graph,
    exploit_node,
    report_node,
)
from src.state.attack_graph import AttackGraph
from src.state.schemas import CVENode, HostNode, PenTestState, ServiceNode


def _make_state(**overrides: Any) -> PenTestState:
    """Create a PenTestState with sensible defaults."""
    state: PenTestState = {
        "target": "10.10.10.10",
        "attack_graph": AttackGraph(),
        "current_phase": "recon",
        "exploit_attempts": [],
        "sessions": [],
        "step_count": 0,
        "max_steps": 20,
        "cloud_tokens_used": 0,
        "findings": [],
        "routing_decisions": [],
        "exploit_candidates": [],
        "router_enabled": True,
    }
    state.update(overrides)  # type: ignore[typeddict-item]
    return state


def _populate_graph(ag: AttackGraph) -> None:
    """Add a host, service, and CVE to the attack graph for testing."""
    ag.add_host(HostNode(ip="10.10.10.10"))
    ag.add_service(
        ServiceNode(
            host_ip="10.10.10.10",
            port=21,
            protocol="tcp",
            name="ftp",
            product="vsftpd",
            version="2.3.4",
        )
    )
    ag.add_cve(
        CVENode(cve_id="CVE-2011-2523", cvss_score=10.0),
        service_node_id="service:10.10.10.10:21/tcp",
    )


def _mock_llm_response() -> str:
    """Return a valid LLM JSON response for exploit recommendations."""
    return json.dumps(
        {
            "recommendations": [
                {
                    "module_path": "exploit/unix/ftp/vsftpd_234_backdoor",
                    "payload": "cmd/unix/interact",
                    "confidence_score": 0.95,
                    "reasoning": "Known backdoor in vsftpd 2.3.4",
                }
            ]
        }
    )


@pytest.mark.integration
def test_build_graph_compiles() -> None:
    """Build the full LangGraph and verify it compiles."""
    graph = build_graph()
    assert graph is not None


@pytest.mark.integration
@patch("src.agents.orchestrator._llm_client")
@patch("src.agents.orchestrator._router")
def test_analyze_graph_uses_router(
    mock_router: MagicMock,
    mock_llm_client: MagicMock,
) -> None:
    """Verify analyze_graph_node invokes LLMRouter when services exist."""
    ag = AttackGraph()
    _populate_graph(ag)
    state = _make_state(attack_graph=ag)

    # Setup router mock
    mock_decision = MagicMock()
    mock_decision.route = "LOCAL"
    mock_decision.model = "llama3:8b"
    mock_decision.sensitivity_score = 0.2
    mock_decision.complexity_score = 0.3
    mock_decision.reasoning = "Local route"
    mock_router.route.return_value = mock_decision

    # Setup LLM client mock
    mock_llm_client.generate.return_value = _mock_llm_response()

    result = analyze_graph_node(state)

    # Router should have been called
    mock_router.route.assert_called_once()
    # LLM client should have been called
    mock_llm_client.generate.assert_called_once()
    # Routing decision should be logged
    assert len(result["routing_decisions"]) == 1
    assert result["routing_decisions"][0]["route"] == "LOCAL"


@pytest.mark.integration
@patch("src.agents.orchestrator._llm_client")
@patch("src.agents.orchestrator._router")
def test_router_disabled_forces_local(
    mock_router: MagicMock,
    mock_llm_client: MagicMock,
) -> None:
    """Verify router_enabled=False forces LOCAL route."""
    ag = AttackGraph()
    _populate_graph(ag)
    state = _make_state(attack_graph=ag, router_enabled=False)

    mock_decision = MagicMock()
    mock_decision.route = "LOCAL"
    mock_decision.model = "llama3:8b"
    mock_decision.sensitivity_score = 0.0
    mock_decision.complexity_score = 0.0
    mock_decision.reasoning = "Forced LOCAL"
    mock_router.route.return_value = mock_decision

    mock_llm_client.generate.return_value = _mock_llm_response()

    result = analyze_graph_node(state)

    # Router should be called with force_route="LOCAL"
    mock_router.route.assert_called_once()
    call_kwargs = mock_router.route.call_args
    assert call_kwargs.kwargs.get("force_route") == "LOCAL"

    # Decision should log ablation
    assert "ablation" in result["routing_decisions"][0].get("reasoning", "").lower()


@pytest.mark.integration
@patch("src.agents.orchestrator._llm_client")
@patch("src.agents.orchestrator._router")
def test_llm_candidates_generated(
    mock_router: MagicMock,
    mock_llm_client: MagicMock,
) -> None:
    """Verify LLM response is parsed into exploit_candidates."""
    ag = AttackGraph()
    _populate_graph(ag)
    state = _make_state(attack_graph=ag)

    mock_decision = MagicMock()
    mock_decision.route = "LOCAL"
    mock_decision.model = "llama3:8b"
    mock_decision.sensitivity_score = 0.1
    mock_decision.complexity_score = 0.2
    mock_decision.reasoning = "test"
    mock_router.route.return_value = mock_decision
    mock_llm_client.generate.return_value = _mock_llm_response()

    result = analyze_graph_node(state)

    assert len(result["exploit_candidates"]) == 1
    assert result["exploit_candidates"][0]["module_path"] == (
        "exploit/unix/ftp/vsftpd_234_backdoor"
    )
    assert result["exploit_candidates"][0]["source"] == "llm"


@pytest.mark.integration
@patch("src.agents.orchestrator._cost_tracker")
@patch("src.agents.orchestrator._llm_client")
@patch("src.agents.orchestrator._router")
def test_cloud_cost_tracking(
    mock_router: MagicMock,
    mock_llm_client: MagicMock,
    mock_cost_tracker: MagicMock,
) -> None:
    """Verify cloud token cost is tracked when route is CLOUD."""
    ag = AttackGraph()
    _populate_graph(ag)
    state = _make_state(attack_graph=ag)

    mock_decision = MagicMock()
    mock_decision.route = "CLOUD"
    mock_decision.model = "gpt-4o"
    mock_decision.sensitivity_score = 0.8
    mock_decision.complexity_score = 0.9
    mock_decision.reasoning = "High complexity"
    mock_router.route.return_value = mock_decision
    mock_llm_client.generate.return_value = _mock_llm_response()

    result = analyze_graph_node(state)

    # Cost tracker should be called for CLOUD route
    mock_cost_tracker.add_run.assert_called_once()
    # Cloud tokens should be updated
    assert result["cloud_tokens_used"] > 0


@pytest.mark.integration
@patch("src.agents.orchestrator.msf_client")
def test_exploit_node_with_llm_candidates(
    mock_msf: MagicMock,
) -> None:
    """Verify exploit_node passes LLM candidates to ExploitAgent."""
    ag = AttackGraph()
    _populate_graph(ag)

    state = _make_state(
        attack_graph=ag,
        exploit_candidates=[
            {
                "module_path": "exploit/unix/ftp/vsftpd_234_backdoor",
                "payload": "cmd/unix/interact",
                "confidence": 0.95,
                "source": "llm",
            }
        ],
    )

    with patch("src.agents.orchestrator.ExploitAgent") as MockAgent:
        mock_agent = MagicMock()
        mock_result = MagicMock()
        mock_result.attempts = []
        mock_agent.run.return_value = mock_result
        MockAgent.return_value = mock_agent

        result = exploit_node(state)

        # ExploitAgent.run should be called with candidates
        mock_agent.run.assert_called_once()
        call_args = mock_agent.run.call_args
        assert call_args.kwargs.get("candidates") is not None
        # Candidates should be cleared after consumption
        assert result["exploit_candidates"] == []


@pytest.mark.integration
@patch("src.agents.orchestrator._cost_tracker")
def test_report_node_logs_cost_summary(
    mock_cost_tracker: MagicMock,
) -> None:
    """Verify report_node appends cost summary to findings."""
    mock_cost_tracker.get_stats.return_value = {
        "total_cloud_tokens": 500,
        "total_cost_usd": 0.01,
    }

    state = _make_state()

    with patch("src.agents.orchestrator.ReportGenerator") as MockReporter:
        mock_reporter = MagicMock()
        mock_reporter.generate_all.return_value = {"html": "report.html"}
        MockReporter.return_value = mock_reporter

        result = report_node(state)

        # Cost summary should be in findings
        cost_findings = [f for f in result["findings"] if "cost_summary" in f]
        assert len(cost_findings) == 1
        assert cost_findings[0]["cost_summary"]["total_cloud_tokens"] == 500
