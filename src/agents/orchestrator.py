"""src/agents/orchestrator.py — LangGraph state machine.

Owner: Vighnesh (Member B)
"""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from src.agents.exploit_agent import ExploitAgent
from src.agents.recon_agent import ReconAgent
from src.agents.verification_agent import VerificationAgent
from src.state.attack_graph import AttackGraph
from src.state.schemas import PenTestState
from src.tools.metasploit_rpc import MetasploitRPCClient
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)

# Module-level instances for tools that maintain connections
msf_client = MetasploitRPCClient()


def recon_node(state: PenTestState) -> PenTestState:
    """Docstring."""
    logger.info("Executing recon node")
    state["current_phase"] = "recon"

    target = state["target"]
    ag: AttackGraph = state["attack_graph"]

    # Run the real Recon Agent
    agent = ReconAgent(attack_graph=ag)
    try:
        agent.run(target)
    except Exception as e:
        logger.error("Recon node failed: %s", e)

    state["step_count"] += 1
    return state


def analyze_graph_node(state: PenTestState) -> PenTestState:
    """Docstring."""
    logger.info("Executing analyze_graph node")
    state["step_count"] += 1
    return state


def exploit_node(state: PenTestState) -> PenTestState:
    """Docstring."""
    logger.info("Executing exploit node")
    state["current_phase"] = "exploit"
    ag: AttackGraph = state["attack_graph"]

    exploitable = ag.get_exploitable_services()
    if not exploitable:
        logger.warning("No exploitable services found")
        return state

    # Run the real Exploit Agent
    agent = ExploitAgent(attack_graph=ag, msf_client=msf_client)
    try:
        result = agent.run(state["target"])
        # Append attempts to state
        state["exploit_attempts"].extend(result.attempts)
    except Exception as e:
        logger.error("Exploit node failed: %s", e)

    state["step_count"] += 1
    return state


def verify_node(state: PenTestState) -> PenTestState:
    """Docstring."""
    logger.info("Executing verify node")
    state["current_phase"] = "verify"

    if not state["exploit_attempts"]:
        return state

    last_attempt = state["exploit_attempts"][-1]

    # Run the Verification Agent stub
    agent = VerificationAgent(attack_graph=state["attack_graph"])
    verified_attempt = agent.verify(last_attempt)

    state["exploit_attempts"][-1] = verified_attempt

    state["step_count"] += 1
    return state


def replan_node(state: PenTestState) -> PenTestState:
    """Docstring."""
    logger.info("Executing replan node")
    state["step_count"] += 1
    return state


def report_node(state: PenTestState) -> PenTestState:
    """Docstring."""
    logger.info("Executing report node")
    state["current_phase"] = "report"
    state["step_count"] += 1
    return state


def has_exploitable(state: PenTestState) -> Literal["exploit", "report"]:
    """Docstring."""
    ag: AttackGraph = state["attack_graph"]
    if ag.get_exploitable_services():
        return "exploit"
    return "report"


def check_success(state: PenTestState) -> Literal["report", "replan"]:
    """Docstring."""
    if not state["exploit_attempts"]:
        return "report"

    last = state["exploit_attempts"][-1]
    if last.result == "success":
        return "report"

    # Check max retries
    if len(state["exploit_attempts"]) >= state.get("max_steps", 100):
        return "report"

    return "replan"


def build_graph() -> CompiledStateGraph:
    """Build and compile the LangGraph."""
    workflow = StateGraph(PenTestState)

    workflow.add_node("recon", recon_node)
    workflow.add_node("analyze_graph", analyze_graph_node)
    workflow.add_node("exploit", exploit_node)
    workflow.add_node("verify", verify_node)
    workflow.add_node("replan", replan_node)
    workflow.add_node("report", report_node)

    workflow.set_entry_point("recon")
    workflow.add_edge("recon", "analyze_graph")

    workflow.add_conditional_edges("analyze_graph", has_exploitable)

    workflow.add_edge("exploit", "verify")

    workflow.add_conditional_edges("verify", check_success)

    workflow.add_edge("replan", "exploit")
    workflow.add_edge("report", END)

    return workflow.compile()
