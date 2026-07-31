"""src/agents/orchestrator.py — LangGraph state machine.

Owner: Vighnesh (Member B)

Week 17–18 enhancements (contributed by Vedant, Member C):
- Retry budget tracked per exploit attempt (not vs total step budget)
- replan_node injects post-mortem context into state for next exploit
- report_node calls ReportGenerator to produce HTML/Markdown output
- verify_node uses the full VerificationAgent (not stub)
"""

from __future__ import annotations

from typing import Any, Literal

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from src.agents.exploit_agent import ExploitAgent
from src.agents.recon_agent import ReconAgent
from src.agents.verification_agent import VerificationAgent
from src.reporting.report_generator import ReportGenerator
from src.state.attack_graph import AttackGraph
from src.state.schemas import PenTestState
from src.tools.metasploit_rpc import MetasploitRPCClient
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)

# Module-level instances for tools that maintain connections
msf_client = MetasploitRPCClient()

# Maximum exploit attempts before forcing report (safety guard)
_MAX_EXPLOIT_ATTEMPTS = 9


def recon_node(state: PenTestState) -> PenTestState:
    """Run the Recon Agent against the target and populate the attack graph."""
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
    """Analyse the attack graph to determine next steps."""
    logger.info("Executing analyze_graph node")
    state["step_count"] += 1
    return state


def exploit_node(state: PenTestState) -> PenTestState:
    """Run the Exploit Agent against discoverable services.

    On replanning iterations, post-mortem context from the previous failure
    is available in ``state['findings']`` and can be used to bias module
    selection toward untried options.
    """
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
    """Verify the last exploit attempt via MSF session confirmation."""
    logger.info("Executing verify node")
    state["current_phase"] = "verify"

    if not state["exploit_attempts"]:
        return state

    last_attempt = state["exploit_attempts"][-1]

    # Use the full VerificationAgent (not the stub)
    agent = VerificationAgent(
        attack_graph=state["attack_graph"],
        msf_client=msf_client if msf_client.is_connected() else None,
    )
    result = agent.verify_attempt(last_attempt)

    # Update the state with the verified attempt
    state["exploit_attempts"][-1] = result.attempt

    # Record post-mortem in findings for replan context
    if result.post_mortem is not None:
        state["findings"].append(result.post_mortem.to_dict())

    # Track confirmed sessions
    if result.success and result.session_id is not None:
        from src.state.schemas import SessionNode

        session_node = SessionNode(
            session_id=str(result.session_id),
            host_ip=(
                last_attempt.target_service_id.split(":")[1]
                if ":" in last_attempt.target_service_id
                else state["target"]
            ),
            privilege=result.privilege,
        )
        state["sessions"].append(session_node)

    state["step_count"] += 1
    return state


def replan_node(state: PenTestState) -> PenTestState:
    """Replan after a verification failure.

    Injects the most recent post-mortem into findings so the next
    exploit node iteration has context about what went wrong.
    """
    logger.info("Executing replan node")

    # Log post-mortem context available for replanning
    if state["findings"]:
        last_finding = state["findings"][-1]
        logger.info(
            "Replanning with context: error_type=%s action=%s",
            last_finding.get("error_type", "unknown"),
            last_finding.get("recommended_action", "unknown"),
        )

    state["step_count"] += 1
    return state


def report_node(state: PenTestState) -> PenTestState:
    """Generate HTML and Markdown reports from the attack graph."""
    logger.info("Executing report node")
    state["current_phase"] = "report"

    ag: AttackGraph = state["attack_graph"]
    run_id = state["target"].replace(".", "_").replace("/", "_")

    try:
        reporter = ReportGenerator(
            attack_graph=ag,
            output_dir="runs/reports",
            run_id=run_id,
        )
        paths = reporter.generate_all()
        logger.info(
            "Reports generated: %s",
            ", ".join(f"{k}={v}" for k, v in paths.items()),
        )
        # Store report paths in findings for external access
        state["findings"].append({"reports": paths})
    except Exception as e:
        logger.error("Report generation failed: %s", e)

    state["step_count"] += 1
    return state


def has_exploitable(state: PenTestState) -> Literal["exploit", "report"]:
    """Conditional edge: route to exploit if services found, else report."""
    ag: AttackGraph = state["attack_graph"]
    if ag.get_exploitable_services():
        return "exploit"
    return "report"


def check_success(state: PenTestState) -> Literal["report", "replan"]:
    """Conditional edge after verification.

    Routes to 'report' when:
    - The last attempt succeeded
    - The exploit attempt budget is exhausted (max 9 attempts)
    - The step budget is exceeded

    Routes to 'replan' when the attempt failed and budget remains.
    """
    if not state["exploit_attempts"]:
        return "report"

    last = state["exploit_attempts"][-1]

    # Success → generate report
    if last.result == "success":
        logger.info("Exploit succeeded — routing to report")
        return "report"

    # Step budget exhausted
    if state["step_count"] >= state.get("max_steps", 100):
        logger.warning("Step budget exhausted — routing to report")
        return "report"

    # Exploit attempt hard cap (prevents infinite retry loops)
    if len(state["exploit_attempts"]) >= _MAX_EXPLOIT_ATTEMPTS:
        logger.warning(
            "Exploit attempt cap (%d) reached — routing to report",
            _MAX_EXPLOIT_ATTEMPTS,
        )
        return "report"

    # Still attempts remaining — try replanning
    return "replan"


def build_graph() -> CompiledStateGraph[Any, Any, Any]:
    """Build and compile the LangGraph state machine.

    Graph topology::

        recon → analyze_graph → [exploit | report]
                                    ↓
                                 verify
                                    ↓
                            [report | replan]
                                    ↓
                                 exploit  (retry loop)
    """
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
