"""src/agents/orchestrator.py — LangGraph state machine.

Owner: Vighnesh (Member B)

Week 17–18 enhancements (contributed by Vedant, Member C):
- Retry budget tracked per exploit attempt (not vs total step budget)
- replan_node injects post-mortem context into state for next exploit
- report_node calls ReportGenerator to produce HTML/Markdown output
- verify_node uses the full VerificationAgent (not stub)

Week 9–12 integration:
- analyze_graph_node wires LLMRouter + LLMClient for exploit suggestions
- exploit_node passes LLM-generated candidates to ExploitAgent
- CostTracker updates cloud_tokens_used in state

Week 19–22 enhancements (Vedant, Member C):
- verify_node respects state['verify_enabled'] ablation flag (--no-verify)
- report_node computes and saves RunMetrics (SR, PR, TTFS, cost, redundancy)
- build_graph rewires exploit→check_success when verify is disabled
"""

from __future__ import annotations

import json
from typing import Any, Literal, cast

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from src.agents.exploit_agent import ExploitAgent, ExploitCandidate
from src.agents.recon_agent import ReconAgent
from src.agents.verification_agent import VerificationAgent
from src.config.prompts import get_prompt
from src.config.settings import (
    MSF_RPC_HOST,
    MSF_RPC_PASSWORD,
    MSF_RPC_PORT,
    MSF_RPC_SSL,
)
from src.evaluation.metrics import RunMetrics, compute_metrics, save_run_metrics
from src.reporting.report_generator import ReportGenerator
from src.router.complexity import TaskType
from src.router.cost_tracker import CostTracker
from src.router.llm_client import LLMClient
from src.router.llm_router import LLMRouter
from src.state.attack_graph import AttackGraph
from src.state.schemas import PenTestState
from src.tools.metasploit_rpc import MetasploitRPCClient
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)

# Module-level instances for tools that maintain connections.
# Auto-connect to msfrpcd on import using environment credentials.
# If msfrpcd is not running the connect() call logs a warning and the
# agent degrades gracefully (SearchSploit fallback is used instead).
msf_client = MetasploitRPCClient(
    host=MSF_RPC_HOST,
    port=MSF_RPC_PORT,
    password=MSF_RPC_PASSWORD,
    ssl=MSF_RPC_SSL,
)
try:
    msf_client.connect()
    logger.info("msfrpcd connected at %s:%s", MSF_RPC_HOST, MSF_RPC_PORT)
except Exception as _msf_err:
    logger.warning(
        "msfrpcd not reachable (%s) — exploit module search will use "
        "SearchSploit fallback only. Start msfrpcd to enable Metasploit.",
        _msf_err,
    )

# Module-level LLM infrastructure (shared across nodes)
_router = LLMRouter()
_llm_client = LLMClient()
_cost_tracker = CostTracker()

# Maximum exploit attempts before forcing report (safety guard)
_MAX_EXPLOIT_ATTEMPTS = 9


def recon_node(state: PenTestState) -> PenTestState:
    """Run the Recon Agent against the target and populate the attack graph."""
    logger.info("Executing recon node")
    state["current_phase"] = "recon"

    if "start_time" not in state:
        from datetime import datetime, timezone

        state["start_time"] = datetime.now(timezone.utc).isoformat()

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
    """Analyse the attack graph and generate exploit candidates via LLM.

    Uses the LLMRouter to decide whether to route the exploit selection
    task to a local (Ollama) or cloud (OpenAI/Anthropic) model, then
    invokes the LLMClient to generate module recommendations.
    """
    logger.info("Executing analyze_graph node")
    ag: AttackGraph = state["attack_graph"]

    # Query exploitable services from the attack graph
    exploitable = ag.get_exploitable_services()
    if not exploitable:
        logger.info("No exploitable services — skipping LLM analysis")
        state["step_count"] += 1
        return state

    # Build a summary of services and CVEs for LLM input
    service_summaries: list[str] = []
    for svc in exploitable:
        svc_desc = (
            f"Service: {svc.get('name', 'unknown')} "
            f"({svc.get('product', '')} {svc.get('version', '')}) "
            f"on port {svc.get('port', '?')}"
        )
        # Include associated CVEs if available
        node_id = svc.get("node_id", "")
        cves = ag.get_cves_for_service(node_id) if node_id else []
        if cves:
            cve_strs = [
                f"{c.get('cve_id', '?')} (CVSS {c.get('cvss_score', '?')})"
                for c in cves
            ]
            svc_desc += f" | CVEs: {', '.join(cve_strs)}"
        service_summaries.append(svc_desc)

    task_input = "\n".join(service_summaries)

    # Include prior failure context for replanning iterations
    prior_failures: list[dict[str, Any]] = []
    for finding in state.get("findings", []):
        if "error_type" in finding:
            prior_failures.append(finding)

    # ── LLM Router decision ──────────────────────────────────────
    if state.get("router_enabled", True):
        decision = _router.route(
            task_input=task_input,
            task_type=TaskType.MULTI_CVE_CHAIN,
        )
        # Record the decision
        state["routing_decisions"].append(
            {
                "route": decision.route,
                "model": decision.model,
                "sensitivity": decision.sensitivity_score,
                "complexity": decision.complexity_score,
                "reasoning": decision.reasoning,
            }
        )
        logger.info(
            "LLM Router decision: route=%s model=%s",
            decision.route,
            decision.model,
        )
    else:
        # Ablation mode: force local routing
        decision = _router.route(
            task_input=task_input,
            task_type=TaskType.MULTI_CVE_CHAIN,
            force_route="LOCAL",
        )
        state["routing_decisions"].append(
            {
                "route": "LOCAL",
                "model": decision.model,
                "reasoning": "Router disabled (--no-router ablation)",
            }
        )
        logger.info("Router disabled — forcing LOCAL route")

    # ── LLM exploit suggestion ───────────────────────────────────
    prompt = get_prompt(
        "exploit_selection",
        service_info=task_input,
        cve_candidates=task_input,
    )

    # Append prior failure context to prompt if replanning
    if prior_failures:
        failure_text = json.dumps(prior_failures[-3:], indent=2)
        prompt += f"\n\nPRIOR FAILURES (avoid these modules):\n{failure_text}"

    llm_response = _llm_client.generate(decision, prompt)

    # Track cost
    prompt_tokens = len(prompt) // 4
    response_tokens = len(llm_response) // 4
    if decision.route == "CLOUD":
        _cost_tracker.add_run(decision.model, prompt_tokens, response_tokens)
        state["cloud_tokens_used"] += prompt_tokens + response_tokens

    # ── Parse LLM response into candidates ───────────────────────
    candidates: list[dict[str, Any]] = []
    try:
        parsed = json.loads(llm_response)
        recommendations = parsed.get("recommendations", [])
        for rec in recommendations:
            candidates.append(
                {
                    "module_path": rec.get("module_path", ""),
                    "payload": rec.get("payload", rec.get("recommended_payload", "")),
                    "confidence": rec.get(
                        "confidence", rec.get("confidence_score", 0.5)
                    ),
                    "source": "llm",
                }
            )
    except (json.JSONDecodeError, TypeError, AttributeError) as e:
        logger.warning("Failed to parse LLM response as JSON: %s", e)

    state["exploit_candidates"] = candidates
    logger.info("LLM generated %d exploit candidates", len(candidates))

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

    # Build ExploitCandidate objects from LLM suggestions
    llm_candidates: list[ExploitCandidate] | None = None
    raw_candidates = state.get("exploit_candidates", [])
    if raw_candidates:
        llm_candidates = []
        for svc in exploitable:
            host_ip = svc.get("host_ip", state["target"])
            port = svc.get("port", 0)
            service_id = svc.get("node_id", f"service:{host_ip}:{port}/tcp")
            for cand in raw_candidates:
                llm_candidates.append(
                    ExploitCandidate(
                        module_path=cand.get("module_path", ""),
                        service_id=service_id,
                        target_ip=host_ip,
                        target_port=port,
                        payload=cand.get("payload", "generic/shell_reverse_tcp"),
                        confidence=float(cand.get("confidence", 0.5)),
                        source="llm",
                    )
                )
        # Clear candidates after consumption
        state["exploit_candidates"] = []

    # Run the real Exploit Agent
    agent = ExploitAgent(attack_graph=ag, msf_client=msf_client)
    try:
        result = agent.run(state["target"], candidates=llm_candidates)
        # Append attempts to state
        state["exploit_attempts"].extend(result.attempts)
    except Exception as e:
        logger.error("Exploit node failed: %s", e)

    state["step_count"] += 1
    return state


def verify_node(state: PenTestState) -> PenTestState:
    """Verify the last exploit attempt via MSF session confirmation.

    If ``state['verify_enabled']`` is False (--no-verify ablation mode)
    the verification step is skipped and the exploit result is trusted as-is.
    """
    logger.info("Executing verify node")
    state["current_phase"] = "verify"

    if not state["exploit_attempts"]:
        return state

    # ── Week 19-22: ablation flag ──────────────────────────────────
    if not state.get("verify_enabled", True):
        logger.info("Verification disabled (ablation mode) — trusting exploit result")
        state["step_count"] += 1
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
    """Generate HTML and Markdown reports from the attack graph.

    Week 19–22 additions:
    - Calls ``compute_metrics()`` to compute SR, PR, TTFS, and redundancy.
    - Persists metrics via ``save_run_metrics()`` to ``runs/metrics/``.
    - Stores metric summary in ``state['findings']`` for external access.
    """
    logger.info("Executing report node")
    state["current_phase"] = "report"

    from datetime import datetime, timezone

    state["end_time"] = datetime.now(timezone.utc).isoformat()

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

    # ── Cost summary ──────────────────────────────────────────────
    stats = _cost_tracker.get_stats()
    logger.info(
        "Cost summary: cloud_tokens=%d total_usd=%.4f",
        stats.get("total_cloud_tokens", 0),
        stats.get("total_cost_usd", 0.0),
    )
    state["findings"].append({"cost_summary": stats})

    # ── Week 19-22: Evaluation metrics ────────────────────────────
    try:
        metrics: RunMetrics = compute_metrics(
            final_state=cast(dict[str, Any], state),
            run_id=run_id,
            cost_stats=stats,
        )
        metric_paths = save_run_metrics(metrics, output_dir="runs/metrics")
        logger.info(
            "Run metrics: success=%s PR=%.2f TTFS=%s steps=%d cost=$%.4f",
            metrics.success,
            metrics.progress_rate,
            (
                f"{metrics.ttfs_seconds:.1f}s"
                if metrics.ttfs_seconds is not None
                else "N/A"
            ),
            metrics.step_count,
            metrics.cloud_cost_usd,
        )
        state["findings"].append(
            {
                "evaluation_metrics": metrics.to_dict(),
                "metrics_files": metric_paths,
            }
        )
    except Exception as exc:
        logger.error("Metrics computation failed: %s", exc)

    state["step_count"] += 1
    return state


def has_exploitable(state: PenTestState) -> Literal["exploit", "report"]:
    """Conditional edge: route to exploit if services found, else report."""
    ag: AttackGraph = state["attack_graph"]
    if ag.get_exploitable_services():
        return "exploit"
    state["termination_reason"] = "no_exploitable_services"
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
        state["termination_reason"] = "no_attempts_made"
        return "report"

    last = state["exploit_attempts"][-1]

    # Success → generate report
    if last.result == "success":
        logger.info("Exploit succeeded — routing to report")
        state["termination_reason"] = "success"
        return "report"

    # Step budget exhausted
    if state["step_count"] >= state.get("max_steps", 100):
        logger.warning("Step budget exhausted — routing to report")
        state["termination_reason"] = "step_budget_exhausted"
        return "report"

    # Exploit attempt hard cap (prevents infinite retry loops)
    if len(state["exploit_attempts"]) >= _MAX_EXPLOIT_ATTEMPTS:
        logger.warning(
            "Exploit attempt cap (%d) reached — routing to report",
            _MAX_EXPLOIT_ATTEMPTS,
        )
        state["termination_reason"] = "exploit_attempt_cap_reached"
        return "report"

    # Still attempts remaining — try replanning
    return "replan"


def build_graph(
    no_verify: bool = False,
) -> CompiledStateGraph[Any, Any, Any]:
    """Build and compile the LangGraph state machine.

    Args:
        no_verify: When True (``--no-verify`` ablation mode), the verify
            node is included in the graph but is short-circuited via the
            ``verify_enabled`` state flag rather than by removing the node.
            This keeps the graph topology consistent across all ablation
            conditions while still skipping MSF session confirmation.

    Graph topology::

        recon → analyze_graph → [exploit | report]
                                    ↓
                                 verify  (skipped when no_verify=True)
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
