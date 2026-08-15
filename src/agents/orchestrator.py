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
import os
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
    OPENAI_API_KEY,
    ANTHROPIC_API_KEY,
    OLLAMA_MODEL_LOCAL,
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

# Module-level LLM infrastructure (shared across nodes)
_router = LLMRouter()
_llm_client = LLMClient()
_cost_tracker = CostTracker()

# Maximum exploit attempts before forcing report (safety guard)
_MAX_EXPLOIT_ATTEMPTS = 18

# Module-level ExploitAgent — persisted across replan cycles so _globally_tried
# and _attempt_history survive from one exploit_node() call to the next.
# Initialized to None; created lazily on first exploit_node() invocation.
_exploit_agent: ExploitAgent | None = None


def _get_msf_client() -> MetasploitRPCClient | None:
    """Attempt to connect to msfrpcd using settings from .env.

    Returns a connected :class:`MetasploitRPCClient` on success,
    or ``None`` when msfrpcd is unreachable so callers can fall back
    gracefully to SearchSploit discovery.
    """
    client = MetasploitRPCClient(
        host=MSF_RPC_HOST,
        port=MSF_RPC_PORT,
        password=MSF_RPC_PASSWORD,
        ssl=MSF_RPC_SSL,
    )
    try:
        connected = client.connect()
        if connected:
            logger.info(
                "Connected to msfrpcd at %s:%d (ssl=%s)",
                MSF_RPC_HOST,
                MSF_RPC_PORT,
                MSF_RPC_SSL,
            )
            return client
        logger.warning(
            "msfrpcd at %s:%d is reachable but connect() returned False — "
            "check password/SSL settings. Falling back to SearchSploit.",
            MSF_RPC_HOST,
            MSF_RPC_PORT,
        )
    except Exception as exc:
        logger.warning(
            "msfrpcd unavailable at %s:%d (%s) — "
            "ExploitAgent will fall back to SearchSploit discovery.",
            MSF_RPC_HOST,
            MSF_RPC_PORT,
            exc,
        )
    return None


def recon_node(state: PenTestState) -> PenTestState:
    """Run the Recon Agent against the target and populate the attack graph."""
    logger.info("Executing recon node")
    state["current_phase"] = "recon"

    if "start_time" not in state:
        from datetime import datetime, timezone

        state["start_time"] = datetime.now(timezone.utc).isoformat()

    target = state["target"]
    ag: AttackGraph = state["attack_graph"]

    # Pick scan preset from state (set by CLI --mode in main.py)
    # Falls back to 'quick' if not set (safe default for HTB VPN)
    scan_type = state.get("nmap_scan_type", "quick")

    print(f"[RECON] Starting nmap scan against {target} (preset: {scan_type}) ...")
    print("[RECON] This may take 1-5 min over VPN. Check logs for live progress.")

    # Run the real Recon Agent
    agent = ReconAgent(attack_graph=ag, scan_type=scan_type)
    try:
        result = agent.run(target)
        print(
            f"[RECON] Done: {len(result.hosts)} hosts, "
            f"{len(result.services)} services, "
            f"{len(result.web_endpoints)} web endpoints, "
            f"{len(result.cve_candidates)} CVE candidates"
        )
    except Exception as e:
        logger.error("Recon node failed: %s", e)
        print(f"[RECON] ERROR: {e}")

    state["step_count"] += 1
    return state


def analyze_graph_node(state: PenTestState) -> PenTestState:
    """Analyse the attack graph and generate exploit candidates via LLM.

    Uses the LLMRouter to decide whether to route the exploit selection
    task to a local (Ollama) or cloud (OpenAI/Anthropic) model, then
    invokes the LLMClient to generate module recommendations.

    In ``recon-only`` mode this node is a no-op: it logs and returns
    immediately without touching the LLM, preventing Ollama timeouts
    on every replan iteration.
    """
    logger.info("Executing analyze_graph node")
    print("[ANALYZE] Querying attack graph for exploitable services ...")
    ag: AttackGraph = state["attack_graph"]

    # ── recon-only short-circuit ──────────────────────────────────
    # No LLM call needed: the conditional edge `has_exploitable` will
    # route directly to `report` after this node returns.
    if state.get("mode") == "recon-only":
        logger.info("recon-only mode — skipping LLM analysis")
        print("[ANALYZE] recon-only mode — skipping LLM analysis.")
        state["step_count"] += 1
        return state

    # Query exploitable services from the attack graph
    exploitable = ag.get_exploitable_services()
    if not exploitable:
        logger.info("No exploitable services — skipping LLM analysis")
        print("[ANALYZE] No exploitable services found. Skipping LLM analysis.")
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
        # If no cloud keys exist, the invocation actually executed locally on Ollama at $0 cost
        has_cloud_key = bool(
            os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        )
        actual_model = (
            decision.model
            if has_cloud_key
            else (OLLAMA_MODEL_LOCAL or "llama3:8b")
        )
        _cost_tracker.add_run(actual_model, prompt_tokens, response_tokens)
        state["cloud_tokens_used"] += prompt_tokens + response_tokens
    else:
        _cost_tracker.add_run(decision.model, prompt_tokens, response_tokens)

    # ── Parse LLM response into candidates ───────────────────────
    candidates: list[dict[str, Any]] = []
    try:
        parsed = json.loads(llm_response)

        # If LLM chose the fallback path, skip to SearchSploit (no candidates)
        if parsed.get("fallback") == "searchsploit":
            logger.info("LLM deferred to SearchSploit for: %s", parsed.get("query", ""))
        else:
            recommendations = parsed.get("recommendations", [])
            for rec in recommendations:
                module_path = rec.get("module_path", "").strip()

                # ── Hallucination filter ───────────────────────────────────
                # Reject any path that isn't a valid Metasploit module path.
                # Valid paths start with 'exploit/' and contain no spaces.
                if not module_path.startswith("exploit/") or " " in module_path:
                    logger.warning(
                        "Rejected hallucinated module path from LLM: %r — "
                        "must start with 'exploit/' and contain no spaces.",
                        module_path,
                    )
                    continue

                candidates.append(
                    {
                        "module_path": module_path,
                        "payload": rec.get(
                            "payload", rec.get("recommended_payload", "")
                        ),
                        "confidence": rec.get(
                            "confidence", rec.get("confidence_score", 0.5)
                        ),
                        "source": "llm",
                    }
                )
    except (json.JSONDecodeError, TypeError, AttributeError) as e:
        logger.warning("Failed to parse LLM response as JSON: %s", e)

    state["exploit_candidates"] = candidates
    logger.info("LLM generated %d valid exploit candidates", len(candidates))

    state["step_count"] += 1
    return state


def exploit_node(state: PenTestState) -> PenTestState:
    """Run the Exploit Agent against discoverable services.

    On replanning iterations, post-mortem context from the previous failure
    is available in ``state['findings']`` and can be used to bias module
    selection toward untried options.

    The ``ExploitAgent`` is persisted at module level so its ``_globally_tried``
    and ``_attempt_history`` sets survive across replan cycles — preventing the
    same modules from being retried on every iteration.
    """
    global _exploit_agent

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

    # If LLM generated no valid candidates, set llm_candidates = None so
    # ExploitAgent auto-discovers real verified modules from Metasploit RPC
    if llm_candidates is not None and len(llm_candidates) == 0:
        logger.info(
            "No valid LLM candidates available — falling back to Metasploit/SearchSploit discovery"
        )
        llm_candidates = None

    # Connect to msfrpcd; falls back to None (SearchSploit) if unreachable.
    msf_client = _get_msf_client()

    # Reuse (or lazily create) the module-level ExploitAgent so its
    # _globally_tried / _attempt_history persists across replan cycles.
    if _exploit_agent is None:
        _exploit_agent = ExploitAgent(attack_graph=ag, msf_client=msf_client)
        logger.info("Created new persistent ExploitAgent")
    else:
        # Update mutable references in case graph or MSF client changed
        _exploit_agent._graph = ag
        if msf_client is not None:
            _exploit_agent._msf = msf_client
        logger.info(
            "Reusing persistent ExploitAgent — %d module/service pairs already tried",
            len(_exploit_agent._globally_tried),
        )

    try:
        result = _exploit_agent.run(state["target"], candidates=llm_candidates)
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
    # Reuse an msfrpcd connection for session verification if available.
    msf_client = _get_msf_client()
    agent = VerificationAgent(
        attack_graph=state["attack_graph"],
        msf_client=msf_client,
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
    """Conditional edge: route to exploit if services found, else report.

    If state['mode'] is 'recon-only', force route to 'report'.
    """
    if state.get("mode") == "recon-only":
        logger.info("Recon-only mode — routing directly to report")
        state["termination_reason"] = "recon_only_completed"
        return "report"

    ag: AttackGraph = state["attack_graph"]
    if ag.get_exploitable_services():
        return "exploit"
    state["termination_reason"] = "no_exploitable_services"
    return "report"


def check_success(state: PenTestState) -> Literal["report", "replan"]:
    """Conditional edge after verification.

    Routes to 'report' when:
    - The last attempt succeeded
    - Mode is recon-only (no exploit phase intended)
    - The exploit attempt budget is exhausted (max 9 attempts)
    - The step budget is exceeded
    - All recent attempts share the same unrecoverable error (loop guard)

    Routes to 'replan' when the attempt failed and budget remains.
    """
    # recon-only: exploit node should never run, but if it does, stop immediately.
    if state.get("mode") == "recon-only":
        logger.info("recon-only mode — routing to report from check_success")
        state["termination_reason"] = "recon_only_completed"
        return "report"

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

    # ── Unrecoverable-error loop guard ───────────────────────────
    # If no new LLM candidates exist AND the last N attempts all share
    # the same terminal error (module_not_found OR connection_refused),
    # replanning cannot help — break the loop and report.
    _TERMINAL_ERRORS = ("module_not_found", "connection_refused")
    if not state.get("exploit_candidates") and last.error_type in _TERMINAL_ERRORS:
        recent = state["exploit_attempts"][-min(3, len(state["exploit_attempts"])):]
        all_terminal = all(a.error_type in _TERMINAL_ERRORS for a in recent)
        if all_terminal:
            logger.warning(
                "All recent attempts ended with unrecoverable errors (%s) "
                "and no new candidates — routing to report to break loop.",
                ", ".join(a.error_type or "?" for a in recent),
            )
            state["termination_reason"] = "no_valid_modules_found"
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
    # NOTE: msfrpcd connection is intentionally NOT attempted here.
    # build_graph() is called for ALL run modes (including recon-only)
    # and must never block on network I/O. The ExploitAgent manages
    # its own MSF connection lazily inside exploit_node() only when needed.
    print("[*] Building execution graph ...")

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

    workflow.add_edge("replan", "analyze_graph")  # re-run LLM with failure context
    workflow.add_edge("report", END)

    return workflow.compile()
