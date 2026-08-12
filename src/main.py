"""src/main.py — CLI entry point.

Owner: Vighnesh (Member B)
"""

from __future__ import annotations

import argparse
import sys
import time

import requests

from src.config.settings import MAX_TOTAL_STEPS, OLLAMA_HOST
from src.state.attack_graph import AttackGraph
from src.state.persistence import PersistenceManager
from src.state.schemas import PenTestState
from src.utils.logging_config import get_run_logger
from src.utils.validators import TargetValidationError, validate_target

_BANNER = """
╔══════════════════════════════════════════════════════╗
║          PrivacyAware-PenAgent  v0.1                 ║
╚══════════════════════════════════════════════════════╝"""


def _check_ollama(no_router: bool) -> None:
    """Warn if Ollama is unreachable when the local route will be used."""
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        tags = r.json().get("models", [])
        if not tags:
            print(
                "[WARN] Ollama is running but NO models are loaded.\n"
                "       Run: ollama pull xploiter/pentester"
            )
        else:
            names = [m.get("name", "") for m in tags]
            print(f"[OK]  Ollama reachable — loaded models: {', '.join(names)}")
    except Exception:
        print(
            "[WARN] Ollama is NOT reachable at",
            OLLAMA_HOST,
            "\n"
            "       Local LLM calls will fail (180 s timeout each).\n"
            "       Start Ollama: ollama serve",
        )
        if no_router:
            print(
                "[ERR]  --no-router forces LOCAL route but Ollama is down.\n"
                "       Either start Ollama or remove --no-router."
            )
            sys.exit(1)


def main() -> None:
    """Docstring."""
    parser = argparse.ArgumentParser(description="PrivacyAware-PenAgent")
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument(
        "--mode", choices=["full", "recon-only"], default="full", help="Operation mode"
    )
    parser.add_argument(
        "--no-router",
        action="store_true",
        help="Ablation: Disable LLM router, force local",
    )
    parser.add_argument(
        "--no-graph", action="store_true", help="Ablation: Disable state graph"
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Ablation: Disable verification agent",
    )
    parser.add_argument(
        "--visualize",
        action="store_true",
        help="Generate attack graph visualization after run",
    )

    args = parser.parse_args()

    run_ts = int(time.time())
    run_id = f"{args.target.replace('/', '_')}_{run_ts}"
    logger = get_run_logger(run_id)

    print(_BANNER)
    print(f"[*] Target      : {args.target}")
    print(f"[*] Mode        : {args.mode}")
    print(f"[*] No-router   : {args.no_router}")
    print(f"[*] Run ID      : {run_id}")
    print(f"[*] Log file    : logs/{run_id}.jsonl")
    print()

    logger.info(
        "Starting PenAgent",
        extra={"target": args.target, "mode": args.mode, "run_id": run_id},
    )

    try:
        validate_target(args.target)
    except TargetValidationError as e:
        logger.critical(str(e))
        print(f"[ERR] Target validation failed: {e}")
        sys.exit(1)

    if args.no_graph:
        logger.warning("Graph ablation mode enabled. Graph state will not be tracked.")

    if args.no_router:
        logger.info("Router ablation mode enabled. Forcing local LLM only.")

    if args.no_verify:
        logger.info("Verification ablation mode enabled. Skipping verify node.")

    # Ollama health check — warn early instead of hanging silently later
    _check_ollama(args.no_router)

    # Initialize state — each run gets its OWN fresh database so data from
    # previous runs never contaminates the current attack graph.
    target_safe = args.target.replace(".", "_").replace("/", "_")
    run_db_path = f"runs/{target_safe}_{run_ts}.db"

    # Map CLI --mode to nmap scan preset:
    #   recon-only → quick  (top 100 ports, ~1-2 min over VPN)
    #   full       → default (-sV -sC top 1000 ports, ~3-5 min)
    # Use NMAP_SCAN_TYPE env override to force any preset.
    import os
    _mode_to_scan = {"full": "default", "recon-only": "quick"}
    scan_type = os.getenv("NMAP_SCAN_TYPE", _mode_to_scan.get(args.mode, "quick"))

    initial_state: PenTestState = {
        "target": args.target,
        "attack_graph": AttackGraph(db_path=run_db_path),
        "current_phase": "recon",
        "exploit_attempts": [],
        "sessions": [],
        "step_count": 0,
        "max_steps": MAX_TOTAL_STEPS,
        "cloud_tokens_used": 0,
        "findings": [],
        "routing_decisions": [],
        "exploit_candidates": [],
        "router_enabled": not args.no_router,
        "verify_enabled": not args.no_verify,  # Week 19-22: ablation flag
        "run_start_ts": time.time(),  # Week 19-22: used for TTFS metric
        "start_time": "",
        "end_time": "",
        "termination_reason": "",
        "nmap_scan_type": scan_type,  # passed to recon_node
        "mode": args.mode,
    }

    # Build LangGraph — import here (not at top of file) so that any
    # module-level code in orchestrator.py only runs AFTER the banner
    # and Ollama check above have already printed to the terminal.
    from src.agents.orchestrator import build_graph  # noqa: PLC0415
    app = build_graph(no_verify=args.no_verify)

    # Execute graph
    logger.info("Invoking graph")
    print(f"[*] Nmap preset : {scan_type}")
    print(f"[*] Starting graph execution ... (logs → logs/{run_id}.jsonl)")
    print()
    try:
        final_state = app.invoke(initial_state)

        logger.info(
            "Graph execution completed", extra={"steps": final_state["step_count"]}
        )

        # Save persistence
        db_path = f"runs/{args.target.replace('.', '_')}_{run_ts}.db"
        pm = PersistenceManager(db_path=db_path)
        pm.save_graph(final_state["attack_graph"].graph)

        # Generate visualization if requested
        if args.visualize:
            from src.utils.visualize import visualize_attack_graph

            output_file = f"runs/{run_id}_attack_graph.png"
            visualize_attack_graph(final_state["attack_graph"], output_file)
            logger.info("Attack graph visualization saved to %s", output_file)

        # Log routing summary
        routing_decisions = final_state.get("routing_decisions", [])
        if routing_decisions:
            cloud_count = sum(1 for d in routing_decisions if d.get("route") == "CLOUD")
            local_count = sum(1 for d in routing_decisions if d.get("route") == "LOCAL")
            logger.info(
                "Routing summary: %d cloud, %d local decisions",
                cloud_count,
                local_count,
            )

        # Print evaluation metrics summary to stdout
        for finding in reversed(final_state.get("findings", [])):
            if "evaluation_metrics" in finding:
                m = finding["evaluation_metrics"]
                print("\n" + "=" * 50)
                print("  RUN SUMMARY")
                print("=" * 50)
                print(f"  Target       : {m.get('target', 'unknown')}")
                print(f"  Success      : {'YES ✅' if m.get('success') else 'NO ❌'}")
                print(f"  Progress Rate: {m.get('progress_rate', 0) * 100:.0f}%")
                print(f"  Milestones   : {m.get('milestones_hit', [])!r}")
                ttfs = m.get("ttfs_seconds")
                print(
                    f"  TTFS         : {f'{ttfs:.1f}s' if ttfs is not None else 'N/A'}"
                )
                print(f"  Steps        : {m.get('step_count', 0)}")
                print(f"  Cloud calls  : {m.get('cloud_api_calls', 0)}")
                print(f"  Cloud cost   : ${m.get('cloud_cost_usd', 0.0):.4f}")
                print("=" * 50 + "\n")
                break

    except Exception as e:
        logger.error("Graph execution failed", extra={"error": str(e)}, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
