"""src/main.py — CLI entry point.

Owner: Vighnesh (Member B)
"""

from __future__ import annotations

import argparse
import sys
import time

from src.agents.orchestrator import build_graph
from src.config.settings import MAX_TOTAL_STEPS
from src.state.attack_graph import AttackGraph
from src.state.persistence import PersistenceManager
from src.state.schemas import PenTestState
from src.utils.logging_config import get_run_logger
from src.utils.validators import TargetValidationError, validate_target


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

    args = parser.parse_args()

    run_ts = int(time.time())
    run_id = f"{args.target.replace('/', '_')}_{run_ts}"
    logger = get_run_logger(run_id)

    logger.info(
        "Starting PenAgent",
        extra={"target": args.target, "mode": args.mode, "run_id": run_id},
    )

    try:
        validate_target(args.target)
    except TargetValidationError as e:
        logger.critical(str(e))
        sys.exit(1)

    if args.no_graph:
        logger.warning("Graph ablation mode enabled. Graph state will not be tracked.")

    # Initialize state
    initial_state: PenTestState = {
        "target": args.target,
        "attack_graph": AttackGraph(),
        "current_phase": "recon",
        "exploit_attempts": [],
        "sessions": [],
        "step_count": 0,
        "max_steps": MAX_TOTAL_STEPS,
        "cloud_tokens_used": 0,
        "findings": [],
    }

    # Build LangGraph
    app = build_graph()

    # Execute graph
    logger.info("Invoking graph")
    try:
        final_state = app.invoke(initial_state)

        logger.info(
            "Graph execution completed", extra={"steps": final_state["step_count"]}
        )

        # Save persistence
        db_path = f"runs/{args.target.replace('.', '_')}_{run_ts}.db"
        pm = PersistenceManager(db_path=db_path)
        pm.save_graph(final_state["attack_graph"].graph)

    except Exception as e:
        logger.error("Graph execution failed", extra={"error": str(e)}, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
