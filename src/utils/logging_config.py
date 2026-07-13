"""src/utils/logging_config.py — Logging configuration re-exports and run logger.

Re-exports ``setup_logger`` from ``src.utils.logger`` and adds a
per-run file logger factory used by ``src/main.py``.

Owner: Vighnesh (Member B)
"""

from __future__ import annotations

import logging
from pathlib import Path

from src.utils.logger import JSONFormatter, setup_logger  # noqa: F401 — re-export

__all__ = ["setup_logger", "get_run_logger"]


def get_run_logger(run_id: str, log_dir: str = "logs") -> logging.Logger:
    """Create a per-run logger that writes to ``logs/<run_id>.jsonl``.

    Args:
        run_id: Unique identifier for this penetration-test run.
        log_dir: Directory to write run log files into.

    Returns:
        A :class:`logging.Logger` configured with both console and file
        handlers using the JSON formatter.
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    log_file = log_path / f"{run_id}.jsonl"
    logger = logging.getLogger(f"run.{run_id}")

    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = JSONFormatter()

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(str(log_file))
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
