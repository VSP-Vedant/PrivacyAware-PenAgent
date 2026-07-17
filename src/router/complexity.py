"""Complexity Classifier for PrivacyAware-PenAgent.

This module maps different penetration testing tasks to their reasoning
complexity score between 0.0 and 1.0.
"""

from __future__ import annotations

from enum import Enum
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)


class TaskType(str, Enum):
    """Enumeration of pentest task types mapping to reasoning complexity."""

    SUMMARIZE = "SUMMARIZE"
    FORMAT_OUTPUT = "FORMAT_OUTPUT"
    COMMAND_TEMPLATE = "COMMAND_TEMPLATE"
    CVE_LOOKUP = "CVE_LOOKUP"
    EXPLOIT_SELECTION = "EXPLOIT_SELECTION"
    PRIV_ESC_REASONING = "PRIV_ESC_REASONING"
    MULTI_CVE_CHAIN = "MULTI_CVE_CHAIN"


# Base complexity score mappings as defined in ARCHITECTURE.md
COMPLEXITY_MAP: dict[TaskType, float] = {
    TaskType.SUMMARIZE: 0.1,
    TaskType.FORMAT_OUTPUT: 0.2,
    TaskType.COMMAND_TEMPLATE: 0.3,
    TaskType.CVE_LOOKUP: 0.5,
    TaskType.EXPLOIT_SELECTION: 0.7,
    TaskType.PRIV_ESC_REASONING: 0.9,
    TaskType.MULTI_CVE_CHAIN: 1.0,
}


def classify_complexity(task_type: TaskType | str) -> float:
    """Classify the reasoning complexity of a task type.

    Args:
        task_type: The task type as a TaskType enum or matching string.

    Returns:
        A complexity score between 0.0 and 1.0.
    """
    try:
        # Convert string to enum if necessary
        if isinstance(task_type, str):
            enum_val = TaskType(task_type.upper())
        else:
            enum_val = task_type
    except ValueError:
        logger.warning(
            "Unknown task type string received, defaulting to moderate complexity",
            extra={"raw_task_type": task_type},
        )
        return 0.5

    score = COMPLEXITY_MAP.get(enum_val, 0.5)

    logger.debug(
        "Complexity classification completed",
        extra={
            "task_type": enum_val.value,
            "complexity_score": score,
        },
    )

    return score
