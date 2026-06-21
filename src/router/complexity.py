"""Complexity classifier for LLM routing. Member A owned.

Maps task types to complexity scores as defined in ARCHITECTURE.md.
"""

from typing import Dict

TASK_COMPLEXITY: Dict[str, float] = {
    "SUMMARIZE": 0.1,
    "FORMAT_OUTPUT": 0.2,
    "COMMAND_TEMPLATE": 0.3,
    "CVE_LOOKUP": 0.5,
    "EXPLOIT_SELECTION": 0.7,
    "PRIV_ESC_REASONING": 0.9,
    "MULTI_CVE_CHAIN": 1.0,
    "POST_MORTEM": 0.6,
    "GRAPH_QUERY": 0.4,
    "REPORT_GENERATION": 0.25,
    "SENSITIVITY_CLASSIFICATION": 0.2,
}


def classify_complexity(task_type: str) -> float:
    """Map task type to complexity score (0.0-1.0)."""
    if not task_type:
        return 0.5
    return TASK_COMPLEXITY.get(task_type.upper(), 0.5)
