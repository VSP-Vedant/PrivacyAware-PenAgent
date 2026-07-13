"""LLM Router for PrivacyAware-PenAgent. Member A owned.

Core innovation: Runtime routing between local and cloud LLMs
based on sensitivity and complexity + cost tracking.
"""

import os
from typing import Literal, NamedTuple, cast

from dotenv import load_dotenv

from .complexity import classify_complexity
from .cost_tracker import cost_tracker
from .sensitivity import classify_sensitivity

load_dotenv()

SENSITIVITY_THRESHOLD = float(os.getenv("SENSITIVITY_THRESHOLD", 0.6))
COMPLEXITY_THRESHOLD = float(os.getenv("COMPLEXITY_THRESHOLD", 0.7))


class RoutingDecision(NamedTuple):
    """Runtime decision object (mypy workaround)."""

    model: str
    route: Literal["LOCAL", "CLOUD"]
    sensitivity: float
    complexity: float
    reasoning: str


def route(task_input: str, task_type: str) -> RoutingDecision:
    """Main routing decision logic per ARCHITECTURE.md."""
    sensitivity = classify_sensitivity(task_input)
    complexity = classify_complexity(task_type)

    if sensitivity > SENSITIVITY_THRESHOLD or complexity > COMPLEXITY_THRESHOLD:
        model = "gpt-4o"
        route_type = cast(Literal["LOCAL", "CLOUD"], "CLOUD")
        reasoning = f"High sensitivity ({sensitivity}) or complexity ({complexity})"
    else:
        model = "llama3:8b"
        route_type = cast(Literal["LOCAL", "CLOUD"], "LOCAL")
        reasoning = f"Low risk task (sens={sensitivity}, comp={complexity})"

    # Record for cost tracking (token count will be updated by actual LLM calls)
    cost_tracker.record_call(model, 0, 0)

    return RoutingDecision(model, route_type, sensitivity, complexity, reasoning)
