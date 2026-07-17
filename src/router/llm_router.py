"""LLM Router for PrivacyAware-PenAgent.

This module coordinates sensitivity and complexity classifiers, checks the cloud
token budget, and decides whether to dispatch a task to a local model (Ollama)
or a cloud model (OpenAI/Anthropic).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal
from src.router.complexity import TaskType, classify_complexity
from src.router.cost_tracker import CostTracker
from src.router.sensitivity import classify_sensitivity
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)


@dataclass
class RoutingDecision:
    """Information representing a routing decision."""

    model: str
    route: Literal["LOCAL", "CLOUD"]
    sensitivity_score: float
    complexity_score: float
    reasoning: str


class LLMRouter:
    """Decides between local and cloud LLM execution based on data constraints."""

    def __init__(self, cost_tracker: CostTracker | None = None) -> None:
        """Initialize LLMRouter.

        Args:
            cost_tracker: Optional CostTracker. If not provided, a new one is
              created.
        """
        self.cost_tracker = cost_tracker or CostTracker()

        # Load thresholds from environment or use standard defaults
        self.sensitivity_threshold = float(os.getenv("SENSITIVITY_THRESHOLD", "0.6"))
        self.complexity_threshold = float(os.getenv("COMPLEXITY_THRESHOLD", "0.7"))

        # Default model assignments
        self.local_model = os.getenv("LOCAL_MODEL", "llama3:8b")
        self.cloud_model = os.getenv("CLOUD_MODEL", "gpt-4o")

        logger.debug(
            "LLM Router configured",
            extra={
                "sensitivity_threshold": self.sensitivity_threshold,
                "complexity_threshold": self.complexity_threshold,
                "local_model": self.local_model,
                "cloud_model": self.cloud_model,
            },
        )

    def route(
        self,
        task_input: str,
        task_type: TaskType | str,
        force_route: Literal["LOCAL", "CLOUD"] | None = None,
    ) -> RoutingDecision:
        """Determine the target LLM route for the given input and task type.

        Decision is made by scoring data sensitivity and task complexity. If
        either exceeds its configured threshold, cloud route is chosen. If
        the cloud token budget is exceeded, local route is forced as fallback.

        Args:
            task_input: The input string (e.g., tool output, task details).
            task_type: The type of task (determining reasoning complexity).
            force_route: Optional override to bypass classification logic.

        Returns:
            A RoutingDecision object.
        """
        # 1. Handle force override (ablation runs)
        if force_route == "CLOUD":
            return RoutingDecision(
                model=self.cloud_model,
                route="CLOUD",
                sensitivity_score=0.0,
                complexity_score=0.0,
                reasoning="Routing forced to CLOUD (ablation/override)",
            )
        elif force_route == "LOCAL":
            return RoutingDecision(
                model=self.local_model,
                route="LOCAL",
                sensitivity_score=0.0,
                complexity_score=0.0,
                reasoning="Routing forced to LOCAL (ablation/override)",
            )

        # 2. Score input and task
        sensitivity_score = classify_sensitivity(task_input)
        complexity_score = classify_complexity(task_type)

        # 3. Check cloud budget
        budget_exceeded = self.cost_tracker.is_budget_exceeded()

        # 4. Make decision
        decision: Literal["LOCAL", "CLOUD"]
        if budget_exceeded:
            decision = "LOCAL"
            model = self.local_model
            reasoning = "Forced local: cloud token budget exceeded"
        elif (
            sensitivity_score >= self.sensitivity_threshold
            or complexity_score >= self.complexity_threshold
        ):
            decision = "CLOUD"
            model = self.cloud_model
            reasoning = (
                f"Cloud route selected: sensitivity ({sensitivity_score:.2f}) "
                f">= {self.sensitivity_threshold} OR "
                f"complexity ({complexity_score:.2f}) >= {self.complexity_threshold}"
            )
        else:
            decision = "LOCAL"
            model = self.local_model
            reasoning = (
                f"Local route selected: sensitivity ({sensitivity_score:.2f}) "
                f"< {self.sensitivity_threshold} AND "
                f"complexity ({complexity_score:.2f}) < {self.complexity_threshold}"
            )

        routing_decision = RoutingDecision(
            model=model,
            route=decision,
            sensitivity_score=sensitivity_score,
            complexity_score=complexity_score,
            reasoning=reasoning,
        )

        logger.info(
            "Routing decision made",
            extra={
                "task_type": (
                    task_type.value if isinstance(task_type, TaskType) else task_type
                ),
                "sensitivity_score": sensitivity_score,
                "complexity_score": complexity_score,
                "route": decision,
                "model": model,
                "reasoning": reasoning,
            },
        )

        return routing_decision
