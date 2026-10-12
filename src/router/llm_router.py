"""LLM Router for PrivacyAware-PenAgent.

This module coordinates sensitivity and complexity classifiers, checks the cloud
token budget, and decides whether to dispatch a task to a local model (Ollama)
or a cloud model (OpenAI/Anthropic).

When local execution is selected, the router further selects the appropriate
local model based on ``local_task_type`` (synthesis vs. generation) using
the model registry loaded from ``src/config/models.yaml``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Literal

from src.config.settings import load_model_config
from src.router.complexity import TaskType, classify_complexity
from src.router.cost_tracker import CostTracker
from src.router.sensitivity import classify_sensitivity
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)


def _cloud_key_available() -> bool:
    """Return True if at least one cloud API key is configured."""
    import os

    return bool(os.getenv("OPENAI_API_KEY", "") or os.getenv("ANTHROPIC_API_KEY", ""))


@dataclass
class RoutingDecision:
    """Information representing a routing decision."""

    model: str
    route: Literal["LOCAL", "CLOUD"]
    sensitivity_score: float = 0.0
    complexity_score: float = 0.0
    reasoning: str = ""
    # Aliases accepted by older test code that used 'sensitivity'/'complexity'
    sensitivity: float = 0.0
    complexity: float = 0.0
    # ── Task-aware local model routing fields ──
    local_task_type: str = ""
    model_config_entry: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Sync alias fields with canonical fields."""
        # If caller used alias names, populate the canonical names
        if self.sensitivity and not self.sensitivity_score:
            self.sensitivity_score = self.sensitivity
        if self.complexity and not self.complexity_score:
            self.complexity_score = self.complexity
        # Keep aliases in sync too
        if self.sensitivity_score and not self.sensitivity:
            self.sensitivity = self.sensitivity_score
        if self.complexity_score and not self.complexity:
            self.complexity = self.complexity_score


class LLMRouter:
    """Decides between local and cloud LLM execution based on data constraints.

    When local execution is selected, the router further picks the appropriate
    Ollama model based on ``local_task_type``:

    * ``"synthesis"`` — vulnerability profiling / CVE reasoning
      → Foundation-Sec-8B-Instruct (fallback: WhiteRabbitNeo-v1.5a)
    * ``"generation"`` — structured JSON payload output for ExploitAgent
      → Qwen2.5-Coder-14B with Ollama ``format="json"``

    Model assignments are loaded from ``src/config/models.yaml`` and can be
    swapped without touching router code.
    """

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

        # Default model assignments — LOCAL_MODEL (legacy single-model fallback)
        self.local_model = os.getenv("LOCAL_MODEL", "llama3:8b")
        self.cloud_model = os.getenv("CLOUD_MODEL", "gpt-4o")

        # Load task-aware local model config from models.yaml
        self._model_config: dict[str, dict[str, Any]] = load_model_config()

        # Detect whether any cloud API key is configured
        self._cloud_available = bool(
            os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        )

        logger.debug(
            "LLM Router configured",
            extra={
                "sensitivity_threshold": self.sensitivity_threshold,
                "complexity_threshold": self.complexity_threshold,
                "local_model": self.local_model,
                "cloud_model": self.cloud_model,
                "cloud_available": self._cloud_available,
                "local_model_config": {
                    k: v.get("ollama_tag", "?") for k, v in self._model_config.items()
                },
            },
        )

    def _resolve_local_model(
        self, local_task_type: str | None,
    ) -> tuple[str, str, dict[str, Any]]:
        """Pick the Ollama model tag and human name for a local_task_type.

        Returns:
            ``(ollama_tag, human_name, full_config_entry)``
        """
        if local_task_type and local_task_type in self._model_config:
            entry = self._model_config[local_task_type]
            tag = str(entry.get("ollama_tag", self.local_model))
            name = str(entry.get("name", tag))
            return tag, name, dict(entry)

        # Fallback: use legacy single local model
        return self.local_model, self.local_model, {}

    def route(
        self,
        task_input: str,
        task_type: TaskType | str,
        force_route: Literal["LOCAL", "CLOUD"] | None = None,
        local_task_type: str | None = None,
    ) -> RoutingDecision:
        """Determine the target LLM route for the given input and task type.

        Decision is made by scoring data sensitivity and task complexity. If
        either exceeds its configured threshold, cloud route is chosen. If
        the cloud token budget is exceeded, local route is forced as fallback.

        When the decision is **LOCAL**, the specific Ollama model is selected
        based on ``local_task_type`` (defaulting to ``"synthesis"`` when not
        provided).

        Args:
            task_input: The input string (e.g., tool output, task details).
            task_type: The type of task (determining reasoning complexity).
            force_route: Optional override to bypass classification logic.
            local_task_type: Which local model role to use — ``"synthesis"``
                for vulnerability reasoning, ``"generation"`` for structured
                JSON output.  Ignored when routing to CLOUD.

        Returns:
            A RoutingDecision object.
        """
        # Normalise local_task_type default
        effective_local_task_type = local_task_type or "synthesis"

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
            tag, name, entry = self._resolve_local_model(effective_local_task_type)
            return RoutingDecision(
                model=tag,
                route="LOCAL",
                sensitivity_score=0.0,
                complexity_score=0.0,
                reasoning=f"Routing forced to LOCAL (ablation/override) → {name}",
                local_task_type=effective_local_task_type,
                model_config_entry=entry,
            )

        # 2. Score input and task
        sensitivity_score = classify_sensitivity(task_input)
        complexity_score = classify_complexity(task_type)

        # 3. Check cloud budget
        budget_exceeded = self.cost_tracker.is_budget_exceeded()

        # 4. Make decision
        decision: Literal["LOCAL", "CLOUD"]
        model_config_entry: dict[str, Any] = {}
        resolved_local_task_type = ""

        if budget_exceeded:
            decision = "LOCAL"
            tag, name, model_config_entry = self._resolve_local_model(
                effective_local_task_type
            )
            model = tag
            resolved_local_task_type = effective_local_task_type
            reasoning = f"Forced local: cloud token budget exceeded → {name}"
        elif (
            sensitivity_score >= self.sensitivity_threshold
            or complexity_score >= self.complexity_threshold
        ):
            decision = "CLOUD"
            model = self.cloud_model
            resolved_local_task_type = effective_local_task_type
            _, _, model_config_entry = self._resolve_local_model(
                effective_local_task_type
            )
            reasoning = (
                f"Cloud route selected: sensitivity ({sensitivity_score:.2f}) "
                f">= {self.sensitivity_threshold} OR "
                f"complexity ({complexity_score:.2f}) >= {self.complexity_threshold}"
            )
        else:
            decision = "LOCAL"
            tag, name, model_config_entry = self._resolve_local_model(
                effective_local_task_type
            )
            model = tag
            resolved_local_task_type = effective_local_task_type
            reasoning = (
                f"Local route selected: sensitivity ({sensitivity_score:.2f}) "
                f"< {self.sensitivity_threshold} AND "
                f"complexity ({complexity_score:.2f}) < {self.complexity_threshold}"
                f" → {name}"
            )

        routing_decision = RoutingDecision(
            model=model,
            route=decision,
            sensitivity_score=sensitivity_score,
            complexity_score=complexity_score,
            reasoning=reasoning,
            local_task_type=resolved_local_task_type,
            model_config_entry=model_config_entry,
        )

        logger.info(
            "Routing decision made",
            extra={
                "task_type": (
                    task_type.value if isinstance(task_type, TaskType) else task_type
                ),
                "local_task_type": resolved_local_task_type or "(cloud)",
                "sensitivity_score": sensitivity_score,
                "complexity_score": complexity_score,
                "route": decision,
                "model": model,
                "reasoning": reasoning,
            },
        )

        return routing_decision
