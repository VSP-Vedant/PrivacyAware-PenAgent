"""Cost Tracker for PrivacyAware-PenAgent.

This module tracks token usage and USD costs for both local and cloud LLM
invocations. It also enforces the cloud token budget per run.
"""

from __future__ import annotations

import os
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)

# Model pricing mapping per 1,000,000 tokens (in USD)
# Format: (input_cost_per_1m, output_cost_per_1m)
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-2024-11-20": (2.50, 10.00),
    "gpt-4o-mini": (0.150, 0.600),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-5-sonnet-20241022": (3.00, 15.00),
    "llama3:8b": (0.0, 0.0),
    "llama3:8b-instruct-q4_K_M": (0.0, 0.0),
    "mistral:7b": (0.0, 0.0),
    "mistral:7b-instruct-v0.3-q4_K_M": (0.0, 0.0),
}


class CostTracker:
    """Tracks token consumption and financial cost of LLM runs.

    Args:
        max_cloud_tokens: The token limit for cloud model execution.
    """

    def __init__(self, max_cloud_tokens: int | None = None) -> None:
        """Initialize the CostTracker."""
        if max_cloud_tokens is None:
            # Load from environment or default to 50,000
            env_limit = os.getenv("MAX_CLOUD_TOKENS_PER_RUN")
            self.max_cloud_tokens = int(env_limit) if env_limit else 50000
        else:
            self.max_cloud_tokens = max_cloud_tokens

        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0

        logger.debug(
            "Cost tracker initialized",
            extra={"max_cloud_tokens": self.max_cloud_tokens},
        )

    def add_run(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        latency_ms: float = 0.0,
    ) -> float:
        """Record token counts for a run and compute cost in USD.

        Args:
            model: The name of the LLM model used.
            input_tokens: Number of prompt/input tokens.
            output_tokens: Number of completion/output tokens.
            latency_ms: Time taken for the API response.

        Returns:
            The calculated cost of this run in USD.
        """
        # Determine pricing rate (default to gpt-4o if cloud model is unknown)
        pricing = MODEL_PRICING.get(model)
        if pricing is None:
            if any(k in model.lower() for k in ["llama", "mistral", "local"]):
                pricing = (0.0, 0.0)
            else:
                pricing = MODEL_PRICING["gpt-4o"]
                logger.warning(
                    f"Unknown cloud model '{model}', using gpt-4o rate",
                    extra={"model": model},
                )

        input_rate, output_rate = pricing
        run_cost = (input_tokens / 1_000_000 * input_rate) + (
            output_tokens / 1_000_000 * output_rate
        )

        # Update totals if it's a cloud model (pricing is non-zero)
        if input_rate > 0.0 or output_rate > 0.0:
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_usd += run_cost

        logger.info(
            "LLM API call tracked",
            extra={
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "latency_ms": latency_ms,
                "cost_usd": run_cost,
                "cumulative_cost_usd": self.total_cost_usd,
            },
        )

        return run_cost

    def is_budget_exceeded(self) -> bool:
        """Check if the cloud token budget has been exceeded.

        Returns:
            True if the limit has been reached, otherwise False.
        """
        total_used = self.total_input_tokens + self.total_output_tokens
        exceeded = total_used >= self.max_cloud_tokens
        if exceeded:
            logger.warning(
                "Cloud token budget exceeded! Forcing local routing.",
                extra={
                    "total_used": total_used,
                    "budget_limit": self.max_cloud_tokens,
                },
            )
        return exceeded

    def reset(self) -> None:
        """Reset the tracker's metrics for a new execution session."""
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0
        logger.info("Cost tracker reset to zero usage")
