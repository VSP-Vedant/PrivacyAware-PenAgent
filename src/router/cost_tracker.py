"""Cost Tracker for LLM calls. Member A owned.

Tracks token usage and estimated USD cost for hybrid routing.
"""

from datetime import datetime
from typing import TypedDict

from dotenv import load_dotenv

load_dotenv()

# Pricing (approximate, June 2026 rates)
LOCAL_COST_PER_1M_TOKENS = 0.0  # Free on Ollama
CLOUD_COST_PER_1M_INPUT_TOKENS = 0.03  # GPT-4o
CLOUD_COST_PER_1M_OUTPUT_TOKENS = 0.06


class CostEntry(TypedDict):
    """Docstring."""
    model: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    cost_usd: float
    timestamp: str


class CostTracker:
    """Docstring."""
    def __init__(self) -> None:
        """Docstring."""
        self.entries: list[CostEntry] = []
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0

    def record_call(self, model: str, input_tokens: int, output_tokens: int) -> None:
        """Record a single LLM call."""
        cost = self._calculate_cost(model, input_tokens, output_tokens)

        entry: CostEntry = {
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "cost_usd": cost,
            "timestamp": self._get_timestamp(),
        }

        self.entries.append(entry)
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cost_usd += cost

    def _calculate_cost(
        self, model: str, input_tokens: int, output_tokens: int
    ) -> float:
        """Calculate cost based on model type."""
        if "gpt-4o" in model.lower():
            return (input_tokens / 1_000_000) * CLOUD_COST_PER_1M_INPUT_TOKENS + (
                output_tokens / 1_000_000
            ) * CLOUD_COST_PER_1M_OUTPUT_TOKENS
        # Local models are free
        return 0.0

    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def get_summary(self) -> str:
        """Return human-readable summary."""
        return (
            "Cost Summary:\n"
            f"  Total Calls: {len(self.entries)}\n"
            f"  Total Input Tokens: {self.total_input_tokens}\n"
            f"  Total Output Tokens: {self.total_output_tokens}\n"
            f"  Total Cost: ${self.total_cost_usd:.6f}\n"
            f"  Cloud Usage: {sum(1 for e in self.entries if 'gpt-4o' in e['model'])} calls\n"  # noqa: E501
        )

    def get_detailed_log(self) -> list[CostEntry]:
        """Return full log."""
        return self.entries.copy()

    def reset(self) -> None:
        """Reset tracker for new run."""
        self.entries = []
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0


cost_tracker = CostTracker()
