"""Chart generation for evaluation results.

Produces publication-ready figures using matplotlib, saved as PNG files
in ``data/analysis/charts/``.

Owner: Parth (Member D) — Week 25–28 deliverable
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.utils.logger import setup_logger

logger = setup_logger(__name__)

# Default output directory for charts
_CHARTS_DIR = "data/analysis/charts"


def _ensure_dir(directory: str) -> Path:
    """Create directory if it does not exist and return its Path."""
    p = Path(directory)
    p.mkdir(parents=True, exist_ok=True)
    return p


def generate_sr_pr_bar_chart(
    per_target: dict[str, dict[str, Any]],
    output_dir: str = _CHARTS_DIR,
) -> str | None:
    """Generate a grouped bar chart of Success Rate and Progress Rate per target.

    Args:
        per_target: Output from ``aggregator.per_target_breakdown()``.
        output_dir: Directory to save the chart image.

    Returns:
        Path to the saved PNG, or None if matplotlib is unavailable.
    """
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib not installed — skipping SR/PR chart")
        return None

    targets = list(per_target.keys())
    sr_vals = [per_target[t].get("success_rate", 0.0) for t in targets]
    pr_vals = [per_target[t].get("mean_progress_rate", 0.0) for t in targets]

    # Shorten target names for display
    short_names = [t.replace(".", "_")[-12:] for t in targets]

    fig, ax = plt.subplots(figsize=(max(6, len(targets) * 1.5), 5))
    x = range(len(targets))
    width = 0.35

    ax.bar(
        [i - width / 2 for i in x],
        sr_vals,
        width,
        label="Success Rate (SR)",
        color="#3fb950",
        edgecolor="#21262d",
    )
    ax.bar(
        [i + width / 2 for i in x],
        pr_vals,
        width,
        label="Progress Rate (PR)",
        color="#58a6ff",
        edgecolor="#21262d",
    )

    ax.set_xlabel("Target")
    ax.set_ylabel("Rate (0.0 – 1.0)")
    ax.set_title("Success Rate & Progress Rate per Target")
    ax.set_xticks(list(x))
    ax.set_xticklabels(short_names, rotation=45, ha="right")
    ax.set_ylim(0, 1.1)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()

    out = _ensure_dir(output_dir) / "sr_pr_per_target.png"
    fig.savefig(str(out), dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.info("SR/PR bar chart saved to %s", out)
    return str(out)


def generate_routing_pie_chart(
    records: list[dict[str, Any]],
    output_dir: str = _CHARTS_DIR,
) -> str | None:
    """Generate a pie chart showing Cloud vs Local LLM routing ratio.

    Args:
        records: List of metric dicts.
        output_dir: Directory to save the chart image.

    Returns:
        Path to the saved PNG, or None if matplotlib is unavailable.
    """
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib not installed — skipping routing chart")
        return None

    cloud = sum(r.get("cloud_api_calls", 0) for r in records)
    # Estimate total calls from step counts (each step may invoke LLM)
    total_steps = sum(r.get("step_count", 0) for r in records)
    local = max(0, total_steps - cloud)

    if cloud + local == 0:
        logger.warning("No routing data available — skipping chart")
        return None

    fig, ax = plt.subplots(figsize=(6, 5))
    sizes = [local, cloud]
    labels = [f"Local (Ollama)\n{local} calls", f"Cloud\n{cloud} calls"]
    colors = ["#3fb950", "#f85149"]
    explode = (0.03, 0.03)

    ax.pie(
        sizes,
        explode=explode,
        labels=labels,
        colors=colors,
        autopct="%1.1f%%",
        shadow=False,
        startangle=90,
        textprops={"fontsize": 10},
    )
    ax.set_title("LLM Routing Distribution\n(Local vs Cloud)")
    fig.tight_layout()

    out = _ensure_dir(output_dir) / "routing_distribution.png"
    fig.savefig(str(out), dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.info("Routing pie chart saved to %s", out)
    return str(out)


def generate_ttfs_bar_chart(
    per_target: dict[str, dict[str, Any]],
    output_dir: str = _CHARTS_DIR,
) -> str | None:
    """Generate a bar chart of Time-to-First-Shell per target.

    Args:
        per_target: Output from ``aggregator.per_target_breakdown()``.
        output_dir: Directory to save the chart image.

    Returns:
        Path to the saved PNG, or None if matplotlib is unavailable.
    """
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib not installed — skipping TTFS chart")
        return None

    targets = []
    ttfs_vals = []
    for t, data in per_target.items():
        ttfs = data.get("mean_ttfs_seconds")
        if ttfs is not None:
            targets.append(t.replace(".", "_")[-12:])
            ttfs_vals.append(ttfs)

    if not targets:
        logger.warning("No TTFS data available — skipping chart")
        return None

    fig, ax = plt.subplots(figsize=(max(6, len(targets) * 1.5), 5))
    bars = ax.bar(
        targets,
        ttfs_vals,
        color="#e8963a",
        edgecolor="#21262d",
    )

    # Add value labels on bars
    for bar_item, val in zip(bars, ttfs_vals):
        ax.text(
            bar_item.get_x() + bar_item.get_width() / 2,
            bar_item.get_height() + 5,
            f"{val:.0f}s",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    ax.set_xlabel("Target")
    ax.set_ylabel("Time-to-First-Shell (seconds)")
    ax.set_title("Time-to-First-Shell per Target")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()

    out = _ensure_dir(output_dir) / "ttfs_per_target.png"
    fig.savefig(str(out), dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.info("TTFS bar chart saved to %s", out)
    return str(out)


def generate_exploit_efficiency_chart(
    per_target: dict[str, dict[str, Any]],
    output_dir: str = _CHARTS_DIR,
) -> str | None:
    """Generate a stacked bar chart of successful vs failed exploit attempts.

    Args:
        per_target: Output from ``aggregator.per_target_breakdown()``.
        output_dir: Directory to save the chart image.

    Returns:
        Path to the saved PNG, or None if matplotlib is unavailable.
    """
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib not installed — skipping efficiency chart")
        return None

    targets = list(per_target.keys())
    short_names = [t.replace(".", "_")[-12:] for t in targets]
    successes = [per_target[t].get("total_successful_exploits", 0) for t in targets]
    failures = [
        per_target[t].get("total_exploit_attempts", 0)
        - per_target[t].get("total_successful_exploits", 0)
        for t in targets
    ]

    fig, ax = plt.subplots(figsize=(max(6, len(targets) * 1.5), 5))
    ax.bar(
        short_names,
        successes,
        label="Successful",
        color="#3fb950",
        edgecolor="#21262d",
    )
    ax.bar(
        short_names,
        failures,
        bottom=successes,
        label="Failed",
        color="#f85149",
        edgecolor="#21262d",
    )

    ax.set_xlabel("Target")
    ax.set_ylabel("Number of Exploit Attempts")
    ax.set_title("Exploit Attempt Efficiency per Target")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.xticks(rotation=45, ha="right")
    fig.tight_layout()

    out = _ensure_dir(output_dir) / "exploit_efficiency.png"
    fig.savefig(str(out), dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.info("Exploit efficiency chart saved to %s", out)
    return str(out)


def generate_all_charts(
    records: list[dict[str, Any]],
    per_target: dict[str, dict[str, Any]],
    output_dir: str = _CHARTS_DIR,
) -> dict[str, str | None]:
    """Generate all available charts.

    Args:
        records: List of metric dicts.
        per_target: Per-target breakdown from aggregator.
        output_dir: Directory to save chart images.

    Returns:
        Dict mapping chart name → file path (or None on failure).
    """
    return {
        "sr_pr": generate_sr_pr_bar_chart(per_target, output_dir),
        "routing": generate_routing_pie_chart(records, output_dir),
        "ttfs": generate_ttfs_bar_chart(per_target, output_dir),
        "exploit_efficiency": generate_exploit_efficiency_chart(per_target, output_dir),
    }
