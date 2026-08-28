"""Statistical variance analysis for repeated pentest runs.

Computes mean ± standard deviation, confidence intervals, and
distributional summaries for key evaluation metrics across multiple
runs of the same configuration.

Owner: Parth (Member D) — Week 27–28 deliverable
"""

from __future__ import annotations

import math
import statistics
from typing import Any


def variance_summary(
    records: list[dict[str, Any]],
    fields: list[str] | None = None,
) -> dict[str, dict[str, float | None]]:
    """Compute mean, std, stderr, and 95% CI for numeric fields.

    Args:
        records: List of metric dicts (one per run).
        fields: Optional list of field names to analyse. Defaults to
            common evaluation fields.

    Returns:
        Dict mapping field name → {n, mean, std, stderr, ci_lo, ci_hi}.
    """
    if fields is None:
        fields = [
            "progress_rate",
            "ttfs_seconds",
            "exploit_attempts",
            "successful_exploits",
            "verified_findings_count",
            "cloud_cost_usd",
            "duration_seconds",
            "exploit_redundancy_rate",
        ]

    result: dict[str, dict[str, float | None]] = {}
    for field in fields:
        values = [r[field] for r in records if r.get(field) is not None]
        n = len(values)
        if n == 0:
            result[field] = {
                "n": 0,
                "mean": None,
                "std": None,
                "stderr": None,
                "ci_lo": None,
                "ci_hi": None,
            }
        elif n == 1:
            result[field] = {
                "n": 1,
                "mean": values[0],
                "std": 0.0,
                "stderr": 0.0,
                "ci_lo": values[0],
                "ci_hi": values[0],
            }
        else:
            m = statistics.mean(values)
            s = statistics.stdev(values)
            se = s / math.sqrt(n)
            # Use t=1.96 as approximation for 95% CI (valid for n >= 30,
            # acceptable approximation for small n in engineering contexts)
            t_val = 1.96
            result[field] = {
                "n": n,
                "mean": m,
                "std": s,
                "stderr": se,
                "ci_lo": m - t_val * se,
                "ci_hi": m + t_val * se,
            }
    return result


def success_rate_ci(
    records: list[dict[str, Any]],
) -> dict[str, float | None]:
    """Compute success rate with 95% Wilson confidence interval.

    The Wilson score interval is more appropriate than the normal
    approximation for small sample sizes and proportions near 0 or 1.

    Args:
        records: List of metric dicts.

    Returns:
        Dict with keys: n, successes, rate, ci_lo, ci_hi.
    """
    n = len(records)
    if n == 0:
        return {"n": 0, "successes": 0, "rate": None, "ci_lo": None, "ci_hi": None}

    successes = sum(1 for r in records if r.get("success", False))
    p = successes / n
    z = 1.96  # 95% confidence

    denominator = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z**2 / (4 * n)) / n) / denominator

    return {
        "n": n,
        "successes": successes,
        "rate": p,
        "ci_lo": max(0.0, centre - margin),
        "ci_hi": min(1.0, centre + margin),
    }


def format_variance_table(
    summary: dict[str, dict[str, float | None]],
) -> list[dict[str, str]]:
    """Format a variance summary into a human-readable table.

    Args:
        summary: Output from :func:`variance_summary`.

    Returns:
        List of row dicts with columns: field, n, mean_std, ci_95.
    """
    rows: list[dict[str, str]] = []
    for field, stats in summary.items():
        n = stats.get("n", 0)
        mean = stats.get("mean")
        std = stats.get("std")
        ci_lo = stats.get("ci_lo")
        ci_hi = stats.get("ci_hi")

        if mean is None:
            mean_std_str = "N/A"
            ci_str = "N/A"
        else:
            mean_std_str = f"{mean:.3f} ± {std:.3f}" if std else f"{mean:.3f}"
            ci_str = f"[{ci_lo:.3f}, {ci_hi:.3f}]" if ci_lo is not None else "N/A"

        rows.append(
            {
                "field": field,
                "n": str(n),
                "mean_std": mean_std_str,
                "ci_95": ci_str,
            }
        )
    return rows
