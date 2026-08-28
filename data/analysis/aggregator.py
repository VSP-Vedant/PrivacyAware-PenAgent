"""Metrics aggregator — aggregates run data across targets and conditions.

Reads JSON metrics files produced by ``src.evaluation.metrics.save_run_metrics``
and computes aggregate statistics (mean, std, min, max) for numeric fields.

Also produces comparison tables for baselines (PentestGPT, manual, no-LLM)
and per-target breakdowns.

Owner: Parth (Member D) — Week 23–28 deliverable
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any

from src.utils.logger import setup_logger

logger = setup_logger(__name__)

# Numeric fields to aggregate across runs
_NUMERIC_FIELDS = [
    "progress_rate",
    "ttfs_seconds",
    "step_count",
    "cloud_api_calls",
    "cloud_cost_usd",
    "exploit_attempts",
    "successful_exploits",
    "verified_findings_count",
    "exploit_redundancy_rate",
    "hosts_discovered",
    "services_discovered",
    "cves_mapped",
    "duration_seconds",
]


def load_all_metrics(metrics_dir: str = "runs/metrics") -> list[dict[str, Any]]:
    """Load all JSON metrics files from a directory.

    Args:
        metrics_dir: Directory containing ``*_metrics.json`` files.

    Returns:
        List of metric dicts, sorted by ``run_start_ts``.
    """
    path = Path(metrics_dir)
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for fp in sorted(path.glob("*_metrics.json")):
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
            # Deserialise JSON-encoded list/dict fields
            if isinstance(data.get("milestones_hit"), str):
                data["milestones_hit"] = json.loads(data["milestones_hit"])
            if isinstance(data.get("findings_by_category"), str):
                data["findings_by_category"] = json.loads(data["findings_by_category"])
            records.append(data)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load %s: %s", fp, exc)
    records.sort(key=lambda r: r.get("run_start_ts", 0))
    return records


def compute_aggregate_stats(
    records: list[dict[str, Any]],
) -> dict[str, dict[str, float | None]]:
    """Compute aggregate statistics for a set of run metrics.

    For each numeric field, computes: count, mean, std, min, max.
    Fields with all-None values are reported as None for mean/std/min/max.

    Args:
        records: List of metric dicts (from ``load_all_metrics``).

    Returns:
        Dict mapping field name → {count, mean, std, min, max}.
    """
    stats: dict[str, dict[str, float | None]] = {}
    for field in _NUMERIC_FIELDS:
        values = [r[field] for r in records if r.get(field) is not None]
        if not values:
            stats[field] = {
                "count": 0,
                "mean": None,
                "std": None,
                "min": None,
                "max": None,
            }
        elif len(values) == 1:
            stats[field] = {
                "count": 1,
                "mean": values[0],
                "std": 0.0,
                "min": values[0],
                "max": values[0],
            }
        else:
            stats[field] = {
                "count": len(values),
                "mean": statistics.mean(values),
                "std": statistics.stdev(values),
                "min": min(values),
                "max": max(values),
            }
    # Success rate is a boolean — compute as fraction
    successes = [r.get("success", False) for r in records]
    total = len(successes)
    success_count = sum(1 for s in successes if s)
    stats["success_rate"] = {
        "count": total,
        "mean": success_count / total if total > 0 else None,
        "std": None,
        "min": None,
        "max": None,
    }
    return stats


def per_target_breakdown(
    records: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Group metrics by target IP and summarise each target.

    Args:
        records: List of metric dicts.

    Returns:
        Dict mapping target IP → summary dict with key fields.
    """
    targets: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        t = r.get("target", "unknown")
        targets.setdefault(t, []).append(r)

    breakdown: dict[str, dict[str, Any]] = {}
    for target, runs in targets.items():
        pr_values = [r.get("progress_rate", 0.0) for r in runs]
        ttfs_values = [
            r["ttfs_seconds"] for r in runs if r.get("ttfs_seconds") is not None
        ]
        breakdown[target] = {
            "num_runs": len(runs),
            "success_count": sum(1 for r in runs if r.get("success")),
            "success_rate": sum(1 for r in runs if r.get("success")) / len(runs),
            "mean_progress_rate": statistics.mean(pr_values),
            "mean_ttfs_seconds": (
                statistics.mean(ttfs_values) if ttfs_values else None
            ),
            "total_exploit_attempts": sum(r.get("exploit_attempts", 0) for r in runs),
            "total_successful_exploits": sum(
                r.get("successful_exploits", 0) for r in runs
            ),
            "total_verified_findings": sum(
                r.get("verified_findings_count", 0) for r in runs
            ),
            "mean_cloud_cost_usd": statistics.mean(
                [r.get("cloud_cost_usd", 0.0) for r in runs]
            ),
            "mean_duration_seconds": statistics.mean(
                [r.get("duration_seconds", 0.0) for r in runs]
            ),
        }
    return breakdown


def build_comparison_table(
    our_records: list[dict[str, Any]],
    baseline_records: list[dict[str, Any]] | None = None,
    baseline_name: str = "PentestGPT",
) -> list[dict[str, Any]]:
    """Build a comparison table between our system and a baseline.

    If no baseline data is available, the baseline columns are filled
    with ``"N/A"`` so that the table structure is ready for future data.

    Args:
        our_records: Metric dicts for PrivacyAware-PenAgent.
        baseline_records: Optional metric dicts for the baseline system.
        baseline_name: Human-readable name of the baseline.

    Returns:
        List of row dicts with columns: metric, ours, baseline, delta.
    """
    our_stats = compute_aggregate_stats(our_records)
    bl_stats = compute_aggregate_stats(baseline_records) if baseline_records else {}

    rows: list[dict[str, Any]] = []
    display_fields = [
        ("success_rate", "Task Success Rate (SR)", "{:.1%}"),
        ("progress_rate", "Progress Rate (PR)", "{:.2f}"),
        ("ttfs_seconds", "Time-to-First-Shell (s)", "{:.1f}"),
        ("exploit_attempts", "Total Exploit Attempts", "{:.0f}"),
        ("successful_exploits", "Successful Exploits", "{:.0f}"),
        ("verified_findings_count", "Verified Findings", "{:.0f}"),
        ("cloud_api_calls", "Cloud API Calls", "{:.0f}"),
        ("cloud_cost_usd", "Cloud Cost (USD)", "${:.4f}"),
        ("exploit_redundancy_rate", "Exploit Redundancy Rate", "{:.1%}"),
        ("duration_seconds", "Run Duration (s)", "{:.0f}"),
    ]

    for field, label, fmt in display_fields:
        our_val = our_stats.get(field, {}).get("mean")
        bl_val = bl_stats.get(field, {}).get("mean") if bl_stats else None

        our_str = fmt.format(our_val) if our_val is not None else "N/A"
        bl_str = fmt.format(bl_val) if bl_val is not None else "N/A"

        delta = None
        if our_val is not None and bl_val is not None:
            delta = our_val - bl_val

        rows.append(
            {
                "metric": label,
                "ours": our_str,
                baseline_name: bl_str,
                "delta": f"{delta:+.2f}" if delta is not None else "N/A",
            }
        )
    return rows


def save_aggregate_report(
    records: list[dict[str, Any]],
    output_path: str = "data/analysis/aggregate_report.json",
) -> str:
    """Compute and save a full aggregate analysis report.

    Args:
        records: List of metric dicts.
        output_path: Path to write the JSON report.

    Returns:
        Absolute path to the written file.
    """
    report = {
        "total_runs": len(records),
        "aggregate_stats": compute_aggregate_stats(records),
        "per_target": per_target_breakdown(records),
        "comparison_table": build_comparison_table(records),
    }
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    logger.info("Aggregate report written to %s", out)
    return str(out.resolve())
