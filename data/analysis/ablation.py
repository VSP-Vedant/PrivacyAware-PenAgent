"""Ablation analysis module — Phase 5 (Weeks 23–28).

Aggregates metrics across the 5 ablation conditions:
1. full (Ours: Hybrid Router + AttackGraph + Closed-Loop Verification)
2. no-router-local (Ollama Llama3 8B only)
3. no-router-cloud (GPT-4o cloud only)
4. no-graph (Stateless agent)
5. no-verify (Open-loop agent without verification replan feedback)

Generates ablation comparison tables and publication-ready charts.

Owner: Parth (Member D) & Team
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np

logger = logging.getLogger(__name__)


def extract_condition_from_run_id(run_id: str) -> str:
    """Extract condition name from run_id string."""
    for cond in ("no-router-local", "no-router-cloud", "no-graph", "no-verify", "full"):
        if f"_{cond}_" in run_id or run_id.endswith(f"_{cond}"):
            return cond
    return "full"


def aggregate_by_condition(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Group metrics by ablation condition and compute means."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        cond = extract_condition_from_run_id(r.get("run_id", ""))
        grouped.setdefault(cond, []).append(r)

    stats: dict[str, dict[str, Any]] = {}
    for cond, recs in grouped.items():
        n = len(recs)
        succ = sum(1 for r in recs if r.get("success"))
        sr = succ / n if n > 0 else 0.0
        prs: list[float] = [
            float(r["progress_rate"])
            for r in recs
            if r.get("progress_rate") is not None
        ]
        mean_pr = float(np.mean(prs)) if prs else 0.0

        ttfss: list[float] = [
            float(r["ttfs_seconds"]) for r in recs if r.get("ttfs_seconds") is not None
        ]
        mean_ttfs = float(np.mean(ttfss)) if ttfss else None

        costs: list[float] = [
            float(r["cloud_cost_usd"])
            for r in recs
            if r.get("cloud_cost_usd") is not None
        ]
        mean_cost = float(np.mean(costs)) if costs else 0.0

        reds: list[float] = [
            float(r["exploit_redundancy_rate"])
            for r in recs
            if r.get("exploit_redundancy_rate") is not None
        ]
        mean_red = float(np.mean(reds)) if reds else 0.0

        calls: list[float] = [
            float(r["cloud_api_calls"])
            for r in recs
            if r.get("cloud_api_calls") is not None
        ]
        mean_calls = float(np.mean(calls)) if calls else 0.0

        stats[cond] = {
            "num_runs": n,
            "success_rate": round(sr, 4),
            "mean_progress_rate": round(mean_pr, 4),
            "mean_ttfs_seconds": round(mean_ttfs, 2) if mean_ttfs is not None else None,
            "mean_cloud_cost_usd": round(mean_cost, 4),
            "mean_cloud_calls": round(mean_calls, 2),
            "mean_redundancy_rate": round(mean_red, 4),
        }
    return stats


def build_ablation_table(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate structured ablation comparison rows."""
    agg = aggregate_by_condition(records)
    rows: list[dict[str, Any]] = []

    condition_labels = {
        "full": "PrivacyAware-PenAgent (Full)",
        "no-router-cloud": "Ablation: Cloud-Only (No Router)",
        "no-router-local": "Ablation: Local-Only (No Router)",
        "no-graph": "Ablation: Stateless (No Attack Graph)",
        "no-verify": "Ablation: Open-Loop (No Verification)",
    }

    for cond, label in condition_labels.items():
        if cond in agg:
            s = agg[cond]
            ttfs_str = (
                f"{s['mean_ttfs_seconds']:.1f}s" if s["mean_ttfs_seconds"] else "N/A"
            )
            rows.append(
                {
                    "condition": label,
                    "sr": f"{s['success_rate'] * 100:.1f}%",
                    "pr": f"{s['mean_progress_rate'] * 100:.1f}%",
                    "ttfs": ttfs_str,
                    "cloud_cost": f"${s['mean_cloud_cost_usd']:.4f}",
                    "cloud_calls": f"{s['mean_cloud_calls']:.1f}",
                    "redundancy": f"{s['mean_redundancy_rate'] * 100:.2f}%",
                }
            )
    return rows


def generate_ablation_charts(
    records: list[dict[str, Any]],
    output_dir: str = "runs/reports/charts",
) -> dict[str, str]:
    """Generate visual plots comparing ablation conditions."""
    agg = aggregate_by_condition(records)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    order = ["full", "no-router-cloud", "no-router-local", "no-graph", "no-verify"]
    labels = ["Full System", "Cloud-Only", "Local-Only", "No-Graph", "No-Verify"]
    valid_keys = [k for k in order if k in agg]
    valid_labels = [labels[order.index(k)] for k in valid_keys]

    charts_created: dict[str, str] = {}

    # ── Chart 1: SR & PR across Ablation Conditions ──────────────────
    fig, ax = plt.subplots(figsize=(10, 5.5))
    x = np.arange(len(valid_keys))
    width = 0.35

    srs = [agg[k]["success_rate"] * 100 for k in valid_keys]
    prs = [agg[k]["mean_progress_rate"] * 100 for k in valid_keys]

    rects1 = ax.bar(
        x - width / 2, srs, width, label="Success Rate (SR %)", color="#2b5c8f"
    )
    rects2 = ax.bar(
        x + width / 2, prs, width, label="Progress Rate (PR %)", color="#3da4ab"
    )

    ax.set_ylabel("Rate (%)", fontsize=12)
    ax.set_title(
        "Ablation Study: Success Rate & Progress Rate Comparison",
        fontsize=14,
        fontweight="bold",
    )
    ax.set_xticks(x)
    ax.set_xticklabels(valid_labels, rotation=15, ha="right", fontsize=11)
    ax.legend(fontsize=11)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    ax.set_ylim(0, 110)

    # Value labels
    for rect in rects1:
        h = rect.get_height()
        ax.annotate(
            f"{h:.1f}%",
            xy=(rect.get_x() + rect.get_width() / 2, h),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=9,
        )
    for rect in rects2:
        h = rect.get_height()
        ax.annotate(
            f"{h:.1f}%",
            xy=(rect.get_x() + rect.get_width() / 2, h),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    fig.tight_layout()
    chart1_file = str(out_path / "ablation_sr_pr.png")
    fig.savefig(chart1_file, dpi=150)
    plt.close(fig)
    charts_created["ablation_sr_pr"] = chart1_file

    # ── Chart 2: Cost vs. Performance Trade-off ───────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    costs = [agg[k]["mean_cloud_cost_usd"] for k in valid_keys]
    colors = ["#2ecc71", "#e74c3c", "#3498db", "#9b59b6", "#f39c12"]

    ax.scatter(
        costs,
        srs,
        s=[180 + 10 * p for p in prs],
        c=colors[: len(valid_keys)],
        alpha=0.85,
        edgecolors="black",
        linewidth=1.5,
    )

    for i, txt in enumerate(valid_labels):
        ax.annotate(
            f" {txt}",
            (costs[i], srs[i]),
            fontsize=10,
            fontweight="bold",
            xytext=(5, 5),
            textcoords="offset points",
        )

    ax.set_xlabel("Average Cloud Cost per Run (USD $)", fontsize=12)
    ax.set_ylabel("Task Success Rate (%)", fontsize=12)
    ax.set_title(
        "Privacy/Cost vs. Exploitation Capability Trade-off",
        fontsize=13,
        fontweight="bold",
    )
    ax.grid(True, linestyle="--", alpha=0.5)
    fig.tight_layout()

    chart2_file = str(out_path / "ablation_cost_tradeoff.png")
    fig.savefig(chart2_file, dpi=150)
    plt.close(fig)
    charts_created["ablation_cost_tradeoff"] = chart2_file

    # ── Chart 3: Redundancy Rate Comparison ───────────────────────────
    fig, ax = plt.subplots(figsize=(8, 4.5))
    reds = [agg[k]["mean_redundancy_rate"] * 100 for k in valid_keys]
    bars = ax.bar(valid_labels, reds, color="#e67e22", width=0.5, edgecolor="black")

    ax.set_ylabel("Exploit Redundancy Rate (%)", fontsize=12)
    ax.set_title(
        "Exploit Redundancy: Graph Memory & Verification Impact",
        fontsize=13,
        fontweight="bold",
    )
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    plt.xticks(rotation=15, ha="right", fontsize=11)

    for bar in bars:
        h = bar.get_height()
        ax.annotate(
            f"{h:.2f}%",
            xy=(bar.get_x() + bar.get_width() / 2, h),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )

    fig.tight_layout()
    chart3_file = str(out_path / "ablation_redundancy.png")
    fig.savefig(chart3_file, dpi=150)
    plt.close(fig)
    charts_created["ablation_redundancy"] = chart3_file

    return charts_created
