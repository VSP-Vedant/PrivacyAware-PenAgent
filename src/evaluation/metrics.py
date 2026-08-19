"""Evaluation metrics module — Phase 4 (Weeks 19–22).

Computes and persists standardised evaluation metrics for every pentest run:

  - **Task Success Rate (SR)**: binary flag — was at least one session obtained?
  - **Progress Rate (PR)**: fraction of four milestones hit:
        recon_done | cve_mapped | exploit_attempted | session_obtained
  - **Time-to-First-Shell (TTFS)**: elapsed seconds from run start to first
    confirmed session node, or ``None`` if no session.
  - **Step Count**: total orchestrator node transitions.
  - **Cloud API Call Count**: routing decisions that went to CLOUD.
  - **Cloud API Cost USD**: cumulative cost tracked by CostTracker.
  - **Exploit Redundancy Rate**: fraction of exploit attempts that reused a
    (module_path, service_id) pair already tried in the same run.

Metrics are written to ``runs/metrics/`` as both JSON and CSV so they can
be imported into analysis notebooks without any extra dependencies.

Owner: Vedant (Member C) — Week 19–20 deliverable
"""

from __future__ import annotations

import csv
import json

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from src.utils.logger import setup_logger

logger = setup_logger(__name__)

# ---------------------------------------------------------------------------
# Milestone constants (used in Progress Rate calculation)
# ---------------------------------------------------------------------------

_MILESTONE_RECON = "recon_done"
_MILESTONE_CVE = "cve_mapped"
_MILESTONE_EXPLOIT = "exploit_attempted"
_MILESTONE_SESSION = "session_obtained"
_ALL_MILESTONES = [
    _MILESTONE_RECON,
    _MILESTONE_CVE,
    _MILESTONE_EXPLOIT,
    _MILESTONE_SESSION,
]


# ---------------------------------------------------------------------------
# RunMetrics dataclass
# ---------------------------------------------------------------------------


@dataclass
class RunMetrics:
    """Structured evaluation metrics for a single pentest run.

    Attributes:
        run_id: Unique identifier for this run.
        target: Target IP / hostname.
        success: True if at least one shell session was obtained.
        progress_rate: Fraction of milestones completed (0.0 – 1.0).
        milestones_hit: List of milestone names that were completed.
        ttfs_seconds: Time-to-first-shell in seconds, or None.
        step_count: Total orchestrator steps executed.
        cloud_api_calls: Number of routing decisions routed to CLOUD.
        cloud_cost_usd: Total USD cost of cloud LLM calls.
        exploit_attempts: Total exploit attempts made.
        successful_exploits: Number of attempts that produced a session.
        verified_findings_count: Total verified security findings across all categories.
        findings_by_category: Dictionary of finding counts keyed by category.
        exploit_redundancy_rate: Fraction of attempts reusing a prior (module, service).
        hosts_discovered: Number of hosts found by recon.
        services_discovered: Number of services enumerated.
        cves_mapped: Number of CVE nodes in the final graph.
        run_start_ts: Unix timestamp when the run started.
        run_end_ts: Unix timestamp when metrics were computed.
        duration_seconds: Total run duration.
    """

    run_id: str
    target: str
    success: bool = False
    progress_rate: float = 0.0
    milestones_hit: list[str] = field(default_factory=list)
    ttfs_seconds: float | None = None
    step_count: int = 0
    cloud_api_calls: int = 0
    cloud_cost_usd: float = 0.0
    exploit_attempts: int = 0
    successful_exploits: int = 0
    verified_findings_count: int = 0
    findings_by_category: dict[str, int] = field(default_factory=dict)
    exploit_redundancy_rate: float = 0.0
    hosts_discovered: int = 0
    services_discovered: int = 0
    cves_mapped: int = 0
    run_start_ts: float = field(default_factory=time.time)
    run_end_ts: float = field(default_factory=time.time)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a flat dictionary (JSON-safe)."""
        d = asdict(self)
        d["milestones_hit"] = json.dumps(d["milestones_hit"])
        d["findings_by_category"] = json.dumps(d["findings_by_category"])
        return d


# ---------------------------------------------------------------------------
# Metric computation
# ---------------------------------------------------------------------------


def compute_metrics(
    final_state: dict[str, Any],
    run_id: str,
    *,
    cost_stats: dict[str, Any] | None = None,
) -> RunMetrics:
    """Compute evaluation metrics from the final LangGraph state.

    This function is the canonical entry point for metric collection.
    It is called by ``report_node`` after the pipeline terminates.

    Args:
        final_state: The final ``PenTestState`` dict from LangGraph.
        run_id: Unique identifier for this run.
        cost_stats: Optional dict from ``CostTracker.get_stats()``.

    Returns:
        A populated :class:`RunMetrics` instance.
    """
    ag = final_state.get("attack_graph")
    if ag is None:
        logger.warning(
            "compute_metrics: no attack_graph in state — returning empty metrics"
        )
        return RunMetrics(run_id=run_id, target=final_state.get("target", "unknown"))

    target = final_state.get("target", "unknown")
    run_start = float(final_state.get("run_start_ts", time.time()))
    run_end = time.time()

    # ── Graph queries ─────────────────────────────────────────────
    hosts = ag.get_hosts()
    services = ag.get_exploitable_services()
    sessions = ag.get_sessions()
    failed_attempts = ag.get_failed_attempts()
    verified_findings = ag.get_verified_findings()

    # Finding breakdown by category
    findings_by_cat: dict[str, int] = {}
    for f in verified_findings:
        c = f.get("category", "general_vulnerability")
        findings_by_cat[c] = findings_by_cat.get(c, 0) + 1

    # CVE count — iterate graph nodes directly
    cves = [
        data for _, data in ag.graph.nodes(data=True) if data.get("node_type") == "cve"
    ]

    # ── Exploit attempt history from SQLite ───────────────────────
    exploit_records = ag.get_exploit_attempts()

    # ── Milestones ───────────────────────────────────────────────
    milestones_hit: list[str] = []

    # Recon done: at least one service discovered
    if services:
        milestones_hit.append(_MILESTONE_RECON)

    # CVE mapped: at least one CVE node in graph
    if cves:
        milestones_hit.append(_MILESTONE_CVE)

    # Exploit attempted: at least one attempt record
    if exploit_records or failed_attempts:
        milestones_hit.append(_MILESTONE_EXPLOIT)

    # Session obtained: at least one session node
    if sessions:
        milestones_hit.append(_MILESTONE_SESSION)

    progress_rate = len(milestones_hit) / len(_ALL_MILESTONES)
    success = _MILESTONE_SESSION in milestones_hit or len(verified_findings) > 0

    # ── TTFS ─────────────────────────────────────────────────────
    ttfs: float | None = None
    if sessions:
        # Use the earliest opened_at timestamp among session nodes
        session_times: list[float] = []
        for sess in sessions:
            opened_at = sess.get("opened_at")
            if opened_at:
                try:
                    from datetime import datetime

                    dt = datetime.fromisoformat(opened_at)
                    session_times.append(dt.timestamp())
                except (ValueError, TypeError):
                    pass
        if session_times:
            ttfs = min(session_times) - run_start

    # ── Cloud API stats ───────────────────────────────────────────
    routing_decisions = final_state.get("routing_decisions", [])
    cloud_api_calls = sum(1 for d in routing_decisions if d.get("route") == "CLOUD")
    cloud_cost = 0.0
    if cost_stats:
        cloud_cost = float(cost_stats.get("total_cost_usd", 0.0))

    # ── Exploit redundancy ────────────────────────────────────────
    redundancy_rate = _compute_redundancy(exploit_records)

    # ── Successful exploit count ──────────────────────────────────
    successful_exploits = sum(
        1 for r in exploit_records if r.get("result") == "success"
    )

    metrics = RunMetrics(
        run_id=run_id,
        target=target,
        success=success,
        progress_rate=progress_rate,
        milestones_hit=milestones_hit,
        ttfs_seconds=ttfs,
        step_count=final_state.get("step_count", 0),
        cloud_api_calls=cloud_api_calls,
        cloud_cost_usd=cloud_cost,
        exploit_attempts=len(exploit_records),
        successful_exploits=successful_exploits,
        verified_findings_count=len(verified_findings),
        findings_by_category=findings_by_cat,
        exploit_redundancy_rate=redundancy_rate,
        hosts_discovered=len(hosts),
        services_discovered=len(services),
        cves_mapped=len(cves),
        run_start_ts=run_start,
        run_end_ts=run_end,
        duration_seconds=run_end - run_start,
    )

    logger.info(
        "Metrics computed: run_id=%s success=%s PR=%.2f TTFS=%s steps=%d",
        run_id,
        success,
        progress_rate,
        f"{ttfs:.1f}s" if ttfs is not None else "N/A",
        metrics.step_count,
    )
    return metrics


def _compute_redundancy(exploit_records: list[dict[str, Any]]) -> float:
    """Compute the exploit redundancy rate for a set of records.

    Redundancy is the fraction of attempts that reuse a (module_used,
    target_service_id) pair that was already attempted earlier in the run.

    Args:
        exploit_records: List of exploit attempt dicts from SQLite.

    Returns:
        A float in [0.0, 1.0].
    """
    if not exploit_records:
        return 0.0
    seen: set[tuple[str, str]] = set()
    redundant = 0
    for rec in exploit_records:
        key = (rec.get("module_used", ""), rec.get("target_service_id", ""))
        if key in seen:
            redundant += 1
        else:
            seen.add(key)
    return redundant / len(exploit_records)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def save_run_metrics(
    metrics: RunMetrics, output_dir: str = "runs/metrics"
) -> dict[str, str]:
    """Write run metrics to JSON and CSV files.

    Args:
        metrics: The :class:`RunMetrics` to persist.
        output_dir: Directory to write files into (created if absent).

    Returns:
        Dict mapping ``'json'`` and ``'csv'`` to their absolute file paths.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    flat = metrics.to_dict()

    # JSON
    json_path = out / f"{metrics.run_id}_metrics.json"
    json_path.write_text(json.dumps(flat, indent=2, default=str), encoding="utf-8")
    logger.info("Metrics JSON written to %s", json_path)

    # CSV — single-row with all fields
    csv_path = out / f"{metrics.run_id}_metrics.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(flat.keys()))
        writer.writeheader()
        writer.writerow(flat)
    logger.info("Metrics CSV written to %s", csv_path)

    return {"json": str(json_path), "csv": str(csv_path)}


def load_all_metrics(metrics_dir: str = "runs/metrics") -> list[dict[str, Any]]:
    """Load all JSON metrics files from a directory.

    Useful for aggregating results across multiple runs in analysis notebooks.

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
            records.append(data)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load %s: %s", fp, exc)
    records.sort(key=lambda r: r.get("run_start_ts", 0))
    return records
