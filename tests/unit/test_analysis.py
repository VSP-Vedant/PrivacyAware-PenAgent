"""Unit tests for the data analysis engine.

Tests the aggregator, variance, and charts modules using synthetic
metrics data and the real runs/metrics/ JSON files.

Owner: Parth (Member D)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# ── Fixtures ─────────────────────────────────────────────────


def _make_record(**overrides: Any) -> dict[str, Any]:
    """Create a synthetic metrics record with sensible defaults."""
    base: dict[str, Any] = {
        "run_id": "test_run",
        "target": "192.168.0.12",
        "success": True,
        "progress_rate": 1.0,
        "milestones_hit": [
            "recon_done",
            "cve_mapped",
            "exploit_attempted",
            "session_obtained",
        ],
        "ttfs_seconds": 120.0,
        "step_count": 4,
        "cloud_api_calls": 1,
        "cloud_cost_usd": 0.05,
        "exploit_attempts": 10,
        "successful_exploits": 2,
        "verified_findings_count": 5,
        "findings_by_category": {"remote_code_execution": 3, "authentication": 2},
        "exploit_redundancy_rate": 0.1,
        "hosts_discovered": 1,
        "services_discovered": 5,
        "cves_mapped": 8,
        "run_start_ts": 1000000.0,
        "run_end_ts": 1000120.0,
        "duration_seconds": 120.0,
    }
    base.update(overrides)
    return base


@pytest.fixture
def sample_records() -> list[dict[str, Any]]:
    """Three runs: 2 successes and 1 failure across 2 targets."""
    return [
        _make_record(
            run_id="run1",
            target="192.168.0.12",
            success=True,
            progress_rate=1.0,
            ttfs_seconds=120.0,
            exploit_attempts=10,
            successful_exploits=2,
            duration_seconds=300.0,
        ),
        _make_record(
            run_id="run2",
            target="192.168.0.12",
            success=True,
            progress_rate=1.0,
            ttfs_seconds=180.0,
            exploit_attempts=15,
            successful_exploits=3,
            duration_seconds=450.0,
        ),
        _make_record(
            run_id="run3",
            target="10.10.10.10",
            success=False,
            progress_rate=0.5,
            ttfs_seconds=None,
            exploit_attempts=5,
            successful_exploits=0,
            duration_seconds=60.0,
        ),
    ]


@pytest.fixture
def metrics_dir(tmp_path: Path, sample_records: list[dict[str, Any]]) -> str:
    """Write sample records as JSON files and return the directory path."""
    for rec in sample_records:
        fp = tmp_path / f"{rec['run_id']}_metrics.json"
        # Serialize list/dict fields like the real metrics module does
        serialised = dict(rec)
        serialised["milestones_hit"] = json.dumps(rec["milestones_hit"])
        serialised["findings_by_category"] = json.dumps(rec["findings_by_category"])
        fp.write_text(json.dumps(serialised, indent=2), encoding="utf-8")
    return str(tmp_path)


# ── Aggregator tests ─────────────────────────────────────────


class TestLoadAllMetrics:
    """Tests for aggregator.load_all_metrics."""

    def test_loads_from_directory(self, metrics_dir: str) -> None:
        from data.analysis.aggregator import load_all_metrics

        records = load_all_metrics(metrics_dir)
        assert len(records) == 3

    def test_deserialises_json_strings(self, metrics_dir: str) -> None:
        from data.analysis.aggregator import load_all_metrics

        records = load_all_metrics(metrics_dir)
        for r in records:
            assert isinstance(r["milestones_hit"], list)
            assert isinstance(r["findings_by_category"], dict)

    def test_returns_empty_for_missing_dir(self) -> None:
        from data.analysis.aggregator import load_all_metrics

        records = load_all_metrics("/nonexistent/path")
        assert records == []

    def test_sorted_by_timestamp(self, metrics_dir: str) -> None:
        from data.analysis.aggregator import load_all_metrics

        records = load_all_metrics(metrics_dir)
        timestamps = [r.get("run_start_ts", 0) for r in records]
        assert timestamps == sorted(timestamps)


class TestComputeAggregateStats:
    """Tests for aggregator.compute_aggregate_stats."""

    def test_success_rate(self, sample_records: list) -> None:
        from data.analysis.aggregator import compute_aggregate_stats

        stats = compute_aggregate_stats(sample_records)
        sr = stats["success_rate"]
        assert sr["mean"] == pytest.approx(2 / 3, abs=0.01)

    def test_progress_rate_mean(self, sample_records: list) -> None:
        from data.analysis.aggregator import compute_aggregate_stats

        stats = compute_aggregate_stats(sample_records)
        pr = stats["progress_rate"]
        # (1.0 + 1.0 + 0.5) / 3 = 0.833...
        assert pr["mean"] == pytest.approx(0.833, abs=0.01)

    def test_ttfs_excludes_none(self, sample_records: list) -> None:
        from data.analysis.aggregator import compute_aggregate_stats

        stats = compute_aggregate_stats(sample_records)
        ttfs = stats["ttfs_seconds"]
        # Only 2 runs have TTFS: (120 + 180) / 2 = 150
        assert ttfs["count"] == 2
        assert ttfs["mean"] == pytest.approx(150.0)

    def test_empty_records(self) -> None:
        from data.analysis.aggregator import compute_aggregate_stats

        stats = compute_aggregate_stats([])
        assert stats["progress_rate"]["count"] == 0
        assert stats["success_rate"]["mean"] is None


class TestPerTargetBreakdown:
    """Tests for aggregator.per_target_breakdown."""

    def test_groups_by_target(self, sample_records: list) -> None:
        from data.analysis.aggregator import per_target_breakdown

        bd = per_target_breakdown(sample_records)
        assert "192.168.0.12" in bd
        assert "10.10.10.10" in bd

    def test_run_counts(self, sample_records: list) -> None:
        from data.analysis.aggregator import per_target_breakdown

        bd = per_target_breakdown(sample_records)
        assert bd["192.168.0.12"]["num_runs"] == 2
        assert bd["10.10.10.10"]["num_runs"] == 1

    def test_success_rate_per_target(self, sample_records: list) -> None:
        from data.analysis.aggregator import per_target_breakdown

        bd = per_target_breakdown(sample_records)
        assert bd["192.168.0.12"]["success_rate"] == 1.0
        assert bd["10.10.10.10"]["success_rate"] == 0.0

    def test_ttfs_none_for_failed_target(self, sample_records: list) -> None:
        from data.analysis.aggregator import per_target_breakdown

        bd = per_target_breakdown(sample_records)
        assert bd["10.10.10.10"]["mean_ttfs_seconds"] is None


class TestBuildComparisonTable:
    """Tests for aggregator.build_comparison_table."""

    def test_returns_rows(self, sample_records: list) -> None:
        from data.analysis.aggregator import build_comparison_table

        table = build_comparison_table(sample_records)
        assert len(table) > 0
        assert all("metric" in row for row in table)

    def test_baseline_na_when_missing(self, sample_records: list) -> None:
        from data.analysis.aggregator import build_comparison_table

        table = build_comparison_table(sample_records, baseline_name="Manual")
        for row in table:
            assert row["Manual"] == "N/A"

    def test_delta_computed_with_baseline(self, sample_records: list) -> None:
        from data.analysis.aggregator import build_comparison_table

        baseline = [_make_record(progress_rate=0.5, success=False)]
        table = build_comparison_table(sample_records, baseline, "Baseline")
        # At least some rows should have computed delta
        assert any(row["delta"] != "N/A" for row in table)


class TestSaveAggregateReport:
    """Tests for aggregator.save_aggregate_report."""

    def test_writes_json(self, sample_records: list, tmp_path: Path) -> None:
        from data.analysis.aggregator import save_aggregate_report

        out = tmp_path / "test_report.json"
        path = save_aggregate_report(sample_records, str(out))
        assert Path(path).exists()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        assert data["total_runs"] == 3
        assert "aggregate_stats" in data
        assert "per_target" in data


# ── Variance tests ───────────────────────────────────────────


class TestVarianceSummary:
    """Tests for variance.variance_summary."""

    def test_mean_and_std(self, sample_records: list) -> None:
        from data.analysis.variance import variance_summary

        result = variance_summary(sample_records, ["progress_rate"])
        pr = result["progress_rate"]
        assert pr["n"] == 3
        assert pr["mean"] == pytest.approx(0.833, abs=0.01)
        assert pr["std"] is not None and pr["std"] > 0

    def test_single_record(self) -> None:
        from data.analysis.variance import variance_summary

        records = [_make_record(progress_rate=0.75)]
        result = variance_summary(records, ["progress_rate"])
        assert result["progress_rate"]["n"] == 1
        assert result["progress_rate"]["std"] == 0.0

    def test_empty_records(self) -> None:
        from data.analysis.variance import variance_summary

        result = variance_summary([], ["progress_rate"])
        assert result["progress_rate"]["n"] == 0
        assert result["progress_rate"]["mean"] is None

    def test_ci_contains_mean(self, sample_records: list) -> None:
        from data.analysis.variance import variance_summary

        result = variance_summary(sample_records, ["exploit_attempts"])
        ea = result["exploit_attempts"]
        assert ea["ci_lo"] is not None
        assert ea["ci_lo"] <= ea["mean"] <= ea["ci_hi"]

    def test_none_values_excluded(self) -> None:
        from data.analysis.variance import variance_summary

        records = [
            _make_record(ttfs_seconds=100.0),
            _make_record(ttfs_seconds=None),
            _make_record(ttfs_seconds=200.0),
        ]
        result = variance_summary(records, ["ttfs_seconds"])
        assert result["ttfs_seconds"]["n"] == 2
        assert result["ttfs_seconds"]["mean"] == pytest.approx(150.0)


class TestSuccessRateCI:
    """Tests for variance.success_rate_ci."""

    def test_all_success(self) -> None:
        from data.analysis.variance import success_rate_ci

        records = [_make_record(success=True) for _ in range(5)]
        ci = success_rate_ci(records)
        assert ci["rate"] == 1.0
        assert ci["ci_hi"] == 1.0

    def test_no_success(self) -> None:
        from data.analysis.variance import success_rate_ci

        records = [_make_record(success=False) for _ in range(5)]
        ci = success_rate_ci(records)
        assert ci["rate"] == 0.0
        assert ci["ci_lo"] == 0.0

    def test_mixed(self, sample_records: list) -> None:
        from data.analysis.variance import success_rate_ci

        ci = success_rate_ci(sample_records)
        assert ci["n"] == 3
        assert ci["successes"] == 2
        assert 0.0 <= ci["ci_lo"] <= ci["rate"] <= ci["ci_hi"] <= 1.0

    def test_empty(self) -> None:
        from data.analysis.variance import success_rate_ci

        ci = success_rate_ci([])
        assert ci["rate"] is None


class TestFormatVarianceTable:
    """Tests for variance.format_variance_table."""

    def test_returns_rows(self, sample_records: list) -> None:
        from data.analysis.variance import format_variance_table, variance_summary

        summary = variance_summary(sample_records, ["progress_rate", "ttfs_seconds"])
        rows = format_variance_table(summary)
        assert len(rows) == 2
        assert all("field" in row for row in rows)
        assert all("mean_std" in row for row in rows)


# ── Charts tests ─────────────────────────────────────────────


class TestCharts:
    """Tests for charts module — verifies chart generation without crashing."""

    def test_sr_pr_chart(self, sample_records: list, tmp_path: Path) -> None:
        from data.analysis.aggregator import per_target_breakdown
        from data.analysis.charts import generate_sr_pr_bar_chart

        pt = per_target_breakdown(sample_records)
        result = generate_sr_pr_bar_chart(pt, str(tmp_path))
        if result is not None:
            assert Path(result).exists()
            assert result.endswith(".png")

    def test_routing_chart(self, sample_records: list, tmp_path: Path) -> None:
        from data.analysis.charts import generate_routing_pie_chart

        result = generate_routing_pie_chart(sample_records, str(tmp_path))
        if result is not None:
            assert Path(result).exists()

    def test_ttfs_chart(self, sample_records: list, tmp_path: Path) -> None:
        from data.analysis.aggregator import per_target_breakdown
        from data.analysis.charts import generate_ttfs_bar_chart

        pt = per_target_breakdown(sample_records)
        result = generate_ttfs_bar_chart(pt, str(tmp_path))
        if result is not None:
            assert Path(result).exists()

    def test_exploit_efficiency_chart(
        self, sample_records: list, tmp_path: Path
    ) -> None:
        from data.analysis.aggregator import per_target_breakdown
        from data.analysis.charts import generate_exploit_efficiency_chart

        pt = per_target_breakdown(sample_records)
        result = generate_exploit_efficiency_chart(pt, str(tmp_path))
        if result is not None:
            assert Path(result).exists()

    def test_generate_all_charts(self, sample_records: list, tmp_path: Path) -> None:
        from data.analysis.aggregator import per_target_breakdown
        from data.analysis.charts import generate_all_charts

        pt = per_target_breakdown(sample_records)
        results = generate_all_charts(sample_records, pt, str(tmp_path))
        assert isinstance(results, dict)
        assert "sr_pr" in results

    def test_no_data(self, tmp_path: Path) -> None:
        from data.analysis.charts import generate_routing_pie_chart

        result = generate_routing_pie_chart([], str(tmp_path))
        assert result is None


# ── Integration: Load real metrics ────────────────────────────


class TestRealMetrics:
    """Tests using the actual runs/metrics/ directory if available."""

    @pytest.fixture
    def real_records(self) -> list[dict[str, Any]]:
        from data.analysis.aggregator import load_all_metrics

        return load_all_metrics("runs/metrics")

    def test_loads_real_data(self, real_records: list) -> None:
        # Should load at least the Metasploitable2 run
        assert len(real_records) >= 1

    def test_real_aggregate_stats(self, real_records: list) -> None:
        from data.analysis.aggregator import compute_aggregate_stats

        stats = compute_aggregate_stats(real_records)
        # Success rate should be defined
        assert stats["success_rate"]["count"] >= 1

    def test_real_variance(self, real_records: list) -> None:
        from data.analysis.variance import variance_summary

        result = variance_summary(real_records)
        assert "progress_rate" in result

    def test_real_comparison_table(self, real_records: list) -> None:
        from data.analysis.aggregator import build_comparison_table

        table = build_comparison_table(real_records)
        assert len(table) > 0
        assert table[0]["metric"] == "Task Success Rate (SR)"
