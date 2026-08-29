"""Unit tests for the Phase 5 ablation analysis module."""

from __future__ import annotations

import os

import pytest

from data.analysis.ablation import (
    aggregate_by_condition,
    build_ablation_table,
    extract_condition_from_run_id,
    generate_ablation_charts,
)


@pytest.fixture
def sample_ablation_records() -> list[dict]:
    return [
        {
            "run_id": "devvortex_full_1_1787980000",
            "target": "10.129.244.146",
            "success": True,
            "progress_rate": 1.0,
            "ttfs_seconds": 180.5,
            "cloud_cost_usd": 0.035,
            "cloud_api_calls": 2,
            "exploit_redundancy_rate": 0.01,
        },
        {
            "run_id": "devvortex_full_2_1787980001",
            "target": "10.129.244.146",
            "success": True,
            "progress_rate": 1.0,
            "ttfs_seconds": 210.0,
            "cloud_cost_usd": 0.040,
            "cloud_api_calls": 3,
            "exploit_redundancy_rate": 0.00,
        },
        {
            "run_id": "devvortex_no-router-local_1_1787980002",
            "target": "10.129.244.146",
            "success": False,
            "progress_rate": 0.5,
            "ttfs_seconds": None,
            "cloud_cost_usd": 0.0,
            "cloud_api_calls": 0,
            "exploit_redundancy_rate": 0.05,
        },
        {
            "run_id": "devvortex_no-graph_1_1787980003",
            "target": "10.129.244.146",
            "success": True,
            "progress_rate": 1.0,
            "ttfs_seconds": 450.0,
            "cloud_cost_usd": 0.08,
            "cloud_api_calls": 6,
            "exploit_redundancy_rate": 0.35,
        },
    ]


def test_extract_condition_from_run_id() -> None:
    assert extract_condition_from_run_id("target_full_1_12345") == "full"
    assert (
        extract_condition_from_run_id("target_no-router-local_2_12345")
        == "no-router-local"
    )
    assert (
        extract_condition_from_run_id("target_no-router-cloud_3_12345")
        == "no-router-cloud"
    )
    assert extract_condition_from_run_id("target_no-graph_1_12345") == "no-graph"
    assert extract_condition_from_run_id("target_no-verify_2_12345") == "no-verify"
    assert extract_condition_from_run_id("unknown_name") == "full"


def test_aggregate_by_condition(sample_ablation_records: list[dict]) -> None:
    stats = aggregate_by_condition(sample_ablation_records)
    assert "full" in stats
    assert stats["full"]["num_runs"] == 2
    assert stats["full"]["success_rate"] == 1.0
    assert stats["full"]["mean_progress_rate"] == 1.0
    assert stats["full"]["mean_ttfs_seconds"] == 195.25

    assert "no-router-local" in stats
    assert stats["no-router-local"]["num_runs"] == 1
    assert stats["no-router-local"]["success_rate"] == 0.0
    assert stats["no-router-local"]["mean_cloud_cost_usd"] == 0.0

    assert "no-graph" in stats
    assert stats["no-graph"]["mean_redundancy_rate"] == 0.35


def test_build_ablation_table(sample_ablation_records: list[dict]) -> None:
    rows = build_ablation_table(sample_ablation_records)
    assert len(rows) >= 3
    full_row = next((r for r in rows if "Full" in r["condition"]), None)
    assert full_row is not None
    assert full_row["sr"] == "100.0%"
    assert full_row["pr"] == "100.0%"


def test_generate_ablation_charts(
    sample_ablation_records: list[dict], tmp_path
) -> None:
    out_dir = str(tmp_path / "charts")
    charts = generate_ablation_charts(sample_ablation_records, output_dir=out_dir)
    assert "ablation_sr_pr" in charts
    assert "ablation_cost_tradeoff" in charts
    assert "ablation_redundancy" in charts
    for p in charts.values():
        assert os.path.exists(p)
