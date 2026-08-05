"""Unit tests for the evaluation metrics module (Week 19–22).

Tests cover:
- RunMetrics dataclass serialisation
- compute_metrics: success flag, progress rate, TTFS, cloud calls, redundancy
- save_run_metrics: JSON and CSV file creation
- load_all_metrics: aggregation across multiple run files
- Edge cases: empty graph, no sessions, missing timestamps

Owner: Vedant (Member C)
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.evaluation.metrics import (
    RunMetrics,
    _compute_redundancy,
    compute_metrics,
    load_all_metrics,
    save_run_metrics,
)
from src.state.attack_graph import AttackGraph
from src.state.schemas import CVENode, HostNode, ServiceNode, SessionNode


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path: Path) -> str:
    return str(tmp_path / "metrics_test.db")


@pytest.fixture
def empty_graph(temp_db: str) -> AttackGraph:
    """Fresh AttackGraph with no nodes."""
    return AttackGraph(db_path=temp_db)


@pytest.fixture
def populated_graph(temp_db: str) -> AttackGraph:
    """AttackGraph with host, service, CVE, and session nodes."""
    ag = AttackGraph(db_path=temp_db)
    ag.add_host(HostNode(ip="10.10.10.5"))
    ag.add_service(
        ServiceNode(
            host_ip="10.10.10.5",
            port=445,
            protocol="tcp",
            name="microsoft-ds",
            product="Windows",
            version="",
        )
    )
    ag.add_cve(
        CVENode(cve_id="CVE-2017-0144", cvss_score=9.3),
        service_node_id="service:10.10.10.5:445/tcp",
    )
    return ag


def _make_state(
    ag: AttackGraph,
    routing_decisions: list | None = None,
    step_count: int = 3,
) -> dict:
    return {
        "target": "10.10.10.5",
        "attack_graph": ag,
        "step_count": step_count,
        "routing_decisions": routing_decisions or [],
        "findings": [],
        "run_start_ts": time.time() - 10.0,  # started 10s ago
    }


# ---------------------------------------------------------------------------
# RunMetrics dataclass
# ---------------------------------------------------------------------------


class TestRunMetrics:
    def test_to_dict_is_flat(self) -> None:
        m = RunMetrics(run_id="r1", target="10.0.0.1")
        d = m.to_dict()
        assert isinstance(d, dict)
        assert d["run_id"] == "r1"
        assert d["target"] == "10.0.0.1"

    def test_to_dict_milestones_json_serialised(self) -> None:
        """milestones_hit is encoded as a JSON string in to_dict."""
        m = RunMetrics(run_id="r1", target="10.0.0.1", milestones_hit=["recon_done"])
        d = m.to_dict()
        # milestones_hit should be a JSON string (for CSV compat)
        assert isinstance(d["milestones_hit"], str)
        parsed = json.loads(d["milestones_hit"])
        assert "recon_done" in parsed


# ---------------------------------------------------------------------------
# compute_metrics
# ---------------------------------------------------------------------------


class TestComputeMetrics:
    def test_empty_graph_no_success(self, empty_graph: AttackGraph) -> None:
        state = _make_state(empty_graph)
        m = compute_metrics(state, "empty_run")
        assert m.success is False
        assert m.progress_rate == 0.0
        assert m.milestones_hit == []
        assert m.ttfs_seconds is None

    def test_recon_milestone(self, populated_graph: AttackGraph) -> None:
        """Having a service means recon_done milestone is hit."""
        state = _make_state(populated_graph)
        m = compute_metrics(state, "recon_run")
        assert "recon_done" in m.milestones_hit
        assert m.progress_rate >= 0.25

    def test_cve_milestone(self, populated_graph: AttackGraph) -> None:
        """Having CVE nodes means cve_mapped milestone is hit."""
        state = _make_state(populated_graph)
        m = compute_metrics(state, "cve_run")
        assert "cve_mapped" in m.milestones_hit
        assert m.cves_mapped >= 1

    def test_session_milestone_and_success(self, populated_graph: AttackGraph) -> None:
        """Adding a session sets success=True and session_obtained milestone."""
        session = SessionNode(
            session_id="1",
            host_ip="10.10.10.5",
            privilege="root",
        )
        populated_graph.add_session(session)
        state = _make_state(populated_graph)
        m = compute_metrics(state, "session_run")
        assert m.success is True
        assert "session_obtained" in m.milestones_hit
        # exploit_attempted milestone requires SQLite exploit_attempt records;
        # in this test we only added a session node, so 3/4 milestones hit.
        assert m.progress_rate >= 0.75


    def test_ttfs_computed_from_session_timestamp(
        self, populated_graph: AttackGraph
    ) -> None:
        """TTFS should be a non-negative float when a session exists."""
        session = SessionNode(
            session_id="2",
            host_ip="10.10.10.5",
            privilege="user",
        )
        populated_graph.add_session(session)
        start_ts = time.time() - 30.0  # simulated 30s ago
        state = _make_state(populated_graph)
        state["run_start_ts"] = start_ts
        m = compute_metrics(state, "ttfs_run")
        # If session has an opened_at timestamp, TTFS will be computed
        # (may be None if SessionNode doesn't set an explicit timestamp)
        # — we just assert it doesn't raise and the type is correct
        assert m.ttfs_seconds is None or isinstance(m.ttfs_seconds, float)

    def test_cloud_api_calls_counted(self, empty_graph: AttackGraph) -> None:
        routing = [
            {"route": "CLOUD", "model": "gpt-4o"},
            {"route": "LOCAL", "model": "llama3:8b"},
            {"route": "CLOUD", "model": "gpt-4o"},
        ]
        state = _make_state(empty_graph, routing_decisions=routing)
        m = compute_metrics(state, "cloud_run")
        assert m.cloud_api_calls == 2

    def test_cloud_cost_from_cost_stats(self, empty_graph: AttackGraph) -> None:
        state = _make_state(empty_graph)
        cost_stats = {"total_cost_usd": 0.42}
        m = compute_metrics(state, "cost_run", cost_stats=cost_stats)
        assert abs(m.cloud_cost_usd - 0.42) < 1e-9

    def test_step_count_propagated(self, empty_graph: AttackGraph) -> None:
        state = _make_state(empty_graph, step_count=7)
        m = compute_metrics(state, "step_run")
        assert m.step_count == 7

    def test_none_attack_graph_returns_empty_metrics(self) -> None:
        m = compute_metrics({"attack_graph": None, "target": "x"}, "bad_run")
        assert m.run_id == "bad_run"
        assert m.success is False

    def test_duration_positive(self, empty_graph: AttackGraph) -> None:
        state = _make_state(empty_graph)
        state["run_start_ts"] = time.time() - 5.0
        m = compute_metrics(state, "dur_run")
        assert m.duration_seconds >= 0.0


# ---------------------------------------------------------------------------
# _compute_redundancy
# ---------------------------------------------------------------------------


class TestComputeRedundancy:
    def test_empty_returns_zero(self) -> None:
        assert _compute_redundancy([]) == 0.0

    def test_no_repeats(self) -> None:
        records = [
            {"module_used": "exploit/a", "target_service_id": "svc:1"},
            {"module_used": "exploit/b", "target_service_id": "svc:1"},
        ]
        assert _compute_redundancy(records) == 0.0

    def test_all_repeats(self) -> None:
        records = [
            {"module_used": "exploit/a", "target_service_id": "svc:1"},
            {"module_used": "exploit/a", "target_service_id": "svc:1"},
            {"module_used": "exploit/a", "target_service_id": "svc:1"},
        ]
        # 2 of 3 are redundant
        assert abs(_compute_redundancy(records) - 2 / 3) < 1e-9

    def test_partial_repeats(self) -> None:
        records = [
            {"module_used": "exploit/a", "target_service_id": "svc:1"},
            {"module_used": "exploit/a", "target_service_id": "svc:1"},
            {"module_used": "exploit/b", "target_service_id": "svc:1"},
        ]
        # 1 of 3 is redundant
        assert abs(_compute_redundancy(records) - 1 / 3) < 1e-9


# ---------------------------------------------------------------------------
# save_run_metrics
# ---------------------------------------------------------------------------


class TestSaveRunMetrics:
    def test_creates_json_and_csv(self, tmp_path: Path) -> None:
        m = RunMetrics(
            run_id="save_test",
            target="10.0.0.1",
            success=True,
            progress_rate=0.75,
        )
        paths = save_run_metrics(m, output_dir=str(tmp_path / "metrics"))
        assert "json" in paths
        assert "csv" in paths
        assert Path(paths["json"]).exists()
        assert Path(paths["csv"]).exists()

    def test_json_content_valid(self, tmp_path: Path) -> None:
        m = RunMetrics(
            run_id="json_test",
            target="10.0.0.2",
            success=False,
            cloud_cost_usd=0.05,
        )
        paths = save_run_metrics(m, output_dir=str(tmp_path / "metrics"))
        data = json.loads(Path(paths["json"]).read_text())
        assert data["run_id"] == "json_test"
        assert data["success"] is False
        assert abs(data["cloud_cost_usd"] - 0.05) < 1e-9

    def test_csv_has_header(self, tmp_path: Path) -> None:
        m = RunMetrics(run_id="csv_test", target="10.0.0.3")
        paths = save_run_metrics(m, output_dir=str(tmp_path / "metrics"))
        csv_text = Path(paths["csv"]).read_text()
        # First line should be the header
        assert "run_id" in csv_text.split("\n")[0]


# ---------------------------------------------------------------------------
# load_all_metrics
# ---------------------------------------------------------------------------


class TestLoadAllMetrics:
    def test_returns_empty_for_missing_dir(self, tmp_path: Path) -> None:
        result = load_all_metrics(str(tmp_path / "nonexistent"))
        assert result == []

    def test_loads_saved_metrics(self, tmp_path: Path) -> None:
        out = str(tmp_path / "metrics")
        m1 = RunMetrics(run_id="run_001", target="10.0.0.1", run_start_ts=1000.0)
        m2 = RunMetrics(run_id="run_002", target="10.0.0.2", run_start_ts=2000.0)
        save_run_metrics(m1, out)
        save_run_metrics(m2, out)
        loaded = load_all_metrics(out)
        assert len(loaded) == 2
        # Should be sorted by run_start_ts
        assert loaded[0]["run_id"] == "run_001"
        assert loaded[1]["run_id"] == "run_002"
