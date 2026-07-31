"""Unit tests for the ReportGenerator (Week 17–18).

Owner: Vedant (Member C)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.reporting.report_generator import ReportGenerator
from src.state.attack_graph import AttackGraph
from src.state.schemas import HostNode, ServiceNode, SessionNode


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def empty_graph(tmp_path: Path) -> AttackGraph:
    """A fresh AttackGraph with no nodes."""
    return AttackGraph(db_path=str(tmp_path / "test.db"))


@pytest.fixture
def populated_graph(tmp_path: Path) -> AttackGraph:
    """AttackGraph with host, service, and session nodes for testing."""
    ag = AttackGraph(db_path=str(tmp_path / "test.db"))

    host = HostNode(ip="10.10.11.10", hostname="target.htb", os_guess="Linux")
    ag.add_host(host)

    svc = ServiceNode(
        host_ip="10.10.11.10",
        port=21,
        protocol="tcp",
        name="ftp",
        product="vsftpd",
        version="2.3.4",
        state="open",
    )
    ag.add_service(svc)

    svc_http = ServiceNode(
        host_ip="10.10.11.10",
        port=80,
        protocol="tcp",
        name="http",
        product="Apache httpd",
        version="2.4.49",
        state="open",
    )
    ag.add_service(svc_http)

    # Add a session node directly
    session = SessionNode(
        session_id="3",
        host_ip="10.10.11.10",
        privilege="root",
        shell_type="shell",
    )
    ag.graph.add_node(session.node_id, **session.to_dict())

    return ag


@pytest.fixture
def report_dir(tmp_path: Path) -> str:
    return str(tmp_path / "reports")


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestReportGeneratorInit:
    def test_creates_output_dir(self, empty_graph: AttackGraph, tmp_path: Path) -> None:
        out = str(tmp_path / "new_reports")
        ReportGenerator(attack_graph=empty_graph, output_dir=out)
        assert Path(out).exists()

    def test_run_id_stored(self, empty_graph: AttackGraph, report_dir: str) -> None:
        rg = ReportGenerator(
            attack_graph=empty_graph, output_dir=report_dir, run_id="myrun"
        )
        assert rg._run_id == "myrun"


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------


class TestHTMLReport:
    def test_generates_html_file(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(
            attack_graph=populated_graph, output_dir=report_dir, run_id="test"
        )
        path = rg.generate_html()
        assert Path(path).exists()
        assert path.endswith(".html")

    def test_html_contains_run_id(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(
            attack_graph=populated_graph, output_dir=report_dir, run_id="myrun123"
        )
        path = rg.generate_html()
        content = Path(path).read_text(encoding="utf-8")
        assert "myrun123" in content

    def test_html_contains_services(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(attack_graph=populated_graph, output_dir=report_dir)
        path = rg.generate_html()
        content = Path(path).read_text(encoding="utf-8")
        assert "vsftpd" in content
        assert "10.10.11.10" in content

    def test_html_contains_session_info(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(attack_graph=populated_graph, output_dir=report_dir)
        path = rg.generate_html()
        content = Path(path).read_text(encoding="utf-8")
        assert "root" in content

    def test_html_valid_structure(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(attack_graph=populated_graph, output_dir=report_dir)
        path = rg.generate_html()
        content = Path(path).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content

    def test_empty_graph_html(self, empty_graph: AttackGraph, report_dir: str) -> None:
        rg = ReportGenerator(
            attack_graph=empty_graph, output_dir=report_dir, run_id="empty"
        )
        path = rg.generate_html()
        assert Path(path).exists()
        content = Path(path).read_text(encoding="utf-8")
        assert "No services discovered" in content


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


class TestMarkdownReport:
    def test_generates_md_file(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(
            attack_graph=populated_graph, output_dir=report_dir, run_id="test"
        )
        path = rg.generate_markdown()
        assert Path(path).exists()
        assert path.endswith(".md")

    def test_md_contains_summary_table(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(attack_graph=populated_graph, output_dir=report_dir)
        path = rg.generate_markdown()
        content = Path(path).read_text()
        assert "## Summary" in content
        assert "Hosts discovered" in content

    def test_md_contains_service_table(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(attack_graph=populated_graph, output_dir=report_dir)
        path = rg.generate_markdown()
        content = Path(path).read_text()
        assert "vsftpd" in content
        assert "2.3.4" in content

    def test_empty_graph_md(self, empty_graph: AttackGraph, report_dir: str) -> None:
        rg = ReportGenerator(
            attack_graph=empty_graph, output_dir=report_dir, run_id="empty"
        )
        path = rg.generate_markdown()
        assert Path(path).exists()
        content = Path(path).read_text()
        assert "No services discovered" in content


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------


class TestJSONReport:
    def test_generates_json_file(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(
            attack_graph=populated_graph, output_dir=report_dir, run_id="test"
        )
        path = rg.generate_json()
        assert Path(path).exists()
        assert path.endswith(".json")

    def test_json_valid_and_structured(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(attack_graph=populated_graph, output_dir=report_dir)
        path = rg.generate_json()
        data = json.loads(Path(path).read_text())

        assert "summary" in data
        assert "hosts" in data
        assert "services" in data
        assert "sessions" in data
        assert data["summary"]["total_services"] == 2
        assert data["summary"]["total_sessions"] == 1

    def test_json_summary_counts(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(attack_graph=populated_graph, output_dir=report_dir)
        path = rg.generate_json()
        data = json.loads(Path(path).read_text())

        assert data["summary"]["total_hosts"] >= 1
        assert data["summary"]["total_services"] >= 1


# ---------------------------------------------------------------------------
# generate_all
# ---------------------------------------------------------------------------


class TestGenerateAll:
    def test_generate_all_returns_three_paths(
        self, populated_graph: AttackGraph, report_dir: str
    ) -> None:
        rg = ReportGenerator(
            attack_graph=populated_graph, output_dir=report_dir, run_id="all_test"
        )
        paths = rg.generate_all()
        assert set(paths.keys()) == {"html", "markdown", "json"}
        for path in paths.values():
            assert Path(path).exists()
