"""Unit tests for the SQLite persistence layer.

Tests save/load round-trips, exploit attempt recording and querying,
post-mortem recording and querying, and edge-case handling.

Owner: Parth (Member D)
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from src.state.persistence import PersistenceManager
from src.state.schemas import ExploitAttempt, ExploitPostMortem


@pytest.fixture
def pm(tmp_path: Path) -> PersistenceManager:
    """Provide a fresh PersistenceManager backed by a temporary database."""
    return PersistenceManager(db_path=str(tmp_path / "test_pm.db"))


# ── Graph save/load ─────────────────────────────────────────


class TestGraphSaveLoad:
    """Tests for save_graph() and load_graph()."""

    def test_save_and_load_empty_graph(self, pm: PersistenceManager) -> None:
        """Verify an empty graph can be saved and reloaded."""
        graph = nx.DiGraph()
        pm.save_graph(graph)

        loaded = pm.load_graph()
        assert loaded is not None
        assert len(loaded.nodes) == 0

    def test_save_and_load_graph_with_nodes(self, pm: PersistenceManager) -> None:
        """Verify a graph with nodes survives round-trip."""
        graph = nx.DiGraph()
        graph.add_node("host:10.10.10.5", node_type="host", ip="10.10.10.5")
        graph.add_node(
            "service:10.10.10.5:22/tcp", node_type="service", port=22
        )
        graph.add_edge(
            "host:10.10.10.5",
            "service:10.10.10.5:22/tcp",
            type="hosts_service",
        )

        pm.save_graph(graph)
        loaded = pm.load_graph()

        assert loaded is not None
        assert "host:10.10.10.5" in loaded.nodes
        assert loaded.nodes["host:10.10.10.5"]["ip"] == "10.10.10.5"
        assert loaded.has_edge("host:10.10.10.5", "service:10.10.10.5:22/tcp")

    def test_save_overwrites_previous(self, pm: PersistenceManager) -> None:
        """Verify saving twice keeps only the latest state."""
        graph1 = nx.DiGraph()
        graph1.add_node("host:10.10.10.5", node_type="host")
        pm.save_graph(graph1)

        graph2 = nx.DiGraph()
        graph2.add_node("host:10.10.10.6", node_type="host")
        pm.save_graph(graph2)

        loaded = pm.load_graph()
        assert loaded is not None
        assert "host:10.10.10.6" in loaded.nodes
        assert "host:10.10.10.5" not in loaded.nodes

    def test_load_graph_returns_none_when_empty(
        self, tmp_path: Path
    ) -> None:
        """Verify load_graph returns None when no graph has been saved."""
        fresh_pm = PersistenceManager(db_path=str(tmp_path / "empty.db"))
        loaded = fresh_pm.load_graph()
        assert loaded is None

    def test_graph_preserves_edge_attributes(
        self, pm: PersistenceManager
    ) -> None:
        """Verify edge attributes survive serialization round-trip."""
        graph = nx.DiGraph()
        graph.add_node("a", label="node_a")
        graph.add_node("b", label="node_b")
        graph.add_edge("a", "b", type="exploit_attempt", result="failure")

        pm.save_graph(graph)
        loaded = pm.load_graph()

        assert loaded is not None
        edge_data = loaded.edges["a", "b"]
        assert edge_data["type"] == "exploit_attempt"
        assert edge_data["result"] == "failure"

    def test_graph_preserves_node_types(self, pm: PersistenceManager) -> None:
        """Verify node_type attributes survive round-trip."""
        graph = nx.DiGraph()
        graph.add_node("host:10.10.10.5", node_type="host", ip="10.10.10.5")
        graph.add_node(
            "service:10.10.10.5:80/tcp",
            node_type="service",
            port=80,
            name="http",
        )
        graph.add_node("cve:CVE-2021-44228", node_type="cve", cvss_score=10.0)
        graph.add_node("session:1", node_type="session", privilege="root")
        graph.add_node(
            "web:10.10.10.5:80/admin",
            node_type="web_endpoint",
            url="/admin",
        )

        pm.save_graph(graph)
        loaded = pm.load_graph()

        assert loaded is not None
        assert loaded.nodes["host:10.10.10.5"]["node_type"] == "host"
        assert loaded.nodes["service:10.10.10.5:80/tcp"]["node_type"] == "service"
        assert loaded.nodes["cve:CVE-2021-44228"]["node_type"] == "cve"
        assert loaded.nodes["session:1"]["node_type"] == "session"
        assert (
            loaded.nodes["web:10.10.10.5:80/admin"]["node_type"]
            == "web_endpoint"
        )


# ── Exploit attempt recording and querying ──────────────────


class TestExploitAttempts:
    """Tests for record_exploit_attempt() and get_exploit_attempts()."""

    def test_record_and_query_attempt(self, pm: PersistenceManager) -> None:
        """Verify an exploit attempt can be recorded and queried."""
        attempt = ExploitAttempt(
            target_service_id="service:10.10.10.5:22/tcp",
            module_used="exploit/linux/ssh/test",
            result="failure",
            error_type="no_session",
        )
        pm.record_exploit_attempt(attempt)

        results = pm.get_exploit_attempts()
        assert len(results) == 1
        assert results[0]["target_service_id"] == "service:10.10.10.5:22/tcp"
        assert results[0]["module_used"] == "exploit/linux/ssh/test"
        assert results[0]["result"] == "failure"

    def test_record_multiple_attempts(self, pm: PersistenceManager) -> None:
        """Verify multiple exploit attempts are recorded in order."""
        for i in range(3):
            pm.record_exploit_attempt(
                ExploitAttempt(
                    target_service_id=f"service:10.10.10.5:{21 + i}/tcp",
                    module_used=f"exploit/module_{i}",
                )
            )

        results = pm.get_exploit_attempts()
        assert len(results) == 3
        # Verify ordering by ID
        assert results[0]["id"] < results[1]["id"] < results[2]["id"]

    def test_query_attempts_filtered_by_service(
        self, pm: PersistenceManager
    ) -> None:
        """Verify filtered query returns only matching service."""
        pm.record_exploit_attempt(
            ExploitAttempt(
                target_service_id="service:10.10.10.5:21/tcp",
                module_used="exploit/ftp/test",
            )
        )
        pm.record_exploit_attempt(
            ExploitAttempt(
                target_service_id="service:10.10.10.5:22/tcp",
                module_used="exploit/ssh/test",
            )
        )
        pm.record_exploit_attempt(
            ExploitAttempt(
                target_service_id="service:10.10.10.5:21/tcp",
                module_used="exploit/ftp/test2",
            )
        )

        ftp_attempts = pm.get_exploit_attempts("service:10.10.10.5:21/tcp")
        assert len(ftp_attempts) == 2
        for a in ftp_attempts:
            assert a["target_service_id"] == "service:10.10.10.5:21/tcp"

    def test_query_attempts_no_match(self, pm: PersistenceManager) -> None:
        """Verify filtered query returns empty when no match."""
        pm.record_exploit_attempt(
            ExploitAttempt(
                target_service_id="service:10.10.10.5:22/tcp",
                module_used="exploit/ssh/test",
            )
        )

        results = pm.get_exploit_attempts("service:10.10.10.99:80/tcp")
        assert results == []

    def test_attempt_all_fields_recorded(self, pm: PersistenceManager) -> None:
        """Verify all ExploitAttempt fields are stored and returned."""
        attempt = ExploitAttempt(
            target_service_id="service:10.10.10.5:21/tcp",
            module_used="exploit/unix/ftp/vsftpd_234_backdoor",
            payload="cmd/unix/interact",
            result="success",
            session_id="5",
            error_type="",
            raw_error="",
        )
        pm.record_exploit_attempt(attempt)

        results = pm.get_exploit_attempts()
        assert len(results) == 1
        r = results[0]
        assert r["payload"] == "cmd/unix/interact"
        assert r["result"] == "success"
        assert r["session_id"] == "5"


# ── Post-mortem recording and querying ──────────────────────


class TestPostMortems:
    """Tests for record_post_mortem() and get_post_mortems()."""

    def test_record_and_query_post_mortem(
        self, pm: PersistenceManager
    ) -> None:
        """Verify a post-mortem can be recorded and queried."""
        post_mortem = ExploitPostMortem(
            target_service="SSH on port 22",
            module_used="exploit/linux/ssh/test",
            error_type="no_session",
            hypothesis="Service patched",
            recommended_action="try_alternative_module",
        )
        pm.record_post_mortem(post_mortem)

        results = pm.get_post_mortems()
        assert len(results) == 1
        assert results[0]["target_service"] == "SSH on port 22"
        assert results[0]["hypothesis"] == "Service patched"
        assert results[0]["recommended_action"] == "try_alternative_module"

    def test_record_multiple_post_mortems(
        self, pm: PersistenceManager
    ) -> None:
        """Verify multiple post-mortems are recorded in order."""
        for i in range(3):
            pm.record_post_mortem(
                ExploitPostMortem(
                    target_service=f"Service {i}",
                    module_used=f"exploit/module_{i}",
                    error_type="no_session",
                )
            )

        results = pm.get_post_mortems()
        assert len(results) == 3

    def test_query_post_mortems_filtered(
        self, pm: PersistenceManager
    ) -> None:
        """Verify filtered query returns only matching service."""
        pm.record_post_mortem(
            ExploitPostMortem(
                target_service="FTP on port 21",
                module_used="exploit/ftp/test",
            )
        )
        pm.record_post_mortem(
            ExploitPostMortem(
                target_service="SSH on port 22",
                module_used="exploit/ssh/test",
            )
        )

        ftp_pms = pm.get_post_mortems("FTP on port 21")
        assert len(ftp_pms) == 1
        assert ftp_pms[0]["module_used"] == "exploit/ftp/test"

    def test_query_post_mortems_no_match(
        self, pm: PersistenceManager
    ) -> None:
        """Verify filtered query returns empty when no match."""
        pm.record_post_mortem(
            ExploitPostMortem(
                target_service="SSH on port 22",
                module_used="exploit/ssh/test",
            )
        )

        results = pm.get_post_mortems("HTTP on port 80")
        assert results == []

    def test_post_mortem_all_fields_recorded(
        self, pm: PersistenceManager
    ) -> None:
        """Verify all ExploitPostMortem fields are stored and returned."""
        post_mortem = ExploitPostMortem(
            target_service="FTP on port 21",
            module_used="exploit/unix/ftp/vsftpd_234_backdoor",
            error_type="no_session",
            raw_error="No session created after 30 seconds",
            hypothesis="Service patched against this CVE",
            recommended_action="try_alternative_module",
        )
        pm.record_post_mortem(post_mortem)

        results = pm.get_post_mortems()
        assert len(results) == 1
        r = results[0]
        assert r["raw_error"] == "No session created after 30 seconds"
        assert r["error_type"] == "no_session"
