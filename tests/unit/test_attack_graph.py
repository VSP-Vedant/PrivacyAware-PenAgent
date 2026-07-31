"""Unit tests for the AttackGraph state manager.

Tests all node insertion, query, and failure-tracking methods
to ensure zero data loss and correct graph topology.

Owner: Parth (Member D)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.state.attack_graph import AttackGraph
from src.state.schemas import (
    CVENode,
    EdgeType,
    ExploitAttempt,
    ExploitPostMortem,
    HostNode,
    ServiceNode,
    SessionNode,
    WebEndpointNode,
)


@pytest.fixture
def ag(tmp_path: Path) -> AttackGraph:
    """Provide a fresh AttackGraph backed by a temporary SQLite database."""
    return AttackGraph(db_path=str(tmp_path / "test_ag.db"))


# ── Host and Service insertion ──────────────────────────────


class TestAddHostAndService:
    """Tests for add_host() and add_service()."""

    def test_add_host(self, ag: AttackGraph) -> None:
        """Verify adding a host creates the node with correct attributes."""
        host = HostNode(ip="10.10.10.5", hostname="target.htb", os_guess="Linux")
        ag.add_host(host)

        assert "host:10.10.10.5" in ag.graph.nodes
        data = ag.graph.nodes["host:10.10.10.5"]
        assert data["ip"] == "10.10.10.5"
        assert data["hostname"] == "target.htb"
        assert data["node_type"] == "host"

    def test_add_service_creates_host_automatically(self, ag: AttackGraph) -> None:
        """Verify add_service auto-creates the host node if missing."""
        svc = ServiceNode(host_ip="10.10.10.5", port=80, name="http")
        ag.add_service(svc)

        assert "host:10.10.10.5" in ag.graph.nodes
        assert svc.node_id in ag.graph.nodes
        assert ag.graph.has_edge("host:10.10.10.5", svc.node_id)

    def test_add_service_links_to_existing_host(self, ag: AttackGraph) -> None:
        """Verify add_service links to an already-existing host node."""
        host = HostNode(ip="10.10.10.5", hostname="target.htb")
        ag.add_host(host)
        svc = ServiceNode(host_ip="10.10.10.5", port=22, name="ssh")
        ag.add_service(svc)

        # Should have exactly one host node, not two
        hosts = ag.get_hosts()
        assert len(hosts) == 1
        assert hosts[0]["hostname"] == "target.htb"

    def test_add_multiple_services_same_host(self, ag: AttackGraph) -> None:
        """Verify multiple services can be added to the same host."""
        ag.add_service(ServiceNode(host_ip="10.10.10.5", port=22, name="ssh"))
        ag.add_service(ServiceNode(host_ip="10.10.10.5", port=80, name="http"))
        ag.add_service(ServiceNode(host_ip="10.10.10.5", port=443, name="https"))

        services = ag.get_exploitable_services()
        assert len(services) == 3
        ports = {s["port"] for s in services}
        assert ports == {22, 80, 443}

    def test_service_edge_type(self, ag: AttackGraph) -> None:
        """Verify the edge type between host and service is HOSTS_SERVICE."""
        svc = ServiceNode(host_ip="10.10.10.5", port=21, name="ftp")
        ag.add_service(svc)

        edge_data = ag.graph.edges["host:10.10.10.5", svc.node_id]
        assert edge_data["type"] == EdgeType.HOSTS_SERVICE.value


# ── CVE node insertion ──────────────────────────────────────


class TestAddCVE:
    """Tests for add_cve()."""

    def test_add_cve_to_service(self, ag: AttackGraph) -> None:
        """Verify CVE node is created and linked to a service."""
        svc = ServiceNode(host_ip="10.10.10.5", port=21, name="ftp", version="2.3.4")
        ag.add_service(svc)

        cve = CVENode(
            cve_id="CVE-2011-2523",
            cvss_score=10.0,
            description="vsftpd 2.3.4 backdoor",
        )
        ag.add_cve(cve, svc.node_id)

        assert "cve:CVE-2011-2523" in ag.graph.nodes
        assert ag.graph.has_edge(svc.node_id, cve.node_id)

    def test_cve_edge_type(self, ag: AttackGraph) -> None:
        """Verify the edge type is VULNERABLE_TO."""
        svc = ServiceNode(host_ip="10.10.10.5", port=21, name="ftp")
        ag.add_service(svc)
        cve = CVENode(cve_id="CVE-2021-44228", cvss_score=10.0)
        ag.add_cve(cve, svc.node_id)

        edge_data = ag.graph.edges[svc.node_id, cve.node_id]
        assert edge_data["type"] == EdgeType.VULNERABLE_TO.value

    def test_add_cve_without_existing_service(self, ag: AttackGraph) -> None:
        """Verify CVE is added even if the service doesn't exist (no edge)."""
        cve = CVENode(cve_id="CVE-2020-1234", cvss_score=7.5)
        ag.add_cve(cve, "service:10.10.10.5:999/tcp")

        # CVE node should exist but no edge since service doesn't exist
        assert "cve:CVE-2020-1234" in ag.graph.nodes
        assert not ag.graph.has_edge("service:10.10.10.5:999/tcp", cve.node_id)

    def test_multiple_cves_per_service(self, ag: AttackGraph) -> None:
        """Verify multiple CVEs can be linked to one service."""
        svc = ServiceNode(host_ip="10.10.10.5", port=80, name="http")
        ag.add_service(svc)

        cve1 = CVENode(cve_id="CVE-2021-44228", cvss_score=10.0)
        cve2 = CVENode(cve_id="CVE-2021-45046", cvss_score=9.0)
        ag.add_cve(cve1, svc.node_id)
        ag.add_cve(cve2, svc.node_id)

        cves = ag.get_cves_for_service(svc.node_id)
        assert len(cves) == 2
        cve_ids = {c["cve_id"] for c in cves}
        assert cve_ids == {"CVE-2021-44228", "CVE-2021-45046"}


# ── Web endpoint insertion ──────────────────────────────────


class TestAddWebEndpoint:
    """Tests for add_web_endpoint()."""

    def test_add_web_endpoint(self, ag: AttackGraph) -> None:
        """Verify web endpoint is created and linked to host."""
        ep = WebEndpointNode(
            host_ip="10.10.10.5", port=80, url="/admin", status_code=200
        )
        ag.add_web_endpoint(ep)

        assert ep.node_id in ag.graph.nodes
        assert "host:10.10.10.5" in ag.graph.nodes
        assert ag.graph.has_edge("host:10.10.10.5", ep.node_id)

    def test_web_endpoint_edge_type(self, ag: AttackGraph) -> None:
        """Verify the edge type is HAS_ENDPOINT."""
        ep = WebEndpointNode(host_ip="10.10.10.5", port=80, url="/login")
        ag.add_web_endpoint(ep)

        edge_data = ag.graph.edges["host:10.10.10.5", ep.node_id]
        assert edge_data["type"] == EdgeType.HAS_ENDPOINT.value

    def test_add_web_endpoint_creates_host_if_missing(self, ag: AttackGraph) -> None:
        """Verify host is auto-created when adding a web endpoint."""
        ep = WebEndpointNode(host_ip="10.10.10.99", port=8080, url="/api")
        ag.add_web_endpoint(ep)

        assert "host:10.10.10.99" in ag.graph.nodes

    def test_multiple_endpoints_same_host(self, ag: AttackGraph) -> None:
        """Verify multiple endpoints can be added to one host."""
        ag.add_web_endpoint(
            WebEndpointNode(host_ip="10.10.10.5", port=80, url="/admin")
        )
        ag.add_web_endpoint(
            WebEndpointNode(host_ip="10.10.10.5", port=80, url="/login")
        )
        ag.add_web_endpoint(WebEndpointNode(host_ip="10.10.10.5", port=80, url="/api"))

        endpoints = ag.get_web_endpoints()
        assert len(endpoints) == 3


# ── Session insertion ───────────────────────────────────────


class TestAddSession:
    """Tests for add_session()."""

    def test_add_session(self, ag: AttackGraph) -> None:
        """Verify session node is created and linked to host."""
        session = SessionNode(
            session_id="1",
            host_ip="10.10.10.5",
            privilege="root",
            shell_type="meterpreter",
        )
        ag.add_session(session)

        assert "session:1" in ag.graph.nodes
        assert ag.graph.has_edge("host:10.10.10.5", "session:1")

    def test_session_edge_type(self, ag: AttackGraph) -> None:
        """Verify the edge type is ESCALATED_TO."""
        session = SessionNode(session_id="2", host_ip="10.10.10.5")
        ag.add_session(session)

        edge_data = ag.graph.edges["host:10.10.10.5", "session:2"]
        assert edge_data["type"] == EdgeType.ESCALATED_TO.value

    def test_add_session_creates_host_if_missing(self, ag: AttackGraph) -> None:
        """Verify host is auto-created when adding a session."""
        session = SessionNode(session_id="3", host_ip="10.10.10.99")
        ag.add_session(session)

        assert "host:10.10.10.99" in ag.graph.nodes

    def test_session_privilege_stored(self, ag: AttackGraph) -> None:
        """Verify session privilege level is stored in node data."""
        session = SessionNode(session_id="1", host_ip="10.10.10.5", privilege="root")
        ag.add_session(session)

        data = ag.graph.nodes["session:1"]
        assert data["privilege"] == "root"

    def test_has_active_session_true(self, ag: AttackGraph) -> None:
        """Verify has_active_session returns True when sessions exist."""
        session = SessionNode(session_id="1", host_ip="10.10.10.5")
        ag.add_session(session)
        assert ag.has_active_session() is True

    def test_has_active_session_false(self, ag: AttackGraph) -> None:
        """Verify has_active_session returns False on empty graph."""
        assert ag.has_active_session() is False


# ── Failure tracking ────────────────────────────────────────


class TestRecordFailure:
    """Tests for record_failure()."""

    def test_record_failure_creates_failure_node(self, ag: AttackGraph) -> None:
        """Verify record_failure creates a failure node in the graph."""
        svc = ServiceNode(host_ip="10.10.10.5", port=21, name="ftp")
        ag.add_service(svc)

        attempt = ExploitAttempt(
            target_service_id=svc.node_id,
            module_used="exploit/unix/ftp/vsftpd_234_backdoor",
            result="failure",
            error_type="no_session",
        )
        pm = ExploitPostMortem(
            target_service="FTP on port 21",
            module_used="exploit/unix/ftp/vsftpd_234_backdoor",
            error_type="no_session",
            hypothesis="Service may be patched",
            recommended_action="try_alternative_module",
        )
        ag.record_failure(attempt, pm)

        # Check failure node exists
        failures = ag.get_failed_attempts()
        assert len(failures) == 1
        assert failures[0]["error_type"] == "no_session"

    def test_record_failure_creates_exploit_attempt_edge(self, ag: AttackGraph) -> None:
        """Verify record_failure creates an edge from service to failure."""
        svc = ServiceNode(host_ip="10.10.10.5", port=22, name="ssh")
        ag.add_service(svc)

        attempt = ExploitAttempt(
            target_service_id=svc.node_id,
            module_used="exploit/linux/ssh/libssh_auth_bypass",
            result="failure",
            error_type="timeout",
        )
        pm = ExploitPostMortem(
            target_service="SSH on port 22",
            module_used="exploit/linux/ssh/libssh_auth_bypass",
            error_type="timeout",
            hypothesis="Connection timed out",
        )
        ag.record_failure(attempt, pm)

        failure_id = f"failure:{attempt.module_used}:{svc.node_id}"
        assert ag.graph.has_edge(svc.node_id, failure_id)

        edge_data = ag.graph.edges[svc.node_id, failure_id]
        assert edge_data["type"] == EdgeType.EXPLOIT_ATTEMPT.value
        assert edge_data["result"] == "failure"

    def test_record_failure_persists_to_sqlite(self, ag: AttackGraph) -> None:
        """Verify record_failure writes to exploit_attempts and post_mortems tables."""
        svc = ServiceNode(host_ip="10.10.10.5", port=21, name="ftp")
        ag.add_service(svc)

        attempt = ExploitAttempt(
            target_service_id=svc.node_id,
            module_used="exploit/unix/ftp/vsftpd_234_backdoor",
            result="failure",
            error_type="no_session",
        )
        pm = ExploitPostMortem(
            target_service="FTP on port 21",
            module_used="exploit/unix/ftp/vsftpd_234_backdoor",
            error_type="no_session",
            hypothesis="Patched service",
        )
        ag.record_failure(attempt, pm)

        # Verify SQLite persistence
        attempts = ag.get_exploit_attempts()
        assert len(attempts) == 1
        assert attempts[0]["module_used"] == "exploit/unix/ftp/vsftpd_234_backdoor"

        post_mortems = ag.get_post_mortems()
        assert len(post_mortems) == 1
        assert post_mortems[0]["hypothesis"] == "Patched service"

    def test_record_failure_without_service_in_graph(self, ag: AttackGraph) -> None:
        """Verify record_failure works even when service node doesn't exist."""
        attempt = ExploitAttempt(
            target_service_id="service:10.10.10.99:21/tcp",
            module_used="exploit/unix/ftp/proftpd_modcopy",
            result="failure",
        )
        pm = ExploitPostMortem(
            target_service="FTP on port 21",
            module_used="exploit/unix/ftp/proftpd_modcopy",
        )
        # Should not raise
        ag.record_failure(attempt, pm)

        # Failure node exists but no edge since service is missing
        failures = ag.get_failed_attempts()
        assert len(failures) == 1


# ── Query methods ───────────────────────────────────────────


class TestQueryMethods:
    """Tests for all graph query methods."""

    def test_get_hosts(self, ag: AttackGraph) -> None:
        """Verify get_hosts returns all host nodes."""
        ag.add_host(HostNode(ip="10.10.10.5"))
        ag.add_host(HostNode(ip="10.10.10.6"))

        hosts = ag.get_hosts()
        assert len(hosts) == 2
        ips = {h["ip"] for h in hosts}
        assert ips == {"10.10.10.5", "10.10.10.6"}

    def test_get_exploitable_services_empty(self, ag: AttackGraph) -> None:
        """Verify get_exploitable_services returns empty on fresh graph."""
        assert ag.get_exploitable_services() == []

    def test_get_sessions_empty(self, ag: AttackGraph) -> None:
        """Verify get_sessions returns empty on fresh graph."""
        assert ag.get_sessions() == []

    def test_get_sessions_with_data(self, ag: AttackGraph) -> None:
        """Verify get_sessions returns session data."""
        ag.add_session(
            SessionNode(session_id="1", host_ip="10.10.10.5", privilege="root")
        )
        ag.add_session(
            SessionNode(session_id="2", host_ip="10.10.10.5", privilege="user")
        )

        sessions = ag.get_sessions()
        assert len(sessions) == 2

    def test_get_web_endpoints_empty(self, ag: AttackGraph) -> None:
        """Verify get_web_endpoints returns empty on fresh graph."""
        assert ag.get_web_endpoints() == []

    def test_get_cves_for_service_empty(self, ag: AttackGraph) -> None:
        """Verify get_cves_for_service returns empty for unknown service."""
        assert ag.get_cves_for_service("service:10.10.10.5:99/tcp") == []

    def test_get_cves_for_service_with_data(self, ag: AttackGraph) -> None:
        """Verify CVE query returns correct CVEs for a service."""
        svc = ServiceNode(host_ip="10.10.10.5", port=21, name="ftp")
        ag.add_service(svc)

        cve1 = CVENode(cve_id="CVE-2011-2523", cvss_score=10.0)
        cve2 = CVENode(cve_id="CVE-2015-3306", cvss_score=9.8)
        ag.add_cve(cve1, svc.node_id)
        ag.add_cve(cve2, svc.node_id)

        cves = ag.get_cves_for_service(svc.node_id)
        assert len(cves) == 2

    def test_get_cves_for_service_does_not_cross_services(
        self, ag: AttackGraph
    ) -> None:
        """Verify CVE query doesn't return CVEs from other services."""
        svc1 = ServiceNode(host_ip="10.10.10.5", port=21, name="ftp")
        svc2 = ServiceNode(host_ip="10.10.10.5", port=22, name="ssh")
        ag.add_service(svc1)
        ag.add_service(svc2)

        cve_ftp = CVENode(cve_id="CVE-2011-2523", cvss_score=10.0)
        cve_ssh = CVENode(cve_id="CVE-2018-10933", cvss_score=9.1)
        ag.add_cve(cve_ftp, svc1.node_id)
        ag.add_cve(cve_ssh, svc2.node_id)

        ftp_cves = ag.get_cves_for_service(svc1.node_id)
        assert len(ftp_cves) == 1
        assert ftp_cves[0]["cve_id"] == "CVE-2011-2523"

        ssh_cves = ag.get_cves_for_service(svc2.node_id)
        assert len(ssh_cves) == 1
        assert ssh_cves[0]["cve_id"] == "CVE-2018-10933"

    def test_get_failed_attempts_empty(self, ag: AttackGraph) -> None:
        """Verify get_failed_attempts returns empty on fresh graph."""
        assert ag.get_failed_attempts() == []


# ── Persistence proxies ────────────────────────────────────


class TestPersistenceProxies:
    """Tests for exploit attempt and post-mortem persistence proxies."""

    def test_record_and_query_exploit_attempts(self, ag: AttackGraph) -> None:
        """Verify round-trip: record → query exploit attempts."""
        attempt = ExploitAttempt(
            target_service_id="service:10.10.10.5:22/tcp",
            module_used="exploit/linux/ssh/test",
            result="failure",
        )
        ag.record_exploit_attempt(attempt)

        results = ag.get_exploit_attempts()
        assert len(results) == 1
        assert results[0]["module_used"] == "exploit/linux/ssh/test"

    def test_query_exploit_attempts_with_filter(self, ag: AttackGraph) -> None:
        """Verify filtered query returns only matching service."""
        ag.record_exploit_attempt(
            ExploitAttempt(
                target_service_id="service:10.10.10.5:21/tcp",
                module_used="exploit/unix/ftp/test",
            )
        )
        ag.record_exploit_attempt(
            ExploitAttempt(
                target_service_id="service:10.10.10.5:22/tcp",
                module_used="exploit/linux/ssh/test",
            )
        )

        ftp_attempts = ag.get_exploit_attempts("service:10.10.10.5:21/tcp")
        assert len(ftp_attempts) == 1
        assert ftp_attempts[0]["module_used"] == "exploit/unix/ftp/test"

    def test_record_and_query_post_mortems(self, ag: AttackGraph) -> None:
        """Verify round-trip: record → query post-mortems."""
        pm = ExploitPostMortem(
            target_service="SSH on port 22",
            module_used="exploit/linux/ssh/test",
            error_type="timeout",
            hypothesis="Network unreachable",
        )
        ag.record_post_mortem(pm)

        results = ag.get_post_mortems()
        assert len(results) == 1
        assert results[0]["hypothesis"] == "Network unreachable"

    def test_query_post_mortems_with_filter(self, ag: AttackGraph) -> None:
        """Verify filtered post-mortem query."""
        ag.record_post_mortem(
            ExploitPostMortem(
                target_service="FTP on port 21",
                module_used="exploit/unix/ftp/test",
            )
        )
        ag.record_post_mortem(
            ExploitPostMortem(
                target_service="SSH on port 22",
                module_used="exploit/linux/ssh/test",
            )
        )

        ftp_pms = ag.get_post_mortems("FTP on port 21")
        assert len(ftp_pms) == 1


# ── Persistence round-trip ──────────────────────────────────


class TestPersistenceRoundTrip:
    """Tests verifying graph state survives process restart."""

    def test_graph_survives_reload(self, tmp_path: Path) -> None:
        """Verify the full graph persists and reloads correctly."""
        db_path = str(tmp_path / "roundtrip.db")

        # Build the graph
        ag1 = AttackGraph(db_path=db_path)
        ag1.add_host(HostNode(ip="10.10.10.5", hostname="target.htb"))
        ag1.add_service(
            ServiceNode(host_ip="10.10.10.5", port=22, name="ssh", version="7.6")
        )
        ag1.add_service(ServiceNode(host_ip="10.10.10.5", port=80, name="http"))
        ag1.add_cve(
            CVENode(cve_id="CVE-2018-10933", cvss_score=9.1),
            "service:10.10.10.5:22/tcp",
        )
        ag1.add_web_endpoint(
            WebEndpointNode(host_ip="10.10.10.5", port=80, url="/admin")
        )
        ag1.add_session(
            SessionNode(session_id="1", host_ip="10.10.10.5", privilege="root")
        )

        # Reload from disk
        ag2 = AttackGraph(db_path=db_path)

        assert len(ag2.get_hosts()) == 1
        assert len(ag2.get_exploitable_services()) == 2
        assert len(ag2.get_sessions()) == 1
        assert len(ag2.get_web_endpoints()) == 1
        assert ag2.has_active_session() is True

    def test_exploit_attempts_survive_reload(self, tmp_path: Path) -> None:
        """Verify exploit attempts persist across reloads."""
        db_path = str(tmp_path / "attempts.db")

        ag1 = AttackGraph(db_path=db_path)
        ag1.record_exploit_attempt(
            ExploitAttempt(
                target_service_id="service:10.10.10.5:22/tcp",
                module_used="exploit/linux/ssh/test",
                result="success",
                session_id="1",
            )
        )
        ag1.record_exploit_attempt(
            ExploitAttempt(
                target_service_id="service:10.10.10.5:21/tcp",
                module_used="exploit/unix/ftp/test",
                result="failure",
            )
        )

        # Reload and query
        ag2 = AttackGraph(db_path=db_path)
        attempts = ag2.get_exploit_attempts()
        assert len(attempts) == 2

    def test_post_mortems_survive_reload(self, tmp_path: Path) -> None:
        """Verify post-mortems persist across reloads."""
        db_path = str(tmp_path / "pm.db")

        ag1 = AttackGraph(db_path=db_path)
        ag1.record_post_mortem(
            ExploitPostMortem(
                target_service="SSH on port 22",
                module_used="exploit/linux/ssh/test",
                error_type="no_session",
                hypothesis="Patched",
            )
        )

        ag2 = AttackGraph(db_path=db_path)
        pms = ag2.get_post_mortems()
        assert len(pms) == 1
        assert pms[0]["error_type"] == "no_session"
