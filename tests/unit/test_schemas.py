"""Unit tests for state schemas.

Tests all dataclass node types, edge types, enum values,
and serialization methods.
"""

from __future__ import annotations

from src.state.schemas import (
    CVENode,
    EdgeType,
    ErrorType,
    ExploitAttempt,
    ExploitPostMortem,
    ExploitResult,
    HostNode,
    NodeType,
    PrivilegeLevel,
    ServiceNode,
    SessionNode,
    WebEndpointNode,
)


class TestNodeType:
    """Tests for NodeType enum."""

    def test_host_value(self) -> None:
        """Verify HOST enum has correct string value."""
        assert NodeType.HOST.value == "host"

    def test_service_value(self) -> None:
        """Verify SERVICE enum has correct string value."""
        assert NodeType.SERVICE.value == "service"

    def test_cve_value(self) -> None:
        """Verify CVE enum has correct string value."""
        assert NodeType.CVE.value == "cve"

    def test_session_value(self) -> None:
        """Verify SESSION enum has correct string value."""
        assert NodeType.SESSION.value == "session"

    def test_web_endpoint_value(self) -> None:
        """Verify WEB_ENDPOINT enum has correct string value."""
        assert NodeType.WEB_ENDPOINT.value == "web_endpoint"


class TestEdgeType:
    """Tests for EdgeType enum."""

    def test_all_edge_types_exist(self) -> None:
        """Verify all required edge types are defined."""
        expected = {
            "hosts_service",
            "has_endpoint",
            "vulnerable_to",
            "exploit_attempt",
            "escalated_to",
        }
        actual = {e.value for e in EdgeType}
        assert actual == expected


class TestHostNode:
    """Tests for HostNode dataclass."""

    def test_create_host(self) -> None:
        """Verify host node creation with required fields."""
        host = HostNode(ip="10.10.10.5")
        assert host.ip == "10.10.10.5"
        assert host.hostname == ""
        assert host.status == "up"

    def test_node_id_format(self) -> None:
        """Verify node ID follows 'host:<ip>' format."""
        host = HostNode(ip="10.10.10.5")
        assert host.node_id == "host:10.10.10.5"

    def test_node_type(self) -> None:
        """Verify node type is HOST."""
        host = HostNode(ip="10.10.10.5")
        assert host.node_type == NodeType.HOST

    def test_to_dict_includes_node_id(self) -> None:
        """Verify serialization includes node_id and node_type."""
        host = HostNode(ip="10.10.10.5", hostname="target.htb")
        data = host.to_dict()
        assert data["node_id"] == "host:10.10.10.5"
        assert data["node_type"] == "host"
        assert data["hostname"] == "target.htb"

    def test_to_dict_includes_all_fields(self) -> None:
        """Verify all fields present in serialized output."""
        host = HostNode(
            ip="10.10.10.5",
            hostname="target.htb",
            os_guess="Linux",
            status="up",
        )
        data = host.to_dict()
        assert "ip" in data
        assert "hostname" in data
        assert "os_guess" in data
        assert "status" in data
        assert "discovered_at" in data


class TestServiceNode:
    """Tests for ServiceNode dataclass."""

    def test_create_service(self) -> None:
        """Verify service node creation with required fields."""
        svc = ServiceNode(host_ip="10.10.10.5", port=22)
        assert svc.host_ip == "10.10.10.5"
        assert svc.port == 22
        assert svc.protocol == "tcp"
        assert svc.name == "unknown"

    def test_node_id_format(self) -> None:
        """Verify node ID follows 'service:<ip>:<port>/<proto>' format."""
        svc = ServiceNode(host_ip="10.10.10.5", port=80, protocol="tcp")
        assert svc.node_id == "service:10.10.10.5:80/tcp"

    def test_node_type(self) -> None:
        """Verify node type is SERVICE."""
        svc = ServiceNode(host_ip="10.10.10.5", port=22)
        assert svc.node_type == NodeType.SERVICE

    def test_to_dict(self) -> None:
        """Verify serialization includes all fields."""
        svc = ServiceNode(
            host_ip="10.10.10.5",
            port=22,
            name="ssh",
            version="OpenSSH 7.6",
            product="OpenSSH",
        )
        data = svc.to_dict()
        assert data["port"] == 22
        assert data["name"] == "ssh"
        assert data["version"] == "OpenSSH 7.6"


class TestCVENode:
    """Tests for CVENode dataclass."""

    def test_create_cve(self) -> None:
        """Verify CVE node creation with required fields."""
        cve = CVENode(cve_id="CVE-2021-44228")
        assert cve.cve_id == "CVE-2021-44228"
        assert cve.cvss_score == 0.0

    def test_node_id_format(self) -> None:
        """Verify node ID follows 'cve:<id>' format."""
        cve = CVENode(cve_id="CVE-2021-44228")
        assert cve.node_id == "cve:CVE-2021-44228"

    def test_high_cvss(self) -> None:
        """Verify CVSS score stores correctly."""
        cve = CVENode(cve_id="CVE-2021-44228", cvss_score=10.0)
        assert cve.cvss_score == 10.0

    def test_to_dict(self) -> None:
        """Verify serialization includes all fields."""
        cve = CVENode(
            cve_id="CVE-2021-44228",
            cvss_score=10.0,
            description="Log4Shell RCE",
        )
        data = cve.to_dict()
        assert data["cve_id"] == "CVE-2021-44228"
        assert data["description"] == "Log4Shell RCE"


class TestSessionNode:
    """Tests for SessionNode dataclass."""

    def test_create_session(self) -> None:
        """Verify session node creation with required fields."""
        sess = SessionNode(session_id="1", host_ip="10.10.10.5")
        assert sess.session_id == "1"
        assert sess.privilege == "user"
        assert sess.shell_type == "shell"

    def test_node_id_format(self) -> None:
        """Verify node ID follows 'session:<id>' format."""
        sess = SessionNode(session_id="42", host_ip="10.10.10.5")
        assert sess.node_id == "session:42"

    def test_root_privilege(self) -> None:
        """Verify root privilege stores correctly."""
        sess = SessionNode(session_id="1", host_ip="10.10.10.5", privilege="root")
        assert sess.privilege == "root"


class TestWebEndpointNode:
    """Tests for WebEndpointNode dataclass."""

    def test_create_web_endpoint(self) -> None:
        """Verify web endpoint creation."""
        ep = WebEndpointNode(host_ip="10.10.10.5", port=80, url="/admin")
        assert ep.url == "/admin"
        assert ep.status_code == 200

    def test_node_id_format(self) -> None:
        """Verify node ID follows 'web:<ip>:<port><url>' format."""
        ep = WebEndpointNode(host_ip="10.10.10.5", port=80, url="/login")
        assert ep.node_id == "web:10.10.10.5:80/login"


class TestExploitAttempt:
    """Tests for ExploitAttempt dataclass."""

    def test_create_attempt(self) -> None:
        """Verify exploit attempt creation with defaults."""
        attempt = ExploitAttempt(
            target_service_id="service:10.10.10.5:22/tcp",
            module_used="exploit/unix/ftp/vsftpd_234_backdoor",
        )
        assert attempt.result == "failure"
        assert attempt.session_id == ""

    def test_successful_attempt(self) -> None:
        """Verify successful exploit attempt with session."""
        attempt = ExploitAttempt(
            target_service_id="service:10.10.10.5:21/tcp",
            module_used="exploit/unix/ftp/vsftpd_234_backdoor",
            result="success",
            session_id="1",
        )
        assert attempt.result == "success"
        assert attempt.session_id == "1"

    def test_to_dict(self) -> None:
        """Verify serialization works."""
        attempt = ExploitAttempt(
            target_service_id="service:10.10.10.5:22/tcp",
            module_used="exploit/linux/ssh/libssh_auth_bypass",
        )
        data = attempt.to_dict()
        assert "target_service_id" in data
        assert "module_used" in data
        assert "timestamp" in data


class TestExploitPostMortem:
    """Tests for ExploitPostMortem dataclass."""

    def test_create_post_mortem(self) -> None:
        """Verify post-mortem creation with defaults."""
        pm = ExploitPostMortem(
            target_service="SSH on port 22",
            module_used="exploit/linux/ssh/libssh_auth_bypass",
        )
        assert pm.error_type == "no_session"
        assert pm.recommended_action == "retry_different_payload"

    def test_to_dict(self) -> None:
        """Verify serialization includes all fields."""
        pm = ExploitPostMortem(
            target_service="FTP on port 21",
            module_used="exploit/unix/ftp/vsftpd_234_backdoor",
            error_type="timeout",
            hypothesis="Service may be patched",
            recommended_action="try_alternative_module",
        )
        data = pm.to_dict()
        assert data["hypothesis"] == "Service may be patched"


class TestPrivilegeLevel:
    """Tests for PrivilegeLevel enum."""

    def test_none_value(self) -> None:
        """Verify NONE privilege level."""
        assert PrivilegeLevel.NONE.value == "none"

    def test_user_value(self) -> None:
        """Verify USER privilege level."""
        assert PrivilegeLevel.USER.value == "user"

    def test_root_value(self) -> None:
        """Verify ROOT privilege level."""
        assert PrivilegeLevel.ROOT.value == "root"


class TestExploitResult:
    """Tests for ExploitResult enum."""

    def test_all_results_exist(self) -> None:
        """Verify all result types are defined."""
        expected = {"success", "failure", "timeout", "error"}
        actual = {r.value for r in ExploitResult}
        assert actual == expected


class TestErrorType:
    """Tests for ErrorType enum."""

    def test_all_error_types_exist(self) -> None:
        """Verify all error types match ARCHITECTURE.md spec."""
        expected = {
            "no_session",
            "timeout",
            "connection_refused",
            "auth_failed",
            "module_not_found",
        }
        actual = {e.value for e in ErrorType}
        assert actual == expected
