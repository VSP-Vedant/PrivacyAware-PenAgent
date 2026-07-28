"""Unit tests for the full VerificationAgent (Week 15–16).

Owner: Vedant (Member C)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.agents.verification_agent import VerificationAgent, VerificationResult
from src.state.attack_graph import AttackGraph
from src.state.schemas import ExploitAttempt, ExploitPostMortem, PrivilegeLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_graph(tmp_path) -> AttackGraph:
    """Provide a fresh AttackGraph backed by a temp SQLite database."""
    return AttackGraph(db_path=str(tmp_path / "test.db"))


@pytest.fixture
def failed_attempt() -> ExploitAttempt:
    """A pre-built failed exploit attempt."""
    return ExploitAttempt(
        target_service_id="service:10.10.11.10:21/tcp",
        module_used="exploit/unix/ftp/vsftpd_234_backdoor",
        payload="cmd/unix/interact",
        result="failure",
        error_type="no_session",
        raw_error="No session created",
    )


@pytest.fixture
def success_attempt() -> ExploitAttempt:
    """A pre-built successful exploit attempt (session_id set)."""
    return ExploitAttempt(
        target_service_id="service:10.10.11.10:21/tcp",
        module_used="exploit/unix/ftp/vsftpd_234_backdoor",
        payload="cmd/unix/interact",
        result="success",
        session_id="3",
    )


# ---------------------------------------------------------------------------
# No-MSF mode (testing / recon-only)
# ---------------------------------------------------------------------------


class TestVerificationAgentNoMSF:
    """Tests for VerificationAgent when no MSF client is available."""

    def test_verify_failed_attempt_no_msf(
        self, mock_graph: AttackGraph, failed_attempt: ExploitAttempt
    ) -> None:
        agent = VerificationAgent(attack_graph=mock_graph, msf_client=None)
        result: VerificationResult = agent.verify_attempt(failed_attempt)

        assert result.success is False
        assert result.post_mortem is not None
        assert isinstance(result.post_mortem, ExploitPostMortem)
        assert result.post_mortem.error_type == "no_session"

    def test_verify_success_attempt_no_msf(
        self, mock_graph: AttackGraph, success_attempt: ExploitAttempt
    ) -> None:
        agent = VerificationAgent(attack_graph=mock_graph, msf_client=None)
        result = agent.verify_attempt(success_attempt)

        assert result.success is True
        assert result.privilege == PrivilegeLevel.USER.value

    def test_verify_backwards_compat(
        self, mock_graph: AttackGraph, success_attempt: ExploitAttempt
    ) -> None:
        """verify() returns an ExploitAttempt (backwards-compat API)."""
        agent = VerificationAgent(attack_graph=mock_graph, msf_client=None)
        attempt = agent.verify(success_attempt)
        assert isinstance(attempt, ExploitAttempt)
        assert attempt.result == "success"

    def test_post_mortem_writes_to_graph(
        self, mock_graph: AttackGraph, failed_attempt: ExploitAttempt
    ) -> None:
        """A failed attempt must write a failure edge to the graph."""
        # Add the service node first so the edge source exists
        from src.state.schemas import ServiceNode
        svc = ServiceNode(host_ip="10.10.11.10", port=21, protocol="tcp", name="ftp")
        mock_graph.add_service(svc)

        agent = VerificationAgent(attack_graph=mock_graph, msf_client=None)
        agent.verify_attempt(failed_attempt)

        # Check failure node was added to graph
        failure_nodes = [
            n for n in mock_graph.graph.nodes()
            if str(n).startswith("failure:")
        ]
        assert len(failure_nodes) >= 1

    def test_post_mortem_persisted(
        self, mock_graph: AttackGraph, failed_attempt: ExploitAttempt
    ) -> None:
        """Post-mortem must be saved to the SQLite database."""
        agent = VerificationAgent(attack_graph=mock_graph, msf_client=None)
        agent.verify_attempt(failed_attempt)

        import contextlib
        import sqlite3
        with contextlib.closing(sqlite3.connect(mock_graph.persistence.db_path)) as conn:
            rows = conn.execute("SELECT * FROM post_mortems").fetchall()
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# With MSF client (mocked)
# ---------------------------------------------------------------------------


class TestVerificationAgentWithMSF:
    """Tests for VerificationAgent with a mocked Metasploit RPC client."""

    def _make_msf(
        self,
        sessions: list | None = None,
        id_output: str = "uid=1000(bob) gid=1000(bob)",
    ) -> MagicMock:
        """Build a minimal MSF client mock."""
        from src.tools.metasploit_rpc import SessionInfo

        mock_msf = MagicMock()
        mock_msf.is_connected.return_value = True
        if sessions is None:
            mock_msf.list_sessions.return_value = []
        else:
            mock_msf.list_sessions.return_value = sessions
        mock_msf.run_session_command.return_value = id_output
        return mock_msf

    def test_no_session_found_generates_post_mortem(
        self, mock_graph: AttackGraph, success_attempt: ExploitAttempt
    ) -> None:
        """Exploit agent says success but MSF finds no session → failure."""
        mock_msf = self._make_msf(sessions=[])
        agent = VerificationAgent(attack_graph=mock_graph, msf_client=mock_msf)
        result = agent.verify_attempt(success_attempt)

        assert result.success is False
        assert result.post_mortem is not None
        assert result.post_mortem.error_type == "no_session"
        assert result.attempt.result == "failure"

    def test_session_found_user_privilege(
        self, mock_graph: AttackGraph, success_attempt: ExploitAttempt
    ) -> None:
        """Session found + non-root id output → user privilege."""
        from src.tools.metasploit_rpc import SessionInfo

        session = SessionInfo(
            session_id=3,
            session_type="shell",
            target_host="10.10.11.10",
            username="bob",
            platform="linux",
            via_exploit="exploit/unix/ftp/vsftpd_234_backdoor",
        )
        mock_msf = self._make_msf(
            sessions=[session],
            id_output="uid=1000(bob) gid=1000(bob) groups=1000(bob)",
        )
        agent = VerificationAgent(attack_graph=mock_graph, msf_client=mock_msf)
        result = agent.verify_attempt(success_attempt)

        assert result.success is True
        assert result.privilege == PrivilegeLevel.USER.value
        assert result.session_id == 3

    def test_session_found_root_privilege(
        self, mock_graph: AttackGraph, success_attempt: ExploitAttempt
    ) -> None:
        """Session found + root id output → root privilege."""
        from src.tools.metasploit_rpc import SessionInfo

        session = SessionInfo(
            session_id=5,
            session_type="meterpreter",
            target_host="10.10.11.10",
            username="root",
            platform="linux",
            via_exploit="exploit/unix/ftp/vsftpd_234_backdoor",
        )
        mock_msf = self._make_msf(
            sessions=[session],
            id_output="uid=0(root) gid=0(root) groups=0(root)",
        )
        agent = VerificationAgent(attack_graph=mock_graph, msf_client=mock_msf)
        result = agent.verify_attempt(success_attempt)

        assert result.success is True
        assert result.privilege == PrivilegeLevel.ROOT.value

    def test_session_node_updated_in_graph(
        self, mock_graph: AttackGraph, success_attempt: ExploitAttempt
    ) -> None:
        """A confirmed session must create/update a node in the attack graph."""
        from src.tools.metasploit_rpc import SessionInfo

        session = SessionInfo(
            session_id=7,
            session_type="shell",
            target_host="10.10.11.10",
            username="www-data",
            platform="linux",
            via_exploit="exploit/unix/ftp/vsftpd_234_backdoor",
        )
        mock_msf = self._make_msf(sessions=[session])
        agent = VerificationAgent(attack_graph=mock_graph, msf_client=mock_msf)
        agent.verify_attempt(success_attempt)

        assert mock_graph.graph.has_node("session:7")
        node_data = mock_graph.graph.nodes["session:7"]
        assert node_data["node_type"] == "session"


# ---------------------------------------------------------------------------
# Static helpers
# ---------------------------------------------------------------------------


class TestVerificationAgentHelpers:
    """Tests for the static helper methods."""

    def test_extract_target_ip_valid(self) -> None:
        ip = VerificationAgent._extract_target_ip("service:10.10.11.10:21/tcp")
        assert ip == "10.10.11.10"

    def test_extract_target_ip_fallback(self) -> None:
        ip = VerificationAgent._extract_target_ip("unknown")
        assert ip == "unknown"

    @pytest.mark.parametrize(
        "error_type",
        [
            "no_session",
            "timeout",
            "connection_refused",
            "auth_failed",
            "module_not_found",
            "no_session_after_exploit",
            "exploit_reported_failure",
        ],
    )
    def test_build_hypothesis_returns_string(self, error_type: str) -> None:
        hyp = VerificationAgent._build_hypothesis(error_type)
        assert isinstance(hyp, str)
        assert len(hyp) > 10

    def test_build_hypothesis_unknown_type(self) -> None:
        hyp = VerificationAgent._build_hypothesis("totally_unknown")
        assert "totally_unknown" in hyp

    @pytest.mark.parametrize(
        "error_type,expected_action",
        [
            ("no_session", "retry_different_payload"),
            ("module_not_found", "try_alternative_module"),
            ("connection_refused", "skip_service"),
            ("totally_unknown", "manual_review"),
        ],
    )
    def test_recommend_action(self, error_type: str, expected_action: str) -> None:
        action = VerificationAgent._recommend_action(error_type)
        assert action == expected_action
