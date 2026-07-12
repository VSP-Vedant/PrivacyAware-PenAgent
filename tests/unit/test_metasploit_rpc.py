"""Unit tests for Metasploit RPC wrapper module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.tools.metasploit_rpc import (
    ExploitExecutionResult,
    ExploitOptions,
    MetasploitConnectionError,
    MetasploitModuleError,
    MetasploitRPCClient,
    MetasploitRPCError,
    MsfModule,
    SessionInfo,
)


class TestMsfModule:
    """Tests for MsfModule dataclass."""

    def test_msf_module_creation(self) -> None:
        """Test basic MsfModule instantiation."""
        module = MsfModule(
            name="ms17_010_eternalblue",
            full_path="exploit/windows/smb/ms17_010_eternalblue",
            description="MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
            rank="great",
            references=["CVE-2017-0144", "CVE-2017-0145"],
        )
        assert module.name == "ms17_010_eternalblue"
        assert "exploit/" in module.full_path
        assert module.rank == "great"
        assert len(module.references) == 2

    def test_msf_module_empty_refs(self) -> None:
        """Test MsfModule with empty references."""
        module = MsfModule(
            name="test_module",
            full_path="exploit/test",
            description="Test module",
            rank="normal",
            references=[],
        )
        assert module.references == []


class TestExploitOptions:
    """Tests for ExploitOptions dataclass."""

    def test_exploit_options_defaults(self) -> None:
        """Test ExploitOptions with default values."""
        options = ExploitOptions(
            rhosts="10.10.10.5",
            rport=445,
            payload="windows/x64/meterpreter/reverse_tcp",
        )
        assert options.rhosts == "10.10.10.5"
        assert options.rport == 445
        assert options.lhost == "0.0.0.0"
        assert options.lport == 4444
        assert options.extra_options == {}

    def test_exploit_options_custom(self) -> None:
        """Test ExploitOptions with custom values."""
        options = ExploitOptions(
            rhosts="10.10.10.5",
            rport=80,
            payload="linux/x64/shell_reverse_tcp",
            lhost="10.10.14.1",
            lport=9001,
            extra_options={"TARGETURI": "/vuln"},
        )
        assert options.lhost == "10.10.14.1"
        assert options.lport == 9001
        assert options.extra_options["TARGETURI"] == "/vuln"


class TestExploitExecutionResult:
    """Tests for ExploitExecutionResult dataclass."""

    def test_execution_result_success(self) -> None:
        """Test successful exploit execution result."""
        result = ExploitExecutionResult(
            success=True,
            session_id=1,
            module_used="exploit/windows/smb/ms17_010_eternalblue",
            target="10.10.10.5",
        )
        assert result.success is True
        assert result.session_id == 1
        assert result.error_message == ""

    def test_execution_result_failure(self) -> None:
        """Test failed exploit execution result."""
        result = ExploitExecutionResult(
            success=False,
            session_id=None,
            module_used="exploit/linux/http/apache_path_traversal",
            target="10.10.10.5",
            error_message="Connection refused",
        )
        assert result.success is False
        assert result.session_id is None
        assert result.error_message == "Connection refused"


class TestSessionInfo:
    """Tests for SessionInfo dataclass."""

    def test_session_info_creation(self) -> None:
        """Test basic SessionInfo instantiation."""
        session = SessionInfo(
            session_id=1,
            session_type="meterpreter",
            target_host="10.10.10.5",
            username="root",
            platform="linux",
            via_exploit="exploit/linux/http/apache_rce",
        )
        assert session.session_id == 1
        assert session.session_type == "meterpreter"
        assert session.username == "root"
        assert session.platform == "linux"


class TestMetasploitRPCClient:
    """Tests for MetasploitRPCClient class."""

    def test_client_initialization(self) -> None:
        """Test client stores config without connecting."""
        client = MetasploitRPCClient(
            host="127.0.0.1",
            port=55553,
            password="testpass",
        )
        assert client._host == "127.0.0.1"
        assert client._port == 55553
        assert client.is_connected() is False

    def test_client_default_config(self) -> None:
        """Test client uses sensible defaults."""
        client = MetasploitRPCClient()
        assert client._host == "127.0.0.1"
        assert client._port == 55553
        assert client._ssl is True

    def test_validate_target_before_exploit(self) -> None:
        """Test exploit execution rejects blocked targets."""
        client = MetasploitRPCClient()
        client._client = MagicMock()  # Mock client to bypass connection check
        options = ExploitOptions(
            rhosts="8.8.8.8",
            rport=445,
            payload="windows/x64/meterpreter/reverse_tcp",
        )
        with pytest.raises(
            MetasploitModuleError, match="OUTSIDE allowed ranges"
        ):
            client.execute_exploit(
                "exploit/windows/smb/ms17_010_eternalblue",
                options,
            )

    def test_context_manager(self) -> None:
        """Test MetasploitRPCClient context manager protocol."""
        client = MetasploitRPCClient()
        with patch.object(client, "connect") as mock_connect, \
             patch.object(client, "disconnect") as mock_disconnect:
            # __enter__ should return self
            assert client.__enter__() is client
            mock_connect.assert_called_once()
            # __exit__ should not raise
            client.__exit__(None, None, None)
            mock_disconnect.assert_called_once()

    def test_exception_hierarchy(self) -> None:
        """Test custom exception inheritance chain."""
        assert issubclass(
            MetasploitConnectionError, MetasploitRPCError
        )
        assert issubclass(
            MetasploitModuleError, MetasploitRPCError
        )
        assert issubclass(MetasploitRPCError, Exception)

    def test_health_check_not_connected(self) -> None:
        """Test health check returns False when not connected."""
        client = MetasploitRPCClient()
        assert client.health_check() is False

    def test_search_modules_not_connected(self) -> None:
        """Test search_modules raises when not connected."""
        client = MetasploitRPCClient()
        with pytest.raises(MetasploitConnectionError):
            client.search_modules("eternalblue")

    def test_list_sessions_not_connected(self) -> None:
        """Test list_sessions raises when not connected."""
        client = MetasploitRPCClient()
        with pytest.raises(MetasploitConnectionError):
            client.list_sessions()
