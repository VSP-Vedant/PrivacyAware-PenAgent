"""Gobuster subprocess wrapper for web directory enumeration.

Wraps the ``gobuster dir`` CLI tool, parsing its stdout into
structured :class:`WebEndpoint` / :class:`GobusterResult` dataclasses.
Only endpoints with status codes 200, 301, 302, or 403 are kept.

All targets are validated against ``ALLOWED_TARGET_RANGES`` before any
scan is executed.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Security: allowed target ranges (CLAUDE.md §4.2)
# ------------------------------------------------------------------
ALLOWED_TARGET_RANGES: list[str] = [
    "10.10.0.0/16",
    "10.129.0.0/16",
    "192.168.56.0/24",
    "172.17.0.0/16",
    "127.0.0.1",
]

_ACCEPTED_STATUS_CODES: frozenset[int] = frozenset({200, 301, 302, 403})

_LINE_RE = re.compile(
    r"^(/\S*)\s+"
    r"\(Status:\s*(\d+)\)"
    r"(?:\s+\[Size:\s*(\d+)\])?"
    r"(?:\s+\[Type:\s*([^\]]*)\])?"
    r"(?:\s+-->\s*(\S+))?",
)


# ------------------------------------------------------------------
# Custom exception
# ------------------------------------------------------------------
class GobusterError(Exception):
    """Raised when a Gobuster invocation fails."""


# ------------------------------------------------------------------
# Dataclasses
# ------------------------------------------------------------------
@dataclass
class WebEndpoint:
    """A single discovered web endpoint."""

    url: str
    status_code: int
    content_length: int
    content_type: str = ""
    redirect_url: str = ""


@dataclass
class GobusterResult:
    """Aggregated result of a Gobuster scan."""

    target_url: str
    endpoints: list[WebEndpoint] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    wordlist_used: str = ""
    total_found: int = 0


# ------------------------------------------------------------------
# Wrapper class
# ------------------------------------------------------------------
class GobusterWrapper:
    """Subprocess wrapper around the ``gobuster`` binary.

    Args:
        wordlist: Path to the wordlist file used for enumeration.
        threads: Number of concurrent threads gobuster should use.
        timeout: Maximum wall-clock seconds before the subprocess
            is killed.
    """

    def __init__(
        self,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        threads: int = 10,
        timeout: int = 300,
    ) -> None:
        """Docstring."""
        self._wordlist = wordlist
        self._threads = threads
        self._timeout = timeout

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------
    def scan(
        self,
        target_url: str,
        extensions: str | None = None,
    ) -> GobusterResult:
        """Run ``gobuster dir`` against *target_url*.

        Args:
            target_url: The base URL to enumerate (e.g.
                ``http://10.10.10.5``).
            extensions: Comma-separated list of file extensions to
                probe (e.g. ``"php,html,txt"``).  ``None`` means no
                extension filtering.

        Returns:
            A :class:`GobusterResult` containing discovered endpoints.

        Raises:
            GobusterError: If the target is outside allowed ranges,
                gobuster is not installed, or the subprocess fails.
        """
        self._validate_target(target_url)

        if not self.is_available():
            raise GobusterError("gobuster binary not found on PATH")

        cmd = self._build_command(target_url, extensions)
        logger.info("Starting gobuster scan against %s", target_url)
        logger.debug("Command: %s", " ".join(cmd))

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GobusterError(f"Gobuster timed out after {self._timeout}s") from exc

        elapsed = time.monotonic() - start

        if proc.returncode != 0 and not proc.stdout:
            raise GobusterError(
                f"Gobuster exited with code {proc.returncode}: "
                f"{proc.stderr.strip()}"
            )

        endpoints = self._parse_output(proc.stdout, target_url)
        result = GobusterResult(
            target_url=target_url,
            endpoints=endpoints,
            scan_duration_seconds=round(elapsed, 2),
            wordlist_used=self._wordlist,
            total_found=len(endpoints),
        )
        logger.info(
            "Gobuster finished: %d endpoints in %.2fs",
            result.total_found,
            result.scan_duration_seconds,
        )
        return result

    def is_available(self) -> bool:
        """Check whether the ``gobuster`` binary is on *PATH*.

        Returns:
            ``True`` if the binary is found, ``False`` otherwise.
        """
        return shutil.which("gobuster") is not None

    # ----------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------
    def _parse_output(
        self,
        raw_output: str,
        target_url: str,
    ) -> list[WebEndpoint]:
        """Parse raw gobuster stdout into :class:`WebEndpoint` objects.

        Args:
            raw_output: The complete stdout text produced by
                ``gobuster dir``.
            target_url: The base URL used for the scan (prepended
                to discovered paths).

        Returns:
            A list of :class:`WebEndpoint` instances whose status
            codes are in ``{200, 301, 302, 403}``.
        """
        base = target_url.rstrip("/")
        endpoints: list[WebEndpoint] = []

        for line in raw_output.splitlines():
            line = line.strip()
            match = _LINE_RE.match(line)
            if not match:
                continue

            path = match.group(1)
            status = int(match.group(2))

            if status not in _ACCEPTED_STATUS_CODES:
                logger.debug("Filtering out %s (status %d)", path, status)
                continue

            content_length = int(match.group(3)) if match.group(3) else 0
            content_type = match.group(4) or ""
            redirect_url = match.group(5) or ""

            endpoints.append(
                WebEndpoint(
                    url=f"{base}{path}",
                    status_code=status,
                    content_length=content_length,
                    content_type=content_type,
                    redirect_url=redirect_url,
                )
            )

        return endpoints

    def _build_command(
        self,
        target_url: str,
        extensions: str | None,
    ) -> list[str]:
        """Build the gobuster CLI argument list.

        Args:
            target_url: Target URL.
            extensions: Optional comma-separated extensions.

        Returns:
            A list of strings suitable for :func:`subprocess.run`.
        """
        cmd: list[str] = [
            "gobuster",
            "dir",
            "-u",
            target_url,
            "-w",
            self._wordlist,
            "-t",
            str(self._threads),
            "-q",
        ]
        if extensions:
            cmd.extend(["-x", extensions])
        return cmd

    @staticmethod
    def _validate_target(target_url: str) -> None:
        """Reject targets outside allowed IP ranges.

        Args:
            target_url: The URL whose host portion will be checked.

        Raises:
            GobusterError: If the host resolves to an IP outside
                :data:`ALLOWED_TARGET_RANGES`.
        """
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        if hostname is None:
            raise GobusterError(f"Cannot extract hostname from URL: {target_url}")

        try:
            addr = ip_address(hostname)
        except ValueError as exc:
            raise GobusterError(
                f"Hostname {hostname!r} is not a valid IP address. "
                f"DNS resolution is intentionally not supported "
                f"to prevent scanning unauthorized targets."
            ) from exc

        for net in ALLOWED_TARGET_RANGES:
            try:
                if addr in ip_network(net, strict=False):
                    return
            except ValueError:
                if str(addr) == net:
                    return

        logger.critical(
            "BLOCKED — target %s is outside allowed ranges",
            hostname,
        )
        raise GobusterError(
            f"Target {hostname} is outside allowed ranges. " f"Scan aborted."
        )
