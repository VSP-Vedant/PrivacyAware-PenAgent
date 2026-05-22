"""SearchSploit subprocess wrapper for offline exploit lookup.

Wraps the ``searchsploit`` CLI (ExploitDB local mirror) and parses
its ``--json`` output into structured :class:`ExploitResult` /
:class:`SearchSploitResult` dataclasses.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Custom exception
# ------------------------------------------------------------------
class SearchSploitError(Exception):
    """Raised when a SearchSploit invocation fails."""


# ------------------------------------------------------------------
# Dataclasses
# ------------------------------------------------------------------
@dataclass
class ExploitResult:
    """A single exploit entry returned by SearchSploit."""

    title: str
    edb_id: str
    path: str
    platform: str
    exploit_type: str


@dataclass
class SearchSploitResult:
    """Aggregated results for a SearchSploit query."""

    query: str
    results: list[ExploitResult] = field(default_factory=list)
    total_found: int = 0


# ------------------------------------------------------------------
# Wrapper class
# ------------------------------------------------------------------
class SearchSploitWrapper:
    """Subprocess wrapper around the ``searchsploit`` binary.

    SearchSploit is an offline command-line search tool for
    `Exploit-DB <https://www.exploit-db.com>`_.  This wrapper invokes
    it with ``--json`` output and converts the result into typed
    Python dataclasses.
    """

    def __init__(self) -> None:
        pass

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------
    def search(
        self,
        query: str,
        exact: bool = False,
    ) -> SearchSploitResult:
        """Search the local ExploitDB for *query*.

        Args:
            query: Free-text search string (e.g.
                ``"Apache 2.4.49"``).
            exact: If ``True``, pass ``--exact`` so only exact
                title matches are returned.

        Returns:
            A :class:`SearchSploitResult` with all matching exploits.

        Raises:
            SearchSploitError: If the binary is missing or the
                subprocess fails.
        """
        if not query or not query.strip():
            raise SearchSploitError(
                "Search query must not be empty"
            )

        if not self.is_available():
            raise SearchSploitError(
                "searchsploit binary not found on PATH"
            )

        cmd = self._build_command(query, exact=exact)
        logger.info(
            "Running searchsploit query: %r (exact=%s)",
            query,
            exact,
        )
        logger.debug("Command: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SearchSploitError(
                "searchsploit timed out after 60s"
            ) from exc

        if proc.returncode != 0 and not proc.stdout:
            raise SearchSploitError(
                f"searchsploit exited with code "
                f"{proc.returncode}: {proc.stderr.strip()}"
            )

        exploits = self._parse_json_output(proc.stdout)
        result = SearchSploitResult(
            query=query,
            results=exploits,
            total_found=len(exploits),
        )
        logger.info(
            "SearchSploit found %d results for %r",
            result.total_found,
            query,
        )
        return result

    def is_available(self) -> bool:
        """Check whether the ``searchsploit`` binary is on *PATH*.

        Returns:
            ``True`` if the binary is found, ``False`` otherwise.
        """
        return shutil.which("searchsploit") is not None

    # ----------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------
    def _parse_json_output(
        self,
        raw_json: str,
    ) -> list[ExploitResult]:
        """Parse SearchSploit JSON output into typed objects.

        Args:
            raw_json: The raw stdout string produced by
                ``searchsploit --json``.

        Returns:
            A list of :class:`ExploitResult` instances.

        Raises:
            SearchSploitError: If the JSON cannot be decoded.
        """
        if not raw_json.strip():
            return []

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise SearchSploitError(
                f"Failed to parse searchsploit JSON output: {exc}"
            ) from exc

        exploits_raw = data.get(
            "RESULTS_EXPLOIT", data.get("results", [])
        )
        results: list[ExploitResult] = []

        for entry in exploits_raw:
            results.append(
                ExploitResult(
                    title=str(entry.get("Title", "")),
                    edb_id=str(entry.get("EDB-ID", "")),
                    path=str(entry.get("Path", "")),
                    platform=str(entry.get("Platform", "")),
                    exploit_type=str(entry.get("Type", "")),
                )
            )

        return results

    @staticmethod
    def _build_command(
        query: str,
        *,
        exact: bool = False,
    ) -> list[str]:
        """Build the searchsploit CLI argument list.

        Args:
            query: The search query string.
            exact: Whether to use ``--exact`` matching.

        Returns:
            A list of strings suitable for :func:`subprocess.run`.
        """
        cmd: list[str] = ["searchsploit", "--json"]
        if exact:
            cmd.append("--exact")
        cmd.append(query)
        return cmd
