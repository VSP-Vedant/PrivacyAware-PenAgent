"""Remote Code Execution (RCE) Validator.

Validates:
1. Interactive session establishment (Meterpreter / shell).
2. Direct command execution producing output (blind or non-interactive RCE).
3. Payload delivery confirmation.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from src.state.schemas import FindingCategory, PrivilegeLevel
from src.validators.base import BaseValidator, ValidationOutcome

logger = logging.getLogger(__name__)

# Patterns indicating privilege or successful command execution in output
_ROOT_PATTERN = re.compile(r"uid=0\(root\)|uid=0\b|root@|[\\/]root\b")
_USER_PATTERN = re.compile(r"uid=\d+\(([^)]+)\)|User:|whoami:\s*\w+")
_COMMAND_EXEC_PATTERNS = [
    re.compile(r"uid=\d+.*gid=\d+", re.IGNORECASE),
    re.compile(r"Linux\s+[\w\.\-]+\s+\d+\.\d+", re.IGNORECASE),
    re.compile(r"Windows\s+IP\s+Configuration", re.IGNORECASE),
    re.compile(r"command\s+output:\s*.+", re.IGNORECASE),
    re.compile(r"backdoor\s+command\s+execution", re.IGNORECASE),
    re.compile(r"successfully\s+executed", re.IGNORECASE),
    re.compile(r"payload\s+executed", re.IGNORECASE),
]


class RCEValidator(BaseValidator):
    """Validator for Remote Code Execution vulnerabilities."""

    name: str = "rce_validator"
    category: FindingCategory = FindingCategory.REMOTE_CODE_EXECUTION

    def can_validate(
        self,
        module_path: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Handle standard exploit modules and command execution tools."""
        if module_path.startswith("exploit/"):
            return True
        if any(
            k in module_path.lower()
            for k in ("rce", "exec", "cmd", "command", "backdoor", "shell")
        ):
            return True
        return False

    def validate(
        self,
        target: str,
        service_id: str,
        module_path: str,
        raw_output: str | dict[str, Any],
        msf_client: Any | None = None,
        context: dict[str, Any] | None = None,
    ) -> ValidationOutcome:
        """Validate RCE via active session OR command execution output."""
        output_str = str(raw_output)
        ctx = context or {}

        # ── Check 1: Live Metasploit Session ────────────────────────
        target_ip = target
        if ":" in service_id:
            parts = service_id.split(":")
            if len(parts) >= 2:
                target_ip = parts[1]

        session_id: int | None = None
        privilege = PrivilegeLevel.NONE.value

        if msf_client is not None and hasattr(msf_client, "is_connected") and msf_client.is_connected():
            try:
                sessions = msf_client.list_sessions()
                # Check for session on target matching context or module
                for s in sessions:
                    if s.target_host == target_ip:
                        session_id = s.session_id
                        # Check privilege
                        try:
                            priv_out = msf_client.run_session_command(session_id, "id")
                            if _ROOT_PATTERN.search(priv_out):
                                privilege = PrivilegeLevel.ROOT.value
                            elif _USER_PATTERN.search(priv_out):
                                privilege = PrivilegeLevel.USER.value
                            else:
                                privilege = PrivilegeLevel.USER.value
                        except Exception:
                            privilege = PrivilegeLevel.USER.value
                        break
            except Exception as exc:
                logger.debug("Session verification query failed: %s", exc)

        # Only trust context session_id in offline mode when msf_client is not connected
        if session_id is None and (msf_client is None or not getattr(msf_client, "is_connected", lambda: False)()) and ctx.get("session_id"):
            try:
                session_id = int(ctx["session_id"])
                privilege = ctx.get("privilege", PrivilegeLevel.USER.value)
            except (ValueError, TypeError):
                pass

        if session_id is not None:
            return ValidationOutcome(
                is_valid=True,
                category=FindingCategory.REMOTE_CODE_EXECUTION,
                title=f"Remote Code Execution (Interactive Shell #{session_id})",
                description=(
                    f"Successfully established an interactive {privilege} session on {target_ip} "
                    f"via module {module_path}."
                ),
                evidence=f"Active session {session_id} on {target_ip} with privilege '{privilege}'.",
                privilege=privilege,
                session_id=session_id,
            )

        # ── Check 2: Command Output Evidence (Non-interactive RCE) ───
        for pattern in _COMMAND_EXEC_PATTERNS:
            match = pattern.search(output_str)
            if match:
                evidence_snippet = output_str[max(0, match.start() - 50) : min(len(output_str), match.end() + 150)]
                priv = PrivilegeLevel.ROOT.value if _ROOT_PATTERN.search(output_str) else PrivilegeLevel.USER.value
                return ValidationOutcome(
                    is_valid=True,
                    category=FindingCategory.REMOTE_CODE_EXECUTION,
                    title="Remote Code Execution (Command Output Verified)",
                    description=(
                        f"Demonstrated remote command execution on {target_ip} via {module_path}. "
                        "Execution output verified."
                    ),
                    evidence=evidence_snippet.strip(),
                    privilege=priv,
                )

        return ValidationOutcome(
            is_valid=False,
            category=FindingCategory.REMOTE_CODE_EXECUTION,
            error_type="no_session",
            description="Exploit executed but no interactive session or command execution output was verified.",
        )
