"""Remote Administration Service Validator.

Validates:
1. Unauthenticated remote display access (VNC null auth, Open X11 server).
2. Remote management protocol access (RSH/Rlogin without password, Telnet).
3. Remote Desktop / Terminal access confirmation.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from src.state.schemas import FindingCategory
from src.validators.base import BaseValidator, ValidationOutcome

logger = logging.getLogger(__name__)

# Patterns matching remote administration access
_REMOTE_ADMIN_PATTERNS = [
    re.compile(r"VNC\s+server\s+requires\s+NO\s+authentication|Null\s+Authentication", re.IGNORECASE),
    re.compile(r"Open\s+X11\s+Server\s+Access|X11\s+display\s+accessible", re.IGNORECASE),
    re.compile(r"Connected\s+without\s+authentication", re.IGNORECASE),
    re.compile(r"rlogin\s+session\s+established|rexec\s+successful", re.IGNORECASE),
    re.compile(r"remote\s+access\s+established", re.IGNORECASE),
    re.compile(r"\[\+\]\s+[\d\.\:]+\s+-\s+VNC\s+server\s+security\s+types?:\s*None", re.IGNORECASE),
]


class RemoteAdminValidator(BaseValidator):
    """Validator for Remote Administration services (VNC, X11, RDP, RSH/Rexec)."""

    name: str = "remote_admin_validator"
    category: FindingCategory = FindingCategory.REMOTE_ADMIN

    def can_validate(
        self,
        module_path: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Handle VNC, X11, RDP, and remote administration modules."""
        lowered = module_path.lower()
        if any(
            k in lowered
            for k in (
                "vnc",
                "x11",
                "rdp",
                "rlogin",
                "rsh",
                "rexec",
                "telnet",
                "remote_admin",
                "open_x11",
            )
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
        """Validate remote administration service access."""
        output_str = str(raw_output)

        for pattern in _REMOTE_ADMIN_PATTERNS:
            match = pattern.search(output_str)
            if match:
                evidence = match.group(0).strip()
                return ValidationOutcome(
                    is_valid=True,
                    category=FindingCategory.REMOTE_ADMIN,
                    title=f"Remote Administration Service Access Verified ({service_id})",
                    description=(
                        f"Unauthenticated or weakly authenticated remote administration access "
                        f"verified on {target} ({service_id}) via {module_path}."
                    ),
                    evidence=evidence,
                )

        if "access granted" in output_str.lower() or "connected" in output_str.lower():
            return ValidationOutcome(
                is_valid=True,
                category=FindingCategory.REMOTE_ADMIN,
                title=f"Remote Administration Access ({service_id})",
                description=f"Remote administration access established on {service_id} on {target}.",
                evidence=output_str[:300].strip(),
            )

        return ValidationOutcome(
            is_valid=False,
            category=FindingCategory.REMOTE_ADMIN,
            error_type="validation_failed",
            description="Remote administration access could not be confirmed.",
        )
