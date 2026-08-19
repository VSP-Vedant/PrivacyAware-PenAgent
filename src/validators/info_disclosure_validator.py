"""Information Disclosure & Enumeration Validator.

Validates:
1. Valid service enumeration returning users, metadata, or configurations.
2. Sensitive file disclosure (e.g. passwd, web config, environment variables).
3. Detailed version or architectural information leakage.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from src.state.schemas import FindingCategory
from src.validators.base import BaseValidator, ValidationOutcome

logger = logging.getLogger(__name__)

# Patterns matching information disclosure evidence
_INFO_DISCLOSURE_PATTERNS = [
    re.compile(r"users?\s+found:\s*([^\n\r]+)", re.IGNORECASE),
    re.compile(r"root:x:0:0:root:[^:]+:[^\n]+", re.IGNORECASE),  # /etc/passwd snippet
    re.compile(r"\[\+\]\s+Found\s+user:\s*(\w+)", re.IGNORECASE),
    re.compile(r"phpinfo\(\)", re.IGNORECASE),
    re.compile(r"DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY", re.IGNORECASE),
    re.compile(r"Server\s+version:\s*([^\n\r]+)", re.IGNORECASE),
    re.compile(r"Enumerated\s+(\d+)\s+users?", re.IGNORECASE),
    re.compile(r"Discovered\s+endpoints?:\s*([^\n\r]+)", re.IGNORECASE),
]


class InfoDisclosureValidator(BaseValidator):
    """Validator for Information Disclosure vulnerabilities."""

    name: str = "info_disclosure_validator"
    category: FindingCategory = FindingCategory.INFORMATION_DISCLOSURE

    def can_validate(
        self,
        module_path: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Handle information disclosure, version grabbers, and user enum modules."""
        lowered = module_path.lower()
        if any(
            k in lowered
            for k in (
                "enum",
                "disclosure",
                "version",
                "banner",
                "fingerprint",
                "snmp",
                "smtp_enum",
                "rpc_dump",
                "rpcbind",
                "directory_listing",
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
        """Validate information disclosure evidence."""
        output_str = str(raw_output)

        for pattern in _INFO_DISCLOSURE_PATTERNS:
            match = pattern.search(output_str)
            if match:
                evidence = match.group(0).strip()
                return ValidationOutcome(
                    is_valid=True,
                    category=FindingCategory.INFORMATION_DISCLOSURE,
                    title=f"Information Disclosure Verified ({service_id})",
                    description=(
                        f"Information disclosure verified against {service_id} on {target} "
                        f"using {module_path}."
                    ),
                    evidence=evidence,
                )

        if "discovered" in output_str.lower() and ("user" in output_str.lower() or "version" in output_str.lower()):
            return ValidationOutcome(
                is_valid=True,
                category=FindingCategory.INFORMATION_DISCLOSURE,
                title=f"Information Enumeration Finding ({service_id})",
                description=f"Service information enumerated on {target} via {module_path}.",
                evidence=output_str[:300].strip(),
            )

        return ValidationOutcome(
            is_valid=False,
            category=FindingCategory.INFORMATION_DISCLOSURE,
            error_type="validation_failed",
            description="Module completed without discovering significant sensitive information.",
        )
