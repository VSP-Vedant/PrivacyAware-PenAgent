"""Web Application Vulnerability Validator.

Validates:
1. Local File Inclusion (LFI) / Arbitrary File Read.
2. SQL Injection / Data extraction.
3. Web Administrative Console / Panel bypass.
4. Exposed endpoints (Spring actuator, .git, WebDAV, phpMyAdmin).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from src.state.schemas import FindingCategory
from src.validators.base import BaseValidator, ValidationOutcome

logger = logging.getLogger(__name__)

# Patterns matching web application exploit outcomes
_WEB_APP_PATTERNS = [
    re.compile(r"root:x:0:0:root:[^:]+:[^\n]+", re.IGNORECASE),  # /etc/passwd in web response
    re.compile(r"<\?php\b", re.IGNORECASE),  # Source code disclosure
    re.compile(r"HTTP/\d\.\d\s+200\s+OK.*(?:admin|dashboard|management)", re.IGNORECASE),
    re.compile(r"LFI\s+verified|file\s+read\s+successful", re.IGNORECASE),
    re.compile(r"SQL\s+injection\s+confirmed|UNION\s+SELECT", re.IGNORECASE),
    re.compile(r"Discovered\s+critical\s+endpoint:\s*([^\n\r]+)", re.IGNORECASE),
    re.compile(r"uploaded\s+file\s+accessible\s+at:\s*([^\n\r]+)", re.IGNORECASE),
]


class WebAppValidator(BaseValidator):
    """Validator for Web Application vulnerabilities."""

    name: str = "web_app_validator"
    category: FindingCategory = FindingCategory.WEB_APPLICATION

    def can_validate(
        self,
        module_path: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Handle web application modules, HTTP exploits, and web scanners."""
        lowered = module_path.lower()
        if any(
            k in lowered
            for k in (
                "http",
                "webapp",
                "lfi",
                "rfi",
                "phpmyadmin",
                "tomcat",
                "wordpress",
                "drupal",
                "joomla",
                "jenkins",
                "gitlab",
                "web_scanner",
                "gobuster",
                "sql_injection",
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
        """Validate web application vulnerability evidence."""
        output_str = str(raw_output)

        for pattern in _WEB_APP_PATTERNS:
            match = pattern.search(output_str)
            if match:
                evidence = match.group(0).strip()
                return ValidationOutcome(
                    is_valid=True,
                    category=FindingCategory.WEB_APPLICATION,
                    title=f"Web Application Vulnerability Verified ({service_id})",
                    description=(
                        f"Web application vulnerability successfully verified on {target} "
                        f"({service_id}) via {module_path}."
                    ),
                    evidence=evidence,
                )

        if "vulnerability verified" in output_str.lower() or "file read" in output_str.lower():
            return ValidationOutcome(
                is_valid=True,
                category=FindingCategory.WEB_APPLICATION,
                title=f"Web Application Finding ({service_id})",
                description=f"Web vulnerability verified on {service_id} on {target}.",
                evidence=output_str[:300].strip(),
            )

        return ValidationOutcome(
            is_valid=False,
            category=FindingCategory.WEB_APPLICATION,
            error_type="validation_failed",
            description="Web application module did not verify vulnerability presence.",
        )
