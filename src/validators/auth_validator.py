"""Authentication & Credential Discovery Validator.

Validates:
1. Valid credentials discovered through authentication scanning / brute-forcing.
2. Successful authentication / login verified.
3. Authentication bypass vulnerabilities.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from src.state.schemas import FindingCategory
from src.validators.base import BaseValidator, ValidationOutcome

logger = logging.getLogger(__name__)

# Patterns matching credential discoveries across MSF and custom tools
_CRED_PATTERNS = [
    re.compile(r"Success:\s*['\"]([^'\":]+):([^'\"]*)['\"]", re.IGNORECASE),
    re.compile(r"Login\s+Successful:\s*['\"]?([^'\"\s:]+)[:\s]+([^'\"\s]+)['\"]?", re.IGNORECASE),
    re.compile(r"\[\+\]\s+[\d\.\:]+\s*-\s*Success:\s*['\"]([^'\":]+):([^'\"]*)['\"]", re.IGNORECASE),
    re.compile(r"Valid\s+credentials\s+found:\s*(\w+)[\s\:\/]+([^\s]+)", re.IGNORECASE),
    re.compile(r"credentials?\s+found:\s*(\w+)\s*[:\/]\s*([^\s]+)", re.IGNORECASE),
    re.compile(r"authentication\s+bypass\s+successful", re.IGNORECASE),
    re.compile(r"authenticated\s+as\s+([^\s]+)", re.IGNORECASE),
]


class AuthValidator(BaseValidator):
    """Validator for Authentication and Credential findings."""

    name: str = "auth_validator"
    category: FindingCategory = FindingCategory.AUTHENTICATION

    def can_validate(
        self,
        module_path: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Handle authentication scanners and auth bypass modules."""
        lowered = module_path.lower()
        if "none_auth" in lowered or "no_auth" in lowered or "null_auth" in lowered:
            return False
        if any(
            k in lowered
            for k in (
                "login",
                "auth",
                "brute",
                "credential",
                "password",
                "user_enum",
                "default_accounts",
                "auth_bypass",
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
        """Validate discovered credentials or successful authentication."""
        output_str = str(raw_output)
        ctx = context or {}
        credentials: list[dict[str, str]] = []
        seen_creds: set[tuple[str, str]] = set()

        # Extract credentials using regex patterns
        for pattern in _CRED_PATTERNS:
            for match in pattern.finditer(output_str):
                groups = match.groups()
                if len(groups) >= 2:
                    username, password = groups[0].strip(), groups[1].strip()
                    if (username, password) not in seen_creds:
                        seen_creds.add((username, password))
                        credentials.append(
                            {
                                "username": username,
                                "password": password,
                                "service": service_id,
                                "target": target,
                            }
                        )
                elif len(groups) == 1:
                    username = groups[0].strip()
                    if (username, "<bypass>") not in seen_creds:
                        seen_creds.add((username, "<bypass>"))
                        credentials.append(
                            {
                                "username": username,
                                "password": "<bypass/unknown>",
                                "service": service_id,
                                "target": target,
                            }
                        )

        # Check if session was obtained through auth (e.g. ssh_login)
        session_id = ctx.get("session_id")
        if session_id:
            try:
                session_id = int(session_id)
            except (ValueError, TypeError):
                session_id = None

        if credentials or session_id is not None or "auth bypass" in output_str.lower() or "login found" in output_str.lower():
            cred_str = ", ".join(f"{c['username']}:{c['password']}" for c in credentials) if credentials else "Credentials verified"
            evidence = f"Valid authentication verified on {target} ({service_id}) via {module_path}. Credentials: {cred_str}"
            if session_id:
                evidence += f" (Spawned session #{session_id})"

            return ValidationOutcome(
                is_valid=True,
                category=FindingCategory.AUTHENTICATION,
                title=f"Authentication Success / Valid Credentials Discovered ({service_id})",
                description=(
                    f"Discovered valid credentials or confirmed successful authentication against "
                    f"{service_id} on {target} using {module_path}."
                ),
                evidence=evidence,
                credentials=credentials,
                session_id=session_id,
                privilege="user" if not any(c.get("username") in ("root", "admin", "administrator") for c in credentials) else "root",
            )

        return ValidationOutcome(
            is_valid=False,
            category=FindingCategory.AUTHENTICATION,
            error_type="auth_failed",
            description="Authentication or credential discovery attempt yielded no valid credentials.",
        )
