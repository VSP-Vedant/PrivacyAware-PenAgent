"""Database Service Vulnerability & Access Validator.

Validates:
1. Database authentication success (default/blank creds, auth bypass).
2. Database schema enumeration and table extraction.
3. Arbitrary SQL query execution.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from src.state.schemas import FindingCategory
from src.validators.base import BaseValidator, ValidationOutcome

logger = logging.getLogger(__name__)

# Patterns matching database capability evidence
_DB_PATTERNS = [
    re.compile(r"schema\s+dump|table\s+names?|columns?:\s*([^\n\r]+)", re.IGNORECASE),
    re.compile(r"databases?:\s*([^\n\r]+)", re.IGNORECASE),
    re.compile(r"query\s+output|result\s+set:\s*([^\n\r]+)", re.IGNORECASE),
    re.compile(r"MySQL\s+authentication\s+bypass\s+successful", re.IGNORECASE),
    re.compile(r"PostgreSQL\s+authenticated", re.IGNORECASE),
    re.compile(r"SELECT\s+version\(\)\s*->\s*([^\n\r]+)", re.IGNORECASE),
    re.compile(r"\[\+\]\s+Database:\s*(\w+)", re.IGNORECASE),
]


class DatabaseValidator(BaseValidator):
    """Validator for Database vulnerabilities (MySQL, PostgreSQL, MSSQL, Redis, MongoDB)."""

    name: str = "database_validator"
    category: FindingCategory = FindingCategory.DATABASE

    def can_validate(
        self,
        module_path: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Handle database modules and scanners."""
        lowered = module_path.lower()
        if any(
            k in lowered
            for k in (
                "mysql",
                "postgres",
                "mssql",
                "oracle",
                "redis",
                "mongodb",
                "database",
                "sqli",
                "sql_query",
                "schemadump",
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
        """Validate database authentication, schema extraction, or query execution."""
        output_str = str(raw_output)

        for pattern in _DB_PATTERNS:
            match = pattern.search(output_str)
            if match:
                evidence = match.group(0).strip()
                return ValidationOutcome(
                    is_valid=True,
                    category=FindingCategory.DATABASE,
                    title=f"Database Access / Query Execution Verified ({service_id})",
                    description=(
                        f"Demonstrated database access, authentication, or query execution on "
                        f"{service_id} ({target}) via {module_path}."
                    ),
                    evidence=evidence,
                )

        if "database" in output_str.lower() and ("success" in output_str.lower() or "connected" in output_str.lower()):
            return ValidationOutcome(
                is_valid=True,
                category=FindingCategory.DATABASE,
                title=f"Database Service Access ({service_id})",
                description=f"Database service access confirmed on {target} via {module_path}.",
                evidence=output_str[:300].strip(),
            )

        return ValidationOutcome(
            is_valid=False,
            category=FindingCategory.DATABASE,
            error_type="validation_failed",
            description="Database module did not establish query execution or schema extraction.",
        )
