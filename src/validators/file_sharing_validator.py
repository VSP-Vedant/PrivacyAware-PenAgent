"""File Sharing & Storage Service Validator.

Validates:
1. Unauthorized file access / anonymous access to SMB, NFS, or FTP shares.
2. Successful enumeration of shares, export lists, or directory contents.
3. Arbitrary file read / write vulnerabilities across file sharing protocols.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from src.state.schemas import FindingCategory
from src.validators.base import BaseValidator, ValidationOutcome

logger = logging.getLogger(__name__)

# Patterns matching file sharing and storage access evidence
_FILE_SHARING_PATTERNS = [
    re.compile(r"READ\s+access|WRITE\s+access|READ/WRITE", re.IGNORECASE),
    re.compile(r"Anonymous\s+read\s+allowed|Anonymous\s+login\s+successful", re.IGNORECASE),
    re.compile(r"NFS\s+Export:\s*([^\n\r]+)", re.IGNORECASE),
    re.compile(r"Share:\s*\\\\([^\n\r]+)", re.IGNORECASE),
    re.compile(r"\[\+\]\s+([A-Za-z0-9_\-\$\.]+)\s+-\s+\((DISK|IPC|PRINT)\)", re.IGNORECASE),
    re.compile(r"230\s+Anonymous\s+access\s+granted", re.IGNORECASE),
    re.compile(r"directory\s+listing:\s*([^\n\r]+)", re.IGNORECASE),
]


class FileSharingValidator(BaseValidator):
    """Validator for File Sharing and Storage vulnerabilities (SMB, NFS, FTP, WebDAV)."""

    name: str = "file_sharing_validator"
    category: FindingCategory = FindingCategory.FILE_SHARING

    def can_validate(
        self,
        module_path: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Handle SMB, NFS, FTP anonymous, and storage sharing modules."""
        lowered = module_path.lower()
        if any(
            k in lowered
            for k in (
                "smb",
                "samba",
                "nfs",
                "share",
                "enumshares",
                "anonymous",
                "ftp_anonymous",
                "nfsmount",
                "webdav",
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
        """Validate unauthorized file sharing access or share enumeration."""
        output_str = str(raw_output)

        for pattern in _FILE_SHARING_PATTERNS:
            match = pattern.search(output_str)
            if match:
                evidence = match.group(0).strip()
                return ValidationOutcome(
                    is_valid=True,
                    category=FindingCategory.FILE_SHARING,
                    title=f"Unauthorized File Share Access / Share Enumeration ({service_id})",
                    description=(
                        f"Demonstrated unauthorized access or directory/share enumeration on {target} "
                        f"({service_id}) using {module_path}."
                    ),
                    evidence=evidence,
                )

        if "anonymous" in output_str.lower() and ("access" in output_str.lower() or "granted" in output_str.lower()):
            return ValidationOutcome(
                is_valid=True,
                category=FindingCategory.FILE_SHARING,
                title=f"Anonymous File Sharing Access ({service_id})",
                description=f"Anonymous access granted on {service_id} on {target}.",
                evidence=output_str[:300].strip(),
            )

        return ValidationOutcome(
            is_valid=False,
            category=FindingCategory.FILE_SHARING,
            error_type="validation_failed",
            description="No unauthorized file access or share enumeration was established.",
        )
