"""Base interfaces and data structures for the pluggable validator architecture.

Defines the BaseValidator abstract class and ValidationOutcome dataclass
used to evaluate whether an exploit or auxiliary module execution demonstrated
a verified security capability.

Owner: Shared Security Foundation
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from src.state.schemas import FindingCategory, PrivilegeLevel

logger = logging.getLogger(__name__)


@dataclass
class ValidationOutcome:
    """Outcome of validating an exploit or security action.

    Attributes:
        is_valid: Whether the security capability / finding was verified.
        category: The capability category (RCE, Auth, Info Disclosure, etc.).
        title: Human-readable title for the verified finding.
        description: Detailed explanation of the verified finding.
        evidence: Concrete proof extracted from output or session state.
        privilege: Privilege level achieved ('none', 'user', 'root').
        session_id: Interactive Metasploit session ID if one was established.
        credentials: List of credential dicts (username, password, service).
        error_type: Failure classification if is_valid is False.
        cve_id: Associated CVE ID if known.
        cvss_score: CVSS severity score if known.
    """

    is_valid: bool = False
    category: FindingCategory = FindingCategory.GENERAL_VULNERABILITY
    title: str = ""
    description: str = ""
    evidence: str = ""
    privilege: str = PrivilegeLevel.NONE.value
    session_id: int | None = None
    credentials: list[dict[str, str]] = field(default_factory=list)
    error_type: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0


class BaseValidator(ABC):
    """Abstract base class for pluggable security capability validators.

    Validators evaluate the output of modules (Metasploit exploits, auxiliary
    scanners, custom probes, or web scanners) to verify whether specific security
    capabilities were demonstrated.
    """

    name: str = "base_validator"
    category: FindingCategory = FindingCategory.GENERAL_VULNERABILITY

    @abstractmethod
    def can_validate(
        self,
        module_path: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Return True if this validator can handle the given module/action.

        Args:
            module_path: Metasploit module path or tool identifier.
            context: Optional dictionary with service, port, or target metadata.
        """
        ...

    @abstractmethod
    def validate(
        self,
        target: str,
        service_id: str,
        module_path: str,
        raw_output: str | dict[str, Any],
        msf_client: Any | None = None,
        context: dict[str, Any] | None = None,
    ) -> ValidationOutcome:
        """Validate execution results and return a structured ValidationOutcome.

        Args:
            target: Target host IP or hostname.
            service_id: Graph node ID of the targeted service.
            module_path: Module or action that was executed.
            raw_output: Raw output string or dictionary returned by the tool.
            msf_client: Optional MetasploitRPCClient instance for live checks.
            context: Additional context (e.g. session snapshot, options used).
        """
        ...
