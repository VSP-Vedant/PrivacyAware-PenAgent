"""Pluggable Validator Registry for PrivacyAware-PenAgent.

Dispatches exploit and module outcomes to the appropriate capability validator
and allows registering custom validators for new target environments without
modifying core engine code.
"""

from __future__ import annotations

import logging
from typing import Any

from src.validators.auth_validator import AuthValidator
from src.validators.base import BaseValidator, ValidationOutcome
from src.validators.database_validator import DatabaseValidator
from src.validators.file_sharing_validator import FileSharingValidator
from src.validators.info_disclosure_validator import InfoDisclosureValidator
from src.validators.rce_validator import RCEValidator
from src.validators.remote_admin_validator import RemoteAdminValidator
from src.validators.web_app_validator import WebAppValidator

logger = logging.getLogger(__name__)


class ValidatorRegistry:
    """Registry managing pluggable capability validators."""

    def __init__(self, register_defaults: bool = True) -> None:
        """Initialize the registry with optional default validators."""
        self._validators: list[tuple[BaseValidator, int]] = []
        if register_defaults:
            self._register_default_validators()

    def _register_default_validators(self) -> None:
        """Register the standard built-in validators ordered by priority."""
        # Specific capability validators first (higher priority number = checked earlier)
        self.register_validator(AuthValidator(), priority=90)
        self.register_validator(DatabaseValidator(), priority=80)
        self.register_validator(FileSharingValidator(), priority=80)
        self.register_validator(RemoteAdminValidator(), priority=80)
        self.register_validator(WebAppValidator(), priority=70)
        self.register_validator(InfoDisclosureValidator(), priority=60)
        # General RCE validator as fallback for exploits
        self.register_validator(RCEValidator(), priority=50)

    def register_validator(self, validator: BaseValidator, priority: int = 100) -> None:
        """Register a new validator into the registry.

        Args:
            validator: The BaseValidator instance to add.
            priority: Evaluation priority (higher numbers evaluated first).
        """
        self._validators.append((validator, priority))
        # Sort descending by priority
        self._validators.sort(key=lambda item: item[1], reverse=True)
        logger.debug(
            "Registered validator '%s' (priority %d, category: %s)",
            validator.name,
            priority,
            validator.category.value,
        )

    def get_validator(
        self,
        module_path: str,
        context: dict[str, Any] | None = None,
    ) -> BaseValidator:
        """Find the highest-priority validator capable of handling the module.

        Args:
            module_path: Metasploit module path or tool identifier.
            context: Optional dictionary with service, port, or target metadata.

        Returns:
            The matching BaseValidator, or RCEValidator as fallback.
        """
        for val, _ in self._validators:
            try:
                if val.can_validate(module_path, context):
                    return val
            except Exception as exc:
                logger.debug("Validator %s can_validate failed: %s", val.name, exc)

        # Fallback to RCEValidator
        return RCEValidator()

    def validate(
        self,
        target: str,
        service_id: str,
        module_path: str,
        raw_output: str | dict[str, Any],
        msf_client: Any | None = None,
        context: dict[str, Any] | None = None,
    ) -> ValidationOutcome:
        """Find the appropriate validator and execute validation.

        Args:
            target: Target host IP or hostname.
            service_id: Graph node ID of the targeted service.
            module_path: Module or action that was executed.
            raw_output: Raw output string or dictionary returned by the tool.
            msf_client: Optional MetasploitRPCClient instance for live checks.
            context: Additional context (e.g. session snapshot, options used).

        Returns:
            A populated ValidationOutcome.
        """
        validator = self.get_validator(module_path, context)
        logger.debug(
            "Validating %s against %s using validator '%s'",
            module_path,
            service_id,
            validator.name,
        )
        return validator.validate(
            target=target,
            service_id=service_id,
            module_path=module_path,
            raw_output=raw_output,
            msf_client=msf_client,
            context=context,
        )


# Global default registry instance
default_registry = ValidatorRegistry()
