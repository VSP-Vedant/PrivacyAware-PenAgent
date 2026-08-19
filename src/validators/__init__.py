"""Pluggable Validation Architecture package for PrivacyAware-PenAgent.

Exports:
- ValidatorRegistry, default_registry
- BaseValidator, ValidationOutcome
- Category-specific validators: RCEValidator, AuthValidator, InfoDisclosureValidator,
  FileSharingValidator, DatabaseValidator, WebAppValidator, RemoteAdminValidator
"""

from src.validators.auth_validator import AuthValidator
from src.validators.base import BaseValidator, ValidationOutcome
from src.validators.database_validator import DatabaseValidator
from src.validators.file_sharing_validator import FileSharingValidator
from src.validators.info_disclosure_validator import InfoDisclosureValidator
from src.validators.rce_validator import RCEValidator
from src.validators.registry import ValidatorRegistry, default_registry
from src.validators.remote_admin_validator import RemoteAdminValidator
from src.validators.web_app_validator import WebAppValidator

__all__ = [
    "ValidatorRegistry",
    "default_registry",
    "BaseValidator",
    "ValidationOutcome",
    "RCEValidator",
    "AuthValidator",
    "InfoDisclosureValidator",
    "FileSharingValidator",
    "DatabaseValidator",
    "WebAppValidator",
    "RemoteAdminValidator",
]
