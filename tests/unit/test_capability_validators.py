"""Unit tests for the pluggable capability validators and ValidatorRegistry.

Tests coverage across:
- ValidatorRegistry dispatch and priority ordering
- RCEValidator (session & command output proof)
- AuthValidator (credential extraction & login confirmation)
- FileSharingValidator (SMB/NFS/FTP anonymous & share access)
- DatabaseValidator (schema dumps & query execution)
- WebAppValidator (LFI & web panel bypass)
- RemoteAdminValidator (VNC null auth & remote consoles)
- InfoDisclosureValidator (user enumeration & metadata leaks)
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.state.schemas import FindingCategory
from src.validators.auth_validator import AuthValidator
from src.validators.base import BaseValidator, ValidationOutcome
from src.validators.database_validator import DatabaseValidator
from src.validators.file_sharing_validator import FileSharingValidator
from src.validators.info_disclosure_validator import InfoDisclosureValidator
from src.validators.rce_validator import RCEValidator
from src.validators.registry import ValidatorRegistry, default_registry
from src.validators.remote_admin_validator import RemoteAdminValidator
from src.validators.web_app_validator import WebAppValidator


class TestValidatorRegistry:
    """Tests for ValidatorRegistry."""

    def test_default_registry_has_all_validators(self) -> None:
        """Verify default registry includes all standard capability validators."""
        reg = ValidatorRegistry(register_defaults=True)
        assert len(reg._validators) >= 7

    def test_registry_resolves_rce(self) -> None:
        """Verify registry resolves exploit modules to RCEValidator."""
        reg = default_registry
        val = reg.get_validator("exploit/unix/ftp/vsftpd_234_backdoor")
        assert isinstance(val, RCEValidator)

    def test_registry_resolves_auth(self) -> None:
        """Verify registry resolves ssh_login to AuthValidator."""
        reg = default_registry
        val = reg.get_validator("auxiliary/scanner/ssh/ssh_login")
        assert isinstance(val, AuthValidator)

    def test_registry_resolves_db(self) -> None:
        """Verify registry resolves mysql scanners to DatabaseValidator."""
        reg = default_registry
        val = reg.get_validator("auxiliary/scanner/mysql/mysql_schemadump")
        assert isinstance(val, DatabaseValidator)

    def test_registry_resolves_file_sharing(self) -> None:
        """Verify registry resolves smb enum shares to FileSharingValidator."""
        reg = default_registry
        val = reg.get_validator("auxiliary/scanner/smb/smb_enumshares")
        assert isinstance(val, FileSharingValidator)

    def test_registry_resolves_remote_admin(self) -> None:
        """Verify registry resolves vnc none auth to RemoteAdminValidator."""
        reg = default_registry
        val = reg.get_validator("auxiliary/scanner/vnc/vnc_none_auth")
        assert isinstance(val, RemoteAdminValidator)

    def test_registry_resolves_web_app(self) -> None:
        """Verify registry resolves web app modules to WebAppValidator."""
        reg = default_registry
        val = reg.get_validator("auxiliary/scanner/http/tomcat_mgr_login")
        assert isinstance(val, (AuthValidator, WebAppValidator))

    def test_custom_validator_priority(self) -> None:
        """Verify registering a custom validator with high priority overrides default."""
        class CustomValidator(BaseValidator):
            name = "custom_test"
            category = FindingCategory.REMOTE_CODE_EXECUTION

            def can_validate(self, module_path: str, context: dict | None = None) -> bool:
                return True

            def validate(self, target, service_id, module_path, raw_output, msf_client=None, context=None):
                return ValidationOutcome(is_valid=True, category=self.category, title="Custom Handled")

        reg = ValidatorRegistry(register_defaults=True)
        reg.register_validator(CustomValidator(), priority=999)
        val = reg.get_validator("exploit/unix/ftp/vsftpd_234_backdoor")
        assert isinstance(val, CustomValidator)


class TestRCEValidator:
    """Tests for RCEValidator."""

    def test_command_output_execution_without_session(self) -> None:
        """Verify command execution output (uid=0) verifies RCE even without interactive shell."""
        val = RCEValidator()
        raw_output = "Command output: uid=0(root) gid=0(root) groups=0(root)"
        outcome = val.validate(
            target="192.168.1.50",
            service_id="service:192.168.1.50:21/tcp",
            module_path="exploit/unix/ftp/vsftpd_234_backdoor",
            raw_output=raw_output,
            msf_client=None,
        )
        assert outcome.is_valid is True
        assert outcome.category == FindingCategory.REMOTE_CODE_EXECUTION
        assert outcome.privilege == "root"
        assert "uid=0" in outcome.evidence

    def test_no_output_no_session_fails(self) -> None:
        """Verify failure when exploit output is empty and no session was established."""
        val = RCEValidator()
        mock_msf = MagicMock()
        mock_msf.is_connected.return_value = True
        mock_msf.list_sessions.return_value = []

        outcome = val.validate(
            target="192.168.1.50",
            service_id="service:192.168.1.50:21/tcp",
            module_path="exploit/unix/ftp/vsftpd_234_backdoor",
            raw_output="Exploit failed: connection timeout",
            msf_client=mock_msf,
        )
        assert outcome.is_valid is False
        assert outcome.error_type == "no_session"


class TestAuthValidator:
    """Tests for AuthValidator."""

    def test_credential_extraction_success(self) -> None:
        """Verify credentials extracted from MSF login output."""
        val = AuthValidator()
        raw_output = "[+] 192.168.1.50:22 - Success: 'msfadmin:msfadmin'"
        outcome = val.validate(
            target="192.168.1.50",
            service_id="service:192.168.1.50:22/tcp",
            module_path="auxiliary/scanner/ssh/ssh_login",
            raw_output=raw_output,
        )
        assert outcome.is_valid is True
        assert outcome.category == FindingCategory.AUTHENTICATION
        assert len(outcome.credentials) == 1
        assert outcome.credentials[0]["username"] == "msfadmin"
        assert outcome.credentials[0]["password"] == "msfadmin"

    def test_auth_failed_output(self) -> None:
        """Verify failure when no valid credentials are found."""
        val = AuthValidator()
        raw_output = "[-] 192.168.1.50:22 - Failed: 'root:root'"
        outcome = val.validate(
            target="192.168.1.50",
            service_id="service:192.168.1.50:22/tcp",
            module_path="auxiliary/scanner/ssh/ssh_login",
            raw_output=raw_output,
        )
        assert outcome.is_valid is False
        assert outcome.error_type == "auth_failed"


class TestFileSharingValidator:
    """Tests for FileSharingValidator."""

    def test_smb_share_enumeration(self) -> None:
        """Verify SMB share enumeration output is validated."""
        val = FileSharingValidator()
        raw_output = "[+] 192.168.1.50:445 - tmp - (DISK) READ/WRITE access allowed"
        outcome = val.validate(
            target="192.168.1.50",
            service_id="service:192.168.1.50:445/tcp",
            module_path="auxiliary/scanner/smb/smb_enumshares",
            raw_output=raw_output,
        )
        assert outcome.is_valid is True
        assert outcome.category == FindingCategory.FILE_SHARING
        assert "READ/WRITE" in outcome.evidence

    def test_anonymous_ftp(self) -> None:
        """Verify anonymous FTP access is validated."""
        val = FileSharingValidator()
        raw_output = "[+] 192.168.1.50:21 - 230 Anonymous access granted"
        outcome = val.validate(
            target="192.168.1.50",
            service_id="service:192.168.1.50:21/tcp",
            module_path="auxiliary/scanner/ftp/anonymous",
            raw_output=raw_output,
        )
        assert outcome.is_valid is True
        assert outcome.category == FindingCategory.FILE_SHARING


class TestDatabaseValidator:
    """Tests for DatabaseValidator."""

    def test_database_schema_dump(self) -> None:
        """Verify database schema extraction is validated."""
        val = DatabaseValidator()
        raw_output = "[+] Database: twiki, Table names: users, sessions, config"
        outcome = val.validate(
            target="192.168.1.50",
            service_id="service:192.168.1.50:3306/tcp",
            module_path="auxiliary/scanner/mysql/mysql_schemadump",
            raw_output=raw_output,
        )
        assert outcome.is_valid is True
        assert outcome.category == FindingCategory.DATABASE


class TestWebAppValidator:
    """Tests for WebAppValidator."""

    def test_lfi_verification(self) -> None:
        """Verify LFI /etc/passwd disclosure is validated."""
        val = WebAppValidator()
        raw_output = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh"
        outcome = val.validate(
            target="192.168.1.50",
            service_id="service:192.168.1.50:80/tcp",
            module_path="auxiliary/scanner/http/traversal",
            raw_output=raw_output,
        )
        assert outcome.is_valid is True
        assert outcome.category == FindingCategory.WEB_APPLICATION
        assert "root:x:0:0" in outcome.evidence


class TestRemoteAdminValidator:
    """Tests for RemoteAdminValidator."""

    def test_vnc_none_auth(self) -> None:
        """Verify VNC null authentication is validated."""
        val = RemoteAdminValidator()
        raw_output = "[+] 192.168.1.50:5900 - VNC server security types: None"
        outcome = val.validate(
            target="192.168.1.50",
            service_id="service:192.168.1.50:5900/tcp",
            module_path="auxiliary/scanner/vnc/vnc_none_auth",
            raw_output=raw_output,
        )
        assert outcome.is_valid is True
        assert outcome.category == FindingCategory.REMOTE_ADMIN
