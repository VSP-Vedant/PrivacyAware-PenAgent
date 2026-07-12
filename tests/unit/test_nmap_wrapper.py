"""Unit tests for Nmap wrapper module."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.tools.nmap_wrapper import (
    HostInfo,
    NmapScanError,
    NmapScanResult,
    NmapWrapper,
    ServiceInfo,
)


class TestServiceInfo:
    """Tests for ServiceInfo dataclass."""

    def test_service_info_creation(self) -> None:
        """Test basic ServiceInfo instantiation."""
        service = ServiceInfo(
            port=22,
            protocol="tcp",
            service="ssh",
            version="8.9p1",
            state="open",
            product="OpenSSH",
            extra_info="Ubuntu Linux",
        )
        assert service.port == 22
        assert service.protocol == "tcp"
        assert service.service == "ssh"
        assert service.version == "8.9p1"
        assert service.state == "open"
        assert service.product == "OpenSSH"

    def test_service_info_defaults(self) -> None:
        """Test ServiceInfo with default optional fields."""
        service = ServiceInfo(
            port=80,
            protocol="tcp",
            service="http",
            version="2.4.52",
            state="open",
        )
        assert service.product == ""
        assert service.extra_info == ""

    def test_service_info_to_dict(self) -> None:
        """Test ServiceInfo serialization to dictionary."""
        service = ServiceInfo(
            port=443,
            protocol="tcp",
            service="https",
            version="1.18.0",
            state="open",
        )
        result = service.to_dict()
        assert isinstance(result, dict)
        assert result["port"] == 443
        assert result["service"] == "https"


class TestHostInfo:
    """Tests for HostInfo dataclass."""

    def test_host_info_creation(self) -> None:
        """Test basic HostInfo instantiation."""
        host = HostInfo(
            ip="10.10.10.5",
            hostname="htb-target.htb",
            os_guess="Linux 5.4",
            status="up",
        )
        assert host.ip == "10.10.10.5"
        assert host.hostname == "htb-target.htb"
        assert host.os_guess == "Linux 5.4"
        assert host.status == "up"


class TestNmapWrapper:
    """Tests for NmapWrapper class."""

    def test_validate_target_allowed_htb(self) -> None:
        """Test target validation passes for HTB range."""
        wrapper = NmapWrapper()
        assert wrapper.validate_target("10.10.10.5") is True

    def test_validate_target_allowed_htb_alt(self) -> None:
        """Test target validation passes for HTB alt range."""
        wrapper = NmapWrapper()
        assert wrapper.validate_target("10.129.1.50") is True

    def test_validate_target_allowed_localhost(self) -> None:
        """Test target validation passes for localhost."""
        wrapper = NmapWrapper()
        assert wrapper.validate_target("127.0.0.1") is True

    def test_validate_target_allowed_docker(self) -> None:
        """Test target validation passes for Docker range."""
        wrapper = NmapWrapper()
        assert wrapper.validate_target("172.17.0.2") is True

    def test_validate_target_allowed_virtualbox(self) -> None:
        """Test target validation passes for VirtualBox range."""
        wrapper = NmapWrapper()
        assert wrapper.validate_target("192.168.56.10") is True

    def test_validate_target_blocked(self) -> None:
        """Test target validation rejects external IPs."""
        wrapper = NmapWrapper()
        assert wrapper.validate_target("8.8.8.8") is False

    def test_validate_target_blocked_public(self) -> None:
        """Test target validation rejects public IPs."""
        wrapper = NmapWrapper()
        assert wrapper.validate_target("1.1.1.1") is False

    def test_validate_target_invalid_format(self) -> None:
        """Test target validation handles invalid IP format."""
        wrapper = NmapWrapper()
        assert wrapper.validate_target("not-an-ip") is False

    def test_scan_blocked_target_raises(self) -> None:
        """Test scan raises NmapScanError for blocked target."""
        wrapper = NmapWrapper()
        with pytest.raises(NmapScanError, match="not in allowed"):
            wrapper.scan("8.8.8.8")

    def test_scan_invalid_scan_type(self) -> None:
        """Test scan raises error for unknown scan type."""
        wrapper = NmapWrapper()
        with pytest.raises(NmapScanError, match="Unknown scan type"):
            wrapper.scan("10.10.10.5", scan_type="invalid")

    def test_parse_xml_file_not_found(self) -> None:
        """Test parse_xml raises error for missing file."""
        wrapper = NmapWrapper()
        with pytest.raises(NmapScanError, match="not found"):
            wrapper.parse_xml("/nonexistent/path.xml")

    def test_nmap_scan_result_creation(self) -> None:
        """Test NmapScanResult instantiation."""
        result = NmapScanResult(
            hosts=[],
            services=[],
            os_guess=None,
            scan_duration_seconds=0.0,
            raw_xml_path=None,
            scan_command="nmap -sV 10.10.10.5",
        )
        assert result.hosts == []
        assert result.services == []
        assert result.os_guess is None
        assert result.scan_command == "nmap -sV 10.10.10.5"
