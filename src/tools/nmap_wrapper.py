"""Nmap tool wrapper for PrivacyAware-PenAgent.

Provides structured Nmap scanning with XML output parsing,
target validation against allowed IP ranges, and multiple
scan type presets.

Owner: Vedant (Member C)
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Allowed target ranges for ethical scanning
ALLOWED_TARGET_RANGES = [
    "10.10.0.0/16",
    "10.129.0.0/16",
    "192.168.56.0/24",
    "172.17.0.0/16",
    "127.0.0.1/32",
]

# Scan type presets
SCAN_PRESETS: dict[str, str] = {
    "default": "-sV -sC",
    "full": "-sV -sC -O -p-",
    "quick": "-sV --top-ports 100",
    "stealth": "-sS -sV",
}


class NmapScanError(Exception):
    """Raised when an Nmap scan fails or target is invalid."""


@dataclass
class ServiceInfo:
    """Discovered network service from Nmap scan."""

    port: int
    protocol: str
    service: str
    version: str
    state: str
    product: str = ""
    extra_info: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for graph node attributes."""
        return asdict(self)


@dataclass
class HostInfo:
    """Discovered host information from Nmap scan."""

    ip: str
    hostname: str
    os_guess: str
    status: str


@dataclass
class NmapScanResult:
    """Complete result of an Nmap scan."""

    hosts: list[HostInfo]
    services: list[ServiceInfo]
    os_guess: str | None
    scan_duration_seconds: float
    raw_xml_path: str | None
    scan_command: str


class NmapWrapper:
    """Wrapper around python-nmap for structured scanning.

    Enforces target validation against allowed IP ranges
    before executing any scan.

    Args:
        timeout: Maximum scan duration in seconds.
    """

    def __init__(self, timeout: int = 600) -> None:
        """Initialize NmapWrapper.

        Args:
            timeout: Scan timeout in seconds.
        """
        self._timeout = timeout
        self._logger = logging.getLogger(f"{__name__}.NmapWrapper")

    def validate_target(self, target: str) -> bool:
        """Check if target IP is in allowed ranges.

        Args:
            target: IP address to validate.

        Returns:
            True if target is in allowed ranges.
        """
        try:
            addr = ip_address(target)
            return any(addr in ip_network(net) for net in ALLOWED_TARGET_RANGES)
        except ValueError:
            self._logger.warning("Invalid IP address format: %s", target)
            return False

    def scan(
        self,
        target: str,
        scan_type: str = "default",
        ports: str | None = None,
    ) -> NmapScanResult:
        """Run Nmap scan against target.

        Args:
            target: Target IP address.
            scan_type: One of 'default', 'full', 'quick', 'stealth'.
            ports: Optional port specification (e.g., '22,80,443').

        Returns:
            Structured scan results.

        Raises:
            NmapScanError: If target is blocked or scan fails.
        """
        if not self.validate_target(target):
            msg = f"Target {target} not in allowed ranges"
            self._logger.critical("Security boundary violation: %s", msg)
            raise NmapScanError(msg)

        if scan_type not in SCAN_PRESETS:
            raise NmapScanError(
                f"Unknown scan type: {scan_type}. "
                f"Valid: {list(SCAN_PRESETS.keys())}"
            )

        try:
            import nmap
        except ImportError as exc:
            raise NmapScanError(
                "python-nmap not installed. " "Run: pip install python-nmap"
            ) from exc

        scanner = nmap.PortScanner()
        arguments = SCAN_PRESETS[scan_type]

        if ports:
            arguments = f"{arguments} -p {ports}"

        self._logger.info(
            "Starting Nmap scan",
            extra={
                "target": target,
                "scan_type": scan_type,
                "arguments": arguments,
            },
        )

        start_time = time.time()

        try:
            scanner.scan(
                hosts=target,
                arguments=arguments,
                timeout=self._timeout,
            )
        except nmap.PortScannerError as exc:
            raise NmapScanError(f"Nmap scan failed: {exc}") from exc
        except Exception as exc:
            raise NmapScanError(f"Unexpected scan error: {exc}") from exc

        duration = time.time() - start_time

        hosts: list[HostInfo] = []
        services: list[ServiceInfo] = []
        os_guess: str | None = None

        for host_ip in scanner.all_hosts():
            host_data = scanner[host_ip]
            host_info, host_services = self._parse_host(host_ip, host_data)
            hosts.append(host_info)
            services.extend(host_services)

            if host_info.os_guess and not os_guess:
                os_guess = host_info.os_guess

        scan_command = scanner.command_line()

        self._logger.info(
            "Scan complete",
            extra={
                "target": target,
                "hosts_found": len(hosts),
                "services_found": len(services),
                "duration_seconds": round(duration, 2),
            },
        )

        return NmapScanResult(
            hosts=hosts,
            services=services,
            os_guess=os_guess,
            scan_duration_seconds=round(duration, 2),
            raw_xml_path=None,
            scan_command=scan_command,
        )

    def parse_xml(self, xml_path: str) -> NmapScanResult:
        """Parse Nmap XML output file.

        Args:
            xml_path: Path to Nmap XML output file.

        Returns:
            Structured scan results.

        Raises:
            NmapScanError: If file not found or parse fails.
        """
        path = Path(xml_path)
        if not path.exists():
            raise NmapScanError(f"XML file not found: {xml_path}")

        try:
            import nmap
        except ImportError as exc:
            raise NmapScanError("python-nmap not installed") from exc

        try:
            scanner = nmap.PortScanner()
            with open(xml_path, "r", encoding="utf-8") as f:
                xml_content = f.read()
            scanner.analyse_nmap_xml_scan(xml_content)
        except Exception as exc:
            raise NmapScanError(f"Failed to parse XML: {exc}") from exc

        hosts: list[HostInfo] = []
        services: list[ServiceInfo] = []
        os_guess: str | None = None

        for host_ip in scanner.all_hosts():
            host_data = scanner[host_ip]
            host_info, host_services = self._parse_host(host_ip, host_data)
            hosts.append(host_info)
            services.extend(host_services)

            if host_info.os_guess and not os_guess:
                os_guess = host_info.os_guess

        self._logger.info(
            "Parsed XML file",
            extra={
                "xml_path": xml_path,
                "hosts_found": len(hosts),
                "services_found": len(services),
            },
        )

        return NmapScanResult(
            hosts=hosts,
            services=services,
            os_guess=os_guess,
            scan_duration_seconds=0.0,
            raw_xml_path=xml_path,
            scan_command="",
        )

    def _parse_host(
        self, host_ip: str, host_data: dict[str, Any]
    ) -> tuple[HostInfo, list[ServiceInfo]]:
        """Parse host data from nmap scanner output.

        Args:
            host_ip: IP address of the host.
            host_data: Raw host data from python-nmap.

        Returns:
            Tuple of HostInfo and list of ServiceInfo.
        """
        hostname = ""
        if "hostnames" in host_data:
            hostnames = host_data["hostnames"]
            if hostnames and isinstance(hostnames, list):
                hostname = hostnames[0].get("name", "")

        os_guess = ""
        if "osmatch" in host_data:
            os_matches = host_data["osmatch"]
            if os_matches and isinstance(os_matches, list):
                os_guess = os_matches[0].get("name", "")

        status = host_data.get("status", {}).get("state", "unknown")

        host_info = HostInfo(
            ip=host_ip,
            hostname=hostname,
            os_guess=os_guess,
            status=status,
        )

        services: list[ServiceInfo] = []
        for proto in ["tcp", "udp"]:
            if proto not in host_data:
                continue
            for port_num, port_data in host_data[proto].items():
                if port_data.get("state") != "open":
                    continue
                service = ServiceInfo(
                    port=int(port_num),
                    protocol=proto,
                    service=port_data.get("name", "unknown"),
                    version=port_data.get("version", ""),
                    state=port_data.get("state", "unknown"),
                    product=port_data.get("product", ""),
                    extra_info=port_data.get("extrainfo", ""),
                )
                services.append(service)

        return host_info, services
