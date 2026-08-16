"""Web Application Scanner Wrapper for PrivacyAware-PenAgent.

Performs high-signal, lightweight web application reconnaissance and
vulnerability probing on discovered HTTP/HTTPS services.

Owner: Vedant (Member C) / Shared Security Foundation
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from src.config.settings import ALLOWED_TARGET_RANGES
from src.state.schemas import CVENode, WebEndpointNode
from src.utils.logging_config import setup_logger
from src.utils.validators import TargetValidationError, validate_target

logger = setup_logger(__name__)

# High-priority security and administrative endpoints to probe
_HIGH_PRIORITY_PROBES: list[dict[str, str]] = [
    {"path": "/admin", "category": "admin_panel"},
    {"path": "/login", "category": "authentication"},
    {"path": "/api", "category": "api_endpoint"},
    {"path": "/actuator/env", "category": "spring_actuator"},
    {"path": "/console", "category": "web_console"},
    {"path": "/.git/HEAD", "category": "exposed_git"},
    {"path": "/robots.txt", "category": "information_disclosure"},
    {"path": "/phpmyadmin", "category": "database_admin"},
    {"path": "/server-status", "category": "server_status"},
]


@dataclass
class WebScanResult:
    """Outcome of a web endpoint scan against a single service.

    Attributes:
        target: Target IP or hostname.
        port: Web service port.
        base_url: Scanned base URL.
        endpoints: List of discovered WebEndpointNode objects.
        cves: List of discovered CVENode objects.
        technologies: Detected web technologies/frameworks.
    """

    target: str
    port: int
    base_url: str
    endpoints: list[WebEndpointNode] = field(default_factory=list)
    cves: list[CVENode] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)


class WebScanner:
    """Lightweight, adaptive web vulnerability and endpoint scanner.

    Gated strictly by ALLOWED_TARGET_RANGES validation.
    """

    def __init__(self, timeout_secs: float = 3.0) -> None:
        """Initialize the WebScanner.

        Args:
            timeout_secs: Per-request HTTP timeout in seconds.
        """
        self._timeout = timeout_secs
        self._session = requests.Session()
        self._session.headers.update(
            {"User-Agent": "Mozilla/5.0 (PenAgent-WebScanner/1.0)"}
        )

    def scan_service(
        self,
        target: str,
        port: int,
        protocol: str = "http",
        vhost: str | None = None,
    ) -> WebScanResult:
        """Scan a web service for endpoints, technologies, and vulnerabilities.

        Args:
            target: Target host IP or domain.
            port: Port number.
            protocol: 'http' or 'https'.
            vhost: Optional virtual host to inject into Host header.

        Returns:
            A :class:`WebScanResult` containing discovered endpoints and CVEs.

        Raises:
            TargetValidationError: If target is outside ALLOWED_TARGET_RANGES.
        """
        # Security validation
        validate_target(target)

        base_url = f"{protocol}://{target}:{port}"
        result = WebScanResult(target=target, port=port, base_url=base_url)

        headers = {}
        if vhost:
            headers["Host"] = vhost

        # 1. Probe base URL for server headers and technology indicators
        try:
            resp = self._session.get(
                base_url,
                headers=headers,
                timeout=self._timeout,
                allow_redirects=True,
                verify=False,
            )
            server_hdr = resp.headers.get("Server", "")
            powered_by = resp.headers.get("X-Powered-By", "")

            if server_hdr:
                result.technologies.append(f"Server: {server_hdr}")
            if powered_by:
                result.technologies.append(f"PoweredBy: {powered_by}")

            # Check for Spring Boot Actuator / Spring4Shell indicators
            if "whitelabel error page" in resp.text.lower():
                result.technologies.append("Spring Boot")

        except requests.RequestException as e:
            logger.debug("Base URL probe failed for %s: %s", base_url, e)

        # 2. Probe high-priority paths
        for probe in _HIGH_PRIORITY_PROBES:
            path = probe["path"]
            url = urljoin(base_url, path)
            try:
                probe_resp = self._session.get(
                    url,
                    headers=headers,
                    timeout=self._timeout,
                    allow_redirects=False,
                    verify=False,
                )
                status = probe_resp.status_code
                if status in (200, 301, 302, 401, 403):
                    endpoint = WebEndpointNode(
                        host_ip=target,
                        port=port,
                        url=path,
                        status_code=status,
                        content_type=probe_resp.headers.get("Content-Type", ""),
                    )
                    result.endpoints.append(endpoint)

                    # Check for exposed git repository
                    if path == "/.git/HEAD" and "ref: refs/" in probe_resp.text:
                        result.cves.append(
                            CVENode(
                                cve_id="MISC-EXPOSED-GIT",
                                cvss_score=7.5,
                                description="Exposed .git repository directory disclosure",
                            )
                        )

            except requests.RequestException:
                continue

        logger.info(
            "Web scan complete for %s:%d — %d endpoints, %d technologies",
            target,
            port,
            len(result.endpoints),
            len(result.technologies),
        )
        return result
