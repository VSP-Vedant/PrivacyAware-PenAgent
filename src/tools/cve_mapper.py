"""CVE Mapper — maps discovered service versions to CVE candidates.

Provides offline CVE lookup via a curated knowledge base of common
service vulnerabilities, with optional SearchSploit fallback for
broader coverage.

Owner: Vedant (Member C)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from src.state.schemas import CVENode
from src.tools.searchsploit import SearchSploitWrapper

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known CVE database — curated high-value mappings
# ---------------------------------------------------------------------------
# Each entry: (service_regex, version_regex) → list of CVENode-like dicts
_KNOWN_CVES: list[dict[str, Any]] = [
    # OpenSSH
    {
        "service_pattern": r"^ssh$",
        "product_pattern": r"OpenSSH",
        "version_pattern": r"^7\.[0-6]",
        "cves": [
            {
                "cve_id": "CVE-2016-10009",
                "cvss_score": 7.3,
                "description": "OpenSSH before 7.4 - agent forwarding arbitrary library load",  # noqa: E501
            },
            {
                "cve_id": "CVE-2016-10010",
                "cvss_score": 6.2,
                "description": "OpenSSH before 7.4 - privilege escalation via forwarded agent socket",  # noqa: E501
            },
        ],
    },
    {
        "service_pattern": r"^ssh$",
        "product_pattern": r"OpenSSH",
        "version_pattern": r"^8\.[0-3]",
        "cves": [
            {
                "cve_id": "CVE-2020-15778",
                "cvss_score": 7.8,
                "description": "OpenSSH through 8.3p1 - command injection via scp",
            },
        ],
    },
    # Apache HTTP Server
    {
        "service_pattern": r"^https?$",
        "product_pattern": r"Apache",
        "version_pattern": r"^2\.4\.(49|50)$",
        "cves": [
            {
                "cve_id": "CVE-2021-41773",
                "cvss_score": 7.5,
                "description": "Apache 2.4.49 path traversal and RCE",
            },
            {
                "cve_id": "CVE-2021-42013",
                "cvss_score": 9.8,
                "description": "Apache 2.4.49-50 path traversal bypass (RCE)",
            },
        ],
    },
    {
        "service_pattern": r"^https?$",
        "product_pattern": r"Apache",
        "version_pattern": r"^2\.4\.(1[0-9]|2[0-9]|3[0-9]|4[0-8])$",
        "cves": [
            {
                "cve_id": "CVE-2019-0211",
                "cvss_score": 7.8,
                "description": "Apache 2.4.17-2.4.38 local privilege escalation",
            },
        ],
    },
    # Nginx
    {
        "service_pattern": r"^https?$",
        "product_pattern": r"nginx",
        "version_pattern": r"^1\.(1[0-7]|[0-9])\..*",
        "cves": [
            {
                "cve_id": "CVE-2019-20372",
                "cvss_score": 5.3,
                "description": "nginx before 1.17.7 HTTP request smuggling",
            },
        ],
    },
    # vsftpd
    {
        "service_pattern": r"^ftp$",
        "product_pattern": r"vsftpd",
        "version_pattern": r"^2\.3\.4$",
        "cves": [
            {
                "cve_id": "CVE-2011-2523",
                "cvss_score": 10.0,
                "description": "vsftpd 2.3.4 backdoor command execution",
            },
        ],
    },
    # ProFTPD
    {
        "service_pattern": r"^ftp$",
        "product_pattern": r"ProFTPD",
        "version_pattern": r"^1\.3\.[0-5]",
        "cves": [
            {
                "cve_id": "CVE-2015-3306",
                "cvss_score": 10.0,
                "description": "ProFTPD before 1.3.5e - mod_copy arbitrary file copy",
            },
        ],
    },
    # SMB / Samba
    {
        "service_pattern": r"^(microsoft-ds|smb|netbios-ssn)$",
        "product_pattern": r"(Samba|Windows)",
        "version_pattern": r".*",
        "cves": [
            {
                "cve_id": "CVE-2017-0144",
                "cvss_score": 9.8,
                "description": "EternalBlue - Windows SMBv1 RCE (MS17-010)",
            },
            {
                "cve_id": "CVE-2017-7494",
                "cvss_score": 9.8,
                "description": "Samba 3.5.0-4.6.4 - is_known_pipename() RCE",
            },
        ],
    },
    # MySQL
    {
        "service_pattern": r"^mysql$",
        "product_pattern": r"MySQL",
        "version_pattern": r"^5\.[0-5]",
        "cves": [
            {
                "cve_id": "CVE-2012-2122",
                "cvss_score": 7.5,
                "description": "MySQL 5.1/5.5/5.6 authentication bypass",
            },
        ],
    },
    # Apache Tomcat
    {
        "service_pattern": r"^https?$",
        "product_pattern": r"(Tomcat|Apache Coyote)",
        "version_pattern": r"^(8\.5\.[0-4][0-9]|9\.0\.[0-3][0-9])",
        "cves": [
            {
                "cve_id": "CVE-2020-1938",
                "cvss_score": 9.8,
                "description": "Apache Tomcat AJP Ghostcat file read/include",
            },
        ],
    },
]


@dataclass
class CVECandidate:
    """A CVE candidate mapped from a discovered service."""

    cve_id: str
    cvss_score: float = 0.0
    description: str = ""
    exploitdb_ref: str = ""
    source: str = "knowledge_base"
    confidence: float = 0.0

    def to_cve_node(self) -> CVENode:
        """Convert to a CVENode for the attack graph."""
        return CVENode(
            cve_id=self.cve_id,
            cvss_score=self.cvss_score,
            description=self.description,
            exploitdb_ref=self.exploitdb_ref,
        )


@dataclass
class CVEMappingResult:
    """Aggregated CVE mapping results for a service."""

    service_name: str
    service_version: str
    candidates: list[CVECandidate] = field(default_factory=list)
    total_found: int = 0


class CVEMapper:
    """Maps discovered service versions to known CVE candidates.

    Uses a curated knowledge base of common service vulnerabilities
    and falls back to SearchSploit for broader coverage.

    Args:
        use_searchsploit: Whether to attempt SearchSploit fallback
            when the knowledge base returns no results.
    """

    def __init__(self, use_searchsploit: bool = True) -> None:
        """Docstring."""
        self._use_searchsploit = use_searchsploit
        self._searchsploit = SearchSploitWrapper()

    def map_service(
        self,
        service_name: str,
        product: str,
        version: str,
    ) -> CVEMappingResult:
        """Map a single service to CVE candidates.

        Args:
            service_name: Service name (e.g., 'ssh', 'http').
            product: Product name (e.g., 'OpenSSH', 'Apache').
            version: Version string (e.g., '8.9p1').

        Returns:
            A :class:`CVEMappingResult` with all matched CVEs.
        """
        candidates: list[CVECandidate] = []

        # 1) Knowledge base lookup
        kb_candidates = self._lookup_knowledge_base(service_name, product, version)
        candidates.extend(kb_candidates)

        # 2) SearchSploit fallback
        if not candidates and self._use_searchsploit:
            ssploit_candidates = self._lookup_searchsploit(product, version)
            candidates.extend(ssploit_candidates)

        # Deduplicate by cve_id
        seen: set[str] = set()
        unique: list[CVECandidate] = []
        for c in candidates:
            if c.cve_id not in seen:
                seen.add(c.cve_id)
                unique.append(c)

        result = CVEMappingResult(
            service_name=service_name,
            service_version=version,
            candidates=unique,
            total_found=len(unique),
        )
        logger.info(
            "CVE mapping for %s/%s %s: %d candidate(s)",
            service_name,
            product,
            version,
            result.total_found,
        )
        return result

    def map_services(
        self,
        services: list[dict[str, Any]],
    ) -> list[CVEMappingResult]:
        """Map multiple services to CVE candidates.

        Args:
            services: List of dicts with keys 'service', 'product',
                'version' (matching NmapWrapper.ServiceInfo fields).

        Returns:
            A list of :class:`CVEMappingResult` for each service.
        """
        results: list[CVEMappingResult] = []
        for svc in services:
            result = self.map_service(
                service_name=svc.get("service", svc.get("name", "unknown")),
                product=svc.get("product", ""),
                version=svc.get("version", ""),
            )
            results.append(result)
        return results

    def _lookup_knowledge_base(
        self,
        service_name: str,
        product: str,
        version: str,
    ) -> list[CVECandidate]:
        """Check the curated knowledge base for matching CVEs."""
        candidates: list[CVECandidate] = []
        # Strip version suffixes like 'p1', '(Ubuntu)' for regex match
        clean_version = re.sub(r"[a-z].*$", "", version, flags=re.IGNORECASE).strip()

        for entry in _KNOWN_CVES:
            service_match = re.search(
                entry["service_pattern"], service_name, re.IGNORECASE
            )
            product_match = re.search(entry["product_pattern"], product, re.IGNORECASE)

            if not (service_match and product_match):
                continue

            version_match = re.search(entry["version_pattern"], clean_version)
            if not version_match:
                continue

            for cve_data in entry["cves"]:
                candidates.append(
                    CVECandidate(
                        cve_id=cve_data["cve_id"],
                        cvss_score=cve_data["cvss_score"],
                        description=cve_data["description"],
                        source="knowledge_base",
                        confidence=0.8,
                    )
                )

        logger.debug(
            "Knowledge base: %d CVE(s) for %s %s",
            len(candidates),
            product,
            version,
        )
        return candidates

    def _lookup_searchsploit(
        self,
        product: str,
        version: str,
    ) -> list[CVECandidate]:
        """Fallback: query SearchSploit for exploit references.

        This only works if searchsploit is installed on the system.
        """
        if not product:
            return []

        query = f"{product} {version}".strip()
        try:
            if not self._searchsploit.is_available():
                logger.debug("SearchSploit not available, skipping fallback")
                return []

            result = self._searchsploit.search(query)
            candidates: list[CVECandidate] = []
            for exploit in result.results[:10]:  # Cap at 10
                candidates.append(
                    CVECandidate(
                        cve_id=f"EDB-{exploit.edb_id}",
                        cvss_score=0.0,
                        description=exploit.title,
                        exploitdb_ref=exploit.edb_id,
                        source="searchsploit",
                        confidence=0.5,
                    )
                )
            logger.debug(
                "SearchSploit: %d result(s) for '%s'",
                len(candidates),
                query,
            )
            return candidates
        except Exception as exc:
            logger.warning("SearchSploit fallback failed: %s", exc)
            return []
