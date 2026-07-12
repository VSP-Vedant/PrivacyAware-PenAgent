"""Recon Agent — full Nmap + Gobuster reconnaissance pipeline.

Orchestrates the reconnaissance phase of the penetration test:
1. Execute Nmap scan against the target
2. Parse results into structured host/service data
3. Detect HTTP/HTTPS ports and trigger Gobuster enumeration
4. Map discovered service versions to CVE candidates
5. Write all discoveries to the attack graph

Owner: Vedant (Member C)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from src.state.attack_graph import AttackGraph
from src.state.schemas import EdgeType, HostNode, ServiceNode, WebEndpointNode
from src.tools.cve_mapper import CVECandidate, CVEMapper
from src.tools.gobuster_wrapper import GobusterError, GobusterWrapper, WebEndpoint
from src.tools.nmap_wrapper import HostInfo, NmapScanResult, NmapWrapper, ServiceInfo

logger = logging.getLogger(__name__)

# HTTP service names that trigger Gobuster
_HTTP_SERVICE_NAMES = frozenset({"http", "https", "http-proxy", "https-alt"})


@dataclass
class ReconResult:
    """Complete result of a reconnaissance run.

    Attributes:
        hosts: Discovered hosts.
        services: Discovered services across all hosts.
        web_endpoints: Web endpoints discovered by Gobuster.
        cve_candidates: CVE candidates mapped from service versions.
        os_guess: Best OS guess from Nmap, or None.
        scan_duration_seconds: Total recon duration.
        target: The original scan target.
    """

    hosts: list[HostInfo] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)
    web_endpoints: list[WebEndpoint] = field(default_factory=list)
    cve_candidates: list[CVECandidate] = field(default_factory=list)
    os_guess: str | None = None
    scan_duration_seconds: float = 0.0
    target: str = ""


class ReconAgent:
    """Reconnaissance agent that runs the full Nmap + Gobuster pipeline.

    Scans the target, populates the attack graph with discovered
    hosts, services, web endpoints, and CVE candidates.

    Args:
        attack_graph: The shared attack graph to populate.
        nmap_timeout: Maximum Nmap scan duration in seconds.
        scan_type: Nmap scan preset ('default', 'full', 'quick', 'stealth').
        use_gobuster: Whether to run Gobuster on HTTP ports.
        use_cve_mapping: Whether to map services to CVEs.
    """

    def __init__(
        self,
        attack_graph: AttackGraph,
        nmap_timeout: int = 600,
        scan_type: str = "default",
        use_gobuster: bool = True,
        use_cve_mapping: bool = True,
    ) -> None:
        """Docstring."""
        self._graph = attack_graph
        self._nmap = NmapWrapper(timeout=nmap_timeout)
        self._gobuster = GobusterWrapper()
        self._cve_mapper = CVEMapper(use_searchsploit=True)
        self._scan_type = scan_type
        self._use_gobuster = use_gobuster
        self._use_cve_mapping = use_cve_mapping

    def run(
        self,
        target: str,
        ports: str | None = None,
    ) -> ReconResult:
        """Execute the full reconnaissance pipeline.

        Args:
            target: Target IP address.
            ports: Optional port specification (e.g., '22,80,443').

        Returns:
            A :class:`ReconResult` with all discoveries.

        Raises:
            NmapScanError: If target validation or scan fails.
        """
        logger.info("Starting recon pipeline against %s", target)

        result = ReconResult(target=target)

        # ── Step 1: Nmap scan ────────────────────────────────────
        nmap_result = self._run_nmap(target, ports)
        result.hosts = nmap_result.hosts
        result.services = nmap_result.services
        result.os_guess = nmap_result.os_guess
        result.scan_duration_seconds = nmap_result.scan_duration_seconds

        # ── Step 2: Populate attack graph with hosts & services ──
        self._populate_graph_from_nmap(nmap_result, target)

        # ── Step 3: Gobuster on HTTP ports ───────────────────────
        if self._use_gobuster:
            web_endpoints = self._run_gobuster(target, nmap_result.services)
            result.web_endpoints = web_endpoints
            self._populate_graph_web_endpoints(
                target, web_endpoints, nmap_result.services
            )

        # ── Step 4: CVE mapping ──────────────────────────────────
        if self._use_cve_mapping:
            cve_candidates = self._run_cve_mapping(nmap_result.services)
            result.cve_candidates = cve_candidates
            self._populate_graph_cves(cve_candidates, nmap_result.services)

        logger.info(
            "Recon complete: %d hosts, %d services, %d web endpoints, %d CVEs",
            len(result.hosts),
            len(result.services),
            len(result.web_endpoints),
            len(result.cve_candidates),
        )
        return result

    def run_from_xml(
        self,
        xml_path: str,
        target: str,
    ) -> ReconResult:
        """Run the pipeline from a pre-existing Nmap XML file.

        Useful for testing or replaying scans without re-scanning.

        Args:
            xml_path: Path to the Nmap XML output file.
            target: Target IP (for graph association).

        Returns:
            A :class:`ReconResult` with discoveries from the XML.
        """
        logger.info("Running recon from XML: %s", xml_path)
        nmap_result = self._nmap.parse_xml(xml_path)
        result = ReconResult(
            target=target,
            hosts=nmap_result.hosts,
            services=nmap_result.services,
            os_guess=nmap_result.os_guess,
            scan_duration_seconds=0.0,
        )

        self._populate_graph_from_nmap(nmap_result, target)

        if self._use_cve_mapping:
            cve_candidates = self._run_cve_mapping(nmap_result.services)
            result.cve_candidates = cve_candidates
            self._populate_graph_cves(cve_candidates, nmap_result.services)

        return result

    # ── Internal pipeline steps ──────────────────────────────────

    def _run_nmap(
        self,
        target: str,
        ports: str | None,
    ) -> NmapScanResult:
        """Execute the Nmap scan."""
        logger.info(
            "Running Nmap scan (type=%s) against %s",
            self._scan_type,
            target,
        )
        return self._nmap.scan(
            target=target,
            scan_type=self._scan_type,
            ports=ports,
        )

    def _run_gobuster(
        self,
        target: str,
        services: list[ServiceInfo],
    ) -> list[WebEndpoint]:
        """Run Gobuster against HTTP/HTTPS services."""
        all_endpoints: list[WebEndpoint] = []
        http_services = [svc for svc in services if svc.service in _HTTP_SERVICE_NAMES]

        if not http_services:
            logger.info("No HTTP services found, skipping Gobuster")
            return all_endpoints

        if not self._gobuster.is_available():
            logger.warning("Gobuster binary not found, skipping web enumeration")
            return all_endpoints

        for svc in http_services:
            scheme = "https" if svc.service in {"https", "https-alt"} else "http"
            url = f"{scheme}://{target}:{svc.port}"

            logger.info("Running Gobuster against %s", url)
            try:
                gb_result = self._gobuster.scan(url)
                all_endpoints.extend(gb_result.endpoints)
                logger.info(
                    "Gobuster found %d endpoints on %s",
                    gb_result.total_found,
                    url,
                )
            except GobusterError as exc:
                logger.warning(
                    "Gobuster scan failed for %s: %s",
                    url,
                    exc,
                )
        return all_endpoints

    def _run_cve_mapping(
        self,
        services: list[ServiceInfo],
    ) -> list[CVECandidate]:
        """Map services to CVE candidates."""
        service_dicts: list[dict[str, Any]] = []
        for svc in services:
            service_dicts.append(
                {
                    "service": svc.service,
                    "product": svc.product,
                    "version": svc.version,
                }
            )

        mapping_results = self._cve_mapper.map_services(service_dicts)
        all_candidates: list[CVECandidate] = []
        for mr in mapping_results:
            all_candidates.extend(mr.candidates)

        logger.info(
            "CVE mapping found %d total candidate(s) across %d services",
            len(all_candidates),
            len(services),
        )
        return all_candidates

    # ── Graph population ─────────────────────────────────────────

    def _populate_graph_from_nmap(
        self,
        nmap_result: NmapScanResult,
        target: str,
    ) -> None:
        """Write Nmap discoveries to the attack graph."""
        for host_info in nmap_result.hosts:
            host_node = HostNode(
                ip=host_info.ip,
                hostname=host_info.hostname,
                os_guess=host_info.os_guess,
                status=host_info.status,
            )
            self._graph.add_host(host_node)
            logger.debug("Added host node: %s", host_info.ip)

        for svc_info in nmap_result.services:
            # Find the host IP for this service — use the target if hosts
            # list doesn't contain it (single-host scan case)
            host_ip = target
            for h in nmap_result.hosts:
                if h.ip:
                    host_ip = h.ip
                    break

            service_node = ServiceNode(
                host_ip=host_ip,
                port=svc_info.port,
                protocol=svc_info.protocol,
                name=svc_info.service,
                version=svc_info.version,
                state=svc_info.state,
                product=svc_info.product,
                extra_info=svc_info.extra_info,
            )
            self._graph.add_service(service_node)
            logger.debug(
                "Added service node: %s:%d/%s",
                host_ip,
                svc_info.port,
                svc_info.protocol,
            )

    def _populate_graph_web_endpoints(
        self,
        target: str,
        endpoints: list[WebEndpoint],
        services: list[ServiceInfo],
    ) -> None:
        """Write Gobuster web endpoint discoveries to the graph."""
        for endpoint in endpoints:
            # Determine the port from the URL or default
            port = 80
            for svc in services:
                if svc.service in _HTTP_SERVICE_NAMES:
                    port = svc.port
                    break

            web_node = WebEndpointNode(
                host_ip=target,
                port=port,
                url=endpoint.url,
                status_code=endpoint.status_code,
                content_type=endpoint.content_type,
            )
            node_id = web_node.node_id
            self._graph.graph.add_node(node_id, **web_node.to_dict())

            # Link to the parent service
            service_id = f"service:{target}:{port}/tcp"
            if self._graph.graph.has_node(service_id):
                self._graph.graph.add_edge(
                    service_id,
                    node_id,
                    type=EdgeType.HAS_ENDPOINT.value,
                )
            self._graph.persistence.save_graph(self._graph.graph)

    def _populate_graph_cves(
        self,
        candidates: list[CVECandidate],
        services: list[ServiceInfo],
    ) -> None:
        """Write CVE candidates to the graph and link to services."""
        for candidate in candidates:
            cve_node = candidate.to_cve_node()
            node_id = cve_node.node_id
            self._graph.graph.add_node(node_id, **cve_node.to_dict())

            # Link CVE to all services that could be affected
            # We link based on the CVE description containing the service name
            for svc in services:
                # Try the actual node ID format used by ServiceNode
                for node in self._graph.graph.nodes():
                    if node.startswith("service:") and str(svc.port) in node:
                        self._graph.graph.add_edge(
                            node,
                            node_id,
                            type=EdgeType.VULNERABLE_TO.value,
                            confidence=candidate.confidence,
                        )
                        break

        self._graph.persistence.save_graph(self._graph.graph)
