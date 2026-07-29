"""Attack Graph state manager. Uses NetworkX to store all discoveries.

Owner: Parth (Member D)
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from src.state.persistence import PersistenceManager
from src.state.schemas import (
    CVENode,
    EdgeType,
    ExploitAttempt,
    ExploitPostMortem,
    HostNode,
    ServiceNode,
    SessionNode,
    WebEndpointNode,
)


class AttackGraph:
    """In-memory representation of the target network and vulnerabilities."""

    def __init__(self, db_path: str = "runs/pentest_state.db") -> None:
        """Initialize the AttackGraph with SQLite persistence."""
        self.persistence = PersistenceManager(db_path)
        # Try to load existing graph, otherwise create a new empty one
        self.graph = self.persistence.load_graph() or nx.DiGraph()

    # ── Node insertion ───────────────────────────────────────────

    def add_host(self, host: HostNode) -> None:
        """Add a discovered host to the graph."""
        self.graph.add_node(host.node_id, **host.to_dict())
        self.persistence.save_graph(self.graph)

    def add_service(self, service: ServiceNode) -> None:
        """Add a discovered service and link it to its host."""
        # Ensure host exists first
        host_id = f"host:{service.host_ip}"
        if not self.graph.has_node(host_id):
            self.add_host(HostNode(ip=service.host_ip))

        self.graph.add_node(service.node_id, **service.to_dict())
        self.graph.add_edge(host_id, service.node_id, type=EdgeType.HOSTS_SERVICE.value)
        self.persistence.save_graph(self.graph)

    def add_cve(self, cve: CVENode, service_node_id: str) -> None:
        """Add a CVE node and link it to the vulnerable service.

        Creates a ``VULNERABLE_TO`` edge from the service to the CVE node
        so that the graph tracks which services are affected by which CVEs.

        Args:
            cve: The CVE node to add.
            service_node_id: Node ID of the service this CVE applies to
                (e.g. ``'service:10.10.10.5:21/tcp'``).
        """
        self.graph.add_node(cve.node_id, **cve.to_dict())
        if self.graph.has_node(service_node_id):
            self.graph.add_edge(
                service_node_id,
                cve.node_id,
                type=EdgeType.VULNERABLE_TO.value,
            )
        self.persistence.save_graph(self.graph)

    def add_web_endpoint(self, endpoint: WebEndpointNode) -> None:
        """Add a web endpoint node and link it to its host.

        Creates a ``HAS_ENDPOINT`` edge from the host to the endpoint so
        that directory brute-force results are associated with the correct
        target machine.

        Args:
            endpoint: The web endpoint to add.
        """
        host_id = f"host:{endpoint.host_ip}"
        if not self.graph.has_node(host_id):
            self.add_host(HostNode(ip=endpoint.host_ip))

        self.graph.add_node(endpoint.node_id, **endpoint.to_dict())
        self.graph.add_edge(
            host_id,
            endpoint.node_id,
            type=EdgeType.HAS_ENDPOINT.value,
        )
        self.persistence.save_graph(self.graph)

    def add_session(self, session: SessionNode) -> None:
        """Add a session node and link it to the compromised host.

        Creates an ``ESCALATED_TO`` edge from the host to the session,
        representing that a shell was obtained on that host.

        Args:
            session: The session node to add.
        """
        host_id = f"host:{session.host_ip}"
        if not self.graph.has_node(host_id):
            self.add_host(HostNode(ip=session.host_ip))

        self.graph.add_node(session.node_id, **session.to_dict())
        self.graph.add_edge(
            host_id,
            session.node_id,
            type=EdgeType.ESCALATED_TO.value,
        )
        self.persistence.save_graph(self.graph)

    # ── Failure tracking ─────────────────────────────────────────

    def record_failure(
        self,
        attempt: ExploitAttempt,
        post_mortem: ExploitPostMortem,
    ) -> None:
        """Record a failed exploit attempt as a negative edge in the graph.

        Creates a ``failure`` node and an ``EXPLOIT_ATTEMPT`` edge from the
        target service to the failure node.  Also persists the attempt and
        post-mortem to SQLite via the persistence layer.

        This is the canonical API that agents should use instead of
        writing edges directly to ``self.graph``.

        Args:
            attempt: The failed exploit attempt record.
            post_mortem: The structured post-mortem analysis.
        """
        failure_node_id = f"failure:{attempt.module_used}:{attempt.target_service_id}"

        if not self.graph.has_node(failure_node_id):
            self.graph.add_node(
                failure_node_id,
                node_type="failure",
                module=attempt.module_used,
                error_type=post_mortem.error_type,
                hypothesis=post_mortem.hypothesis,
            )

        if self.graph.has_node(attempt.target_service_id):
            self.graph.add_edge(
                attempt.target_service_id,
                failure_node_id,
                type=EdgeType.EXPLOIT_ATTEMPT.value,
                result="failure",
                error_type=post_mortem.error_type,
                post_mortem=post_mortem.hypothesis,
            )

        self.persistence.save_graph(self.graph)
        self.persistence.record_exploit_attempt(attempt)
        self.persistence.record_post_mortem(post_mortem)

    def record_exploit_attempt(self, attempt: ExploitAttempt) -> None:
        """Persist an exploit attempt record via the persistence layer.

        Public API used by ExploitAgent and VerificationAgent to avoid
        direct coupling to the persistence layer.

        Args:
            attempt: The exploit attempt to record.
        """
        self.persistence.record_exploit_attempt(attempt)

    def record_post_mortem(self, pm: ExploitPostMortem) -> None:
        """Persist a post-mortem record via the persistence layer.

        Args:
            pm: The post-mortem to record.
        """
        self.persistence.record_post_mortem(pm)

    # ── Graph queries ────────────────────────────────────────────

    def get_hosts(self) -> list[dict[str, Any]]:
        """Return all host nodes in the attack graph.

        Returns:
            List of host node data dictionaries.
        """
        return [
            data
            for _, data in self.graph.nodes(data=True)
            if data.get("node_type") == "host"
        ]

    def get_exploitable_services(self) -> list[dict[str, Any]]:
        """Return all discovered services."""
        return [
            data
            for _, data in self.graph.nodes(data=True)
            if data.get("node_type") == "service"
        ]

    def get_sessions(self) -> list[dict[str, Any]]:
        """Return all session nodes in the attack graph.

        Returns:
            List of session node data dictionaries.
        """
        return [
            data
            for _, data in self.graph.nodes(data=True)
            if data.get("node_type") == "session"
        ]

    def has_active_session(self) -> bool:
        """Check if we have achieved a session."""
        return any(
            data.get("node_type") == "session"
            for _, data in self.graph.nodes(data=True)
        )

    def get_web_endpoints(self) -> list[dict[str, Any]]:
        """Return all web endpoint nodes in the attack graph.

        Returns:
            List of web endpoint node data dictionaries.
        """
        return [
            data
            for _, data in self.graph.nodes(data=True)
            if data.get("node_type") == "web_endpoint"
        ]

    def get_cves_for_service(self, service_node_id: str) -> list[dict[str, Any]]:
        """Return all CVE nodes linked to a specific service.

        Follows ``VULNERABLE_TO`` edges outward from the service node.

        Args:
            service_node_id: Node ID of the service to query
                (e.g. ``'service:10.10.10.5:21/tcp'``).

        Returns:
            List of CVE node data dictionaries.
        """
        cves: list[dict[str, Any]] = []
        if not self.graph.has_node(service_node_id):
            return cves
        for _, target, edge_data in self.graph.out_edges(service_node_id, data=True):
            if edge_data.get("type") == EdgeType.VULNERABLE_TO.value:
                node_data = self.graph.nodes[target]
                cves.append(dict(node_data))
        return cves

    def get_failed_attempts(self) -> list[dict[str, Any]]:
        """Return all failure nodes in the attack graph.

        Failure nodes represent exploit attempts that did not result in
        a session.  Each node contains the module used, error type, and
        hypothesis about why the exploit failed.

        Returns:
            List of failure node data dictionaries.
        """
        return [
            data
            for _, data in self.graph.nodes(data=True)
            if data.get("node_type") == "failure"
        ]

    # ── Persistence query proxies ────────────────────────────────

    def get_exploit_attempts(
        self, target_service_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Query exploit attempt records from the SQLite database.

        This is a proxy to :meth:`PersistenceManager.get_exploit_attempts`
        so that callers don't need direct access to the persistence layer.

        Args:
            target_service_id: Optional filter by service node ID.

        Returns:
            List of exploit attempt record dictionaries.
        """
        return self.persistence.get_exploit_attempts(target_service_id)

    def get_post_mortems(
        self, target_service: str | None = None
    ) -> list[dict[str, Any]]:
        """Query post-mortem records from the SQLite database.

        This is a proxy to :meth:`PersistenceManager.get_post_mortems`
        so that callers don't need direct access to the persistence layer.

        Args:
            target_service: Optional filter by target service description.

        Returns:
            List of post-mortem record dictionaries.
        """
        return self.persistence.get_post_mortems(target_service)
