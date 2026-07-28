"""Attack Graph state manager. Uses NetworkX to store all discoveries.

Owner: Parth (Member D)
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from src.state.persistence import PersistenceManager
from src.state.schemas import EdgeType, ExploitAttempt, ExploitPostMortem, HostNode, ServiceNode


class AttackGraph:
    """In-memory representation of the target network and vulnerabilities."""

    def __init__(self, db_path: str = "runs/pentest_state.db") -> None:
        """Initialize the AttackGraph with SQLite persistence."""
        self.persistence = PersistenceManager(db_path)
        # Try to load existing graph, otherwise create a new empty one
        self.graph = self.persistence.load_graph() or nx.DiGraph()

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

    def get_exploitable_services(self) -> list[dict[str, Any]]:
        """Return all discovered services."""
        services = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get("node_type") == "service":
                services.append(data)
        return services

    def has_active_session(self) -> bool:
        """Check if we have achieved a session."""
        for _, data in self.graph.nodes(data=True):
            if data.get("node_type") == "session":
                return True
        return False

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

    def get_sessions(self) -> list[dict[str, Any]]:
        """Return all session nodes in the attack graph.

        Returns:
            List of session node data dictionaries.
        """
        sessions = []
        for _, data in self.graph.nodes(data=True):
            if data.get("node_type") == "session":
                sessions.append(data)
        return sessions

