"""Unit tests for the AttackGraph state manager."""

import tempfile
from pathlib import Path

from src.state.attack_graph import AttackGraph
from src.state.schemas import HostNode, ServiceNode


def test_attack_graph_add_host_and_service() -> None:
    """Verify adding hosts and services creates the correct edges."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    ag = AttackGraph(db_path=db_path)

    # Add a service (should automatically create the host)
    svc = ServiceNode(host_ip="10.10.10.5", port=80, name="http")
    ag.add_service(svc)

    # Check graph properties
    assert "host:10.10.10.5" in ag.graph.nodes
    assert svc.node_id in ag.graph.nodes
    assert ag.graph.has_edge("host:10.10.10.5", svc.node_id)

    # Check queries
    exploitable = ag.get_exploitable_services()
    assert len(exploitable) == 1
    assert exploitable[0]["port"] == 80

    assert ag.has_active_session() is False

    Path(db_path).unlink()
