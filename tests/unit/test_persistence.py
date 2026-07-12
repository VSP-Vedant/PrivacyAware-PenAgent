"""Unit tests for the SQLite persistence layer."""

import tempfile
from pathlib import Path

import networkx as nx

from src.state.persistence import PersistenceManager
from src.state.schemas import ExploitAttempt


def test_save_and_load_graph() -> None:
    """Verify a NetworkX graph can be saved and accurately reloaded."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    pm = PersistenceManager(db_path=db_path)
    
    # Create a dummy graph
    graph = nx.DiGraph()
    graph.add_node("host:10.10.10.5", node_type="host", ip="10.10.10.5")
    graph.add_node("service:10.10.10.5:22/tcp", node_type="service", port=22)
    graph.add_edge("host:10.10.10.5", "service:10.10.10.5:22/tcp", type="hosts_service")

    # Save and reload
    pm.save_graph(graph)
    loaded_graph = pm.load_graph()

    assert loaded_graph is not None
    assert "host:10.10.10.5" in loaded_graph.nodes
    assert loaded_graph.nodes["host:10.10.10.5"]["ip"] == "10.10.10.5"
    assert loaded_graph.has_edge("host:10.10.10.5", "service:10.10.10.5:22/tcp")

    # Cleanup
    Path(db_path).unlink()


def test_record_exploit_attempt() -> None:
    """Verify an exploit attempt can be recorded without errors."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    pm = PersistenceManager(db_path=db_path)
    attempt = ExploitAttempt(
        target_service_id="service:10.10.10.5:22/tcp",
        module_used="exploit/linux/ssh/test",
    )
    
    # Should not raise any exceptions
    pm.record_exploit_attempt(attempt)

    # Cleanup
    Path(db_path).unlink()