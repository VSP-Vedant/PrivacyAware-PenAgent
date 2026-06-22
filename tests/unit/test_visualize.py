"""Unit tests for the visualization module."""

import os
import tempfile
from pathlib import Path

from src.state.attack_graph import AttackGraph
from src.state.schemas import HostNode, ServiceNode
from src.utils.visualize import visualize_attack_graph


def test_visualize_attack_graph() -> None:
    """Verify visualization generates an image file without crashing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    output_path = "test_graph.png"

    try:
        ag = AttackGraph(db_path=db_path)
        
        # Populate with some dummy data
        host = HostNode(ip="10.10.10.5", hostname="target.htb", status="up")
        ag.add_host(host)
        
        svc = ServiceNode(host_ip="10.10.10.5", port=22, name="ssh")
        ag.add_service(svc)
        
        # Test visualization
        visualize_attack_graph(ag, output_file=output_path)
        
        # Verify file exists
        assert os.path.exists(output_path)
        
    finally:
        # Cleanup
        Path(db_path).unlink()
        if os.path.exists(output_path):
            os.remove(output_path)