"""Graph visualization utility for the Attack Graph."""

import matplotlib.pyplot as plt
import networkx as nx

from src.state.attack_graph import AttackGraph
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)


def visualize_attack_graph(
    ag: AttackGraph, output_file: str = "attack_graph.png"
) -> None:
    """Render the attack graph and save it as an image."""
    graph = ag.graph

    if len(graph.nodes) == 0:
        logger.warning("Graph is empty. Nothing to visualize.")
        return

    plt.figure(figsize=(12, 8))

    # Layout strategy
    pos = nx.spring_layout(graph, seed=42)

    # Color nodes based on type
    color_map = []
    for node, data in graph.nodes(data=True):
        node_type = data.get("node_type", "unknown")
        if node_type == "host":
            color_map.append("lightblue")
        elif node_type == "service":
            color_map.append("lightgreen")
        elif node_type == "cve":
            color_map.append("orange")
        elif node_type == "session":
            color_map.append("red")
        else:
            color_map.append("gray")

    nx.draw(
        graph,
        pos,
        node_color=color_map,
        with_labels=True,
        node_size=2000,
        font_size=10,
        font_weight="bold",
        edge_color="gray",
    )

    plt.title("PrivacyAware-PenAgent Attack Graph")
    plt.savefig(output_file)
    plt.close()
    logger.info(f"Graph visualization saved to {output_file}")
