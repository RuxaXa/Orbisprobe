from orbisprobe.surfaces.graph import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    ResearchGraph,
)


def test_graph_tracks_controlled_value_to_dma_endpoint():
    graph = ResearchGraph()
    graph.add_node(GraphNode("field:user.length", NodeType.FIELD, {"controlled": True}))
    graph.add_node(GraphNode("descriptor:dma", NodeType.DESCRIPTOR, {}))
    graph.add_node(GraphNode("hardware:dmac", NodeType.HARDWARE_ENDPOINT, {"class": "DMA"}))
    graph.add_edge(GraphEdge("field:user.length", "descriptor:dma", EdgeType.WRITES))
    graph.add_edge(GraphEdge("descriptor:dma", "hardware:dmac", EdgeType.SUBMITS))
    paths = graph.paths(
        lambda node: node.attributes.get("controlled") is True,
        lambda node: node.node_type == NodeType.HARDWARE_ENDPOINT,
    )
    assert paths == [["field:user.length", "descriptor:dma", "hardware:dmac"]]
    assert {edge["edge_type"] for edge in graph.to_dict()["edges"]} == {"writes", "submits"}


def test_graph_rejects_dangling_edges():
    graph = ResearchGraph()
    graph.add_node(GraphNode("function:a", NodeType.FUNCTION, {}))
    try:
        graph.add_edge(GraphEdge("function:a", "missing", EdgeType.CALLS))
    except ValueError as exc:
        assert "missing graph node" in str(exc)
    else:
        raise AssertionError("dangling edge accepted")
