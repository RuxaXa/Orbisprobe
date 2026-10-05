from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    FUNCTION = "function"
    OBJECT = "object"
    FIELD = "field"
    BUFFER = "buffer"
    MAPPING = "mapping"
    DESCRIPTOR = "descriptor"
    HARDWARE_ENDPOINT = "hardware_endpoint"


class EdgeType(str, Enum):
    READS = "reads"
    WRITES = "writes"
    VALIDATES = "validates"
    MAPS = "maps"
    SUBMITS = "submits"
    COPIES = "copies"
    ALIASES = "aliases"
    CONSUMES = "consumes"
    CALLS = "calls"


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    node_type: NodeType
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["node_type"] = self.node_type.value
        return data


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    edge_type: EdgeType
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["edge_type"] = self.edge_type.value
        return data


class ResearchGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []

    def add_node(self, node: GraphNode) -> None:
        existing = self._nodes.get(node.node_id)
        if existing is not None and existing != node:
            raise ValueError(f"conflicting graph node: {node.node_id}")
        self._nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        missing = [node_id for node_id in (edge.source, edge.target) if node_id not in self._nodes]
        if missing:
            raise ValueError("missing graph node: " + ", ".join(missing))
        if edge not in self._edges:
            self._edges.append(edge)

    def paths(
        self,
        source_predicate: Callable[[GraphNode], bool],
        target_predicate: Callable[[GraphNode], bool],
        max_depth: int = 8,
    ) -> list[list[str]]:
        adjacency: dict[str, list[str]] = {node_id: [] for node_id in self._nodes}
        for edge in self._edges:
            adjacency[edge.source].append(edge.target)
        for targets in adjacency.values():
            targets.sort()

        found: list[list[str]] = []
        starts = sorted(node.node_id for node in self._nodes.values() if source_predicate(node))
        for start in starts:
            queue: list[list[str]] = [[start]]
            while queue:
                path = queue.pop(0)
                current = path[-1]
                if len(path) > 1 and target_predicate(self._nodes[current]):
                    found.append(path)
                    continue
                if len(path) - 1 >= max_depth:
                    continue
                for target in adjacency[current]:
                    if target not in path:
                        queue.append([*path, target])
        return found

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [self._nodes[node_id].to_dict() for node_id in sorted(self._nodes)],
            "edges": [
                edge.to_dict()
                for edge in sorted(
                    self._edges,
                    key=lambda item: (item.source, item.target, item.edge_type.value),
                )
            ],
        }
