from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class KGNode:
    node_id: str
    node_type: str
    attrs: Dict[str, Any]


@dataclass(frozen=True)
class KGEdge:
    src: str
    edge_type: str
    dst: str
    attrs: Dict[str, Any]


class GraphBuilder:
    def __init__(self):
        self.nodes: Dict[str, KGNode] = {}
        self.edges: Set[Tuple[str, str, str, Tuple[Tuple[str, Any], ...]]] = set()
        self.findings: List[Dict[str, Any]] = []

    def add_node(self, node_id: str, node_type: str, **attrs: Any) -> str:
        prev = self.nodes.get(node_id)
        merged = dict(prev.attrs) if prev else {}
        merged.update({k: v for k, v in attrs.items() if v is not None})
        self.nodes[node_id] = KGNode(node_id=node_id, node_type=node_type, attrs=merged)
        return node_id

    def add_edge(self, src: str, edge_type: str, dst: str, **attrs: Any) -> None:
        key = (src, edge_type, dst, tuple(sorted((k, v) for k, v in attrs.items())))
        self.edges.add(key)

    def add_finding(self, finding: Dict[str, Any]) -> None:
        self.findings.append(dict(finding))

    def materialize_edges(self) -> List[KGEdge]:
        out: List[KGEdge] = []
        for src, edge_type, dst, attrs_items in sorted(self.edges):
            out.append(KGEdge(src=src, edge_type=edge_type, dst=dst, attrs=dict(attrs_items)))
        return out

    def materialize_nodes(self) -> List[KGNode]:
        return [self.nodes[k] for k in sorted(self.nodes)]


def function_node_id(name: str, entry: str) -> str:
    return f"func:{name}@{entry}"


def mmio_node_id(addr_hex: str) -> str:
    return f"mmio:{addr_hex.upper()}"


def peripheral_node_id(name: str) -> str:
    return f"periph:{name.upper()}"


def register_node_id(peripheral: str, register: str) -> str:
    return f"reg:{peripheral.upper()}:{register.upper()}"


def field_node_id(peripheral: str, register: str, field: str) -> str:
    return f"field:{peripheral.upper()}:{register.upper()}.{field.upper()}"


def risk_node_id(kind: str, func_name: str, entry: str, index: int) -> str:
    return f"risk:{kind}:{func_name}@{entry}:{index}"


def node_to_dict(node: KGNode) -> Dict[str, Any]:
    d = asdict(node)
    d.update(d.pop("attrs"))
    return d


def edge_to_dict(edge: KGEdge) -> Dict[str, Any]:
    d = asdict(edge)
    d.update(d.pop("attrs"))
    return d
