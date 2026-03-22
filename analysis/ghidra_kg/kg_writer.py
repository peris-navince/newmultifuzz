from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .kg_schema import edge_to_dict, node_to_dict, KGEdge, KGNode


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_graph(outdir: str, nodes: List[KGNode], edges: List[KGEdge], findings: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    root = Path(outdir)
    _write_jsonl(root / "kg_nodes.jsonl", [node_to_dict(n) for n in nodes])
    _write_jsonl(root / "kg_edges.jsonl", [edge_to_dict(e) for e in edges])
    _write_jsonl(root / "kg_findings.jsonl", findings)
    _write_json(root / "summary.json", summary)
