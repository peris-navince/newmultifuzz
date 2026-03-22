from __future__ import annotations

from typing import Any, Dict, List

from utils import load_json, save_json


def build_chunks(
    merged_json: str,
    relation_edges_json: str,
    out_jsonl: str,
):
    merged = load_json(merged_json)
    rel = load_json(relation_edges_json)

    chunks: List[Dict[str, Any]] = []

    chunks.append(
        {
            "chunk_type": "overview",
            "peripheral": merged.get("keyword"),
            "template_instance": merged.get("template_instance"),
            "register_count": len(merged.get("registers") or []),
            "edge_count": len(rel.get("edges") or []),
        }
    )

    for reg in merged.get("registers") or []:
        chunks.append(
            {
                "chunk_type": "register",
                "peripheral": merged.get("keyword"),
                "register": reg.get("name"),
                "absoluteAddress_hex": reg.get("absoluteAddress_hex"),
                "svd_description": reg.get("svd_description"),
                "pdf_description": reg.get("pdf_description"),
                "fields": [
                    {
                        "name": f.get("name"),
                        "bitRange": f.get("bitRange"),
                        "svd_description": f.get("svd_description"),
                        "pdf_description": f.get("pdf_description"),
                    }
                    for f in (reg.get("fields") or [])
                ],
            }
        )

    for e in rel.get("edges") or []:
        chunks.append(
            {
                "chunk_type": "relation",
                "edge_type": e.get("edge_type"),
                "relation": e.get("relation"),
                "src": e.get("src"),
                "dst": e.get("dst"),
                "confidence": e.get("confidence"),
                "evidence": e.get("evidence"),
            }
        )

    with open(out_jsonl, "w", encoding="utf-8") as f:
        for c in chunks:
            f.write(__import__("json").dumps(c, ensure_ascii=False) + "\n")