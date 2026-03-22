from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List


def debug(msg: str):
    print(f"[DEBUG][groups] {msg}")


ROLE_PATTERNS = {
    "target_control": ("CR", "CTRL", "CONTROL", "CFG", "CONFIG", "MR", "MODE"),
    "target_interrupt": ("IER", "IDR", "IMR", "ICR", "ISR"),
    "target_status": ("SR", "STATUS", "STAT", "INTFLAG", "IFR"),
    "target_data": ("DR", "RDR", "TDR", "RHR", "THR", "DATA", "FIFO"),
}


def _infer_target_role(reg_name: str) -> str:
    n = (reg_name or "").upper()
    for role, toks in ROLE_PATTERNS.items():
        if any(tok == n or n.endswith("_" + tok) or tok in n for tok in toks):
            return role
    return "supporting"


def _build_mmio_index(mmio: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out = {}
    periph = mmio.get("peripheral") or mmio.get("template_instance") or "PERIPH"
    for reg in mmio.get("registers") or []:
        out[f"{periph}:{reg['name']}"] = reg
    return out


def _select_target_registers(mmio: Dict[str, Any], max_count: int = 8) -> List[Dict[str, Any]]:
    regs = list(mmio.get("registers") or [])
    scored = []
    for r in regs:
        role = _infer_target_role(r.get("name", ""))
        doc = r.get("documentation_status") or "svd_only"
        doc_pri = 0 if doc == "documented_in_pdf" else 1
        role_pri = {
            "target_control": 1,
            "target_interrupt": 2,
            "target_status": 3,
            "target_data": 4,
            "supporting": 9,
        }.get(role, 9)
        scored.append((doc_pri, role_pri, r.get("name", ""), r, role))

    scored.sort(key=lambda x: (x[0], x[1], x[2]))
    picked = []
    used = set()
    for _, _, _, reg, role in scored:
        key = reg.get("name")
        if key in used:
            continue
        used.add(key)
        reg2 = dict(reg)
        reg2["_role_in_group"] = role
        picked.append(reg2)
        if len(picked) >= max_count:
            break
    return picked


def _evidence_pages(edges: List[Dict[str, Any]]) -> List[int]:
    pages = sorted(
        {
            x.get("page")
            for e in edges
            for x in (e.get("evidence") or [])
            if x.get("page") is not None
        }
    )
    return [int(p) for p in pages]


def build_stream_groups(relation_edges: Dict[str, Any], mmio_map: Dict[str, Any]) -> Dict[str, Any]:
    mmio = mmio_map
    rel = relation_edges

    target_periph = mmio.get("peripheral") or mmio.get("template_instance") or "PERIPH"
    mmio_index = _build_mmio_index(mmio)

    groups = []
    gid = 1

    # A. field_relation_group: aggregate by register pair.
    regpair_to_edges = defaultdict(list)
    for e in rel.get("edges") or []:
        if e.get("edge_type") != "field_to_field":
            continue
        regpair_to_edges[(e["src"]["register"], e["dst"]["register"])].append(e)

    for (src_reg, dst_reg), edges in regpair_to_edges.items():
        src = mmio_index.get(f"{target_periph}:{src_reg}")
        dst = mmio_index.get(f"{target_periph}:{dst_reg}")
        if not src or not dst:
            continue
        groups.append(
            {
                "group_id": f"g_{gid:06d}",
                "group_subtype": "field_relation_group",
                "members": [
                    {
                        "stream_key": src["absoluteAddress_hex"],
                        "peripheral": target_periph,
                        "register": src_reg,
                        "role_in_group": "source_register",
                        "documentation_status": src.get("documentation_status"),
                    },
                    {
                        "stream_key": dst["absoluteAddress_hex"],
                        "peripheral": target_periph,
                        "register": dst_reg,
                        "role_in_group": "target_register",
                        "documentation_status": dst.get("documentation_status"),
                    },
                ],
                "reason_edges": [
                    {
                        "edge_id": e["edge_id"],
                        "edge_type": e["edge_type"],
                        "src_field": e["src"]["field_id"],
                        "dst_field": e["dst"]["field_id"],
                        "relation": e["relation"],
                        "confidence": e["confidence"],
                        "evidence_pages": _evidence_pages([e]),
                    }
                    for e in edges
                ],
                "confidence": round(sum(e["confidence"] for e in edges) / max(1, len(edges)), 4),
                "notes": [],
            }
        )
        gid += 1

    # A1. field_to_register_group: aggregate by source register + target register.
    regpair_to_reg_edges = defaultdict(list)
    for e in rel.get("edges") or []:
        if e.get("edge_type") != "field_to_register":
            continue
        regpair_to_reg_edges[(e["src"]["register"], e["dst"]["register"])].append(e)

    for (src_reg, dst_reg), edges in regpair_to_reg_edges.items():
        src = mmio_index.get(f"{target_periph}:{src_reg}")
        dst = mmio_index.get(f"{target_periph}:{dst_reg}")
        if not src or not dst:
            continue
        groups.append(
            {
                "group_id": f"g_{gid:06d}",
                "group_subtype": "field_to_register_group",
                "members": [
                    {
                        "stream_key": src["absoluteAddress_hex"],
                        "peripheral": target_periph,
                        "register": src_reg,
                        "role_in_group": "source_register",
                        "documentation_status": src.get("documentation_status"),
                    },
                    {
                        "stream_key": dst["absoluteAddress_hex"],
                        "peripheral": target_periph,
                        "register": dst_reg,
                        "role_in_group": "target_register",
                        "documentation_status": dst.get("documentation_status"),
                    },
                ],
                "reason_edges": [
                    {
                        "edge_id": e["edge_id"],
                        "edge_type": e["edge_type"],
                        "src_field": e["src"]["field_id"],
                        "dst_register": e["dst"]["register_id"],
                        "relation": e["relation"],
                        "confidence": e["confidence"],
                        "evidence_pages": _evidence_pages([e]),
                    }
                    for e in edges
                ],
                "confidence": round(sum(e["confidence"] for e in edges) / max(1, len(edges)), 4),
                "notes": [],
            }
        )
        gid += 1

    # A2. field_to_peripheral_group: aggregate by source register + relation.
    f2p_groups = defaultdict(list)
    for e in rel.get("edges") or []:
        if e.get("edge_type") != "field_to_peripheral":
            continue
        f2p_groups[(e["src"]["register"], e.get("relation"))].append(e)

    for (src_reg, relation), edges in f2p_groups.items():
        src_reg_obj = mmio_index.get(f"{target_periph}:{src_reg}")
        members = []
        if src_reg_obj:
            members.append(
                {
                    "stream_key": src_reg_obj.get("absoluteAddress_hex"),
                    "peripheral": target_periph,
                    "register": src_reg,
                    "role_in_group": "source_register",
                    "documentation_status": src_reg_obj.get("documentation_status"),
                }
            )

        seen_targets = set()
        for e in sorted(edges, key=lambda x: (x["dst"]["peripheral"], x["src"].get("field", ""))):
            dstp = e["dst"]["peripheral"]
            if dstp in seen_targets:
                continue
            seen_targets.add(dstp)
            members.append(
                {
                    "stream_key": f"external:{dstp}",
                    "peripheral": dstp,
                    "register": None,
                    "role_in_group": "mentioned_peripheral",
                    "documentation_status": "external_symbolic",
                }
            )

        groups.append(
            {
                "group_id": f"g_{gid:06d}",
                "group_subtype": "field_to_peripheral_group",
                "members": members,
                "reason_edges": [
                    {
                        "edge_id": e["edge_id"],
                        "edge_type": e["edge_type"],
                        "src_field": e["src"]["field_id"],
                        "dst_peripheral": e["dst"]["peripheral"],
                        "relation": e["relation"],
                        "confidence": e["confidence"],
                        "evidence_pages": _evidence_pages([e]),
                    }
                    for e in edges
                ],
                "confidence": round(sum(e["confidence"] for e in edges) / max(1, len(edges)), 4),
                "notes": [f"aggregated_by=src_register+relation", f"edge_count={len(edges)}"],
            }
        )
        gid += 1

    # B. controller_to_peripheral_group (legacy heuristic path).
    target_regs_for_c2p = _select_target_registers(mmio, max_count=8)
    for e in rel.get("edges") or []:
        if e.get("edge_type") != "controller_register_to_peripheral":
            continue

        members = []
        if e["src"].get("register_addr_hex"):
            members.append(
                {
                    "stream_key": e["src"]["register_addr_hex"],
                    "peripheral": e["src"]["peripheral"],
                    "register": e["src"]["register"],
                    "role_in_group": "controller",
                    "documentation_status": "svd_only",
                }
            )
        for r in target_regs_for_c2p:
            members.append(
                {
                    "stream_key": r["absoluteAddress_hex"],
                    "peripheral": target_periph,
                    "register": r["name"],
                    "role_in_group": r["_role_in_group"],
                    "documentation_status": r.get("documentation_status"),
                }
            )

        groups.append(
            {
                "group_id": f"g_{gid:06d}",
                "group_subtype": "controller_to_peripheral_group",
                "members": members,
                "reason_edges": [
                    {
                        "edge_id": e["edge_id"],
                        "edge_type": e["edge_type"],
                        "src_register": e["src"]["register_id"],
                        "dst_peripheral": e["dst"]["peripheral"],
                        "relation": e["relation"],
                        "confidence": e["confidence"],
                        "evidence_pages": _evidence_pages([e]),
                    }
                ],
                "confidence": e["confidence"],
                "notes": [],
            }
        )
        gid += 1

    # C. controller_field_to_peripheral_group: aggregate by source register + relation.
    cf2p_groups = defaultdict(list)
    for e in rel.get("edges") or []:
        if e.get("edge_type") != "controller_field_to_peripheral":
            continue
        cf2p_groups[(e["src"]["register"], e.get("relation"))].append(e)

    for (src_reg, relation), edges in cf2p_groups.items():
        src_reg_obj = mmio_index.get(f"{target_periph}:{src_reg}")
        members = []
        if src_reg_obj:
            members.append(
                {
                    "stream_key": src_reg_obj.get("absoluteAddress_hex"),
                    "peripheral": target_periph,
                    "register": src_reg,
                    "role_in_group": "controller_register",
                    "documentation_status": src_reg_obj.get("documentation_status"),
                }
            )

        # Symbolic targets because destination peripherals are external to this MMIO map.
        seen_targets = set()
        for e in sorted(edges, key=lambda x: (x["dst"]["peripheral"], x["src"].get("field", ""))):
            dstp = e["dst"]["peripheral"]
            if dstp in seen_targets:
                continue
            seen_targets.add(dstp)
            members.append(
                {
                    "stream_key": f"external:{dstp}",
                    "peripheral": dstp,
                    "register": None,
                    "role_in_group": "controlled_peripheral",
                    "documentation_status": "external_symbolic",
                }
            )

        groups.append(
            {
                "group_id": f"g_{gid:06d}",
                "group_subtype": "controller_field_to_peripheral_group",
                "members": members,
                "reason_edges": [
                    {
                        "edge_id": e["edge_id"],
                        "edge_type": e["edge_type"],
                        "src_field": e["src"]["field_id"],
                        "dst_peripheral": e["dst"]["peripheral"],
                        "relation": e["relation"],
                        "confidence": e["confidence"],
                        "evidence_pages": _evidence_pages([e]),
                    }
                    for e in edges
                ],
                "confidence": round(sum(e["confidence"] for e in edges) / max(1, len(edges)), 4),
                "notes": [f"aggregated_by=src_register+relation", f"edge_count={len(edges)}"],
            }
        )
        gid += 1

    # D. controller_to_register_group (legacy heuristic path).
    for e in rel.get("edges") or []:
        if e.get("edge_type") != "controller_register_to_register":
            continue
        dst_reg_name = e["dst"]["register"]
        dst_reg = mmio_index.get(f"{target_periph}:{dst_reg_name}")
        if not dst_reg:
            continue
        members = []
        if e["src"].get("register_addr_hex"):
            members.append(
                {
                    "stream_key": e["src"]["register_addr_hex"],
                    "peripheral": e["src"]["peripheral"],
                    "register": e["src"]["register"],
                    "role_in_group": "controller",
                    "documentation_status": "svd_only",
                }
            )
        members.append(
            {
                "stream_key": dst_reg["absoluteAddress_hex"],
                "peripheral": target_periph,
                "register": dst_reg_name,
                "role_in_group": "target_register",
                "documentation_status": dst_reg.get("documentation_status"),
            }
        )
        for r in mmio.get("registers") or []:
            rn = r.get("name", "")
            if rn == dst_reg_name:
                continue
            if (r.get("documentation_status") or "") != "documented_in_pdf":
                continue
            if _infer_target_role(rn) == "target_status":
                members.append(
                    {
                        "stream_key": r["absoluteAddress_hex"],
                        "peripheral": target_periph,
                        "register": rn,
                        "role_in_group": "supporting_status",
                        "documentation_status": r.get("documentation_status"),
                    }
                )
                break
        groups.append(
            {
                "group_id": f"g_{gid:06d}",
                "group_subtype": "controller_to_register_group",
                "members": members,
                "reason_edges": [
                    {
                        "edge_id": e["edge_id"],
                        "edge_type": e["edge_type"],
                        "src_register": e["src"]["register_id"],
                        "dst_register": e["dst"]["register_id"],
                        "relation": e["relation"],
                        "confidence": e["confidence"],
                        "evidence_pages": _evidence_pages([e]),
                    }
                ],
                "confidence": e["confidence"],
                "notes": [],
            }
        )
        gid += 1

    debug(f"stream groups built: {len(groups)}")
    return {
        "schema": "stream_groups_v2",
        "stream_key_policy": "mmio_or_symbolic",
        "groups": groups,
    }
