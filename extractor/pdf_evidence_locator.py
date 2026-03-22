from __future__ import annotations

import argparse
import os
import re
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from debug_trace import debug, info, load_json, save_json, warn
from pipeline_app import build_argparser, process_peripheral_with_svd
from svd_parser import parse_svd
from svd_resolver import resolve_address


def _page_text(p: Dict[str, Any]) -> str:
    out: List[str] = []
    for ln in p.get("lines", []) or []:
        if isinstance(ln, dict):
            text = str(ln.get("text", "")).strip()
        else:
            text = str(ln).strip()
        if text:
            out.append(text)
    return "\n".join(out).strip()


def _build_default_args(pdf: str, svd: str, outdir: str, extract_strategy: str = "layout") -> SimpleNamespace:
    """
    Reuse pipeline_app defaults instead of manually reconstructing every option.
    """
    ap = build_argparser()
    defaults = ap.parse_args([
        "--pdf", pdf,
        "--svd", svd,
        "--outdir", outdir,
        "--extract-strategy", extract_strategy,
        "--peripheral", "DUMMY",
    ])
    defaults.outdir = outdir
    return defaults


def _int_auto(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except Exception:
        return None


def _dedup_keep_order(items: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in items:
        s = str(x or "").strip().upper()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _instance_family_candidates(instance: str) -> List[str]:
    """
    Generate robust PDF search candidates from an SVD instance name.

    Examples:
      UART0 -> [UART0, UART]
      GPIOA -> [GPIOA, GPIO]
      PORTA -> [PORTA, PORT]
      I2C1  -> [I2C1, I2C]
      SPI0  -> [SPI0, SPI]
    """
    s = str(instance or "").strip().upper()
    if not s:
        return []

    cands = [s]

    # Remove trailing digits only: UART0 -> UART, I2C1 -> I2C
    no_digits = re.sub(r"\d+$", "", s)
    if no_digits and no_digits != s:
        cands.append(no_digits)

    # Banked GPIO/PORT instances: GPIOA -> GPIO, PORTA -> PORT
    m = re.fullmatch(r"(GPIO|PORT)([A-Z])", s)
    if m:
        cands.append(m.group(1))

    return _dedup_keep_order(cands)


def _pdf_search_terms(resolved: Dict[str, Any]) -> List[str]:
    """
    Build ordered PDF search terms.

    Priority:
      1) resolved instance-derived terms (most reliable when addr was resolved)
      2) resolved family
      3) user-provided family (weak fallback)

    This avoids false early matches like:
      addr -> GPIOB, user family -> GPIOA, register -> PDIR
    where GPIOA also contains PDIR but is the wrong bank.
    """
    instance = str(resolved.get("instance") or "").strip().upper()
    family = str(resolved.get("family") or "").strip().upper()
    user_family = str(resolved.get("user_family") or "").strip().upper()

    terms: List[str] = []

    # Most reliable: concrete resolved instance and its normalized variants
    terms.extend(_instance_family_candidates(instance))

    # Then resolved family
    if family and len(family) >= 3:
        terms.append(family)
        fam_no_digits = re.sub(r"\d+$", "", family)
        if fam_no_digits:
            terms.append(fam_no_digits)

    # Finally, user-provided family as a weak fallback
    if user_family and len(user_family) >= 3:
        terms.append(user_family)
        uf_no_digits = re.sub(r"\d+$", "", user_family)
        if uf_no_digits:
            terms.append(uf_no_digits)

    return _dedup_keep_order(terms)


def _manifest_contains_register(manifest: Dict[str, Any], register: str) -> bool:
    artifacts = manifest.get("artifacts", {}) or {}
    reg_pdf_path = artifacts.get("register_pdf_descriptions")
    merged_path = artifacts.get("register_merged")

    reg_up = str(register or "").strip().upper()
    if not reg_up:
        return False

    try:
        if reg_pdf_path and os.path.exists(reg_pdf_path):
            reg_pdf_map = load_json(reg_pdf_path)
            if any(str(k).strip().upper() == reg_up for k in reg_pdf_map.keys()):
                return True
    except Exception:
        pass

    try:
        if merged_path and os.path.exists(merged_path):
            merged = load_json(merged_path)
            for item in merged.get("registers", []) or []:
                if str(item.get("name") or "").strip().upper() == reg_up:
                    return True
    except Exception:
        pass

    return False


def _keyword_conflicts_with_instance(keyword: str, instance: str) -> bool:
    kw = str(keyword or "").strip().upper()
    inst = str(instance or "").strip().upper()
    if not kw or not inst:
        return False

    # Reject only when both look like concrete banked instances and differ.
    # Example: keyword=GPIOA, instance=GPIOB -> reject
    if re.fullmatch(r"(GPIO|PORT)[A-Z]", kw) and re.fullmatch(r"(GPIO|PORT)[A-Z]", inst):
        return kw != inst

    return False


def ensure_peripheral_artifacts(
    pdf_path: str,
    svd_path: str,
    cache_root: str,
    peripheral_keyword: str,
    extract_strategy: str = "layout",
    force: bool = False,
) -> str:
    keyword = str(peripheral_keyword or "").strip().upper()
    if not keyword:
        raise ValueError("peripheral_keyword is empty")

    sub_out = os.path.join(cache_root, keyword.lower())
    manifest_path = os.path.join(sub_out, f"{keyword.lower()}_debug_manifest.json")
    if os.path.exists(manifest_path) and not force:
        info(f"reusing cached PDF extraction for {keyword}: {manifest_path}")
        return manifest_path

    info(f"building on-demand PDF extraction for {keyword} under {sub_out}")
    args = _build_default_args(pdf_path, svd_path, sub_out, extract_strategy=extract_strategy)
    args.peripheral = keyword
    args.controllers = [x.strip() for x in (args.controllers or "").split(",") if x.strip()]
    args.force = force

    svd_info = parse_svd(svd_path)
    process_peripheral_with_svd(svd_info, args, keyword)
    return manifest_path


def locate_register_pdf_evidence(
    pdf_path: str,
    svd_path: str,
    cache_root: str,
    resolved: Dict[str, Any],
    extract_strategy: str = "layout",
    force: bool = False,
) -> Dict[str, Any]:
    register = str(resolved.get("register") or "").strip()
    if not register:
        raise ValueError("resolved entry missing register")

    instance = str(resolved.get("instance") or "").strip().upper()
    family = str(resolved.get("family") or "").strip().upper()

    # Preserve user-family as a separate weak fallback.
    if "user_family" not in resolved and family:
        resolved = dict(resolved)
        resolved["user_family"] = str(resolved.get("user_family") or "").strip().upper()

    # Fallback: if caller did not provide instance/family but did provide address,
    # resolve once directly from SVD so PDF search terms can be recovered.
    if not instance:
        addr_val = _int_auto(
            resolved.get("register_address_hex")
            or resolved.get("register_address")
            or resolved.get("addr")
        )
        if addr_val is not None:
            svd_data = parse_svd(svd_path)
            addr_hit = resolve_address(svd_data, addr_val)
            if addr_hit:
                instance = str(addr_hit.get("instance") or "").strip().upper()
                family = str(addr_hit.get("family") or "").strip().upper()
                resolved = dict(resolved)
                resolved["instance"] = instance
                resolved["family"] = family
                resolved.setdefault("register_address_hex", addr_hit.get("register_address_hex"))
                debug(
                    f"pdf locate backfilled from addr: addr={addr_hit.get('register_address_hex')} "
                    f"instance={instance} family={family} register={addr_hit.get('register')}"
                )

    search_terms = _pdf_search_terms(resolved)
    if not search_terms:
        raise ValueError("resolved entry missing usable family/instance for PDF search")

    debug(
        f"pdf locate start: instance={instance} family={family} "
        f"user_family={resolved.get('user_family')} register={register} search_terms={search_terms}"
    )

    manifest: Optional[Dict[str, Any]] = None
    manifest_path: Optional[str] = None
    used_keyword: Optional[str] = None
    attempt_errors: List[str] = []

    for kw in search_terms:
        if _keyword_conflicts_with_instance(kw, instance):
            attempt_errors.append(f"{kw}: conflicts with resolved instance {instance}")
            debug(f"pdf locate reject keyword={kw}: conflicts with resolved instance {instance}")
            continue

        try:
            cand_manifest_path = ensure_peripheral_artifacts(
                pdf_path=pdf_path,
                svd_path=svd_path,
                cache_root=cache_root,
                peripheral_keyword=kw,
                extract_strategy=extract_strategy,
                force=force,
            )
            cand_manifest = load_json(cand_manifest_path)

            if not _manifest_contains_register(cand_manifest, register):
                attempt_errors.append(f"{kw}: manifest built but register {register} not found")
                debug(f"pdf locate reject keyword={kw}: register {register} not found in manifest")
                continue

            manifest = cand_manifest
            manifest_path = cand_manifest_path
            used_keyword = kw
            debug(f"pdf locate success keyword={kw}: manifest={cand_manifest_path}")
            break
        except Exception as e:
            attempt_errors.append(f"{kw}: {e}")
            warn(f"pdf locate attempt failed keyword={kw}: {e}")

    if manifest is None or manifest_path is None or used_keyword is None:
        raise RuntimeError(
            f"unable to locate PDF evidence for register={register}; "
            f"search_terms={search_terms}; errors={attempt_errors}"
        )

    artifacts = manifest.get("artifacts", {}) or {}

    reg_pdf_map = load_json(artifacts["register_pdf_descriptions"])
    merged = load_json(artifacts["register_merged"])
    mmio_map = load_json(artifacts["mmio_map"])
    selected_pages = load_json(artifacts["selected_pages"])

    reg_pdf = reg_pdf_map.get(register, {})
    merged_reg = None
    for item in merged.get("registers", []) or []:
        if str(item.get("name") or "").upper() == register.upper():
            merged_reg = item
            break

    mmio_reg = None
    reg_addr_hex = str(resolved.get("register_address_hex") or "").upper()
    for item in mmio_map.get("registers", []) or []:
        if str(item.get("address_hex") or "").upper() == reg_addr_hex:
            mmio_reg = item
            break

    source_pages = [int(x) for x in reg_pdf.get("source_pages", []) if isinstance(x, int)]
    page_snippets = []
    nearby_pages = []
    for page in selected_pages:
        page_num = page.get("page_num")
        if not isinstance(page_num, int):
            continue
        txt = _page_text(page)
        record = {
            "page_num": page_num,
            "text": txt,
        }
        if page_num in source_pages:
            page_snippets.append(record)
        elif source_pages and min(abs(page_num - p) for p in source_pages) <= 1:
            nearby_pages.append(record)

    evidence = {
        "status": "ok",
        "manifest": os.path.abspath(manifest_path),
        "peripheral_keyword": used_keyword,
        "search_terms": search_terms,
        "resolved_instance": instance,
        "resolved_family": family,
        "user_family": str(resolved.get("user_family") or "").strip().upper(),
        "register": register,
        "register_pdf_description": reg_pdf.get("register_pdf_description") or "",
        "field_pdf_descriptions": reg_pdf.get("field_pdf_descriptions") or {},
        "source_pages": source_pages,
        "source_page_snippets": page_snippets,
        "nearby_page_snippets": nearby_pages[:4],
        "merged_register": merged_reg,
        "mmio_register": mmio_reg,
        "artifact_paths": artifacts,
    }
    debug(
        f"pdf evidence located: keyword={used_keyword} instance={instance} family={family} "
        f"user_family={resolved.get('user_family')} register={register} "
        f"source_pages={source_pages} field_desc={len(evidence['field_pdf_descriptions'])}"
    )
    return evidence


def main():
    ap = argparse.ArgumentParser(description="Direct PDF evidence locator via reused peripheral extraction")
    ap.add_argument("--pdf", required=True)
    ap.add_argument("--svd", required=True)
    ap.add_argument("--cache-root", required=True)
    ap.add_argument("--family", required=True)
    ap.add_argument("--register", required=True)
    ap.add_argument("--addr")
    ap.add_argument("--out")
    ap.add_argument("--extract-strategy", default="layout")
    args = ap.parse_args()

    resolved: Dict[str, Any] = {
        "user_family": args.family,
        "register": args.register,
        "register_address_hex": args.addr,
    }

    # If address is provided, resolve against SVD first so we can recover instance/family.
    addr_val = _int_auto(args.addr)
    if addr_val is not None:
        svd_data = parse_svd(args.svd)
        addr_hit = resolve_address(svd_data, addr_val)
        if addr_hit:
            resolved = dict(addr_hit)
            resolved["user_family"] = args.family
            if args.register:
                resolved["register"] = args.register
            if args.addr:
                resolved["register_address_hex"] = args.addr
            debug(
                f"cli resolved from addr: addr={args.addr} "
                f"instance={resolved.get('instance')} family={resolved.get('family')} "
                f"user_family={resolved.get('user_family')} register={resolved.get('register')}"
            )
        else:
            warn(f"address {args.addr} not found in SVD; using CLI family/register only")
    else:
        # No addr provided: keep family as a weak hint and also as current family.
        resolved["family"] = args.family

    data = locate_register_pdf_evidence(
        pdf_path=args.pdf,
        svd_path=args.svd,
        cache_root=args.cache_root,
        resolved=resolved,
        extract_strategy=args.extract_strategy,
    )
    if args.out:
        save_json(args.out, data)
    else:
        import json
        print(json.dumps(data, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()