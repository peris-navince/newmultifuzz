from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

import pdfplumber


def _cluster_words_into_lines(words: List[Dict[str, Any]], y_tol: float = 3.0):
    words = sorted(
        words,
        key=lambda w: (round(float(w.get("top", 0)) / y_tol), float(w.get("x0", 0))),
    )
    lines = []
    cur = []
    cur_y = None

    for w in words:
        top = float(w.get("top", 0))
        if cur_y is None or abs(top - cur_y) <= y_tol:
            cur.append(w)
            cur_y = top if cur_y is None else min(cur_y, top)
        else:
            lines.append(sorted(cur, key=lambda x: float(x.get("x0", 0))))
            cur = [w]
            cur_y = top

    if cur:
        lines.append(sorted(cur, key=lambda x: float(x.get("x0", 0))))

    return lines


def _line_to_text(line_words: List[Dict[str, Any]]) -> str:
    out = []
    prev_x1 = None

    for w in line_words:
        x0 = float(w.get("x0", 0))
        txt = str(w.get("text", ""))
        if prev_x1 is not None and x0 - prev_x1 > 6:
            out.append(" ")
        out.append(txt)
        prev_x1 = float(w.get("x1", x0))

    return "".join(out).strip()


def extract_pages(
    pdf_path: str,
    start_page: int,
    end_page: int,
    strategy: str = "layout",
):
    pages = []
    with pdfplumber.open(pdf_path) as pdf:
        start_page = max(1, int(start_page))
        end_page = min(len(pdf.pages), int(end_page))

        for pno in range(start_page, end_page + 1):
            page = pdf.pages[pno - 1]

            if strategy == "plain":
                text = page.extract_text() or ""
                lines = [ln.rstrip() for ln in text.splitlines()]
            else:
                words = page.extract_words(use_text_flow=True, keep_blank_chars=False)
                lines = [_line_to_text(ws) for ws in _cluster_words_into_lines(words)]

            lines = [ln for ln in lines if ln.strip()]
            pages.append(
                {
                    "page_num": pno,
                    "lines": lines,
                    "text": "\n".join(lines),
                }
            )
    return pages


def scan_pdf_for_keywords(
    pdf_path: str,
    keywords: List[str],
    start_page: Optional[int] = None,
    end_page: Optional[int] = None,
) -> Dict[int, Dict[str, int]]:
    out: Dict[int, Dict[str, int]] = {}
    kws = [k.strip().upper() for k in keywords if k and k.strip()]
    with pdfplumber.open(pdf_path) as pdf:
        n_pages = len(pdf.pages)
        s = 1 if start_page is None else max(1, int(start_page))
        e = n_pages if end_page is None else min(n_pages, int(end_page))

        for i in range(s - 1, e):
            text = (pdf.pages[i].extract_text() or "").upper()
            out[i + 1] = {kw: text.count(kw) for kw in kws}
    return out


def select_hot_pages(
    freq_map: Dict[int, Dict[str, int]],
    top_k_pages: int = 12,
    pad: int = 2,
) -> List[int]:
    scored = []
    for p, d in freq_map.items():
        scored.append((sum(d.values()), p))
    scored.sort(key=lambda x: (-x[0], x[1]))

    hot = [p for score, p in scored if score > 0][: max(1, top_k_pages)]
    pages: Set[int] = set()
    for p in hot:
        for x in range(max(1, p - pad), p + pad + 1):
            pages.add(x)
    return sorted(pages)