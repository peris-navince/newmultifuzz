#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def scan_queue(queue_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not queue_dir.exists():
        return rows

    for p in sorted(queue_dir.rglob("*")):
        if not p.is_file():
            continue
        try:
            st = p.stat()
            rows.append({
                "name": p.name,
                "relpath": str(p.relative_to(queue_dir)),
                "size": int(st.st_size),
                "mtime": float(st.st_mtime),
                "sha256": sha256_file(p),
            })
        except Exception as e:
            rows.append({
                "name": p.name,
                "relpath": str(p.relative_to(queue_dir)),
                "size": -1,
                "mtime": 0.0,
                "sha256": f"ERROR:{e}",
            })
    return rows


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def save_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-queue", required=True)
    ap.add_argument("--new-queue", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--copy-new-dir", default=None,
                    help="Optional directory to copy only newly discovered files into")
    args = ap.parse_args()

    old_queue = Path(args.old_queue)
    new_queue = Path(args.new_queue)

    old_rows = scan_queue(old_queue)
    new_rows = scan_queue(new_queue)

    old_by_hash = {r["sha256"] for r in old_rows}
    old_by_relpath = {r["relpath"] for r in old_rows}

    new_only_rows: List[Dict[str, Any]] = []
    for r in new_rows:
        is_new_by_hash = r["sha256"] not in old_by_hash
        is_new_by_relpath = r["relpath"] not in old_by_relpath
        if is_new_by_hash or is_new_by_relpath:
            row = dict(r)
            row["new_by_hash"] = int(is_new_by_hash)
            row["new_by_relpath"] = int(is_new_by_relpath)
            new_only_rows.append(row)

    # 按 mtime 新到旧排序
    new_only_rows.sort(key=lambda x: x["mtime"], reverse=True)

    summary = {
        "old_queue": str(old_queue),
        "new_queue": str(new_queue),
        "old_file_count": len(old_rows),
        "new_file_count": len(new_rows),
        "new_only_count": len(new_only_rows),
        "new_only_rows": new_only_rows,
    }

    save_json(Path(args.out_json), summary)
    save_csv(
        Path(args.out_csv),
        new_only_rows,
        ["relpath", "name", "size", "mtime", "sha256", "new_by_hash", "new_by_relpath"],
    )

    if args.copy_new_dir:
        copy_dir = Path(args.copy_new_dir)
        copy_dir.mkdir(parents=True, exist_ok=True)
        for row in new_only_rows:
            src = new_queue / row["relpath"]
            dst = copy_dir / Path(row["relpath"]).name
            if src.exists():
                shutil.copy2(src, dst)

    print(f"[OK] old_file_count={len(old_rows)}")
    print(f"[OK] new_file_count={len(new_rows)}")
    print(f"[OK] new_only_count={len(new_only_rows)}")
    print(f"[OK] wrote {args.out_json}")
    print(f"[OK] wrote {args.out_csv}")
    if args.copy_new_dir:
        print(f"[OK] copied new files to {args.copy_new_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())