import json
import os
import time
from typing import Any


def ensure_output_dir(outdir: str):
    os.makedirs(outdir, exist_ok=True)


def save_json(path: str, data: Any):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def debug(msg: str):
    print(f"[DEBUG] {msg}")


def stage(msg: str):
    print(f"\n[STAGE] {msg}")


def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())