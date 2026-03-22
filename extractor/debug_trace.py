from __future__ import annotations

import json
import os
import time
from typing import Any


def _debug_enabled() -> bool:
    v = os.getenv("EXTRACTOR_CLOSED_LOOP_DEBUG", "1").strip().lower()
    return v not in {"0", "false", "no", "off"}


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def log(level: str, msg: str):
    if level == "DEBUG" and not _debug_enabled():
        return
    print(f"[{_ts()}] [{level}] {msg}")


def debug(msg: str):
    log("DEBUG", msg)


def info(msg: str):
    log("INFO", msg)


def warn(msg: str):
    log("WARN", msg)


def ensure_parent(path: str):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def load_json(path: str) -> Any:
    debug(f"load_json <- {os.path.abspath(path)}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Any):
    ensure_parent(path)
    debug(f"save_json -> {os.path.abspath(path)}")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def save_text(path: str, text: str):
    ensure_parent(path)
    debug(f"save_text -> {os.path.abspath(path)}")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
