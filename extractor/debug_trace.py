from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
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


def _json_default(obj: Any):
    """
    Safe fallback serializer for common non-JSON-native objects that may
    appear in staged-loop summaries or intermediate artifacts.
    """
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, set):
        return sorted(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if hasattr(obj, "__fspath__"):
        try:
            return os.fspath(obj)
        except Exception:
            pass
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable: {obj!r}")


def load_json(path: str) -> Any:
    debug(f"load_json <- {os.path.abspath(path)}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Any):
    """
    Serialize first, then atomically replace the destination file.

    This prevents 0-byte JSON files when json serialization fails after the
    target file has already been truncated.
    """
    ensure_parent(path)
    abs_path = os.path.abspath(path)

    # Serialize first; if this fails, do not touch the destination file.
    try:
        payload = json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=_json_default,
        )
    except Exception as e:
        warn(f"save_json serialization failed for {abs_path}: {e}")
        raise

    debug(f"save_json -> {abs_path}")

    parent = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_json_", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception as e:
        warn(f"save_json write failed for {abs_path}: {e}")
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def save_text(path: str, text: str):
    """
    Atomically write text files as well, for consistency.
    """
    ensure_parent(path)
    abs_path = os.path.abspath(path)
    debug(f"save_text -> {abs_path}")

    parent = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_txt_", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception as e:
        warn(f"save_text write failed for {abs_path}: {e}")
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise