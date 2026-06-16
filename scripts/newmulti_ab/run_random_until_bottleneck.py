#!/usr/bin/env python3
"""
run_random_until_bottleneck.py

No-LLM online random fuzzing bottleneck controller for MultiFuzz.

This controller runs random fuzzing in repeated chunks (for example 3 replicas x
5 minutes), analyzes the latest chunk after each round, and continues the same
replica by importing the previous chunk's queue when the selected runner exposes
an import mechanism.

The bottleneck decision is not based on coverage alone. It combines coverage,
input/corpus growth, execution health, MMIO repetition, hotspot concentration,
hotspot stability, and multi-replica agreement.

Runner engines:
  template
      Use --run-template with placeholders:
      {repo} {case_id} {rep} {iter} {iteration} {chunk_root} {run_root}
      {out_root} {run_for} {import_dir} {manifest} {observer_dir}

  newmulti-guided-warmup
      Uses scripts/newmulti_ab/run_newmulti_ab.py in guided/no-LLM mode and
      analyzes guided_knowledge/round_0_seed as the observed-random chunk.
      This engine is convenient for your current branch because round_0_seed has
      observer output.

  adaptive-mmio-warmup
      Directly invokes extractor/closed_loop.py adaptive-mmio-loop with --skip-llm
      and analyzes round_0_seed.

Outputs:
  random_bottleneck_history.csv
  random_bottleneck_decision.json per case
  random_until_bottleneck_summary.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import subprocess
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

DURATION_RE = re.compile(r"^\s*(?P<num>\d+(?:\.\d+)?)(?P<unit>s|sec|secs|m|min|mins|h|hr|hrs)?\s*$", re.I)
ADDR_RE = re.compile(r"0[xX][0-9a-fA-F]+")
RUN_RE = re.compile(
    r"\[\s*(?P<t>\d+)\s*s\].*?"
    r"(?:rate=\s*(?P<rate>[0-9.]+)\s*/s)?.*?"
    r"(?:hav:\s*(?P<hav>\d+))?.*?"
    r"crash=\s*(?P<crash>\d+).*?"
    r"hang=\s*(?P<hang>\d+).*?"
    r"cov=\s*(?P<cov>\d+).*?"
    r"in=\s*(?P<inp>\d+)",
    re.IGNORECASE,
)


def parse_duration_seconds(s: str) -> int:
    m = DURATION_RE.match(str(s))
    if not m:
        raise ValueError(f"invalid duration: {s!r}")
    num = float(m.group("num"))
    unit = (m.group("unit") or "s").lower()
    if unit in {"s", "sec", "secs"}:
        return int(num)
    if unit in {"m", "min", "mins"}:
        return int(num * 60)
    if unit in {"h", "hr", "hrs"}:
        return int(num * 3600)
    raise ValueError(f"invalid duration unit: {s!r}")


def duration_for_cli(seconds: int) -> str:
    if seconds >= 3600 and seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds >= 60 and seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def load_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(errors="ignore"))
    except Exception:
        return None


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def normalize_hex(x: Any) -> Optional[str]:
    if x is None:
        return None
    s = str(x).strip()
    if not s:
        return None
    m = ADDR_RE.search(s)
    if m:
        try:
            return f"0x{int(m.group(0), 16):08X}"
        except Exception:
            return m.group(0).lower()
    try:
        return f"0x{int(s, 0):08X}"
    except Exception:
        return None


def safe_id(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.=-]+", "_", str(s)).strip("_") or "case"


def manifest_case_id(row: Dict[str, Any]) -> str:
    return str(row.get("case_id") or row.get("target_id") or row.get("benchmark") or "case")


def abs_under_repo(repo: Path, v: Any) -> Optional[str]:
    if not v:
        return None
    p = Path(str(v))
    return str(p if p.is_absolute() else repo / p)


def command_supports(script: Path, option: str, cwd: Path) -> bool:
    try:
        cp = subprocess.run(
            [sys.executable, str(script), "--help"],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
        )
        return option in cp.stdout
    except Exception:
        return False


def run_cmd(cmd: Sequence[str], *, cwd: Path, log_path: Path, env: Optional[Dict[str, str]] = None, dry_run: bool = False) -> int:
    printable = " ".join(shlex.quote(x) for x in cmd)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(f"\n$ {printable}\n")
    print(f"[cmd] {printable}")
    if dry_run:
        return 0
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    proc = subprocess.Popen(
        list(cmd), cwd=str(cwd), env=merged_env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    assert proc.stdout is not None
    with log_path.open("a", encoding="utf-8") as f:
        for line in proc.stdout:
            sys.stdout.write(line)
            f.write(line)
    proc.wait()
    return int(proc.returncode or 0)


def parse_run_log(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(errors="ignore").splitlines():
        m = RUN_RE.search(line)
        if not m:
            continue
        rows.append({
            "t": int(m.group("t")),
            "cov": int(m.group("cov")),
            "inp": int(m.group("inp")),
            "hang": int(m.group("hang")),
            "crash": int(m.group("crash")),
            "hav": int(m.group("hav")) if m.group("hav") else None,
            "rate": float(m.group("rate")) if m.group("rate") else None,
            "line": line,
        })
    return rows


def window_base(rows: List[Dict[str, Any]], window_s: int) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    if not rows:
        return None, None
    last = rows[-1]
    cutoff = max(0, int(last["t"]) - int(window_s))
    base = rows[0]
    for r in rows:
        if int(r["t"]) >= cutoff:
            base = r
            break
    return base, last


def delta(rows: List[Dict[str, Any]], key: str, window_s: int) -> int:
    base, last = window_base(rows, window_s)
    if not base or not last:
        return 0
    return int(last.get(key) or 0) - int(base.get(key) or 0)


def recent_rate(rows: List[Dict[str, Any]], window_s: int) -> Optional[float]:
    base, _ = window_base(rows, window_s)
    if not base:
        return None
    vals = [r.get("rate") for r in rows if int(r.get("t", 0)) >= int(base["t"]) and r.get("rate") is not None]
    return float(sum(vals) / len(vals)) if vals else None


def queue_dir_from_run_root(run_root: Path) -> Optional[Path]:
    for p in [run_root / "workdir" / "queue", run_root / "queue"]:
        if p.exists():
            return p
    for p in run_root.rglob("queue"):
        if p.is_dir():
            return p
    return None


def stream_addr(item: Dict[str, Any]) -> Optional[str]:
    for key in ("addr", "address", "address_hex", "mmio_addr", "stream_addr"):
        if key in item:
            addr = normalize_hex(item.get(key))
            if addr:
                return addr
    for key in ("key", "stream_key", "hotspot_key", "primary_hotspot_key"):
        if key in item:
            addr = normalize_hex(item.get(key))
            if addr:
                return addr
    return None


def stream_count(item: Dict[str, Any]) -> int:
    for key in ("read_count", "count", "touch_count", "access_count", "total_count", "reads"):
        if key in item and item.get(key) not in (None, ""):
            try:
                return int(item.get(key) or 0)
            except Exception:
                pass
    wc = item.get("width_counts")
    if isinstance(wc, dict):
        total = 0
        for v in wc.values():
            try:
                total += int(v)
            except Exception:
                pass
        return total
    return 0


def width_counts(item: Dict[str, Any]) -> Dict[str, int]:
    wc = item.get("width_counts")
    out: Dict[str, int] = {}
    if isinstance(wc, dict):
        for k, v in wc.items():
            try:
                out[str(k)] = int(v)
            except Exception:
                pass
    return out


def load_observer(run_root: Path) -> Dict[str, Any]:
    obs = run_root / "observer"
    data: Dict[str, Any] = {
        "present": obs.exists(),
        "latest_summary": load_json(obs / "latest_window_summary.json") or {},
        "streams": [],
        "windows": [],
    }
    for name in [
        "latest_window_discovered_streams.json",
        "latest_window_interesting_streams.json",
        "discovered_streams.json",
        "interesting_streams.json",
        "all_ranked_hotspots.json",
        "auxiliary_hotspots.json",
    ]:
        x = load_json(obs / name)
        if isinstance(x, list):
            data["streams"].extend([v for v in x if isinstance(v, dict)])
    win_dir = obs / "windows"
    if win_dir.exists():
        for p in sorted(win_dir.glob("*_summary.json")):
            x = load_json(p)
            if isinstance(x, dict):
                x["_path"] = str(p)
                data["windows"].append(x)
    return data


def window_key(w: Dict[str, Any]) -> Optional[str]:
    for k in ("primary_hotspot_key", "hotspot_key", "dominant_stream_key", "top_stream_key"):
        if w.get(k):
            return str(w.get(k))
    for k in ("primary_hotspot", "top_hotspot"):
        if isinstance(w.get(k), dict):
            addr = stream_addr(w[k])
            if addr:
                return addr
    for k in ("latest_window_discovered_streams", "observer_latest_window_discovered_streams", "discovered_streams", "all_ranked_hotspots"):
        vals = w.get(k)
        if isinstance(vals, list) and vals and isinstance(vals[0], dict):
            addr = stream_addr(vals[0])
            if addr:
                return addr
    return None


def mmio_metrics(run_root: Path) -> Dict[str, Any]:
    obs = load_observer(run_root)
    by_addr: Dict[str, Dict[str, Any]] = {}
    for item in obs["streams"]:
        addr = stream_addr(item)
        cnt = stream_count(item)
        if not addr or cnt <= 0:
            continue
        if addr not in by_addr or cnt > by_addr[addr]["count"]:
            by_addr[addr] = {"addr": addr, "count": cnt, "width_counts": width_counts(item)}
    streams = sorted(by_addr.values(), key=lambda x: x["count"], reverse=True)
    counts = [s["count"] for s in streams]
    total = sum(counts)
    unique = len(counts)
    top = counts[0] if counts else 0
    top_share = top / total if total else 0.0
    hhi = sum((c / total) ** 2 for c in counts) if total else 0.0
    width_diverse = sum(1 for s in streams if len(s.get("width_counts") or {}) > 1)
    latest = obs["latest_summary"] if isinstance(obs["latest_summary"], dict) else {}
    recent_keys = [window_key(w) for w in obs["windows"][-5:]]
    recent_keys = [k for k in recent_keys if k]
    stable3 = len(recent_keys[-3:]) >= 2 and len(set(recent_keys[-3:])) == 1
    stable5 = len(recent_keys[-5:]) >= 3 and len(set(recent_keys[-5:])) <= 2
    try:
        hotspot_count = int(latest.get("hotspot_count") or latest.get("primary_hotspot_count") or 0)
    except Exception:
        hotspot_count = 0
    poll_like = total >= 500 and (top_share >= 0.50 or hhi >= 0.35 or (top >= 1000 and unique <= 32) or stable3)
    return {
        "observer_present": bool(obs["present"]),
        "observer_window_count": len(obs["windows"]),
        "observer_reason": latest.get("reason") or latest.get("finalized_reason") or "",
        "observer_hotspot_count": hotspot_count,
        "mmio_total_accesses": total,
        "mmio_unique_addrs": unique,
        "mmio_top_count": top,
        "mmio_top_share": round(top_share, 6),
        "mmio_hhi": round(hhi, 6),
        "mmio_width_diverse_addrs": width_diverse,
        "mmio_poll_like": bool(poll_like),
        "mmio_hotspot_positive": bool(hotspot_count > 0 or streams),
        "mmio_stable_hotspot_last3": bool(stable3),
        "mmio_stable_hotspot_last5": bool(stable5),
        "mmio_recent_hotspot_keys": "|".join(recent_keys[-5:]),
        "mmio_top_addrs": "|".join(f"{s['addr']}:{s['count']}" for s in streams[:8]),
    }


@dataclass
class Config:
    window_s: int
    min_elapsed_s: int
    cov_epsilon: int
    input_epsilon: int
    min_mmio_accesses: int
    mmio_top_share_threshold: float
    mmio_hhi_threshold: float
    crash_hang_noise_threshold: int
    min_recent_rate: float
    majority: int
    consecutive: int


@dataclass
class Analysis:
    case_id: str
    rep: int
    iteration: int
    run_root: str
    status: str
    decision: str
    score: int
    reasons: str
    elapsed_s: int
    last_cov: int
    last_in: int
    last_hang: int
    last_crash: int
    recent_cov_delta: int
    recent_in_delta: int
    recent_hang_delta: int
    recent_crash_delta: int
    recent_rate: str
    total_cov_delta: int
    total_in_delta: int
    observer_present: bool
    observer_window_count: int
    mmio_total_accesses: int
    mmio_unique_addrs: int
    mmio_top_count: int
    mmio_top_share: float
    mmio_hhi: float
    mmio_poll_like: bool
    mmio_hotspot_positive: bool
    mmio_stable_hotspot_last3: bool
    mmio_stable_hotspot_last5: bool
    mmio_top_addrs: str
    mmio_recent_hotspot_keys: str
    notes: str = ""


BOTTLENECK_STATUSES = {
    "strong_bottleneck",
    "mmio_polling_bottleneck",
    "coverage_input_mmio_bottleneck",
    "coverage_input_stall",
    "crash_hang_trap",
}


def analyze_chunk(case_id: str, rep: int, iteration: int, run_root: Path, cfg: Config) -> Analysis:
    rows = parse_run_log(run_root / "run.log")
    if not rows:
        candidates = sorted(run_root.rglob("run.log"))
        if candidates:
            run_root = candidates[0].parent
            rows = parse_run_log(candidates[0])
    mmio = mmio_metrics(run_root)
    if not rows:
        return Analysis(case_id, rep, iteration, str(run_root), "no_runlog_metrics", "continue", 0, "no_runlog_metrics", 0, 0, 0, 0, 0, 0, 0, 0, 0, "", 0, 0, bool(mmio["observer_present"]), int(mmio["observer_window_count"]), int(mmio["mmio_total_accesses"]), int(mmio["mmio_unique_addrs"]), int(mmio["mmio_top_count"]), float(mmio["mmio_top_share"]), float(mmio["mmio_hhi"]), bool(mmio["mmio_poll_like"]), bool(mmio["mmio_hotspot_positive"]), bool(mmio["mmio_stable_hotspot_last3"]), bool(mmio["mmio_stable_hotspot_last5"]), str(mmio["mmio_top_addrs"]), str(mmio["mmio_recent_hotspot_keys"]))
    elapsed = int(rows[-1]["t"])
    last = rows[-1]
    recent_cov = delta(rows, "cov", cfg.window_s)
    recent_in = delta(rows, "inp", cfg.window_s)
    recent_hang = delta(rows, "hang", cfg.window_s)
    recent_crash = delta(rows, "crash", cfg.window_s)
    rr = recent_rate(rows, cfg.window_s)
    total_cov = int(last["cov"]) - int(rows[0]["cov"])
    total_in = int(last["inp"]) - int(rows[0]["inp"])
    cov_stall = recent_cov <= cfg.cov_epsilon
    input_stall = recent_in <= cfg.input_epsilon
    cov_progress = recent_cov > cfg.cov_epsilon
    input_progress = recent_in > cfg.input_epsilon
    mmio_enough = int(mmio["mmio_total_accesses"]) >= cfg.min_mmio_accesses
    mmio_conc = float(mmio["mmio_top_share"]) >= cfg.mmio_top_share_threshold or float(mmio["mmio_hhi"]) >= cfg.mmio_hhi_threshold
    mmio_repetitive = bool(mmio["mmio_poll_like"]) or (mmio_enough and mmio_conc)
    mmio_stable = bool(mmio["mmio_stable_hotspot_last3"]) or bool(mmio["mmio_stable_hotspot_last5"])
    mmio_hotspot = bool(mmio["mmio_hotspot_positive"])
    crash_hang_noise = (recent_hang + recent_crash) >= cfg.crash_hang_noise_threshold
    reasons: List[str] = []
    score = 0
    if elapsed < cfg.min_elapsed_s:
        status = "too_short"
        decision = "continue"
        reasons.append(f"elapsed<{cfg.min_elapsed_s}s")
    else:
        if cov_stall:
            score += 2; reasons.append("coverage_stall")
        else:
            reasons.append("coverage_growth")
        if input_stall:
            score += 2; reasons.append("input_stall")
        else:
            reasons.append("input_growth")
        if mmio_hotspot:
            score += 1; reasons.append("mmio_hotspot")
        if mmio_repetitive:
            score += 2; reasons.append("mmio_repetitive")
        if mmio_stable:
            score += 2; reasons.append("mmio_stable_hotspot")
        if crash_hang_noise and (cov_stall or input_stall):
            score += 1; reasons.append("crash_hang_noise")
        if rr is not None and rr <= cfg.min_recent_rate and cov_stall and input_stall:
            score += 1; reasons.append("low_recent_rate")
        if cov_progress:
            status, decision = "coverage_growth", "continue"
        elif input_progress and not (mmio_repetitive and mmio_stable):
            status, decision = "input_growth_without_coverage", "continue"
        elif crash_hang_noise and cov_stall and input_stall:
            status, decision = "crash_hang_trap", "candidate_bottleneck"
        elif cov_stall and input_stall and mmio_repetitive and mmio_stable:
            status, decision = "strong_bottleneck", "candidate_bottleneck"
        elif cov_stall and input_stall and mmio_repetitive:
            status, decision = "mmio_polling_bottleneck", "candidate_bottleneck"
        elif cov_stall and input_stall and mmio_hotspot:
            status, decision = "coverage_input_mmio_bottleneck", "candidate_bottleneck"
        elif cov_stall and input_stall:
            status, decision = "coverage_input_stall", "candidate_bottleneck"
        elif cov_stall:
            status, decision = "coverage_stall_only", "continue"
        else:
            status, decision = "insufficient_signal", "continue"
    return Analysis(
        case_id, rep, iteration, str(run_root), status, decision, score, "+".join(reasons), elapsed,
        int(last["cov"]), int(last["inp"]), int(last["hang"]), int(last["crash"]),
        recent_cov, recent_in, recent_hang, recent_crash, "" if rr is None else f"{rr:.3f}",
        total_cov, total_in, bool(mmio["observer_present"]), int(mmio["observer_window_count"]),
        int(mmio["mmio_total_accesses"]), int(mmio["mmio_unique_addrs"]), int(mmio["mmio_top_count"]),
        float(mmio["mmio_top_share"]), float(mmio["mmio_hhi"]), bool(mmio["mmio_poll_like"]),
        bool(mmio["mmio_hotspot_positive"]), bool(mmio["mmio_stable_hotspot_last3"]), bool(mmio["mmio_stable_hotspot_last5"]),
        str(mmio["mmio_top_addrs"]), str(mmio["mmio_recent_hotspot_keys"]),
    )


def write_history_csv(path: Path, rows: List[Analysis]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(Analysis.__dataclass_fields__.keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow(asdict(row))


def rep_confirmed(hist: List[Analysis], consecutive: int) -> bool:
    if len(hist) < consecutive:
        return False
    return all(x.status in BOTTLENECK_STATUSES or x.decision == "candidate_bottleneck" for x in hist[-consecutive:])


def target_decision(rep_histories: Dict[int, List[Analysis]], majority: int, consecutive: int) -> Tuple[bool, Dict[str, Any]]:
    votes = 0
    states = {}
    for rep, hist in sorted(rep_histories.items()):
        ok = rep_confirmed(hist, consecutive)
        votes += int(ok)
        states[str(rep)] = {
            "bottleneck_confirmed": ok,
            "history_len": len(hist),
            "last_status": hist[-1].status if hist else "none",
            "last_reasons": hist[-1].reasons if hist else "",
            "last_score": hist[-1].score if hist else 0,
        }
    return votes >= majority, {"reached": votes >= majority, "votes": votes, "majority": majority, "consecutive": consecutive, "rep_states": states}


def build_template_command(template: str, **kwargs: Any) -> List[str]:
    formatted = template.format(**{k: "" if v is None else str(v) for k, v in kwargs.items()})
    return shlex.split(formatted)


def run_template(repo: Path, case: Dict[str, Any], case_id: str, rep: int, iteration: int, chunk_root: Path, run_for: str, import_dir: Optional[Path], template: str, dry_run: bool) -> Tuple[int, Path, Optional[Path], List[str]]:
    run_root = chunk_root / "run"
    observer_dir = run_root / "observer"
    manifest = chunk_root / "case_manifest.jsonl"
    write_jsonl(manifest, [case])
    cmd = build_template_command(template, repo=repo, case_id=case_id, rep=rep, iter=iteration, iteration=iteration, chunk_root=chunk_root, run_root=run_root, out_root=chunk_root, run_for=run_for, import_dir=import_dir or "", manifest=manifest, observer_dir=observer_dir)
    rc = run_cmd(cmd, cwd=repo, log_path=chunk_root / "controller_runner.log", dry_run=dry_run)
    return rc, run_root, queue_dir_from_run_root(run_root), cmd


def run_newmulti_guided_warmup(repo: Path, case: Dict[str, Any], case_id: str, rep: int, iteration: int, chunk_root: Path, run_for: str, import_dir: Optional[Path], dry_run: bool) -> Tuple[int, Path, Optional[Path], List[str]]:
    script = repo / "scripts" / "newmulti_ab" / "run_newmulti_ab.py"
    manifest = chunk_root / "case_manifest.jsonl"
    write_jsonl(manifest, [case])
    out_root = chunk_root / "newmulti"
    cmd = [
        sys.executable, str(script), "--repo", str(repo), "--manifest", str(manifest), "--out-root", str(out_root),
        "--mode", "guided", "--jobs", "1", "--repeats", "1", "--guided-warmup-run-for", run_for,
        "--probe-run-for", "1s", "--followup-run-for", "1s", "--portfolio-run-for", "1s", "--candidate-run-for", "1s",
        "--rounds", "0", "--beam-width", "1", "--portfolio-max-candidates", "1", "--max-candidates", "1", "--llm-mode", "off",
    ]
    if import_dir:
        if command_supports(script, "--import-dir", repo):
            cmd += ["--import-dir", str(import_dir)]
        elif command_supports(script, "--baseline-import-dir", repo):
            cmd += ["--baseline-import-dir", str(import_dir)]
        elif command_supports(script, "--seed-import-dir", repo):
            cmd += ["--seed-import-dir", str(import_dir)]
        elif command_supports(script, "--setenv", repo):
            cmd += ["--setenv", f"MF_IMPORT_DIR={import_dir}", "--setenv", f"MF_IMPORT_QUEUE_DIR={import_dir}"]
    rc = run_cmd(cmd, cwd=repo, log_path=chunk_root / "controller_runner.log", dry_run=dry_run)
    observed = out_root / case_id / "rep_01" / "guided_knowledge" / "round_0_seed"
    if not observed.exists():
        found = list(out_root.rglob("round_0_seed/run.log"))
        if found:
            observed = found[0].parent
    return rc, observed, queue_dir_from_run_root(observed), cmd


def run_adaptive_mmio_warmup(repo: Path, case: Dict[str, Any], case_id: str, rep: int, iteration: int, chunk_root: Path, run_for: str, import_dir: Optional[Path], dry_run: bool) -> Tuple[int, Path, Optional[Path], List[str]]:
    closed_loop = repo / "extractor" / "closed_loop.py"
    out_root = chunk_root / "adaptive_mmio"
    def field(*names: str) -> Optional[str]:
        for n in names:
            v = case.get(n)
            if v:
                return abs_under_repo(repo, v)
        return None
    cmd = [
        sys.executable, str(closed_loop), "adaptive-mmio-loop",
        "--fuzzer-manifest", str(repo / "Cargo.toml"), "--fuzzer-bin", str(repo / "target" / "debug" / "hail-fuzz"),
        "--out-root", str(out_root), "--materialization-mode", "staged-loop", "--warmup-run-for", run_for,
        "--warmup-restarts", "1", "--probe-run-for", "1s", "--followup-run-for", "1s", "--portfolio-run-for", "1s", "--candidate-run-for", "1s",
        "--rounds", "0", "--beam-width", "1", "--max-llm-cycles", "0", "--main-window-count", "0", "--skip-llm",
        "--benchmark-name", case_id,
    ]
    for key, opt in [("config", "--firmware-config"), ("elf", "--binary"), ("binary_path", "--binary"), ("pdf", "--pdf"), ("svd", "--svd"), ("board", "--board"), ("mcu", "--mcu"), ("ghidra_summary_json", "--ghidra-summary-json"), ("ghidra_export_json", "--ghidra-export-json")]:
        v = field(key) if key not in {"board", "mcu"} else case.get(key)
        if v:
            cmd += [opt, str(v)]
    if import_dir:
        cmd += ["--import-dir", str(import_dir)]
    rc = run_cmd(cmd, cwd=repo, log_path=chunk_root / "controller_runner.log", dry_run=dry_run)
    observed = out_root / "round_0_seed"
    if not observed.exists():
        found = list(out_root.rglob("round_0_seed/run.log"))
        if found:
            observed = found[0].parent
    return rc, observed, queue_dir_from_run_root(observed), cmd


def select_cases(manifest: List[Dict[str, Any]], case_ids: Sequence[str], limit: Optional[int]) -> List[Dict[str, Any]]:
    wanted = set(case_ids)
    out = []
    for row in manifest:
        cid = manifest_case_id(row)
        if wanted and cid not in wanted:
            continue
        out.append(row)
        if limit and len(out) >= limit:
            break
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="No-LLM chunked random fuzzing until multi-signal bottleneck.")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--case-id", action="append", default=[])
    ap.add_argument("--limit", type=int)
    ap.add_argument("--engine", choices=["template", "newmulti-guided-warmup", "adaptive-mmio-warmup"], default="newmulti-guided-warmup")
    ap.add_argument("--run-template", default="")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--chunk-run-for", default="5m")
    ap.add_argument("--max-iters", type=int, default=0, help="0 means unlimited until bottleneck")
    ap.add_argument("--majority", type=int, default=2)
    ap.add_argument("--consecutive", type=int, default=2)
    ap.add_argument("--window-s", type=int)
    ap.add_argument("--min-elapsed-s", type=int)
    ap.add_argument("--cov-epsilon", type=int, default=0)
    ap.add_argument("--input-epsilon", type=int, default=0)
    ap.add_argument("--min-mmio-accesses", type=int, default=500)
    ap.add_argument("--mmio-top-share-threshold", type=float, default=0.50)
    ap.add_argument("--mmio-hhi-threshold", type=float, default=0.35)
    ap.add_argument("--crash-hang-noise-threshold", type=int, default=50)
    ap.add_argument("--min-recent-rate", type=float, default=0.0)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = repo / manifest_path
    out_root = Path(args.out_root)
    if not out_root.is_absolute():
        out_root = repo / out_root
    out_root.mkdir(parents=True, exist_ok=True)

    chunk_s = parse_duration_seconds(args.chunk_run_for)
    cfg = Config(
        window_s=args.window_s if args.window_s is not None else chunk_s,
        min_elapsed_s=args.min_elapsed_s if args.min_elapsed_s is not None else max(30, chunk_s // 2),
        cov_epsilon=args.cov_epsilon,
        input_epsilon=args.input_epsilon,
        min_mmio_accesses=args.min_mmio_accesses,
        mmio_top_share_threshold=args.mmio_top_share_threshold,
        mmio_hhi_threshold=args.mmio_hhi_threshold,
        crash_hang_noise_threshold=args.crash_hang_noise_threshold,
        min_recent_rate=args.min_recent_rate,
        majority=args.majority,
        consecutive=args.consecutive,
    )
    if args.engine == "template" and not args.run_template:
        raise SystemExit("--engine template requires --run-template")
    cases = select_cases(load_jsonl(manifest_path), args.case_id, args.limit)
    if not cases:
        raise SystemExit("No cases selected")
    save_json(out_root / "random_until_bottleneck_config.json", {"repo": str(repo), "manifest": str(manifest_path), "engine": args.engine, "cases": [manifest_case_id(c) for c in cases], "reps": args.reps, "chunk_run_for": args.chunk_run_for, "max_iters": args.max_iters, "config": asdict(cfg)})

    all_analyses: List[Analysis] = []
    final_decisions: Dict[str, Any] = {}
    run_for = duration_for_cli(chunk_s)

    for case in cases:
        case_id = safe_id(manifest_case_id(case))
        print(f"\n===== CASE {case_id} =====")
        rep_histories: Dict[int, List[Analysis]] = {r: [] for r in range(1, args.reps + 1)}
        rep_imports: Dict[int, Optional[Path]] = {r: None for r in range(1, args.reps + 1)}
        case_root = out_root / case_id
        iteration = 0
        while True:
            iteration += 1
            if args.max_iters and iteration > args.max_iters:
                print(f"[stop] max-iters reached for {case_id}")
                break
            print(f"\n--- iteration {iteration} case={case_id} ---")
            for rep in range(1, args.reps + 1):
                if rep_confirmed(rep_histories[rep], cfg.consecutive):
                    print(f"[skip] rep={rep} already confirmed")
                    continue
                chunk_root = case_root / f"rep_{rep:02d}" / f"chunk_{iteration:03d}"
                marker = chunk_root / ".observed_run_root"
                if args.resume and marker.exists():
                    observed = Path(marker.read_text().strip())
                    q = queue_dir_from_run_root(observed)
                    rc = 0
                else:
                    if args.engine == "template":
                        rc, observed, q, _ = run_template(repo, case, case_id, rep, iteration, chunk_root, run_for, rep_imports[rep], args.run_template, args.dry_run)
                    elif args.engine == "newmulti-guided-warmup":
                        rc, observed, q, _ = run_newmulti_guided_warmup(repo, case, case_id, rep, iteration, chunk_root, run_for, rep_imports[rep], args.dry_run)
                    else:
                        rc, observed, q, _ = run_adaptive_mmio_warmup(repo, case, case_id, rep, iteration, chunk_root, run_for, rep_imports[rep], args.dry_run)
                    marker.parent.mkdir(parents=True, exist_ok=True)
                    marker.write_text(str(observed), encoding="utf-8")
                rep_imports[rep] = q
                analysis = analyze_chunk(case_id, rep, iteration, observed, cfg)
                if rc != 0:
                    analysis.notes = f"runner_returncode={rc}"
                    if analysis.status in {"no_runlog_metrics", "too_short"}:
                        analysis.status = "runner_failed_or_incomplete"
                        analysis.decision = "continue"
                        analysis.reasons += f"+runner_rc={rc}"
                rep_histories[rep].append(analysis)
                all_analyses.append(analysis)
                print(f"[analysis] rep={rep} iter={iteration} status={analysis.status} score={analysis.score} covΔ={analysis.recent_cov_delta} inΔ={analysis.recent_in_delta} mmio={analysis.mmio_total_accesses} top={analysis.mmio_top_share} reasons={analysis.reasons}")
            case_rows = [a for hist in rep_histories.values() for a in hist]
            write_history_csv(case_root / "random_bottleneck_history.csv", case_rows)
            write_history_csv(out_root / "random_bottleneck_history.csv", all_analyses)
            reached, decision = target_decision(rep_histories, cfg.majority, cfg.consecutive)
            decision.update({"case_id": case_id, "iteration": iteration, "decision": "stop_random_bottleneck_reached" if reached else "continue_random", "out_root": str(case_root)})
            save_json(case_root / "random_bottleneck_decision.json", decision)
            if reached:
                print(f"[stop] bottleneck reached for {case_id}: votes={decision['votes']}/{decision['majority']}")
                break
            if args.dry_run:
                print("[dry-run] stop after one iteration")
                break
        final_decisions[case_id] = decision

    summary = {"decisions": final_decisions, "status_counts": dict(Counter(a.status for a in all_analyses))}
    save_json(out_root / "random_until_bottleneck_summary.json", summary)
    write_history_csv(out_root / "random_bottleneck_history.csv", all_analyses)
    print("\n===== SUMMARY =====")
    print("out_root:", out_root)
    print("history:", out_root / "random_bottleneck_history.csv")
    print("summary:", out_root / "random_until_bottleneck_summary.json")
    print("status_counts:", summary["status_counts"])


if __name__ == "__main__":
    main()
