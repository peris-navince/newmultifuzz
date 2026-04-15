from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class GhidraExportError(RuntimeError):
    pass


def _candidate_ghidra_homes(extra_roots: Optional[List[str]] = None) -> List[Path]:
    out: List[Path] = []
    for name in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR"):
        value = os.environ.get(name)
        if value:
            out.append(Path(value))

    roots = [Path.cwd(), Path(__file__).resolve().parents[2]]
    for r in extra_roots or []:
        if r:
            out.append(Path(r))
    for root in roots:
        if root.exists():
            out.extend(root.glob("ghidra*"))
            out.extend(root.glob("**/ghidra*"))
            out.extend(root.glob("**/Ghidra*"))
    # Preserve order but remove duplicates.
    seen: set[str] = set()
    deduped: List[Path] = []
    for p in out:
        try:
            key = str(p.resolve())
        except Exception:
            key = str(p)
        if key not in seen:
            seen.add(key)
            deduped.append(p)
    return deduped


def find_analyze_headless(extra_roots: Optional[List[str]] = None) -> Path:
    env_home = os.environ.get("GHIDRA_HOME")
    if env_home:
        p = Path(env_home) / "support" / "analyzeHeadless"
        if p.exists():
            return p

    which = shutil.which("analyzeHeadless")
    if which:
        return Path(which)

    for home in _candidate_ghidra_homes(extra_roots=extra_roots):
        p = home / "support" / "analyzeHeadless"
        if p.exists():
            return p
    raise GhidraExportError("Could not find Ghidra support/analyzeHeadless. Set GHIDRA_HOME or pass --ghidra-home.")


def find_pyghidra_run(extra_roots: Optional[List[str]] = None) -> Optional[Path]:
    env_home = os.environ.get("GHIDRA_HOME")
    if env_home:
        p = Path(env_home) / "support" / "pyghidraRun"
        if p.exists():
            return p

    which = shutil.which("pyghidraRun")
    if which:
        return Path(which)

    for home in _candidate_ghidra_homes(extra_roots=extra_roots):
        p = home / "support" / "pyghidraRun"
        if p.exists():
            return p
    return None


def _parse_java_major(version_text: str) -> Optional[int]:
    # Handles both `openjdk version "21.0.10"` and legacy `1.8.0` formats.
    m = re.search(r'version\s+"([^"]+)"', version_text)
    if not m:
        return None
    version = m.group(1)
    if version.startswith("1."):
        parts = version.split(".")
        if len(parts) > 1 and parts[1].isdigit():
            return int(parts[1])
        return None
    first = re.split(r"[.+_-]", version)[0]
    return int(first) if first.isdigit() else None


def _run_java_version(env: Optional[Dict[str, str]] = None) -> Tuple[Optional[int], str, str]:
    java = shutil.which("java", path=(env or os.environ).get("PATH")) or "java"
    try:
        proc = subprocess.run([java, "-version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, timeout=15)
        text = proc.stdout or ""
        return _parse_java_major(text), java, text.strip()
    except Exception as e:
        return None, java, f"java -version failed: {type(e).__name__}: {e}"


def _check_java21(env: Optional[Dict[str, str]], log: Optional[Path], verbose: bool) -> None:
    major, java, text = _run_java_version(env=env)
    _log_line(log, f"[preflight] java={java}")
    _log_line(log, f"[preflight] java -version: {text}")
    if verbose:
        print(f"[preflight] java={java}", flush=True)
        print(f"[preflight] java -version: {text}", flush=True)
    if major is None or major < 21:
        raise GhidraExportError(
            "Ghidra 12.x requires JDK 21+ but the active Java is not suitable.\n"
            f"Detected java: {java}\n"
            f"Version output:\n{text}\n\n"
            "Fix without root, for example:\n"
            "  export JAVA_HOME=/home/wgh/tools/jdk-21\n"
            "  export PATH=\"$JAVA_HOME/bin:$PATH\"\n"
            "  java -version\n"
        )


def _check_pyghidra_import(log: Optional[Path], verbose: bool) -> None:
    proc = subprocess.run(
        [sys.executable, "-c", "import pyghidra, jpype; print('pyghidra import ok')"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )
    text = (proc.stdout or "").strip()
    _log_line(log, f"[preflight] python={sys.executable}")
    _log_line(log, f"[preflight] pyghidra import: returncode={proc.returncode}; {text}")
    if verbose:
        print(f"[preflight] python={sys.executable}", flush=True)
        print(f"[preflight] pyghidra import: returncode={proc.returncode}; {text}", flush=True)
    if proc.returncode != 0:
        raise GhidraExportError(
            "PyGhidra is not installed in the active Python environment.\n"
            f"Python: {sys.executable}\n"
            f"Output:\n{text}\n\n"
            "Install it explicitly instead of letting pyghidraRun ask interactively:\n"
            "  source extractor/.venv/bin/activate\n"
            "  pip install -r requirements-ghidra.txt\n"
            "or:\n"
            "  pip install pyghidra jpype1 packaging\n"
        )


def _build_headless_cmd(
    *,
    runner: Path,
    runtime: str,
    project_root: Path,
    project_name: str,
    binary_path: Path,
    script_dir_path: Path,
    script_name: str,
    out_json_path: Path,
    processor: Optional[str],
    language_id: Optional[str],
    max_functions: int,
) -> list[str]:
    cmd: list[str] = [str(runner)]
    if runtime == "pyghidra":
        cmd.append("-H")

    cmd.extend([
        str(project_root),
        project_name,
        "-import",
        str(binary_path),
        "-scriptPath",
        str(script_dir_path),
        "-postScript",
        script_name,
        str(out_json_path),
        str(max_functions),
    ])
    if language_id:
        cmd.extend(["-processor", language_id])
    elif processor:
        cmd.extend(["-processor", processor])
    return cmd


def _choose_runtime(script_name: str, ghidra_home: Optional[str], extra_roots: list[str]) -> tuple[str, Path]:
    # In Ghidra 12, plain `.py` Ghidra scripts are served by the PyGhidra provider.
    # Launching them with plain `analyzeHeadless` causes:
    #   "Ghidra was not started with PyGhidra. Python is not available"
    if script_name.endswith(".py"):
        runner = find_pyghidra_run(extra_roots=extra_roots)
        if runner is not None:
            return "pyghidra", runner
        raise GhidraExportError(
            "Python Ghidra script requires support/pyghidraRun, but it was not found. "
            "Install a full Ghidra release with PyGhidra support, or replace the exporter with a non-Python script."
        )

    if ghidra_home:
        runner = Path(ghidra_home) / "support" / "analyzeHeadless"
    else:
        runner = find_analyze_headless(extra_roots=extra_roots)
    return "analyzeHeadless", runner


def _log_line(log_path: Optional[Path], line: str) -> None:
    if not log_path:
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")


def _run_ghidra_command(
    cmd: List[str],
    *,
    env: Dict[str, str],
    log_path: Path,
    timeout_sec: int,
    verbose: bool,
) -> Tuple[int, str]:
    _log_line(log_path, "[ghidra-export] CMD: " + " ".join(cmd))
    _log_line(log_path, f"[ghidra-export] timeout_sec={timeout_sec}")
    if verbose:
        print("[ghidra-export] CMD: " + " ".join(cmd), flush=True)
        print(f"[ghidra-export] stdout/stderr -> {log_path}", flush=True)

    started = time.time()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        env=env,
    )
    lines: List[str] = []
    try:
        assert proc.stdout is not None
        while True:
            if proc.poll() is not None:
                rest = proc.stdout.read() or ""
                if rest:
                    for line in rest.splitlines():
                        lines.append(line)
                        _log_line(log_path, line)
                        if verbose:
                            print(line, flush=True)
                break
            line = proc.stdout.readline()
            if line:
                line = line.rstrip("\n")
                lines.append(line)
                _log_line(log_path, line)
                if verbose:
                    print(line, flush=True)
                if "Do you wish to install PyGhidra" in line:
                    proc.kill()
                    raise GhidraExportError(
                        "pyghidraRun attempted to ask an interactive question: 'Do you wish to install PyGhidra (y/n)?'.\n"
                        "This is not allowed in the automated pipeline. Install dependencies first:\n"
                        "  source extractor/.venv/bin/activate\n"
                        "  pip install -r requirements-ghidra.txt\n"
                        f"Full log: {log_path}"
                    )
            if time.time() - started > timeout_sec:
                proc.kill()
                raise GhidraExportError(
                    f"Ghidra export timed out after {timeout_sec}s. Full stdout/stderr was written to: {log_path}"
                )
            if not line:
                time.sleep(0.1)
    finally:
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    return proc.returncode or 0, "\n".join(lines)


def export_with_ghidra(
    binary: str,
    out_json: str,
    ghidra_home: Optional[str] = None,
    script_dir: Optional[str] = None,
    processor: Optional[str] = None,
    language_id: Optional[str] = None,
    max_functions: int = 0,
    *,
    timeout_sec: int = 1800,
    log_path: str | None = None,
    verbose: bool = False,
) -> dict:
    binary_path = Path(binary).resolve()
    out_json_path = Path(out_json).resolve()
    if not binary_path.exists():
        raise FileNotFoundError(f"binary not found: {binary_path}")

    script_dir_path = Path(script_dir or Path(__file__).resolve().parent / "ghidra_scripts").resolve()
    script_name = "export_binary_kg.py"
    if not (script_dir_path / script_name).exists():
        raise GhidraExportError(f"Ghidra script missing: {script_dir_path / script_name}")

    extra_roots = [str(binary_path.parent), str(Path.cwd())]
    if ghidra_home:
        extra_roots.append(ghidra_home)
    runtime, runner = _choose_runtime(script_name, ghidra_home=ghidra_home, extra_roots=extra_roots)
    if not runner.exists():
        raise GhidraExportError(f"Ghidra launcher not found: {runner}")

    out_json_path.parent.mkdir(parents=True, exist_ok=True)
    log = Path(log_path).resolve() if log_path else out_json_path.with_suffix(".ghidra.log")
    # Fresh log for each run.
    try:
        log.unlink()
    except FileNotFoundError:
        pass

    env = os.environ.copy()
    # Propagate explicit Ghidra home so pyghidraRun sees the same installation.
    if ghidra_home:
        env["GHIDRA_HOME"] = str(Path(ghidra_home).resolve())

    _log_line(log, f"[preflight] runtime={runtime}")
    _log_line(log, f"[preflight] runner={runner}")
    _check_java21(env=env, log=log, verbose=verbose)
    if runtime == "pyghidra":
        _check_pyghidra_import(log=log, verbose=verbose)

    project_root = Path(tempfile.mkdtemp(prefix="ghidra_kg_proj_"))
    project_name = "kgproj"

    cmd = _build_headless_cmd(
        runner=runner,
        runtime=runtime,
        project_root=project_root,
        project_name=project_name,
        binary_path=binary_path,
        script_dir_path=script_dir_path,
        script_name=script_name,
        out_json_path=out_json_path,
        processor=processor,
        language_id=language_id,
        max_functions=max_functions,
    )

    stdout = ""
    try:
        returncode, stdout = _run_ghidra_command(cmd, env=env, log_path=log, timeout_sec=max(1, int(timeout_sec)), verbose=verbose)
    finally:
        try:
            shutil.rmtree(project_root, ignore_errors=True)
        except Exception:
            pass

    if returncode != 0:
        raise GhidraExportError(f"Ghidra export failed with return code {returncode}.\nCMD: {' '.join(cmd)}\nLog: {log}")

    if not out_json_path.exists():
        raise GhidraExportError(
            f"Ghidra finished but output JSON is missing: {out_json_path}\n"
            f"Runtime: {runtime}\nCMD: {' '.join(cmd)}\nLog: {log}"
        )

    data = json.loads(out_json_path.read_text(encoding="utf-8"))
    data.setdefault("_ghidra_stdout", stdout)
    data.setdefault("_ghidra_runtime", runtime)
    data.setdefault("_ghidra_cmd", cmd)
    data.setdefault("_ghidra_log", str(log))
    data.setdefault("_ghidra_timeout_sec", timeout_sec)
    return data
