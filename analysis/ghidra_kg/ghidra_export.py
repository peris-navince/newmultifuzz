from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional


class GhidraExportError(RuntimeError):
    pass


def _candidate_ghidra_homes(extra_roots: Optional[List[str]] = None) -> List[Path]:
    out: List[Path] = []
    envs = [
        os.environ.get("GHIDRA_HOME"),
        os.environ.get("GHIDRA_INSTALL_DIR"),
    ]
    for x in envs:
        if x:
            out.append(Path(x))

    roots = [Path.cwd(), Path(__file__).resolve().parents[2]]
    for r in extra_roots or []:
        out.append(Path(r))
    for root in roots:
        out.extend(root.glob("ghidra*"))
        out.extend(root.glob("**/ghidra*"))
        out.extend(root.glob("**/Ghidra*"))
    return out


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
    raise GhidraExportError(
        "Could not find Ghidra analyzeHeadless. Set GHIDRA_HOME or pass --ghidra-home."
    )


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


def export_with_ghidra(
    binary: str,
    out_json: str,
    ghidra_home: Optional[str] = None,
    script_dir: Optional[str] = None,
    processor: Optional[str] = None,
    language_id: Optional[str] = None,
    max_functions: int = 0,
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
    runtime, runner = _choose_runtime(script_name, ghidra_home=ghidra_home, extra_roots=extra_roots)
    if not runner.exists():
        raise GhidraExportError(f"Ghidra launcher not found: {runner}")

    out_json_path.parent.mkdir(parents=True, exist_ok=True)
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

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        shutil.rmtree(project_root, ignore_errors=True)
    except Exception:
        pass

    stdout = proc.stdout or ""

    if proc.returncode != 0:
        if runtime == "pyghidra" and "Do you wish to install PyGhidra" in stdout:
            raise GhidraExportError(
                "Ghidra tried to launch the Python exporter via PyGhidra, but PyGhidra is not installed "
                "for this Ghidra user profile.\n"
                "Create/install the Ghidra PyGhidra environment first, then rerun.\n\n"
                f"CMD: {' '.join(cmd)}\n\n{stdout}"
            )
        raise GhidraExportError(f"Ghidra export failed\nCMD: {' '.join(cmd)}\n\n{stdout}")

    if not out_json_path.exists():
        raise GhidraExportError(
            f"Ghidra finished but output JSON missing: {out_json_path}\n\n"
            f"Runtime: {runtime}\n"
            f"CMD: {' '.join(cmd)}\n\n{stdout}"
        )

    data = json.loads(out_json_path.read_text(encoding="utf-8"))
    data.setdefault("_ghidra_stdout", stdout)
    data.setdefault("_ghidra_runtime", runtime)
    data.setdefault("_ghidra_cmd", cmd)
    return data
