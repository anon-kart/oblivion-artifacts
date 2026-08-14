from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict


def check_compile(*, foundry_root: Path, out_dir: Path) -> Dict[str, Any]:
    """
    Runs `forge build` and captures logs with enough detail for debugging.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    stdout_log = out_dir / "compile.stdout.txt"
    stderr_log = out_dir / "compile.stderr.txt"
    combined_log = out_dir / "compile.log.txt"

    cmd = ["forge", "build"]
    res = subprocess.run(
        cmd,
        cwd=str(foundry_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    stdout_text = res.stdout or ""
    stderr_text = res.stderr or ""
    combined_text = stdout_text
    if stderr_text:
        if combined_text:
            combined_text += "\n"
        combined_text += stderr_text

    stdout_log.write_text(stdout_text, encoding="utf-8")
    stderr_log.write_text(stderr_text, encoding="utf-8")
    combined_log.write_text(combined_text, encoding="utf-8")

    # Extract a compact compiler error summary from the last non-empty lines
    tail_lines = [ln.strip() for ln in combined_text.splitlines() if ln.strip()]
    tail_preview = "\n".join(tail_lines[-12:]) if tail_lines else ""

    reason = "ok" if res.returncode == 0 else "compile_failed"

    return {
        "ok": res.returncode == 0,
        "cmd": " ".join(cmd),
        "returncode": res.returncode,
        "reason": reason,
        "log": str(combined_log),
        "stdout_log": str(stdout_log),
        "stderr_log": str(stderr_log),
        "stdout": stdout_text[:4000],
        "stderr": stderr_text[:4000],
        "error_summary": tail_preview[:2000],
    }