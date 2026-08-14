from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional


def check_coverage(
    *,
    baseline_coverage_json: Path,
    foundry_root: Path,
    out_dir: Path,
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Coverage gate (MVP).

    Current behavior:
      - Runs `forge coverage --report lcov` and writes candidate_coverage.lcov
      - Marks ok=True (no diffing yet)

    Upgrade later:
      - Parse LCOV or your coverage.json and ensure no regression
    """
    policy = policy or {}
    out_dir.mkdir(parents=True, exist_ok=True)

    cand_lcov = out_dir / "candidate_coverage.lcov"
    log_path = out_dir / "coverage.log.txt"

    cmd = ["forge", "coverage", "--report", "lcov", "--report-file", str(cand_lcov)]
    res = subprocess.run(
        cmd,
        cwd=str(foundry_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    log_path.write_text(res.stdout or "", encoding="utf-8")

    # permissive MVP: require command success only
    ok = (res.returncode == 0) and cand_lcov.exists()
    return {
        "ok": ok,
        "cmd": " ".join(cmd),
        "returncode": res.returncode,
        "candidate_lcov": str(cand_lcov),
        "baseline_coverage_json": str(baseline_coverage_json),
        "log": str(log_path),
        "note": "MVP coverage gate: only checks coverage command succeeded. Add diffing later.",
    }
