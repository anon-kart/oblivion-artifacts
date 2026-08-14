# validator/test_runner.py

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


def _build_match_test_regex(tests: List[str]) -> str:
    r"""
    Forge --match-test matches test identifiers in a way that can include:
      - testName
      - ContractName.testName
      - ContractName::testName
    We build a regex that matches any of those forms for the given test names.

    Example output patterns we want to match:
      test_sumGridDots_basic
      LoopPlayground_Harness.test_sumGridDots_basic
      LoopPlayground_Harness::test_sumGridDots_basic
    """
    escaped = [re.escape(t.strip()) for t in (tests or []) if t and t.strip()]
    if not escaped:
        return ""

    # Match either:
    #   ^testName$
    #   ^Anything.testName$
    #   ^Anything::testName$
    # We anchor to end to reduce accidental matches.
    parts = [rf"(?:^|.*[.:]{{1,2}}){t}$" for t in escaped]
    return "|".join(parts)


def _parse_gas_from_output(output: str) -> Dict[str, int]:
    """
    Extract gas usage per test from Forge output lines like:
      [PASS] test_xxx() (gas: 12345)
    """
    gas_by_test: Dict[str, int] = {}
    pat = re.compile(r"\[PASS\]\s+(\S+)\(\)\s+\(gas:\s*(\d+)\)")
    for line in output.splitlines():
        m = pat.search(line)
        if m:
            gas_by_test[m.group(1)] = int(m.group(2))
    return gas_by_test


def run_tests(
    *,
    foundry_root: Path,
    out_dir: Path,
    tests: Optional[List[str]] = None,
    force_full_suite: bool = False,
    parse_gas: bool = False,
    log_name: str = "test.log.txt",
    match_contract: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Runs forge tests with optional filtering.

    Recommended usage for your pipeline:
      - pass match_contract="<Contract>_Harness"
      - set force_full_suite=True
      - parse_gas=True
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tests = tests or []
    log_path = out_dir / log_name

    cmd: List[str] = ["forge", "test", "-vv"]

    # Prefer matching the harness contract (stable)
    if match_contract:
        cmd += ["--match-contract", match_contract]

    # Only use match-test if explicitly requested and not running full suite
    if tests and not force_full_suite and not match_contract:
        rgx = _build_match_test_regex(tests)
        if rgx:
            cmd += ["--match-test", rgx]

    res = subprocess.run(
        cmd,
        cwd=str(foundry_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    output = res.stdout or ""
    log_path.write_text(output, encoding="utf-8")

    gas_by_test: Dict[str, int] = {}
    if parse_gas and res.returncode == 0:
        gas_by_test = _parse_gas_from_output(output)

    return {
        "ok": res.returncode == 0,
        "cmd": " ".join(cmd),
        "returncode": res.returncode,
        "log": str(log_path),
        "gas_by_test": gas_by_test,
    }
