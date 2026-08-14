from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

_FUZZ_PASS_RE = re.compile(r"\[PASS\]\s+(\S+)\([^)]*\)\s+\(runs:\s*(\d+)")
_FUZZ_ANY_RE = re.compile(r"\(runs:\s*(\d+)")
_NO_TESTS_RE = re.compile(r"(No tests to run|No tests match the provided pattern)", re.IGNORECASE)

# Discover test contracts that inherit from Test (directly or indirectly in a simple way).
_CONTRACT_RE = re.compile(
    r"contract\s+([A-Za-z_][A-Za-z0-9_]*)\s+is\s+[^{};]*\bTest\b",
    re.MULTILINE,
)

# Discover test functions and capture their parameter list.
# We intentionally keep this permissive for common Foundry test styles.
_TEST_FN_RE = re.compile(
    r"function\s+(test[0-9A-Za-z_]*)\s*\((.*?)\)\s*"
    r"(?:public|external|internal|private)?",
    re.DOTALL,
)


def _parse_fuzz_hits(output: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for line in output.splitlines():
        m = _FUZZ_PASS_RE.search(line)
        if not m:
            continue
        hits.append({"test": m.group(1), "runs": int(m.group(2))})
    return hits


def _extract_contract_blocks(src: str) -> List[Dict[str, str]]:
    """
    Best-effort extraction of Solidity contract blocks so test functions can be
    attributed to the right test contract.

    This is intentionally lightweight and avoids a full parser dependency.
    """
    blocks: List[Dict[str, str]] = []

    for m in _CONTRACT_RE.finditer(src):
        contract_name = m.group(1)
        brace_start = src.find("{", m.end())
        if brace_start == -1:
            continue

        depth = 0
        i = brace_start
        end = -1
        while i < len(src):
            ch = src[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
            i += 1

        if end == -1:
            continue

        body = src[brace_start + 1 : end]
        blocks.append({"contract": contract_name, "body": body})

    return blocks


def discover_fuzzable_tests(foundry_root: Path) -> List[Dict[str, str]]:
    """
    Discover Foundry fuzzable tests by signature, not by name pattern.

    A test is considered fuzzable if:
      - it is inside a contract inheriting from Test, and
      - its name starts with `test`, and
      - it has at least one parameter.

    This aligns better with how Forge fuzzing actually works.
    """
    discovered: List[Dict[str, str]] = []
    test_root = Path(foundry_root) / "test"

    if not test_root.exists():
        return discovered

    for sol in test_root.rglob("*.sol"):
        try:
            src = sol.read_text(encoding="utf-8")
        except Exception:
            continue

        for block in _extract_contract_blocks(src):
            contract_name = block["contract"]
            body = block["body"]

            for fn_name, params in _TEST_FN_RE.findall(body):
                if params.strip():
                    discovered.append(
                        {
                            "file": str(sol),
                            "contract": contract_name,
                            "test": fn_name,
                        }
                    )

    return discovered


def _run_fuzz_cmd(
    *,
    cmd: List[str],
    foundry_root: Path,
    log_path: Path,
    fuzz_runs: int,
    contract: Optional[str] = None,
    test: Optional[str] = None,
) -> Dict[str, Any]:
    env = os.environ.copy()
    env["FOUNDRY_FUZZ_RUNS"] = str(max(1, int(fuzz_runs)))

    proc = subprocess.run(
        cmd,
        cwd=str(foundry_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    output = proc.stdout or ""
    log_path.write_text(output, encoding="utf-8")

    hits = _parse_fuzz_hits(output)
    detected = bool(hits) or bool(_FUZZ_ANY_RE.search(output))
    no_tests = bool(_NO_TESTS_RE.search(output))

    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "cmd": " ".join(cmd),
        "log": str(log_path),
        "fuzz_runs": int(fuzz_runs),
        "detected_fuzz_tests": detected,
        "matched_tests": hits,
        "matched_count": len(hits),
        "no_tests_matched": no_tests,
        "contract": contract,
        "test": test,
    }


def _run_one_fuzz_test(
    *,
    foundry_root: Path,
    out_dir: Path,
    contract: str,
    test: str,
    fuzz_runs: int,
) -> Dict[str, Any]:
    cmd = [
        "forge",
        "test",
        "--match-contract",
        contract,
        "--match-test",
        f"^{re.escape(test)}$",
        "-vv",
    ]
    log_name = f"short_fuzz.{contract}.{test}.log.txt"
    return _run_fuzz_cmd(
        cmd=cmd,
        foundry_root=foundry_root,
        log_path=out_dir / log_name,
        fuzz_runs=fuzz_runs,
        contract=contract,
        test=test,
    )


def check_short_fuzz(
    *,
    foundry_root: Path,
    out_dir: Path,
    policy: Optional[Dict[str, Any]] = None,
    match_contract: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Explicit short fuzz validation pass.

    Updated strategy:
      1) Discover fuzzable Foundry tests by signature (parameterized `test*` functions).
      2) Prefer tests inside `match_contract` if such tests exist.
      3) Run a bounded number of short fuzz checks with low FOUNDRY_FUZZ_RUNS.
      4) If no fuzzable tests exist, mark the stage as skipped rather than failed.

    This makes the short-fuzz stage real and execution-based, not just pattern-based.
    """
    policy = policy or {}
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    enabled = bool(policy.get("short_fuzz_enabled", True))
    if not enabled:
        return {
            "ok": True,
            "skipped": True,
            "stage": "short_fuzz",
            "reason": "short_fuzz_disabled_by_policy",
        }

    fuzz_runs = int(policy.get("short_fuzz_runs", 64))
    max_tests = int(policy.get("short_fuzz_max_tests", 6))

    discovered = discover_fuzzable_tests(foundry_root)

    if match_contract:
        scoped = [x for x in discovered if x.get("contract") == match_contract]
        selected = scoped if scoped else discovered
        scope = "contract_scoped" if scoped else "project_scoped_fallback"
    else:
        selected = discovered
        scope = "project_scoped"

    if not selected:
        return {
            "ok": True,
            "skipped": True,
            "stage": "short_fuzz",
            "reason": "no_fuzzable_tests_detected",
            "policy": {
                "short_fuzz_enabled": enabled,
                "short_fuzz_runs": fuzz_runs,
                "short_fuzz_max_tests": max_tests,
            },
            "discovered_count": 0,
            "executed_count": 0,
            "executed": [],
        }

    executed: List[Dict[str, Any]] = []
    all_ok = True

    for item in selected[:max_tests]:
        res = _run_one_fuzz_test(
            foundry_root=foundry_root,
            out_dir=out_dir,
            contract=item["contract"],
            test=item["test"],
            fuzz_runs=fuzz_runs,
        )
        executed.append(res)
        if not res.get("ok"):
            all_ok = False
            break

    return {
        "ok": all_ok,
        "skipped": False,
        "stage": "short_fuzz",
        "reason": "ok" if all_ok else "short_fuzz_failed",
        "policy": {
            "short_fuzz_enabled": enabled,
            "short_fuzz_runs": fuzz_runs,
            "short_fuzz_max_tests": max_tests,
        },
        "scope": scope,
        "discovered_count": len(discovered),
        "selected_count": min(len(selected), max_tests),
        "executed_count": len(executed),
        "executed": executed,
    }