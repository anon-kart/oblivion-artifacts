from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from execution_evidence import ExecutionEvidence


@dataclass
class BaselineArtifacts:
    foundry_root: Path
    out_dir: Path
    stdout_path: Path
    lcov_path: Path
    coverage_json_path: Path
    traces_dir: Path
    traces_json_path: Path
    test_results_path: Path
    test_summary_path: Path
    evidence: ExecutionEvidence
    evidence_dict: Dict[str, Any]
    fuzz_runs: int
    match_contract: Optional[str]
    forge_bin: str
    verbosity: str


def run_baseline_stage(
    *,
    foundry_root: Path,
    out_dir: Path,
    forge_bin: str = "forge",
    fuzz_runs: int = 256,
    verbosity: str = "-vvvv",
    match_contract: Optional[str] = None,
    traces_subdir_name: str = "traces",
    baseline_prefix: str = "baseline",
) -> BaselineArtifacts:
    foundry_root = Path(foundry_root).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    stdout_path = out_dir / f"{baseline_prefix}_test_stdout.txt"
    lcov_path = out_dir / f"{baseline_prefix}_coverage.lcov"
    snapshot_dir = out_dir / f"{baseline_prefix}_snapshot"

    _run_forge_tests(
        foundry_root=foundry_root,
        stdout_path=stdout_path,
        forge_bin=forge_bin,
        match_contract=match_contract,
        verbosity=verbosity,
        fuzz_runs=fuzz_runs,
    )

    _run_forge_coverage(
        foundry_root=foundry_root,
        lcov_path=lcov_path,
        forge_bin=forge_bin,
        match_contract=match_contract,
        fuzz_runs=fuzz_runs,
    )

    evidence = ExecutionEvidence.from_paths(
        test_stdout=stdout_path,
        coverage_lcov=lcov_path,
    )

    _write_evidence_artifacts(
        evidence=evidence,
        out_dir=snapshot_dir,
        traces_subdir_name=traces_subdir_name,
    )

    evidence_dict = {
        "tests": dict(evidence.tests or {}),
        "traces": dict(evidence.traces or {}),
        "coverage": dict(evidence.coverage or {}),
    }

    return BaselineArtifacts(
        foundry_root=foundry_root,
        out_dir=snapshot_dir,
        stdout_path=stdout_path,
        lcov_path=lcov_path,
        coverage_json_path=snapshot_dir / "coverage.json",
        traces_dir=snapshot_dir / traces_subdir_name,
        traces_json_path=snapshot_dir / "traces.json",
        test_results_path=snapshot_dir / "test_results.json",
        test_summary_path=snapshot_dir / "test_summary.json",
        evidence=evidence,
        evidence_dict=evidence_dict,
        fuzz_runs=fuzz_runs,
        match_contract=match_contract,
        forge_bin=forge_bin,
        verbosity=verbosity,
    )


def _run_forge_tests(
    *,
    foundry_root: Path,
    stdout_path: Path,
    forge_bin: str,
    match_contract: Optional[str],
    verbosity: str,
    fuzz_runs: int,
) -> None:
    cmd = [forge_bin, "test"]

    if match_contract:
        cmd += ["--match-contract", match_contract]

    if verbosity:
        cmd.append(verbosity)

    env = os.environ.copy()
    env["FOUNDRY_FUZZ_RUNS"] = str(max(1, int(fuzz_runs)))

    proc = subprocess.run(
        cmd,
        cwd=str(foundry_root),
        capture_output=True,
        text=True,
        env=env,
    )

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    combined = [
        f"$ {' '.join(cmd)}",
        "",
        "=== STDOUT ===",
        stdout,
        "",
        "=== STDERR ===",
        stderr,
        "",
        f"=== RETURN CODE: {proc.returncode} ===",
    ]

    stdout_path.write_text("\n".join(combined), encoding="utf-8")

    if proc.returncode != 0:
        failing_tests = _extract_failing_tests(stdout + "\n" + stderr)
        failure_hint = ""

        if failing_tests:
            failure_hint = "\nFailing tests:\n" + "\n".join(
                f"  - {name}" for name in failing_tests
            )

        tail = _tail(stdout + "\n" + stderr, lines=80)

        raise RuntimeError(
            f"forge test failed with exit code {proc.returncode}. "
            f"See {stdout_path}"
            f"{failure_hint}\n\n"
            f"Last output lines:\n{tail}"
        )


def _run_forge_coverage(
    *,
    foundry_root: Path,
    lcov_path: Path,
    forge_bin: str,
    match_contract: Optional[str],
    fuzz_runs: int,
) -> None:
    cmd = [forge_bin, "coverage", "--report", "lcov", "--report-file", str(lcov_path)]

    if match_contract:
        cmd += ["--match-contract", match_contract]

    env = os.environ.copy()
    env["FOUNDRY_FUZZ_RUNS"] = str(max(1, int(fuzz_runs)))

    proc = subprocess.run(
        cmd,
        cwd=str(foundry_root),
        capture_output=True,
        text=True,
        env=env,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            "forge coverage failed with exit code "
            f"{proc.returncode}. stdout={proc.stdout[:4000]} stderr={proc.stderr[:4000]}"
        )

    if not lcov_path.exists():
        raise RuntimeError(f"forge coverage completed but LCOV file not found: {lcov_path}")


def _write_evidence_artifacts(
    *,
    evidence: ExecutionEvidence,
    out_dir: Path,
    traces_subdir_name: str,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    tests_payload = dict(evidence.tests or {})
    traces_payload = dict(evidence.traces or {})
    coverage_payload = dict(evidence.coverage or {})

    (out_dir / "test_summary.json").write_text(
        json.dumps(tests_payload, indent=2),
        encoding="utf-8",
    )

    (out_dir / "test_results.json").write_text(
        json.dumps(tests_payload, indent=2),
        encoding="utf-8",
    )

    (out_dir / "traces.json").write_text(
        json.dumps(traces_payload, indent=2),
        encoding="utf-8",
    )

    (out_dir / "coverage.json").write_text(
        json.dumps(coverage_payload, indent=2),
        encoding="utf-8",
    )

    traces_dir = out_dir / traces_subdir_name
    traces_dir.mkdir(parents=True, exist_ok=True)

    for test_name, entries in traces_payload.items():
        safe_name = _sanitize_identifier(test_name)
        (traces_dir / f"{safe_name}.json").write_text(
            json.dumps(entries, indent=2),
            encoding="utf-8",
        )


_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_]+")


def _sanitize_identifier(value: str) -> str:
    out = _SANITIZE_RE.sub("_", str(value).strip())
    out = re.sub(r"_+", "_", out).strip("_")

    if not out:
        out = "generated"

    if out[0].isdigit():
        out = f"g_{out}"

    return out


def _extract_failing_tests(output: str) -> list[str]:
    failing = []

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("[FAIL"):
            match = re.search(r"\]\s+([A-Za-z0-9_]+)\(", line)
            if match:
                failing.append(match.group(1))

    return failing


def _tail(text: str, lines: int = 80) -> str:
    parts = text.splitlines()
    return "\n".join(parts[-lines:])