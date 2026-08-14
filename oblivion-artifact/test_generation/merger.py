from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from execution_evidence import ExecutionEvidence


@dataclass
class MergeArtifacts:
    merged_tests_dir: Path
    merged_manifest_path: Path
    merged_test_results_path: Path
    merged_test_summary_path: Path
    merged_traces_json_path: Path
    merged_traces_dir: Path
    merged_coverage_json_path: Path
    merged_lcov_path: Path
    merged_stdout_path: Path
    retained_tests: List[Dict[str, Any]]
    coverage_gain_summary: Dict[str, Any]
    evidence: ExecutionEvidence
    evidence_dict: Dict[str, Any]


def merge_verified_tests(
    *,
    foundry_root: Path,
    verification_manifest: Sequence[Dict[str, Any]],
    out_dir: Path,
    forge_bin: str = "forge",
    fuzz_runs: int = 256,
    match_contract: Optional[str] = None,
    baseline_coverage: Optional[Dict[str, Any]] = None,
    merge_subdir_name: str = "merged",
    merged_tests_subdir_name: str = "merged_tests",
) -> MergeArtifacts:
    """
    Merge only retained verified tests into the final merged suite, then:
      - rerun forge test
      - rerun forge coverage
      - collect traces
      - emit merged artifacts

    Canonical outputs:
      <out_dir>/<merge_subdir_name>/
        merged_manifest.json
        test_results.json
        test_summary.json
        traces.json
        traces/
        coverage.json
        coverage.lcov
        merged_test_stdout.txt
    """
    foundry_root = Path(foundry_root).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    merged_dir = out_dir / merge_subdir_name
    merged_dir.mkdir(parents=True, exist_ok=True)

    merged_tests_dir = merged_dir / merged_tests_subdir_name
    merged_tests_dir.mkdir(parents=True, exist_ok=True)

    retained_tests = [dict(x) for x in verification_manifest if bool(x.get("retained"))]

    for entry in retained_tests:
        merged_test_path = entry.get("merged_test_path")
        generated_test_path = entry.get("generated_test_path")
        filename = str(entry.get("filename") or "")

        src = None
        if merged_test_path and Path(str(merged_test_path)).exists():
            src = Path(str(merged_test_path))
        elif generated_test_path and Path(str(generated_test_path)).exists():
            src = Path(str(generated_test_path))
        elif filename:
            candidate = merged_tests_dir / filename
            if candidate.exists():
                src = candidate

        if src is None:
            continue

        dst = merged_tests_dir / src.name
        if src.resolve() != dst.resolve():
            shutil.copy2(src, dst)

        entry["final_merged_test_path"] = str(dst)

    merged_manifest_path = merged_dir / "merged_manifest.json"
    merged_stdout_path = merged_dir / "merged_test_stdout.txt"
    merged_lcov_path = merged_dir / "coverage.lcov"
    merged_traces_json_path = merged_dir / "traces.json"
    merged_traces_dir = merged_dir / "traces"
    merged_test_results_path = merged_dir / "test_results.json"
    merged_test_summary_path = merged_dir / "test_summary.json"
    merged_coverage_json_path = merged_dir / "coverage.json"

    _run_merged_forge_tests(
        foundry_root=foundry_root,
        forge_bin=forge_bin,
        stdout_path=merged_stdout_path,
        fuzz_runs=fuzz_runs,
        match_contract=match_contract,
    )

    _run_merged_forge_coverage(
        foundry_root=foundry_root,
        forge_bin=forge_bin,
        lcov_path=merged_lcov_path,
        fuzz_runs=fuzz_runs,
        match_contract=match_contract,
    )

    evidence = ExecutionEvidence.from_paths(
        test_stdout=merged_stdout_path,
        coverage_lcov=merged_lcov_path,
    )

    _write_evidence_artifacts(
        evidence=evidence,
        out_dir=merged_dir,
        traces_subdir_name="traces",
    )

    coverage_gain_summary = _compute_coverage_gain_summary(
        baseline_coverage=baseline_coverage or {},
        merged_coverage=evidence.coverage or {},
    )

    merged_manifest_payload = {
        "retained_tests": retained_tests,
        "num_retained_tests": len(retained_tests),
        "coverage_gain_summary": coverage_gain_summary,
    }
    merged_manifest_path.write_text(
        json.dumps(merged_manifest_payload, indent=2),
        encoding="utf-8",
    )

    evidence_dict = {
        "tests": dict(evidence.tests or {}),
        "traces": dict(evidence.traces or {}),
        "coverage": dict(evidence.coverage or {}),
    }

    return MergeArtifacts(
        merged_tests_dir=merged_tests_dir,
        merged_manifest_path=merged_manifest_path,
        merged_test_results_path=merged_test_results_path,
        merged_test_summary_path=merged_test_summary_path,
        merged_traces_json_path=merged_traces_json_path,
        merged_traces_dir=merged_traces_dir,
        merged_coverage_json_path=merged_coverage_json_path,
        merged_lcov_path=merged_lcov_path,
        merged_stdout_path=merged_stdout_path,
        retained_tests=retained_tests,
        coverage_gain_summary=coverage_gain_summary,
        evidence=evidence,
        evidence_dict=evidence_dict,
    )


def _run_merged_forge_tests(
    *,
    foundry_root: Path,
    forge_bin: str,
    stdout_path: Path,
    fuzz_runs: int,
    match_contract: Optional[str],
) -> None:
    # IMPORTANT:
    # Use -vvvv here so ExecutionEvidence.parse_forge_test_stdout(...)
    # can actually recover the "Traces:" block and internal calls/events.
    cmd = [forge_bin, "test", "-vvvv"]
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
    _write_command_log(stdout_path, cmd, proc.stdout, proc.stderr)

    if proc.returncode != 0:
        raise RuntimeError(
            f"Merged suite forge test failed with exit code {proc.returncode}. "
            f"See {stdout_path}"
        )


def _run_merged_forge_coverage(
    *,
    foundry_root: Path,
    forge_bin: str,
    lcov_path: Path,
    fuzz_runs: int,
    match_contract: Optional[str],
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
            "Merged suite forge coverage failed with exit code "
            f"{proc.returncode}. stdout={proc.stdout[:4000]} stderr={proc.stderr[:4000]}"
        )

    if not lcov_path.exists():
        raise RuntimeError(f"Merged LCOV file not found: {lcov_path}")


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
        safe_name = _sanitize_filename(test_name)
        (traces_dir / f"{safe_name}.json").write_text(
            json.dumps(entries, indent=2),
            encoding="utf-8",
        )


def _compute_coverage_gain_summary(
    *,
    baseline_coverage: Dict[str, Any],
    merged_coverage: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compute lightweight coverage delta summary across matching files.

    Expected coverage shape:
      {
        "src/Foo.sol": {
          "lines": {"10": 1, "11": 0, ...},
          "functions": {"foo": 3, "bar": 0, ...}
        }
      }
    """
    summary: Dict[str, Any] = {
        "files": {},
        "total_newly_hit_lines": 0,
        "total_improved_functions": 0,
    }

    all_files = set()
    all_files.update(str(k) for k in (baseline_coverage or {}).keys())
    all_files.update(str(k) for k in (merged_coverage or {}).keys())

    total_new_lines = 0
    total_improved_functions = 0

    for file_key in sorted(all_files):
        base_entry = _as_dict((baseline_coverage or {}).get(file_key))
        merged_entry = _as_dict((merged_coverage or {}).get(file_key))

        base_lines = _normalize_int_map(base_entry.get("lines") or {})
        merged_lines = _normalize_int_map(merged_entry.get("lines") or {})

        base_functions = _normalize_int_map(base_entry.get("functions") or {}, keys_as_str=True)
        merged_functions = _normalize_int_map(merged_entry.get("functions") or {}, keys_as_str=True)

        newly_hit_lines = sorted(
            int(line_no)
            for line_no, merged_hits in merged_lines.items()
            if merged_hits > 0 and base_lines.get(int(line_no), 0) <= 0
        )

        improved_functions = sorted(
            fn_name
            for fn_name, merged_hits in merged_functions.items()
            if merged_hits > base_functions.get(fn_name, 0)
        )

        file_summary = {
            "newly_hit_lines": newly_hit_lines,
            "num_newly_hit_lines": len(newly_hit_lines),
            "improved_functions": improved_functions,
            "num_improved_functions": len(improved_functions),
        }
        summary["files"][file_key] = file_summary

        total_new_lines += len(newly_hit_lines)
        total_improved_functions += len(improved_functions)

    summary["total_newly_hit_lines"] = total_new_lines
    summary["total_improved_functions"] = total_improved_functions
    return summary


def _normalize_int_map(
    data: Dict[Any, Any],
    *,
    keys_as_str: bool = False,
) -> Dict[Any, int]:
    out: Dict[Any, int] = {}
    for k, v in data.items():
        try:
            key = str(k) if keys_as_str else int(k)
            out[key] = int(v)
        except Exception:
            continue
    return out


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _write_command_log(path: Path, cmd: Sequence[str], stdout: str, stderr: str) -> None:
    content = []
    content.append(f"$ {' '.join(cmd)}")
    content.append("")
    content.append("=== STDOUT ===")
    content.append(stdout or "")
    content.append("")
    content.append("=== STDERR ===")
    content.append(stderr or "")
    path.write_text("\n".join(content), encoding="utf-8")


def _sanitize_filename(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"_", "-", "."} else "_" for ch in str(value))
    safe = safe.strip("._")
    return safe or "trace"