from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass
class VerificationResult:
    name: str
    filename: str
    kind: str
    target: Dict[str, Any]

    compile_ok: bool
    isolated_test_ok: bool
    merged_suite_ok: bool

    verification_status: str
    retained: bool

    coverage_gain_lines: int
    coverage_gain_functions: List[str]

    newly_hit_lines_by_file: Dict[str, List[int]]
    newly_hit_functions_by_file: Dict[str, List[str]]
    target_cluster_touched: bool

    generated_test_path: Optional[str]
    merged_test_path: Optional[str]

    build_stdout_path: Optional[str]
    isolated_stdout_path: Optional[str]
    merged_stdout_path: Optional[str]
    isolated_coverage_lcov_path: Optional[str]

    error: Optional[str] = None


def verify_generated_tests(
    *,
    foundry_root: Path,
    generated_specs: Sequence[Dict[str, Any]],
    work_dir: Path,
    forge_bin: str = "forge",
    match_contract: Optional[str] = None,
    fuzz_runs: int = 256,
    baseline_coverage: Optional[Dict[str, Any]] = None,
    retain_only_with_gain: bool = False,
    merged_test_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """
    Verification flow:
      1) write generated test file directly into Foundry-visible test dir
      2) compile/build
      3) isolated run of generated test
      4) isolated coverage run of generated test
      5) merged suite run
      6) retain only verified tests (optionally require real gain)
      7) return structured manifest entries

    Status values:
      - COMPILE_FAIL
      - TEST_FAIL
      - MERGED_FAIL
      - NO_GAIN
      - RETAINED
      - REJECTED_DUPLICATE
    """
    foundry_root = Path(foundry_root).resolve()
    work_dir = Path(work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    merged_dir = (
        Path(merged_test_dir).resolve()
        if merged_test_dir
        else (foundry_root / "test" / "generated_tests").resolve()
    )
    generated_dir = merged_dir

    generated_dir.mkdir(parents=True, exist_ok=True)
    merged_dir.mkdir(parents=True, exist_ok=True)

    manifest: List[Dict[str, Any]] = []
    seen_code_hashes = set()

    for idx, spec in enumerate(generated_specs, start=1):
        name = str(spec.get("name") or f"generated_{idx}")
        filename = str(spec.get("filename") or f"Generated_{idx}.t.sol")
        kind = str(spec.get("kind") or "generated")
        target = dict(spec.get("target") or {})
        code = str(spec.get("code") or "")

        code_hash = hash(code.strip())
        if code_hash in seen_code_hashes:
            print(f"[VERIFY] name={name} compile_ok=False test_ok=False merged_ok=False status=REJECTED_DUPLICATE")
            result = VerificationResult(
                name=name,
                filename=filename,
                kind=kind,
                target=target,
                compile_ok=False,
                isolated_test_ok=False,
                merged_suite_ok=False,
                verification_status="REJECTED_DUPLICATE",
                retained=False,
                coverage_gain_lines=0,
                coverage_gain_functions=[],
                newly_hit_lines_by_file={},
                newly_hit_functions_by_file={},
                target_cluster_touched=False,
                generated_test_path=None,
                merged_test_path=None,
                build_stdout_path=None,
                isolated_stdout_path=None,
                merged_stdout_path=None,
                isolated_coverage_lcov_path=None,
                error="duplicate_generated_code",
            )
            manifest.append(asdict(result))
            continue
        seen_code_hashes.add(code_hash)

        generated_test_path = generated_dir / filename
        generated_test_path.write_text(code, encoding="utf-8")

        build_stdout_path = work_dir / f"{generated_test_path.stem}.build.log.txt"
        isolated_stdout_path = work_dir / f"{generated_test_path.stem}.isolated.log.txt"
        merged_stdout_path = work_dir / f"{generated_test_path.stem}.merged.log.txt"

        print(f"[VERIFY-PATH] name={name}")
        print(f"[VERIFY-PATH] filename={filename}")
        print(f"[VERIFY-PATH] generated_test_path={generated_test_path}")
        print(f"[VERIFY-PATH] build_stdout_path={build_stdout_path}")

        compile_ok, build_err = _run_forge_build(
            foundry_root=foundry_root,
            forge_bin=forge_bin,
            stdout_path=build_stdout_path,
            fuzz_runs=fuzz_runs,
        )

        print(f"[VERIFY-BUILD] name={name} filename={filename} compile_ok={compile_ok} build_err={build_err}")

        if not compile_ok:
            print(f"[VERIFY] name={name} compile_ok=False test_ok=False merged_ok=False status=COMPILE_FAIL")
            print(f"[VERIFY-FAIL] compile failed: {name}")
            _safe_unlink(generated_test_path)
            result = VerificationResult(
                name=name,
                filename=filename,
                kind=kind,
                target=target,
                compile_ok=False,
                isolated_test_ok=False,
                merged_suite_ok=False,
                verification_status="COMPILE_FAIL",
                retained=False,
                coverage_gain_lines=0,
                coverage_gain_functions=[],
                newly_hit_lines_by_file={},
                newly_hit_functions_by_file={},
                target_cluster_touched=False,
                generated_test_path=str(generated_test_path),
                merged_test_path=None,
                build_stdout_path=str(build_stdout_path),
                isolated_stdout_path=None,
                merged_stdout_path=None,
                isolated_coverage_lcov_path=None,
                error=build_err,
            )
            manifest.append(asdict(result))
            continue

        isolated_test_ok, isolated_err = _run_isolated_test_file(
            foundry_root=foundry_root,
            test_path=generated_test_path,
            forge_bin=forge_bin,
            stdout_path=isolated_stdout_path,
            fuzz_runs=fuzz_runs,
            match_contract=match_contract,
        )

        if not isolated_test_ok:
            print(f"[VERIFY] name={name} compile_ok=True test_ok=False merged_ok=False status=TEST_FAIL")
            print(f"[VERIFY-FAIL] test failed: {name}")
            result = VerificationResult(
                name=name,
                filename=filename,
                kind=kind,
                target=target,
                compile_ok=True,
                isolated_test_ok=False,
                merged_suite_ok=False,
                verification_status="TEST_FAIL",
                retained=False,
                coverage_gain_lines=0,
                coverage_gain_functions=[],
                newly_hit_lines_by_file={},
                newly_hit_functions_by_file={},
                target_cluster_touched=False,
                generated_test_path=str(generated_test_path),
                merged_test_path=None,
                build_stdout_path=str(build_stdout_path),
                isolated_stdout_path=str(isolated_stdout_path),
                merged_stdout_path=None,
                isolated_coverage_lcov_path=None,
                error=isolated_err,
            )
            manifest.append(asdict(result))
            _safe_unlink(generated_test_path)
            continue

        isolated_coverage_lcov_path, isolated_cov_err = _run_isolated_coverage(
            foundry_root=foundry_root,
            test_path=generated_test_path,
            forge_bin=forge_bin,
            fuzz_runs=fuzz_runs,
            match_contract=match_contract,
        )

        if isolated_coverage_lcov_path and isolated_coverage_lcov_path.exists():
            isolated_cov = _parse_lcov_file(isolated_coverage_lcov_path)
            (
                coverage_gain_lines,
                coverage_gain_functions,
                newly_hit_lines_by_file,
                newly_hit_functions_by_file,
                target_cluster_touched,
            ) = _compute_real_coverage_gain(
                baseline_coverage=baseline_coverage or {},
                isolated_coverage=isolated_cov,
                target=target,
            )
        else:
            coverage_gain_lines = 0
            coverage_gain_functions = []
            newly_hit_lines_by_file = {}
            newly_hit_functions_by_file = {}
            target_cluster_touched = False

        merged_path = merged_dir / filename
        if generated_test_path.resolve() != merged_path.resolve():
            shutil.copy2(generated_test_path, merged_path)

        merged_suite_ok, merged_err = _run_merged_suite(
            foundry_root=foundry_root,
            forge_bin=forge_bin,
            stdout_path=merged_stdout_path,
            fuzz_runs=fuzz_runs,
            match_contract=match_contract,
        )

        if not merged_suite_ok:
            print(f"[VERIFY] name={name} compile_ok=True test_ok=True merged_ok=False status=MERGED_FAIL")
            print(f"[VERIFY-FAIL] merged suite failed: {name}")
            _safe_unlink(merged_path)
            _safe_unlink(generated_test_path)
            result = VerificationResult(
                name=name,
                filename=filename,
                kind=kind,
                target=target,
                compile_ok=True,
                isolated_test_ok=True,
                merged_suite_ok=False,
                verification_status="MERGED_FAIL",
                retained=False,
                coverage_gain_lines=coverage_gain_lines,
                coverage_gain_functions=coverage_gain_functions,
                newly_hit_lines_by_file=newly_hit_lines_by_file,
                newly_hit_functions_by_file=newly_hit_functions_by_file,
                target_cluster_touched=target_cluster_touched,
                generated_test_path=str(generated_test_path),
                merged_test_path=None,
                build_stdout_path=str(build_stdout_path),
                isolated_stdout_path=str(isolated_stdout_path),
                merged_stdout_path=str(merged_stdout_path),
                isolated_coverage_lcov_path=(
                    str(isolated_coverage_lcov_path)
                    if isolated_coverage_lcov_path
                    else None
                ),
                error=merged_err,
            )
            manifest.append(asdict(result))
            continue

        retained = True
        status = "RETAINED"
        final_error = isolated_cov_err

        if retain_only_with_gain and coverage_gain_lines <= 0 and not coverage_gain_functions:
            retained = False
            status = "NO_GAIN"
            _safe_unlink(merged_path)
            _safe_unlink(generated_test_path)

        print(
            f"[VERIFY] name={name} compile_ok=True test_ok=True merged_ok=True "
            f"status={status} gain_lines={coverage_gain_lines} "
            f"gain_functions={len(coverage_gain_functions)} "
            f"target_cluster_touched={target_cluster_touched}"
        )
        print(f"[VERIFY-OK] retained={retained} name={name}")

        result = VerificationResult(
            name=name,
            filename=filename,
            kind=kind,
            target=target,
            compile_ok=True,
            isolated_test_ok=True,
            merged_suite_ok=True,
            verification_status=status,
            retained=retained,
            coverage_gain_lines=coverage_gain_lines,
            coverage_gain_functions=coverage_gain_functions,
            newly_hit_lines_by_file=newly_hit_lines_by_file,
            newly_hit_functions_by_file=newly_hit_functions_by_file,
            target_cluster_touched=target_cluster_touched,
            generated_test_path=str(generated_test_path),
            merged_test_path=str(merged_path) if retained else None,
            build_stdout_path=str(build_stdout_path),
            isolated_stdout_path=str(isolated_stdout_path),
            merged_stdout_path=str(merged_stdout_path),
            isolated_coverage_lcov_path=(
                str(isolated_coverage_lcov_path)
                if isolated_coverage_lcov_path
                else None
            ),
            error=final_error,
        )
        manifest.append(asdict(result))

    (work_dir / "generated_tests_manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    retained_tests = [m for m in manifest if m.get("retained")]
    (work_dir / "retained_tests.json").write_text(
        json.dumps(retained_tests, indent=2),
        encoding="utf-8",
    )

    return manifest


def verify_single_generated_test(
    *,
    foundry_root: Path,
    spec: Dict[str, Any],
    work_dir: Path,
    forge_bin: str = "forge",
    match_contract: Optional[str] = None,
    fuzz_runs: int = 256,
    baseline_coverage: Optional[Dict[str, Any]] = None,
    retain_only_with_gain: bool = False,
    merged_test_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    results = verify_generated_tests(
        foundry_root=foundry_root,
        generated_specs=[spec],
        work_dir=work_dir,
        forge_bin=forge_bin,
        match_contract=match_contract,
        fuzz_runs=fuzz_runs,
        baseline_coverage=baseline_coverage,
        retain_only_with_gain=retain_only_with_gain,
        merged_test_dir=merged_test_dir,
    )
    return results[0] if results else {}


def _run_forge_build(
    *,
    foundry_root: Path,
    forge_bin: str,
    stdout_path: Path,
    fuzz_runs: int,
) -> Tuple[bool, Optional[str]]:
    cmd = [forge_bin, "build"]
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
        return False, f"forge build failed ({proc.returncode})"
    return True, None


def _run_isolated_test_file(
    *,
    foundry_root: Path,
    test_path: Path,
    forge_bin: str,
    stdout_path: Path,
    fuzz_runs: int,
    match_contract: Optional[str],
) -> Tuple[bool, Optional[str]]:
    contract_name = _extract_test_contract_name(test_path.read_text(encoding="utf-8", errors="replace"))

    cmd = [forge_bin, "test"]
    if contract_name:
        cmd += ["--match-contract", contract_name]
    elif match_contract:
        cmd += ["--match-contract", match_contract]
    cmd.append("-vvvv")

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
        return False, f"isolated forge test failed ({proc.returncode})"
    return True, None


def _run_isolated_coverage(
    *,
    foundry_root: Path,
    test_path: Path,
    forge_bin: str,
    fuzz_runs: int,
    match_contract: Optional[str] = None,
) -> Tuple[Optional[Path], Optional[str]]:
    foundry_root = Path(foundry_root).resolve()
    test_path = Path(test_path).resolve()

    lcov_path = test_path.parent / f"{test_path.stem}.isolated.coverage.lcov"
    log_path = test_path.parent / f"{test_path.stem}.isolated.coverage.log.txt"

    rel_test_path: Optional[str]
    try:
        rel_test_path = test_path.relative_to(foundry_root).as_posix()
    except Exception:
        rel_test_path = None

    derived_match_contract = match_contract
    if not derived_match_contract:
        try:
            test_src = test_path.read_text(encoding="utf-8", errors="replace")
            derived_match_contract = _extract_test_contract_name(test_src)
        except Exception:
            derived_match_contract = None

    cmd = [
        forge_bin,
        "coverage",
        "--report",
        "lcov",
        "--report-file",
        str(lcov_path),
    ]

    # Prefer matching the exact generated test contract, same strategy as isolated forge test.
    if derived_match_contract:
        cmd += ["--match-contract", derived_match_contract]

    # Also narrow by the real relative path inside the foundry project if available.
    if rel_test_path:
        cmd += ["--match-path", rel_test_path]

    env = os.environ.copy()
    env["FOUNDRY_FUZZ_RUNS"] = str(max(1, int(fuzz_runs)))

    proc = subprocess.run(
        cmd,
        cwd=str(foundry_root),
        capture_output=True,
        text=True,
        env=env,
    )

    try:
        log_path.write_text(
            "\n".join(
                [
                    f"CMD: {' '.join(cmd)}",
                    "",
                    "=== STDOUT ===",
                    proc.stdout or "",
                    "",
                    "=== STDERR ===",
                    proc.stderr or "",
                ]
            ),
            encoding="utf-8",
        )
    except Exception:
        pass

    if proc.returncode != 0:
        return None, f"isolated coverage failed ({proc.returncode})"

    if not lcov_path.exists():
        return None, "isolated coverage lcov not produced"

    return lcov_path, None


def _run_merged_suite(
    *,
    foundry_root: Path,
    forge_bin: str,
    stdout_path: Path,
    fuzz_runs: int,
    match_contract: Optional[str],
) -> Tuple[bool, Optional[str]]:
    cmd = [forge_bin, "test"]
    if match_contract:
        cmd += ["--match-contract", match_contract]
    cmd.append("-vv")

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
        return False, f"merged suite forge test failed ({proc.returncode})"
    return True, None


def _parse_lcov_file(lcov_path: Path) -> Dict[str, Any]:
    coverage: Dict[str, Any] = {}
    current_file: Optional[str] = None

    for raw_line in lcov_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("SF:"):
            current_file = line[3:]
            coverage.setdefault(current_file, {"lines": {}, "functions": {}})
            continue

        if current_file is None:
            continue

        if line.startswith("DA:"):
            try:
                payload = line[3:]
                ln_s, hits_s = payload.split(",", 1)
                coverage[current_file]["lines"][int(ln_s)] = int(hits_s)
            except Exception:
                pass
            continue

        if line.startswith("FNDA:"):
            try:
                payload = line[5:]
                hits_s, fn_name = payload.split(",", 1)
                coverage[current_file]["functions"][fn_name] = int(hits_s)
            except Exception:
                pass
            continue

    return coverage


def _compute_real_coverage_gain(
    *,
    baseline_coverage: Dict[str, Any],
    isolated_coverage: Dict[str, Any],
    target: Dict[str, Any],
) -> Tuple[int, List[str], Dict[str, List[int]], Dict[str, List[str]], bool]:
    newly_hit_lines_by_file: Dict[str, List[int]] = {}
    newly_hit_functions_by_file: Dict[str, List[str]] = {}

    total_new_lines = 0
    all_new_functions: List[str] = []

    all_files = set(baseline_coverage.keys()) | set(isolated_coverage.keys())

    for file_key in all_files:
        base_entry = baseline_coverage.get(file_key, {}) or {}
        iso_entry = isolated_coverage.get(file_key, {}) or {}

        base_lines = {
            int(k): int(v)
            for k, v in (base_entry.get("lines", {}) or {}).items()
            if str(k).isdigit()
        }
        iso_lines = {
            int(k): int(v)
            for k, v in (iso_entry.get("lines", {}) or {}).items()
            if str(k).isdigit()
        }

        base_funcs = {
            str(k): int(v)
            for k, v in (base_entry.get("functions", {}) or {}).items()
        }
        iso_funcs = {
            str(k): int(v)
            for k, v in (iso_entry.get("functions", {}) or {}).items()
        }

        new_lines = sorted(
            ln for ln, hits in iso_lines.items()
            if hits > 0 and base_lines.get(ln, 0) <= 0
        )
        new_funcs = sorted(
            fn for fn, hits in iso_funcs.items()
            if hits > 0 and base_funcs.get(fn, 0) <= 0
        )

        if new_lines:
            newly_hit_lines_by_file[file_key] = new_lines
            total_new_lines += len(new_lines)

        if new_funcs:
            newly_hit_functions_by_file[file_key] = new_funcs
            all_new_functions.extend(new_funcs)

    all_new_functions = sorted(set(all_new_functions))

    target_cluster_touched = False
    if target.get("target_type") == "line_cluster":
        target_lines = set(int(x) for x in (target.get("lines") or []))
        for new_lines in newly_hit_lines_by_file.values():
            if target_lines.intersection(new_lines):
                target_cluster_touched = True
                break
    elif target.get("target_type") == "function":
        fn_name = str(target.get("function") or "")
        target_cluster_touched = fn_name in all_new_functions

    return (
        total_new_lines,
        all_new_functions,
        newly_hit_lines_by_file,
        newly_hit_functions_by_file,
        target_cluster_touched,
    )


def _extract_test_contract_name(code: str) -> Optional[str]:
    matches = re.findall(
        r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\s+is\s+Test\b",
        code or "",
    )
    return matches[0] if matches else None


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


def _safe_unlink(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except Exception:
        pass


def _stable_unique(items: Sequence[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out