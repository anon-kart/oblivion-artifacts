# validator/validator.py
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ValidationResult
from .compile_check import check_compile
from .gas_check import check_gas
from .security_check import check_security
from .test_runner import run_tests
from .workspace import FoundrySwapWorkspace
from .report import write_report
from .fuzz_check import check_short_fuzz

# coverage regression diff (baseline vs candidate)
from .coverage_diff import diff_coverage
from .semantic_check import check_semantic_contract


def validate_candidate(
    *,
    original_src: Path,
    obfuscated_src: Path,
    foundry_root: Path,
    target_relpath: Optional[str] = None,
    tests_to_run: Optional[List[str]] = None,
    baseline_coverage_json: Optional[Path] = None,
    policy: Optional[Dict[str, Any]] = None,
    out_dir: Optional[Path] = None,
    force_full_suite: bool = False,
    baseline_sec_advice_json: Optional[Path] = None,
    contract_name: Optional[str] = None,
    source_relpath: Optional[str] = None,
    candidate_plan: Optional[Dict[str, Any]] = None,
) -> ValidationResult:
    """
    Validate an obfuscated candidate against an isolated scratch copy of the Foundry project.

    Gates:
      1) Compile
      2) Verified tests
      3) Explicit short fuzz pass
      4) Semantic contract / composition gate
      5) Coverage regression gate
      6) Security gate
      7) Gas delta gate
    """
    policy = policy or {}
    tests_to_run = tests_to_run or []
    notes: List[str] = []
    reject_reasons: List[str] = []

    if out_dir is None:
        out_dir = foundry_root / ".oblivion_validator"
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if target_relpath is None:
        target_relpath = f"src/{original_src.name}"
        notes.append(f"defaulted target_relpath to {target_relpath}")

    workspace = FoundrySwapWorkspace(
        foundry_root=foundry_root,
        target_relpath=target_relpath,
        original_src=original_src,
        candidate_src=obfuscated_src,
        out_dir=out_dir,
    )

    # Prepare isolated scratch workspace. All validation-side file mutation happens there.
    workspace.prepare()
    active_foundry_root = workspace.active_foundry_root
    notes.append(f"prepared isolated workspace: {active_foundry_root}")

    compile_res: Dict[str, Any] = {"ok": False, "skipped": False}
    test_res: Dict[str, Any] = {"ok": False, "skipped": False}
    fuzz_res: Dict[str, Any] = {"ok": True, "skipped": True, "reason": "not_run"}
    semantic_res: Dict[str, Any] = {"ok": True, "skipped": True, "reason": "not_run"}
    cov_res: Dict[str, Any] = {"ok": True, "skipped": True}
    sec_res: Dict[str, Any] = {"ok": True, "skipped": True}
    gas_res: Dict[str, Any] = {"ok": True, "skipped": True}

    accepted = False

    inferred_contract = contract_name or original_src.stem
    match_contract = f"{inferred_contract}_Harness" if inferred_contract else None
    target_source_relpath = str(source_relpath or target_relpath).replace("\\", "/")
    target_source_basename = Path(target_source_relpath).name

    # If caller forces full suite, use it. Otherwise run targeted tests when provided.
    run_full = bool(force_full_suite) or (len(tests_to_run) == 0)

    baseline_tests_res: Dict[str, Any] = {}
    baseline_gas_by_test: Dict[str, Any] = {}

    try:
        # Ensure baseline original is present in scratch workspace target.
        workspace.put_original()
        notes.append("put original into isolated workspace before baseline tests")

        # ----------------------------
        # Baseline tests + gas
        # ----------------------------
        baseline_tests_res = run_tests(
            foundry_root=active_foundry_root,
            out_dir=out_dir,
            tests=tests_to_run,
            force_full_suite=run_full,
            log_name="baseline_tests.log.txt",
            parse_gas=True,
            match_contract=match_contract,
        ) or {}

        baseline_gas_by_test = baseline_tests_res.get("gas_by_test", {}) or {}

        if not baseline_tests_res.get("ok"):
            notes.append("baseline tests failed (gas baseline may be incomplete)")
            (out_dir / "baseline_tests_result.json").write_text(
                _safe_json_dumps(baseline_tests_res),
                encoding="utf-8",
            )

        # ----------------------------
        # Baseline scoped coverage
        # ----------------------------
        baseline_validation_lcov = out_dir / "baseline_validation_coverage.lcov"

        # ----------------------------
        # Swap in candidate inside isolated workspace
        # ----------------------------
        workspace.swap_in()

        # 1) Compile gate
        compile_res = check_compile(foundry_root=active_foundry_root, out_dir=out_dir) or {"ok": False}
        compile_res.setdefault("skipped", False)
        compile_res.setdefault("stage", "compile")
        compile_res.setdefault("reason", "compile_failed" if not compile_res.get("ok") else "ok")

        if not compile_res.get("ok"):
            notes.append("compile failed")
            reject_reasons.append("compile_failed")
            return _finalize(
                out_dir=out_dir,
                accepted=accepted,
                compile_res=compile_res,
                tests_res=test_res,
                fuzz_res=fuzz_res,
                semantic_res=semantic_res,
                cov_res=cov_res,
                sec_res=sec_res,
                gas_res=gas_res,
                notes=notes,
                reject_reasons=reject_reasons,
                failure_reason="compile_failed",
            )

        # 2) Tests gate
        test_res = run_tests(
            foundry_root=active_foundry_root,
            out_dir=out_dir,
            tests=tests_to_run,
            force_full_suite=run_full,
            log_name="candidate_tests.log.txt",
            parse_gas=True,
            match_contract=match_contract,
        ) or {"ok": False}

        test_res.setdefault("skipped", False)
        test_res.setdefault("stage", "tests")
        test_res.setdefault("reason", "tests_failed" if not test_res.get("ok") else "ok")

        if not test_res.get("ok"):
            notes.append("tests failed")
            reject_reasons.append("tests_failed")
            return _finalize(
                out_dir=out_dir,
                accepted=accepted,
                compile_res=compile_res,
                tests_res=test_res,
                fuzz_res=fuzz_res,
                semantic_res=semantic_res,
                cov_res=cov_res,
                sec_res=sec_res,
                gas_res=gas_res,
                notes=notes,
                reject_reasons=reject_reasons,
                failure_reason="tests_failed",
            )

        candidate_gas_by_test = test_res.get("gas_by_test", {}) or {}

        # 3) Explicit short fuzz gate
        fuzz_res = check_short_fuzz(
            foundry_root=active_foundry_root,
            out_dir=out_dir,
            policy=policy,
            match_contract=match_contract,
        ) or {"ok": True, "skipped": True, "reason": "short_fuzz_unavailable"}

        fuzz_res.setdefault("skipped", False)
        fuzz_res.setdefault("stage", "short_fuzz")
        fuzz_res.setdefault("reason", "short_fuzz_failed" if not fuzz_res.get("ok") else "ok")

        if not fuzz_res.get("ok"):
            notes.append("short fuzz failed")
            reject_reasons.append("short_fuzz_failed")
            return _finalize(
                out_dir=out_dir,
                accepted=accepted,
                compile_res=compile_res,
                tests_res=test_res,
                fuzz_res=fuzz_res,
                semantic_res=semantic_res,
                cov_res=cov_res,
                sec_res=sec_res,
                gas_res=gas_res,
                notes=notes,
                reject_reasons=reject_reasons,
                failure_reason="short_fuzz_failed",
            )

        # 4) Semantic contract / composition gate
        semantic_res = check_semantic_contract(
            candidate_plan=candidate_plan,
            policy=policy,
            out_dir=out_dir,
            transform_map_json=(out_dir.parent / "obfuscation_engine" / "transform_map.json"),
        ) or {"ok": True, "skipped": True, "reason": "semantic_check_unavailable"}

        semantic_res.setdefault("skipped", False)
        semantic_res.setdefault("stage", "semantic")
        semantic_res.setdefault(
            "reason",
            "semantic_contract_failed" if not semantic_res.get("ok") else "ok",
        )

        if not semantic_res.get("ok"):
            notes.append("semantic contract failed")
            reject_reasons.append("semantic_contract_failed")
            return _finalize(
                out_dir=out_dir,
                accepted=accepted,
                compile_res=compile_res,
                tests_res=test_res,
                fuzz_res=fuzz_res,
                semantic_res=semantic_res,
                cov_res=cov_res,
                sec_res=sec_res,
                gas_res=gas_res,
                notes=notes,
                reject_reasons=reject_reasons,
                failure_reason="semantic_contract_failed",
            )

        # 5) Coverage regression gate
        if baseline_coverage_json:
            coverage_required = bool(policy.get("coverage_required", True))
            coverage_ir_min_fallback = bool(policy.get("coverage_fallback_ir_minimum", True))
            coverage_scope_to_target = bool(policy.get("coverage_scope_to_target_source", True))
            notes.append(
                f"coverage validation scope uses match_contract={match_contract or 'None'} "
                f"and target_source={target_source_relpath}"
            )

            baseline_cov_log = out_dir / "baseline_coverage.log.txt"
            candidate_lcov = out_dir / "candidate_coverage.lcov"
            candidate_cov_log = out_dir / "coverage.log.txt"

            baseline_ok, baseline_cov_msg = _run_scoped_coverage(
                foundry_root=active_foundry_root,
                out_path=baseline_validation_lcov,
                log_path=baseline_cov_log,
                match_contract=match_contract,
                coverage_ir_min_fallback=coverage_ir_min_fallback,
            )

            if not baseline_ok:
                cov_res = {
                    "ok": False,
                    "skipped": False,
                    "stage": "coverage",
                    "reason": "baseline_coverage_compute_failed",
                    "log": str(baseline_cov_log),
                    "detail": baseline_cov_msg,
                    "policy": {
                        "coverage_required": coverage_required,
                        "coverage_fallback_ir_minimum": coverage_ir_min_fallback,
                        "coverage_scope_to_target_source": coverage_scope_to_target,
                    },
                }
                if coverage_required:
                    notes.append("coverage gate failed (baseline coverage could not be computed)")
                    reject_reasons.append("baseline_coverage_compute_failed")
                    return _finalize(
                        out_dir=out_dir,
                        accepted=accepted,
                        compile_res=compile_res,
                        tests_res=test_res,
                        fuzz_res=fuzz_res,
                        semantic_res=semantic_res,
                        cov_res=cov_res,
                        sec_res=sec_res,
                        gas_res=gas_res,
                        notes=notes,
                        reject_reasons=reject_reasons,
                        failure_reason="baseline_coverage_compute_failed",
                    )
                notes.append("baseline coverage skipped due to policy.coverage_required=false")
                cov_res = {**cov_res, "ok": True, "skipped": True, "reason": "coverage_skipped_by_policy"}

            if cov_res.get("ok", True):
                candidate_ok, candidate_cov_msg = _run_scoped_coverage(
                    foundry_root=active_foundry_root,
                    out_path=candidate_lcov,
                    log_path=candidate_cov_log,
                    match_contract=match_contract,
                    coverage_ir_min_fallback=coverage_ir_min_fallback,
                )

                if not candidate_ok:
                    cov_res = {
                        "ok": False,
                        "skipped": False,
                        "stage": "coverage",
                        "reason": "candidate_coverage_compute_failed",
                        "log": str(candidate_cov_log),
                        "detail": candidate_cov_msg,
                        "policy": {
                            "coverage_required": coverage_required,
                            "coverage_fallback_ir_minimum": coverage_ir_min_fallback,
                            "coverage_scope_to_target_source": coverage_scope_to_target,
                        },
                    }
                    if coverage_required:
                        notes.append("coverage gate failed (candidate coverage could not be computed)")
                        reject_reasons.append("candidate_coverage_compute_failed")
                        return _finalize(
                            out_dir=out_dir,
                            accepted=accepted,
                            compile_res=compile_res,
                            tests_res=test_res,
                            fuzz_res=fuzz_res,
                            semantic_res=semantic_res,
                            cov_res=cov_res,
                            sec_res=sec_res,
                            gas_res=gas_res,
                            notes=notes,
                            reject_reasons=reject_reasons,
                            failure_reason="candidate_coverage_compute_failed",
                        )
                    notes.append("candidate coverage skipped due to policy.coverage_required=false")
                    cov_res = {**cov_res, "ok": True, "skipped": True, "reason": "coverage_skipped_by_policy"}

            if cov_res.get("ok", True):
                scoped_baseline_lcov = baseline_validation_lcov
                scoped_candidate_lcov = candidate_lcov

                if coverage_scope_to_target:
                    filtered_baseline_lcov = out_dir / "baseline_validation_coverage.filtered.lcov"
                    filtered_candidate_lcov = out_dir / "candidate_coverage.filtered.lcov"

                    allowed_sources = {target_source_relpath, target_source_basename}

                    baseline_filter_ok = _filter_lcov_file_to_allowed_sources(
                        in_path=baseline_validation_lcov,
                        out_path=filtered_baseline_lcov,
                        allowed_sources=allowed_sources,
                    )
                    candidate_filter_ok = _filter_lcov_file_to_allowed_sources(
                        in_path=candidate_lcov,
                        out_path=filtered_candidate_lcov,
                        allowed_sources=allowed_sources,
                    )

                    if baseline_filter_ok and candidate_filter_ok:
                        scoped_baseline_lcov = filtered_baseline_lcov
                        scoped_candidate_lcov = filtered_candidate_lcov
                        notes.append(f"filtered coverage diff to target source {target_source_relpath}")
                    else:
                        notes.append(
                            "coverage filtering to target source failed; falling back to unfiltered scoped LCOV"
                        )

                coverage_diff_json = out_dir / "coverage_diff.json"
                coverage_policy = {
                    "reject_on_drop": bool(policy.get("coverage_reject_on_drop", False)),
                    "use_line_coverage_gate": bool(policy.get("coverage_use_line_coverage_gate", True)),
                    "min_line_coverage_ratio": float(policy.get("coverage_min_line_coverage_ratio", 0.85)),
                    "max_dropped_lines": int(policy.get("coverage_max_dropped_lines", 12)),
                    "allow_function_name_drift": bool(policy.get("coverage_allow_function_name_drift", True)),
                }

                covdiff = diff_coverage(
                    baseline_lcov=scoped_baseline_lcov,
                    candidate_lcov=scoped_candidate_lcov,
                    out_json=coverage_diff_json,
                    policy=coverage_policy,
                )

                cov_res = {
                    "ok": covdiff.ok,
                    "skipped": covdiff.skipped,
                    "stage": "coverage",
                    "reason": covdiff.reason,
                    "policy": {
                        **coverage_policy,
                        "coverage_required": coverage_required,
                        "coverage_fallback_ir_minimum": coverage_ir_min_fallback,
                        "coverage_scope_to_target_source": coverage_scope_to_target,
                    },
                    "paths": {
                        "baseline_lcov": covdiff.baseline_lcov,
                        "candidate_lcov": covdiff.candidate_lcov,
                        "diff_json": str(coverage_diff_json),
                        "baseline_unfiltered_lcov": str(baseline_validation_lcov),
                        "candidate_unfiltered_lcov": str(candidate_lcov),
                    },
                    "scope": {
                        "match_contract": match_contract,
                        "target_source_relpath": target_source_relpath,
                    },
                    "counts": {
                        "baseline_covered_functions": covdiff.baseline_count,
                        "candidate_covered_functions": covdiff.candidate_count,
                        "dropped": len(covdiff.dropped),
                        "added": len(covdiff.added),
                        "baseline_line_count": covdiff.baseline_line_count,
                        "candidate_line_count": covdiff.candidate_line_count,
                        "dropped_lines": covdiff.dropped_lines,
                        "added_lines": covdiff.added_lines,
                    },
                    "line_coverage_ratio": covdiff.line_coverage_ratio,
                    "line_drop_ratio": covdiff.line_drop_ratio,
                    "dropped": list(covdiff.dropped),
                    "added": list(covdiff.added),
                }

                if not cov_res.get("ok"):
                    notes.append("coverage regression: candidate dropped covered functions/lines beyond policy")
                    reject_reasons.append("coverage_regression")
                    return _finalize(
                        out_dir=out_dir,
                        accepted=accepted,
                        compile_res=compile_res,
                        tests_res=test_res,
                        fuzz_res=fuzz_res,
                        semantic_res=semantic_res,
                        cov_res=cov_res,
                        sec_res=sec_res,
                        gas_res=gas_res,
                        notes=notes,
                        reject_reasons=reject_reasons,
                        failure_reason="coverage_regression",
                    )

        # 6) Security gate
        sec_res = check_security(
            original_src=original_src,
            obfuscated_src=obfuscated_src,
            out_dir=out_dir,
            policy=policy,
            baseline_sec_advice_json=baseline_sec_advice_json,
            contract_name=contract_name,
            source_relpath=source_relpath,
            foundry_root=active_foundry_root,
            transform_map_json=(out_dir.parent / "obfuscation_engine" / "transform_map.json"),
        ) or {"ok": True, "skipped": True}

        sec_res.setdefault("stage", "security")
        sec_res.setdefault("reason", "security_gate_failed" if not sec_res.get("ok") else "ok")

        if not sec_res.get("ok"):
            notes.append("security gate failed")
            reject_reasons.append("security_failed")
            return _finalize(
                out_dir=out_dir,
                accepted=accepted,
                compile_res=compile_res,
                tests_res=test_res,
                fuzz_res=fuzz_res,
                semantic_res=semantic_res,
                cov_res=cov_res,
                sec_res=sec_res,
                gas_res=gas_res,
                notes=notes,
                reject_reasons=reject_reasons,
                failure_reason="security_failed",
            )

        # 7) Gas delta gate
        gas_res = check_gas(
            baseline_gas_by_test=baseline_gas_by_test,
            candidate_gas_by_test=candidate_gas_by_test,
            out_dir=out_dir,
            policy=policy,
        ) or {"ok": True, "skipped": True}

        gas_res.setdefault("stage", "gas")
        gas_res.setdefault("reason", "gas_gate_failed" if not gas_res.get("ok") else "ok")

        if not gas_res.get("ok"):
            notes.append("gas gate failed")
            reject_reasons.append("gas_failed")
            return _finalize(
                out_dir=out_dir,
                accepted=accepted,
                compile_res=compile_res,
                tests_res=test_res,
                fuzz_res=fuzz_res,
                semantic_res=semantic_res,
                cov_res=cov_res,
                sec_res=sec_res,
                gas_res=gas_res,
                notes=notes,
                reject_reasons=reject_reasons,
                failure_reason="gas_failed",
            )

        accepted = True
        notes.append("candidate accepted")
        return _finalize(
            out_dir=out_dir,
            accepted=accepted,
            compile_res=compile_res,
            tests_res=test_res,
            fuzz_res=fuzz_res,
            semantic_res=semantic_res,
            cov_res=cov_res,
            sec_res=sec_res,
            gas_res=gas_res,
            notes=notes,
            reject_reasons=reject_reasons,
            failure_reason="ok",
        )

    finally:
        try:
            workspace.restore()
        except Exception as e:
            notes.append(f"restore warning: {e}")
            try:
                (out_dir / "restore_warning.txt").write_text(str(e), encoding="utf-8")
            except Exception:
                pass


def _run_scoped_coverage(
    *,
    foundry_root: Path,
    out_path: Path,
    log_path: Path,
    match_contract: Optional[str],
    coverage_ir_min_fallback: bool,
) -> tuple[bool, Optional[str]]:
    default_lcov = Path(foundry_root) / "lcov.info"

    def _run_cov(cmd: List[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            cwd=str(foundry_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    cmd = ["forge", "coverage", "--report", "lcov"]
    if match_contract:
        cmd += ["--match-contract", match_contract]

    res = _run_cov(cmd)
    log_chunks = [f"[OBLIVION] CMD: {' '.join(cmd)}\n", res.stdout or ""]

    if (res.returncode != 0 or not default_lcov.exists()) and coverage_ir_min_fallback:
        cmd2 = cmd + ["--ir-minimum"]
        res2 = _run_cov(cmd2)
        log_chunks.append("\n\n[OBLIVION] coverage retry with --ir-minimum\n")
        log_chunks.append(f"[OBLIVION] CMD: {' '.join(cmd2)}\n")
        log_chunks.append(res2.stdout or "")
        res = res2
        cmd = cmd2

    log_path.write_text("".join(log_chunks), encoding="utf-8")

    if res.returncode != 0:
        return False, f"forge coverage failed ({res.returncode})"

    if not default_lcov.exists():
        return False, "lcov.info not produced"

    out_path.write_text(default_lcov.read_text(encoding="utf-8"), encoding="utf-8")
    return True, None


def _filter_lcov_file_to_allowed_sources(
    *,
    in_path: Path,
    out_path: Path,
    allowed_sources: set[str],
) -> bool:
    try:
        text = in_path.read_text(encoding="utf-8")
    except Exception:
        return False

    filtered = _filter_lcov_text_to_allowed_sources(text=text, allowed_sources=allowed_sources)
    if not filtered.strip():
        return False

    out_path.write_text(filtered, encoding="utf-8")
    return True


def _filter_lcov_text_to_allowed_sources(
    *,
    text: str,
    allowed_sources: set[str],
) -> str:
    normalized_allowed = {str(x).replace("\\", "/") for x in allowed_sources}
    normalized_allowed_basenames = {Path(x).name for x in normalized_allowed}

    out_blocks: List[str] = []
    current_block: List[str] = []
    keep_block = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")

        if line.startswith("SF:"):
            current_block = [line]
            src = line[3:].strip().replace("\\", "/")
            src_name = Path(src).name
            keep_block = src in normalized_allowed or src_name in normalized_allowed_basenames
            continue

        if current_block:
            current_block.append(line)
            if line == "end_of_record":
                if keep_block:
                    out_blocks.append("\n".join(current_block))
                current_block = []
                keep_block = False

    if current_block and keep_block:
        out_blocks.append("\n".join(current_block))

    if not out_blocks:
        return ""

    return "\n".join(out_blocks) + "\n"


def _safe_json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, indent=2)
    except Exception:
        try:
            return json.dumps(str(obj), indent=2)
        except Exception:
            return "{}"


def _finalize(
    out_dir: Path,
    accepted: bool,
    compile_res: Dict[str, Any],
    tests_res: Dict[str, Any],
    fuzz_res: Dict[str, Any],
    semantic_res: Dict[str, Any],
    cov_res: Dict[str, Any],
    sec_res: Dict[str, Any],
    gas_res: Dict[str, Any],
    notes: List[str],
    reject_reasons: Optional[List[str]] = None,
    failure_reason: str = "unknown",
) -> ValidationResult:
    reject_reasons = reject_reasons or []

    result = ValidationResult(
        accepted=accepted,
        compile=compile_res,
        tests=tests_res,
        fuzz=fuzz_res,
        semantic=semantic_res,
        coverage=cov_res,
        security=sec_res,
        gas=gas_res,
        notes=notes,
    )

    write_report(out_dir=out_dir, result=result)

    validation_report = {
        "accepted": bool(accepted),
        "status": "accepted" if accepted else "rejected",
        "reason": "accepted" if accepted else "rejected",
        "failure_reason": failure_reason,
        "compile_ok": bool(compile_res.get("ok")),
        "tests_ok": bool(tests_res.get("ok")),
        "fuzz_ok": bool(fuzz_res.get("ok", True)),
        "semantic_ok": bool(semantic_res.get("ok", True)),
        "coverage_ok": bool(cov_res.get("ok", True)),
        "gas_ok": bool(gas_res.get("ok", True)),
        "security_ok": bool(sec_res.get("ok", True)),
        "reject_reasons": list(reject_reasons),
        "notes": list(notes),
        "compile": compile_res,
        "tests": tests_res,
        "fuzz": fuzz_res,
        "semantic": semantic_res,
        "coverage": cov_res,
        "security": sec_res,
        "gas": gas_res,
    }

    (out_dir / "validation_report.json").write_text(
        _safe_json_dumps(validation_report),
        encoding="utf-8",
    )

    return result