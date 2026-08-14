#!/usr/bin/env python3
"""
OBLIVION Test Generation Layer

Explicit pipeline stage for:
1) baseline test execution
2) baseline fuzz/coverage collection
3) uncovered target discovery
4) LLM-guided test synthesis (with deterministic fallback)
5) verification of generated tests
6) merged verified test suite execution
7) unified artifact emission
8) contribution summary emission

Canonical outputs in out_dir:
- coverage.json
- traces.json
- traces/
- test_results.json
- test_summary.json
- uncovered_targets.json
- generated_tests_manifest.json
- retained_tests.json
- merged_manifest.json
- test_generation_summary.json
- baseline_test_stdout.txt
- merged_test_stdout.txt
- coverage.lcov
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from test_generation.baseline import BaselineArtifacts, run_baseline_stage
from test_generation.fallback_synth import build_fallback_test_candidates
from test_generation.merger import MergeArtifacts, merge_verified_tests
from test_generation.schemas import (
    generated_test_candidates_document_schema,
    merged_manifest_schema,
    test_generation_summary_schema,
    uncovered_targets_document_schema,
    validate_with_jsonschema,
    verification_manifest_schema,
)
from test_generation.target_discovery import discover_uncovered_targets
from test_generation.verifier import verify_generated_tests


# ----------------------------------------------------------------------
# Data containers
# ----------------------------------------------------------------------

@dataclass
class TestGenerationConfig:
    forge_bin: str = "forge"
    fuzz_runs: int = 256
    baseline_verbosity: str = "-vvvv"
    merged_verbosity: str = "-vvvv"
    max_uncovered_targets: int = 12
    max_generated_tests: int = 6
    generated_tests_subdir: str = "generated_tests"
    traces_subdir: str = "traces"
    llm_enabled: bool = True
    keep_failed_generated_tests: bool = False

    # existing pipeline knobs that your function already references
    augmentation_rounds: int = 1
    retain_only_with_gain: bool = False

    # new retention behavior
    retain_on_target_touch: bool = True
    retain_on_semantic_value: bool = True

    # temporary debug knob: force-keep any verified generated test
    force_keep_verified_tests: bool = True


@dataclass
class TestGenerationResult:
    baseline_evidence: Dict[str, Any]
    merged_evidence: Dict[str, Any]
    uncovered_targets: List[Dict[str, Any]]
    generated_tests_manifest: List[Dict[str, Any]]
    verified_generated_tests: List[Dict[str, Any]]
    out_dir: Path
    generated_tests_dir: Path
    coverage_path: Path
    traces_dir: Path
    test_results_path: Path
    baseline_artifacts: BaselineArtifacts
    merge_artifacts: MergeArtifacts


# ----------------------------------------------------------------------
# Retention policy helper
# ----------------------------------------------------------------------

def _should_retain_generated_test(
    *,
    entry: Dict[str, Any],
    baseline_evidence: Dict[str, Any],
    merged_evidence: Dict[str, Any],
    config: TestGenerationConfig,
) -> Tuple[bool, str]:
    verified = (
        bool(entry.get("compile_ok")) and
        bool(entry.get("isolated_test_ok")) and
        bool(entry.get("merged_suite_ok"))
    )
    if not verified:
        return False, "NOT_VERIFIED"
    
    gain_lines = int(entry.get("coverage_gain_lines", 0) or 0)
    gain_functions = list(entry.get("coverage_gain_functions") or [])
    if gain_lines > 0 or gain_functions:
        return True, "COVERAGE_GAIN"

    if config.retain_on_target_touch and entry.get("target_cluster_touched"):
        return True, "TARGET_TOUCH"

    if config.retain_on_semantic_value:
        target = entry.get("target") or {}
        tags = set(target.get("semantic_tags") or [])
        useful_tags = {
            "revert_guard_target",
            "storage_write_target",
            "loop_bound_target",
            "external_call_target",
            "payable_target",
        }
        if tags & useful_tags:
            return True, "SEMANTIC_VALUE"

    return False, "NO_GAIN"


# ----------------------------------------------------------------------
# Public entrypoint
# ----------------------------------------------------------------------

def run_test_generation_layer(
    *,
    foundry_root: Path,
    contract_source_path: Path,
    contract_name: str,
    harness_name: Optional[str],
    out_dir: Path,
    llm_generator: Optional[Callable[[Dict[str, Any]], Sequence[Dict[str, Any]]]] = None,
    config: Optional[TestGenerationConfig] = None,
    ir_json: Optional[Dict[str, Any]] = None,
    ir_json_path: Optional[Path] = None,
    abi: Optional[List[Dict[str, Any]]] = None,
) -> TestGenerationResult:
    """
    Main OBLIVION test-generation pipeline stage.
    """
    config = config or TestGenerationConfig()
    foundry_root = Path(foundry_root).resolve()
    contract_source_path = Path(contract_source_path).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    generated_tests_dir = (foundry_root / "test" / config.generated_tests_subdir).resolve()

    if generated_tests_dir.exists():
        import shutil
        shutil.rmtree(generated_tests_dir)

    generated_tests_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1) Baseline tests + baseline fuzz/coverage + traces
    # ------------------------------------------------------------------
    baseline = run_baseline_stage(
        foundry_root=foundry_root,
        out_dir=out_dir,
        forge_bin=config.forge_bin,
        fuzz_runs=config.fuzz_runs,
        verbosity=config.baseline_verbosity,
        match_contract=harness_name,
        traces_subdir_name=config.traces_subdir,
        baseline_prefix="baseline",
    )

    baseline_evidence = baseline.evidence_dict

    if baseline.stdout_path.exists():
        (out_dir / "baseline_test_stdout.txt").write_text(
            baseline.stdout_path.read_text(encoding="utf-8", errors="replace"),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # 2+) Augmentation rounds
    # ------------------------------------------------------------------
    initial_uncovered_targets: List[Dict[str, Any]] = []
    all_manifests: List[Dict[str, Any]] = []
    current_coverage = baseline.evidence.coverage or {}
    current_evidence_dict = baseline_evidence
    last_merge_artifacts: Optional[MergeArtifacts] = None
    rounds_summary: List[Dict[str, Any]] = []

    for round_idx in range(1, max(1, int(config.augmentation_rounds)) + 1):
        round_dir = out_dir / f"round_{round_idx}"
        round_dir.mkdir(parents=True, exist_ok=True)

        round_targets = discover_uncovered_targets(
            coverage=current_coverage,
            contract_source_path=contract_source_path,
            contract_name=contract_name,
            max_targets=config.max_uncovered_targets,
            ir_json=ir_json,
            ir_json_path=ir_json_path,
        )

        if round_idx == 1:
            initial_uncovered_targets = list(round_targets)
            _write_json(out_dir / "uncovered_targets.json", initial_uncovered_targets)
            _validate_and_persist_schema_errors(
                out_dir=out_dir,
                artifact_name="uncovered_targets",
                data=initial_uncovered_targets,
                schema=uncovered_targets_document_schema(),
            )

        _write_json(round_dir / "uncovered_targets.json", round_targets)

        if not round_targets:
            rounds_summary.append(
                {
                    "round": round_idx,
                    "generated_candidates": 0,
                    "retained_generated_tests": 0,
                    "remaining_targets_before_round": 0,
                    "remaining_targets_after_round": 0,
                }
            )
            break

        synthesis_payload: Dict[str, Any] = {
            "contract_name": contract_name,
            "contract_source_path": str(contract_source_path),
            "harness_name": harness_name,
            "baseline_tests": current_evidence_dict.get("tests", {}),
            "baseline_traces": current_evidence_dict.get("traces", {}),
            "coverage": current_coverage,
            "uncovered_targets": round_targets,
            "max_generated_tests": config.max_generated_tests,
            "ir_json": ir_json,
            "ir_json_path": str(ir_json_path) if ir_json_path else None,
            "abi": abi or [],
        }

        generated_specs: List[Dict[str, Any]] = []

        print(f"[DEBUG TESTGEN ROUND {round_idx}] config.llm_enabled={config.llm_enabled}")
        print(f"[DEBUG TESTGEN ROUND {round_idx}] llm_generator_is_none={llm_generator is None}")

        if config.llm_enabled and llm_generator is not None:
            try:
                print(f"[DEBUG TESTGEN ROUND {round_idx}] invoking llm_generator")
                llm_out = llm_generator(synthesis_payload)

                print(f"[DEBUG TESTGEN ROUND {round_idx}] RAW LLM OUTPUT TYPE = {type(llm_out)}")

                if llm_out:
                    print(f"[DEBUG TESTGEN ROUND {round_idx}] llm_out_count={len(llm_out)}")
                    for i, item in enumerate(llm_out):
                        print(
                            f"[DEBUG TESTGEN ROUND {round_idx}] llm_out[{i}] keys = "
                            f"{list(item.keys()) if isinstance(item, dict) else 'NON-DICT'}"
                        )
                    generated_specs = [dict(x) for x in llm_out if isinstance(x, dict)]
                else:
                    print(f"[DEBUG TESTGEN ROUND {round_idx}] llm_out EMPTY OR NONE")

            except Exception as exc:
                generated_specs = []
                print(f"[DEBUG TESTGEN ROUND {round_idx}] llm_generator EXCEPTION = {exc}")
                _write_json(
                    round_dir / "llm_synth_error.json",
                    {
                        "ok": False,
                        "error": str(exc),
                    },
                )

        if not generated_specs:
            print(f"[DEBUG TESTGEN ROUND {round_idx}] FALLBACK ACTIVATED")
            generated_specs = build_fallback_test_candidates(
                contract_name=contract_name,
                contract_source_path=contract_source_path,
                uncovered_targets=round_targets,
                max_generated_tests=config.max_generated_tests,
                ir_json=ir_json,
                abi=abi,
            )

        generated_specs = _prefix_round_specs(round_idx, generated_specs)

        _write_json(round_dir / "generated_test_candidates.json", generated_specs)
        _validate_and_persist_schema_errors(
            out_dir=round_dir,
            artifact_name="generated_test_candidates",
            data=generated_specs,
            schema=generated_test_candidates_document_schema(),
        )

        round_manifest = verify_generated_tests(
            foundry_root=foundry_root,
            generated_specs=generated_specs,
            work_dir=round_dir,
            forge_bin=config.forge_bin,
            match_contract=None,
            fuzz_runs=config.fuzz_runs,
            baseline_coverage=current_coverage,
            retain_only_with_gain=config.retain_only_with_gain,
            merged_test_dir=generated_tests_dir,
        )

        # Apply retention logic after verification.
        for entry in round_manifest:
            # Temporary debug mode: force-keep any test that actually passed verification gates.
            if config.force_keep_verified_tests:
                retain = (
                    bool(entry.get("compile_ok")) and
                    bool(entry.get("isolated_test_ok")) and
                    bool(entry.get("merged_suite_ok"))
                )
                reason = "FORCED_KEEP" if retain else "FORCED_REJECT"
            else:
                retain, reason = _should_retain_generated_test(
                    entry=entry,
                    baseline_evidence=current_evidence_dict,
                    merged_evidence=current_evidence_dict,
                    config=config,
                )

            entry["retained"] = retain
            entry["verification_status"] = reason

        _validate_and_persist_schema_errors(
            out_dir=round_dir,
            artifact_name="generated_tests_manifest",
            data=round_manifest,
            schema=verification_manifest_schema(),
        )

        all_manifests.extend(round_manifest)

        last_merge_artifacts = merge_verified_tests(
            foundry_root=foundry_root,
            verification_manifest=all_manifests,
            out_dir=out_dir,
            forge_bin=config.forge_bin,
            fuzz_runs=config.fuzz_runs,
            match_contract=None,
            baseline_coverage=current_coverage,
            merge_subdir_name=f"merged_round_{round_idx}",
            merged_tests_subdir_name=config.generated_tests_subdir,
        )

        current_coverage = last_merge_artifacts.evidence.coverage or {}
        current_evidence_dict = last_merge_artifacts.evidence_dict

        remaining_targets_after_round = discover_uncovered_targets(
            coverage=current_coverage,
            contract_source_path=contract_source_path,
            contract_name=contract_name,
            max_targets=config.max_uncovered_targets,
            ir_json=ir_json,
            ir_json_path=ir_json_path,
        )

        rounds_summary.append(
            {
                "round": round_idx,
                "generated_candidates": len(generated_specs),
                "retained_generated_tests": len([m for m in round_manifest if bool(m.get("retained"))]),
                "remaining_targets_before_round": len(round_targets),
                "remaining_targets_after_round": len(remaining_targets_after_round),
            }
        )

        # Stop if no improvement direction remains.
        if len(remaining_targets_after_round) >= len(round_targets):
            break

    # ------------------------------------------------------------------
    # 5) Final merged outputs
    # ------------------------------------------------------------------
    if last_merge_artifacts is None:
        # Fallback: merge nothing, but keep baseline-compatible behavior.
        last_merge_artifacts = merge_verified_tests(
            foundry_root=foundry_root,
            verification_manifest=[],
            out_dir=out_dir,
            forge_bin=config.forge_bin,
            fuzz_runs=config.fuzz_runs,
            match_contract=None,
            baseline_coverage=baseline.evidence.coverage or {},
            merge_subdir_name="merged",
            merged_tests_subdir_name=config.generated_tests_subdir,
        )

    _promote_canonical_outputs(
        out_dir=out_dir,
        merge_artifacts=last_merge_artifacts,
        traces_subdir_name=config.traces_subdir,
    )

    _validate_and_persist_schema_errors(
        out_dir=out_dir,
        artifact_name="merged_manifest",
        data=json.loads(last_merge_artifacts.merged_manifest_path.read_text(encoding="utf-8")),
        schema=merged_manifest_schema(),
    )

    retained_tests = [m for m in all_manifests if bool(m.get("retained"))]
    _write_json(out_dir / "generated_tests_manifest.json", all_manifests)
    _write_json(out_dir / "retained_tests.json", retained_tests)

    _validate_and_persist_schema_errors(
        out_dir=out_dir,
        artifact_name="generated_tests_manifest",
        data=all_manifests,
        schema=verification_manifest_schema(),
    )

    # ------------------------------------------------------------------
    # 6) Contribution summary
    # ------------------------------------------------------------------
    final_remaining_targets = discover_uncovered_targets(
        coverage=current_coverage,
        contract_source_path=contract_source_path,
        contract_name=contract_name,
        max_targets=config.max_uncovered_targets,
        ir_json=ir_json,
        ir_json_path=ir_json_path,
    )

    all_new_functions = sorted(
        {
            fn
            for m in retained_tests
            for fn in (m.get("coverage_gain_functions") or [])
        }
    )

    all_new_lines = sum(int(m.get("coverage_gain_lines") or 0) for m in retained_tests)
    cluster_touched_count = sum(
        1 for m in retained_tests if bool(m.get("target_cluster_touched"))
    )

    summary_payload = {
        "baseline_targets": len(initial_uncovered_targets),
        "generated_candidates": len(all_manifests),
        "verified_generated_tests": len(
            [
                m
                for m in all_manifests
                if bool(m.get("compile_ok")) and bool(m.get("isolated_test_ok"))
            ]
        ),
        "retained_generated_tests": len(retained_tests),
        "post_merge_remaining_targets": len(final_remaining_targets),
        "new_lines_hit": all_new_lines,
        "new_functions_hit": all_new_functions,
        "target_clusters_touched": cluster_touched_count,
        "rounds": rounds_summary,
    }

    _write_json(out_dir / "test_generation_summary.json", summary_payload)
    _validate_and_persist_schema_errors(
        out_dir=out_dir,
        artifact_name="test_generation_summary",
        data=summary_payload,
        schema=test_generation_summary_schema(),
    )

    merged_evidence = last_merge_artifacts.evidence_dict

    return TestGenerationResult(
        baseline_evidence=baseline_evidence,
        merged_evidence=merged_evidence,
        uncovered_targets=initial_uncovered_targets,
        generated_tests_manifest=all_manifests,
        verified_generated_tests=retained_tests,
        out_dir=out_dir,
        generated_tests_dir=generated_tests_dir,
        coverage_path=out_dir / "coverage.json",
        traces_dir=out_dir / config.traces_subdir,
        test_results_path=out_dir / "test_results.json",
        baseline_artifacts=baseline,
        merge_artifacts=last_merge_artifacts,
    )


# ----------------------------------------------------------------------
# Output promotion / helpers
# ----------------------------------------------------------------------

def _prefix_round_specs(round_idx: int, specs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for i, spec in enumerate(specs, start=1):
        s = dict(spec)
        base_name = str(s.get("name") or f"generated_{i}")
        base_filename = str(s.get("filename") or f"AutoGen_{i}.t.sol")

        s["name"] = f"round{round_idx}_{base_name}"
        if base_filename.endswith(".t.sol"):
            stem = base_filename[:-6]
            s["filename"] = f"Round{round_idx}_{stem}.t.sol"
        else:
            s["filename"] = f"Round{round_idx}_{base_filename}"

        out.append(s)
    return out


def _promote_canonical_outputs(
    *,
    out_dir: Path,
    merge_artifacts: MergeArtifacts,
    traces_subdir_name: str,
) -> None:
    """
    Promote merged outputs to the exact top-level artifact names expected by
    the rest of the pipeline and by the paper plan.
    """
    out_dir = Path(out_dir).resolve()

    _copy_if_exists(merge_artifacts.merged_test_results_path, out_dir / "test_results.json")
    _copy_if_exists(merge_artifacts.merged_test_summary_path, out_dir / "test_summary.json")
    _copy_if_exists(merge_artifacts.merged_traces_json_path, out_dir / "traces.json")
    _copy_if_exists(merge_artifacts.merged_coverage_json_path, out_dir / "coverage.json")
    _copy_if_exists(merge_artifacts.merged_lcov_path, out_dir / "coverage.lcov")
    _copy_if_exists(merge_artifacts.merged_stdout_path, out_dir / "merged_test_stdout.txt")
    _copy_if_exists(merge_artifacts.merged_manifest_path, out_dir / "merged_manifest.json")

    target_traces_dir = out_dir / traces_subdir_name
    if target_traces_dir.exists():
        for child in target_traces_dir.iterdir():
            if child.is_file():
                child.unlink()
            elif child.is_dir():
                import shutil
                shutil.rmtree(child)

    if merge_artifacts.merged_traces_dir.exists():
        if target_traces_dir.exists():
            import shutil
            shutil.rmtree(target_traces_dir)
        import shutil
        shutil.copytree(merge_artifacts.merged_traces_dir, target_traces_dir)


def _copy_if_exists(src: Path, dst: Path) -> None:
    if src.exists():
        dst.write_bytes(src.read_bytes())


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _validate_and_persist_schema_errors(
    *,
    out_dir: Path,
    artifact_name: str,
    data: Any,
    schema: Dict[str, Any],
) -> None:
    errors = validate_with_jsonschema(data, schema)
    if errors:
        _write_json(out_dir / f"{artifact_name}.schema_errors.json", errors)