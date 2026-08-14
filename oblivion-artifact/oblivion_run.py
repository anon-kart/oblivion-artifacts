#!/usr/bin/env python3
# oblivion_run.py
from execution_evidence import ExecutionEvidence
from obfuscation_advisor import build_contract_advice
from obfuscation_engine import apply_variants_plan
from validator.validator import validate_candidate
from decision.llm_planner import LLMPlanner
from decision.llm_plan_validator import LLMPlanValidatorV1
try:
    from obfuscation_engine.engine import TRANSFORMS as APPLIERS  # type: ignore
except Exception:
    try:
        from obfuscation_engine.transforms import APPLIERS  # type: ignore
    except Exception:
        APPLIERS = {}  # type: ignore
from decision_planner.catalog import default_transform_catalog
from decision_planner.compat_matrix import (
    extract_signals,
    compatible as compat_matrix_compatible,
)
from test_generation.pipeline import TestGenerationConfig, run_test_generation_layer
from test_generation.llm_synth import build_llm_test_generator
import copy
import os
import sys
import json
import subprocess
import itertools
import re
from pathlib import Path
from shutil import copy2
import atexit
import signal

import shutil
from typing import Any, Dict, Optional, List
from decision.composition_graph import filter_graph_to_selected_ids, order_plan_steps
from decision.semantic_rules import (
    build_deterministic_semantic_contract,
    build_deterministic_composition_graph,
    merge_semantic_contracts,
    merge_composition_graphs,
)
import hashlib

def _safe_candidate_dir_name(candidate_obj: Any, fallback_prefix: str = "cand") -> str:
    """
    Produce a short filesystem-safe candidate directory name.
    Never use raw dict/stringified JSON as a path component.
    """
    if isinstance(candidate_obj, dict):
        raw = (
            candidate_obj.get("candidate_id")
            or candidate_obj.get("plan_id")
            or candidate_obj.get("name")
            or candidate_obj.get("id")
            or fallback_prefix
        )
    else:
        raw = str(candidate_obj)

    raw = str(raw).strip() if raw is not None else fallback_prefix
    if not raw:
        raw = fallback_prefix

    # Sanitize aggressively
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-")
    if not safe:
        safe = fallback_prefix

    # Keep path short enough for filesystem safety
    if len(safe) > 80:
        digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]
        safe = f"{safe[:60]}_{digest}"

    return safe

ROOT = Path(__file__).resolve().parent

# Foundry project (where forge test/coverage runs)
FOUNDRY_ROOT = ROOT / "testcrafter-mini" / "artifacts" / "foundry_project"
OBLIVION_OUT = ROOT / "artifacts" / "oblivion_runs"

# AST analyzer (invsol_ast)
AST_ANALYZER_ROOT = Path(
    os.getenv("OBLIVION_AST_ANALYZER_ROOT", ROOT / "invsol_ast_analyzer")
).resolve()

if not AST_ANALYZER_ROOT.exists():
    print("[ERROR] Could not locate AST Analyzer (invsol_ast package).")
    print(f"        Expected it at {AST_ANALYZER_ROOT}")
    print("        Set OBLIVION_AST_ANALYZER_ROOT to the analyzer directory.")
    sys.exit(1)


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _copy_if_exists(src: Optional[Path], dst: Path) -> bool:
    try:
        if src is None:
            return False
        src = Path(src)
        if not src.exists():
            return False
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return True
    except Exception:
        return False

def _snapshot_source_file(src: Path, out_dir: Path) -> Path:
    """
    Create an immutable per-run snapshot of the canonical source file.
    This is the file OBLIVION should treat as the true original.
    """
    src = Path(src).resolve()
    snap_dir = Path(out_dir) / "_source_snapshot"
    snap_dir.mkdir(parents=True, exist_ok=True)

    snap_path = snap_dir / src.name
    shutil.copy2(src, snap_path)
    return snap_path


def _restore_source_file(snapshot_path: Path, live_path: Path) -> bool:
    """
    Restore the canonical live source from the snapshot if it drifted.
    Returns True if a restore happened.
    """
    try:
        snapshot_path = Path(snapshot_path).resolve()
        live_path = Path(live_path).resolve()

        if not snapshot_path.exists():
            return False

        live_path.parent.mkdir(parents=True, exist_ok=True)

        if (not live_path.exists()) or snapshot_path.read_bytes() != live_path.read_bytes():
            shutil.copy2(snapshot_path, live_path)
            return True
        return False
    except Exception:
        return False


def _register_source_restore(snapshot_path: Path, live_path: Path) -> None:
    """
    Best-effort restore hook so the canonical Foundry source is restored
    even if later stages swap candidate code into place.
    """
    restored = {"done": False}

    def _restore_once(*_args):
        if restored["done"]:
            return
        try:
            _restore_source_file(snapshot_path, live_path)
        finally:
            restored["done"] = True

    atexit.register(_restore_once)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            previous = signal.getsignal(sig)

            def _handler(signum, frame, _prev=previous):
                _restore_once()
                if callable(_prev):
                    _prev(signum, frame)
                raise SystemExit(128 + int(signum))

            signal.signal(sig, _handler)
        except Exception:
            pass

def _write_json(dst: Path, payload: Dict[str, Any]) -> bool:
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False
    
def _clone_function_plan_with_subset(
    fp: Dict[str, Any],
    *,
    selected_subset: List[Dict[str, Any]],
) -> Dict[str, Any]:
    import copy

    src = fp if isinstance(fp, dict) else {}

    # Full deep copy — do not manually rebuild partial plan objects.
    out = copy.deepcopy(src)

    # Replace only transforms.
    out["selected_transforms"] = copy.deepcopy(selected_subset or [])

    # Hard guarantee: semantic/security metadata must survive cloning.
    if not out.get("sec_entry"):
        raise RuntimeError(f"BUG: sec_entry missing during clone for {src.get('function')}")

    if not out.get("policy_trace"):
        raise RuntimeError(f"BUG: policy_trace missing during clone for {src.get('function')}")

    return out
    
def _read_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def _aggregate_transform_coverage_for_run(
    *,
    candidate_dirs: list[Path],
    implemented_transform_ids: list[str],
) -> Dict[str, Any]:
    coverage: Dict[str, Dict[str, Any]] = {}

    def _ensure_row(tid: str) -> Dict[str, Any]:
        if tid not in coverage:
            coverage[tid] = {
                "implemented": False,
                "selected": 0,
                "applied": 0,
                "selected_noop": 0,
                "skipped_by_risk": 0,
                "skipped_by_conflict": 0,
                "skipped_no_handler": 0,
                "skipped_unimplemented": 0,
                "transform_failed": 0,
                "dropped_before_execution": 0,
                "rejected_on_validation": 0,
            }
        return coverage[tid]

    for tid in implemented_transform_ids:
        row = _ensure_row(str(tid))
        row["implemented"] = True

    scanned_candidates = 0

    for cand_dir in candidate_dirs:
        tm = _read_json_if_exists(cand_dir / "obfuscation_engine" / "transform_map.json")
        vr = _read_json_if_exists(cand_dir / "validator" / "validation_report.json")

        if not tm:
            continue

        scanned_candidates += 1
        selected = tm.get("selected", []) or []
        applied = tm.get("applied", []) or []
        skipped = tm.get("skipped", []) or []

        selected_ids_in_candidate: set[str] = set()

        # Primary source of truth: selected rows with engine-stamped terminal outcomes
        for row_obj in selected:
            if not isinstance(row_obj, dict):
                continue
            tid = row_obj.get("id") or row_obj.get("transform_id")
            if not tid:
                continue
            tid = str(tid)
            row = _ensure_row(tid)
            row["selected"] += 1
            selected_ids_in_candidate.add(tid)

            outcome = str(row_obj.get("final_outcome") or "").strip()
            if outcome == "applied":
                row["applied"] += 1
            elif outcome == "noop":
                row["selected_noop"] += 1
            elif outcome == "skipped_by_risk":
                row["skipped_by_risk"] += 1
            elif outcome == "skipped_by_conflict":
                row["skipped_by_conflict"] += 1
            elif outcome == "skipped_no_handler":
                row["skipped_no_handler"] += 1
            elif outcome == "skipped_unimplemented":
                row["skipped_unimplemented"] += 1
            elif outcome == "transform_failed":
                row["transform_failed"] += 1
            elif outcome == "dropped_before_execution":
                row["dropped_before_execution"] += 1

        # Backward-compatible fallback for older transform_map.json files
        has_terminal_outcomes = any(
            isinstance(row_obj, dict) and row_obj.get("final_outcome")
            for row_obj in selected
        )

        if not has_terminal_outcomes:
            for row_obj in applied:
                if not isinstance(row_obj, dict):
                    continue
                tid = row_obj.get("id") or row_obj.get("transform_id")
                if not tid:
                    continue
                tid = str(tid)
                row = _ensure_row(tid)
                changed = bool(row_obj.get("changed"))
                if changed:
                    row["applied"] += 1
                else:
                    row["selected_noop"] += 1

            for row_obj in skipped:
                if not isinstance(row_obj, dict):
                    continue
                tid = row_obj.get("id") or row_obj.get("transform_id")
                if not tid:
                    continue
                tid = str(tid)
                row = _ensure_row(tid)

                cat = str(row_obj.get("skip_category") or "").strip()
                reason = str(row_obj.get("reason") or "").lower()

                if cat == "skipped_by_risk" or "engine gate blocked" in reason:
                    row["skipped_by_risk"] += 1
                elif cat == "skipped_by_conflict" or "conflict" in reason:
                    row["skipped_by_conflict"] += 1
                elif cat == "skipped_no_handler" or "no transform handler registered" in reason:
                    row["skipped_no_handler"] += 1
                elif cat == "skipped_unimplemented" or "not implemented" in reason:
                    row["skipped_unimplemented"] += 1
                elif cat == "transform_failed" or "transform failed" in reason:
                    row["transform_failed"] += 1

        accepted = None
        if isinstance(vr, dict):
            accepted = bool(vr.get("accepted"))

        if accepted is False:
            for tid in selected_ids_in_candidate:
                row = _ensure_row(tid)
                row["rejected_on_validation"] += 1

    starved_safe_candidates = []
    for tid, row in sorted(coverage.items()):
        if (
            row["implemented"]
            and row["selected"] > 0
            and row["applied"] == 0
            and row["selected_noop"] == 0
            and row["skipped_by_risk"] == 0
            and row["skipped_by_conflict"] == 0
            and row["skipped_no_handler"] == 0
            and row["skipped_unimplemented"] == 0
            and row["transform_failed"] == 0
            and row["dropped_before_execution"] == 0
            and row["rejected_on_validation"] == 0
        ):
            starved_safe_candidates.append(tid)

    return {
        "candidate_count_scanned": scanned_candidates,
        "implemented_transform_count": len(implemented_transform_ids),
        "per_transform": dict(sorted(coverage.items())),
        "starved_without_risk_or_conflict": starved_safe_candidates,
    }

def run_ast_analyzer(sol_path: Path, ir_out: Path, ast_dump: Path) -> dict:
    cmd = [
        sys.executable,
        "-m",
        "invsol_ast.cli",
        str(sol_path),
        "--out",
        str(ir_out),
        "--dump-ast",
        str(ast_dump),
    ]

    print(
        f"[OBLIVION] Running: {sys.executable} -m invsol_ast.cli {sol_path} "
        f"--out {ir_out} --dump-ast {ast_dump} (cwd={AST_ANALYZER_ROOT})"
    )

    res = subprocess.run(cmd, cwd=str(AST_ANALYZER_ROOT))
    if res.returncode != 0:
        print(f"[OBLIVION] ERROR: AST analyzer exited with code {res.returncode}")
        sys.exit(1)

    with open(ir_out, "r", encoding="utf-8") as f:
        return json.load(f)

def _prune_unsafe_pairs_from_selected(
    selected: List[Dict[str, Any]],
    llm_meta: Dict[str, Any] | None,
    sec_entry: Dict[str, Any] | None = None,
) -> tuple[List[Dict[str, Any]], List[str]]:
    llm_meta = llm_meta if isinstance(llm_meta, dict) else {}
    sec_entry = sec_entry if isinstance(sec_entry, dict) else {}
    graph = llm_meta.get("composition_graph") if isinstance(llm_meta.get("composition_graph"), dict) else {}

    unsafe_pairs = set()
    for item in graph.get("unsafe_pairs", []) or []:
        if not isinstance(item, dict):
            continue
        pair = item.get("pair") or []
        if isinstance(pair, list) and len(pair) == 2:
            a, b = pair[0], pair[1]
            if isinstance(a, str) and isinstance(b, str):
                unsafe_pairs.add(tuple(sorted([a, b])))

    ids: List[str] = []
    by_id: Dict[str, Dict[str, Any]] = {}

    for row in selected or []:
        if not isinstance(row, dict):
            continue
        tid = row.get("id")
        if isinstance(tid, str) and tid.strip():
            ids.append(tid)
            by_id[tid] = row

    to_remove = set()
    reasons: List[str] = []

    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a = ids[i]
            b = ids[j]
            key = tuple(sorted([a, b]))
            if key not in unsafe_pairs:
                continue

            wa = _transform_risk_weight(a, llm_meta=llm_meta, sec_entry=sec_entry)
            wb = _transform_risk_weight(b, llm_meta=llm_meta, sec_entry=sec_entry)

            if wa > wb:
                victim = a
            elif wb > wa:
                victim = b
            else:
                # stable tie-breaker
                victim = sorted([a, b])[1]

            to_remove.add(victim)
            reasons.append(f"unsafe_pair:{a}|{b}:removed={victim}")

    out = [row for row in selected if row.get("id") not in to_remove]
    return out, reasons

def _narrow_semantic_contract(llm_meta: Dict[str, Any] | None, sec_entry: Dict[str, Any] | None) -> bool:
    llm_meta = llm_meta if isinstance(llm_meta, dict) else {}
    sec_entry = sec_entry if isinstance(sec_entry, dict) else {}

    sc = llm_meta.get("semantic_contract") if isinstance(llm_meta.get("semantic_contract"), dict) else {}
    protected_tags = set(
        x for x in (sc.get("protected_region_tags") or [])
        if isinstance(x, str) and x.strip()
    )

    sec_tags = (
        (sec_entry.get("policy_constraints", {}) or {}).get("protected_region_tags", []) or []
    )
    protected_tags.update(
        x for x in sec_tags
        if isinstance(x, str) and x.strip()
    )

    # Narrow means the function is semantically sensitive enough that aggressive transforms
    # should be demoted unless strongly justified.
    if len(protected_tags) >= 1:
        return True

    signals = sec_entry.get("policy_signals") if isinstance(sec_entry.get("policy_signals"), dict) else {}
    if bool(signals.get("arithmetic_sensitive")):
        return True
    if bool(signals.get("loop_gas_sensitive")):
        return True
    if bool(signals.get("revert_semantics_sensitive")):
        return True

    return False


def _transform_risk_weight(
    tid: str,
    *,
    llm_meta: Dict[str, Any] | None,
    sec_entry: Dict[str, Any] | None,
) -> float:
    llm_meta = llm_meta if isinstance(llm_meta, dict) else {}
    sec_entry = sec_entry if isinstance(sec_entry, dict) else {}

    narrow = _narrow_semantic_contract(llm_meta, sec_entry)

    base_weights = {
        "rename_identifiers_v2_scoped": 0.05,
        "rename_identifiers_sha1_v1": 0.10,
        "layout_scramble_v1": 0.20,

        "constant_encoding_v1": 0.35,
        "constant_encoding_v2_layered": 0.42,
        "dynamic_constants_v1": 0.45,

        "inline_internal_v1": 0.50,
        "inline_internal_v2_diversified": 0.62,

        "boolean_split_v1": 0.55,
        "boolean_split_v2_distributed": 0.62,

        "dead_code_v1": 0.65,

        "opaque_predicate_v1": 0.70,
        "opaque_predicate_v2_entangled": 0.78,

        "predicate_masking_v1": 0.80,
        "stack_variable_aliasing_v1": 0.85,
        "local_to_state_lift_v1": 0.90,
        "public_state_accessor_indirection_v1": 0.75,
        "loop_rewrite_v1": 0.85,

        "cfg_flatten_v1": 0.95,
        "cfg_flattening_v1": 0.95,
        "cfg_flatten_v2_hybrid": 0.98,
    }

    w = float(base_weights.get(tid, 0.50))

    if narrow and tid in {
        "dynamic_constants_v1",
        "inline_internal_v1",
        "inline_internal_v2_diversified",
        "dead_code_v1",
        "opaque_predicate_v1",
        "opaque_predicate_v2_entangled",
        "predicate_masking_v1",
        "boolean_split_v2_distributed",
        "loop_rewrite_v1",
        "cfg_flatten_v1",
        "cfg_flattening_v1",
        "cfg_flatten_v2_hybrid",
    }:
        w += 0.25

    return w

def _is_cosmetic_transform_id(tid: str) -> bool:
    return tid in {
        "rename_identifiers_v2_scoped",
        "rename_identifiers_sha1_v1",
        "rename_identifiers_v1",
        "layout_scramble_v1",
    }


def _is_semantic_sensitive_transform_id(tid: str) -> bool:
    return tid in {
        "constant_encoding_v1",
        "constant_encoding_v2_layered",
        "dynamic_constants_v1",
        "string_split_v1",
        "algebraic_identities_v1",
        "inline_internal_v2_diversified",
        "opaque_predicate_v2_entangled",
        "public_state_accessor_indirection_v1",
        "scalar_to_struct_indirection_v1",
        "cfg_flatten_v2_hybrid",
        "yul_microblock_v1",
    }

def _append_visual_potency_transforms(
    *,
    fn_name: str,
    tier: int,
    sev: str,
    selected: list[dict],
    allowed_ids_set: set[str],
    sec_entry: dict | None,
) -> list[dict]:
    """
    Add stronger BiAn-like transforms when available.
    Still later passes through compatibility gate + validator.
    """
    selected = list(selected or [])
    existing = {
        t.get("id")
        for t in selected
        if isinstance(t, dict) and isinstance(t.get("id"), str)
    }

    sec_entry = sec_entry if isinstance(sec_entry, dict) else {}
    signals = sec_entry.get("policy_signals") if isinstance(sec_entry.get("policy_signals"), dict) else {}

    access_sensitive = bool(signals.get("access_control_sensitive"))
    arithmetic_sensitive = bool(signals.get("arithmetic_sensitive"))
    revert_sensitive = bool(signals.get("revert_semantics_sensitive"))
    external_sensitive = bool(signals.get("external_call_sensitive"))

    # Safe visual transforms for almost all functions.
    desired = [
        "rename_identifiers_v2_scoped",
        "layout_scramble_v1",
    ]

    # BiAn-like constant/data-flow obfuscation.
    if not access_sensitive and not external_sensitive:
        desired += [
            "constant_encoding_v1",
            "dynamic_constants_v1",
        ]

    # BiAn-like opaque predicates.
    if tier >= 1 and not access_sensitive and not revert_sensitive:
        desired += [
            "opaque_predicate_v2_entangled",
        ]

    # Conservative CFG flattening on safe/non-access-control functions.
    # v1 preserves statement order and is validator-gated, so allow earlier.
    if tier >= 1 and sev in {"INFO", "LOW"} and not (
        access_sensitive or external_sensitive
    ):
        desired += [
            "cfg_flatten_v1",
        ]

    # Stronger hybrid CFG only for cleaner Tier-2+ functions.
    if tier >= 2 and sev in {"INFO", "LOW"} and not (
        access_sensitive or external_sensitive or revert_sensitive
    ):
        desired += [
            "cfg_flatten_v2_hybrid",
        ]

    for tid in desired:
        if tid in existing:
            continue
        if tid not in allowed_ids_set:
            continue

        selected.append(
            {
                "id": tid,
                "target": {"function": fn_name},
                "params": {},
                "reason": "visual_potency_existing_transform",
            }
        )
        existing.add(tid)

    return selected

def _is_hard_drop_even_when_safe(tid: str) -> bool:
    return tid in {
        # keep this list very small
        "yul_microblock_v1",
    }

def _demote_aggressive_transforms_for_narrow_contract(
    selected: List[Dict[str, Any]],
    *,
    llm_meta: Dict[str, Any] | None,
    sec_entry: Dict[str, Any] | None,
    policy: Dict[str, Any] | None = None,
    fn_entry: Dict[str, Any] | None = None,
) -> tuple[List[Dict[str, Any]], List[str]]:
    llm_meta = llm_meta if isinstance(llm_meta, dict) else {}
    sec_entry = sec_entry if isinstance(sec_entry, dict) else {}
    policy = policy if isinstance(policy, dict) else {}
    fn_entry = fn_entry if isinstance(fn_entry, dict) else {}

    semantic_contract = (
        llm_meta.get("semantic_contract")
        if isinstance(llm_meta.get("semantic_contract"), dict)
        else {}
    )

    tier = int(fn_entry.get("tier", 0) or 0)
    sec_sev = str(
        fn_entry.get("sec_severity")
        or sec_entry.get("sec_severity")
        or sec_entry.get("severity_max")
        or "INFO"
    ).upper()
    runtime_relevance = float(
        fn_entry.get("runtime_relevance", sec_entry.get("runtime_relevance", 0.0)) or 0.0
    )

    narrow_semantic_contract = bool(
        semantic_contract.get("narrow_semantic_contract", False)
        or semantic_contract.get("strict_equivalence", False)
        or semantic_contract.get("event_exactness_required", False)
        or semantic_contract.get("revert_exactness_required", False)
        or _narrow_semantic_contract(llm_meta, sec_entry)
    )

    if not narrow_semantic_contract:
        return list(selected or []), []

    signals = sec_entry.get("policy_signals") if isinstance(sec_entry.get("policy_signals"), dict) else {}
    loop_sensitive = bool(signals.get("loop_gas_sensitive"))
    arithmetic_sensitive = bool(signals.get("arithmetic_sensitive"))
    revert_sensitive = bool(signals.get("revert_semantics_sensitive"))

    safe_survival_mode = (
        narrow_semantic_contract
        and (
            (tier >= 2 and sec_sev in {"INFO", "LOW"})
            or (tier == 1 and sec_sev == "INFO" and runtime_relevance >= 0.12)
        )
    )

    demoted: List[Dict[str, Any]] = []
    reasons: List[str] = []

    for row in selected or []:
        if not isinstance(row, dict):
            continue

        tid = str(row.get("id") or "").strip()
        if not tid:
            continue

        if _is_cosmetic_transform_id(tid):
            demoted.append(row)
            continue

        if not _is_semantic_sensitive_transform_id(tid):
            row2 = dict(row)
            row2["_semantic_priority_penalty"] = float(row2.get("_semantic_priority_penalty", 0.0)) + 0.15
            demoted.append(row2)
            reasons.append(f"{tid}:narrow_semantic_contract_soft_demote")
            continue

        if safe_survival_mode and not _is_hard_drop_even_when_safe(tid):
            row2 = dict(row)
            row2["_semantic_priority_penalty"] = float(row2.get("_semantic_priority_penalty", 0.0)) + 0.20
            row2["_preserved_under_narrow_semantics"] = True
            demoted.append(row2)
            reasons.append(f"{tid}:narrow_semantic_contract_soft_demote")
            continue

        hard_drop = False

        if loop_sensitive and tid in {
            "inline_internal_v2_diversified",
            "opaque_predicate_v2_entangled",
            "cfg_flatten_v1",
            "cfg_flattening_v1",
            "cfg_flatten_v2_hybrid",
            "yul_microblock_v1",
            "scalar_to_struct_indirection_v1",
            "public_state_accessor_indirection_v1",
        }:
            hard_drop = True

        if revert_sensitive and tid in {
            "string_split_v1",
        }:
            hard_drop = True

        if arithmetic_sensitive and tid in {
            "algebraic_identities_v1",
            "predicate_masking_v1",
        }:
            hard_drop = True

        if _is_hard_drop_even_when_safe(tid):
            hard_drop = True

        if hard_drop:
            reasons.append(f"{tid}:narrow_semantic_contract_hard_drop")
            continue

        row2 = dict(row)
        row2["_semantic_priority_penalty"] = float(row2.get("_semantic_priority_penalty", 0.0)) + 0.20
        demoted.append(row2)
        reasons.append(f"{tid}:narrow_semantic_contract_soft_demote")

    # Rescue path: if safe-survival mode ended with only cosmetic transforms,
    # preserve one strongest non-cosmetic transform.
    if safe_survival_mode:
        has_noncosmetic = any(
            isinstance(x, dict)
            and str(x.get("id") or "").strip()
            and not _is_cosmetic_transform_id(str(x.get("id") or "").strip())
            for x in demoted
        )

        if not has_noncosmetic:
            rescue_candidates: List[tuple[int, Dict[str, Any]]] = []

            for row in selected or []:
                if not isinstance(row, dict):
                    continue
                tid = str(row.get("id") or "").strip()
                if not tid:
                    continue
                if _is_cosmetic_transform_id(tid):
                    continue
                if _is_hard_drop_even_when_safe(tid):
                    continue

                score = 0
                if tid in {"opaque_predicate_v2_entangled", "cfg_flatten_v2_hybrid", "scalar_to_struct_indirection_v1"}:
                    score = 30
                elif tid in {"inline_internal_v2_diversified", "public_state_accessor_indirection_v1"}:
                    score = 20
                elif tid in {"constant_encoding_v2_layered", "dynamic_constants_v1", "string_split_v1"}:
                    score = 10
                else:
                    score = 5

                rescue_candidates.append((score, row))

            if rescue_candidates:
                rescue_candidates.sort(key=lambda x: x[0], reverse=True)
                rescued = dict(rescue_candidates[0][1])
                rescued["_semantic_priority_penalty"] = float(rescued.get("_semantic_priority_penalty", 0.0)) + 0.25
                rescued["_rescued_from_hard_drop"] = True
                demoted.append(rescued)
                reasons.append(
                    f"{rescued.get('id')}:narrow_semantic_contract_rescue_preserve_one_noncosmetic"
                )

    def _soft_rank(row: Dict[str, Any]) -> tuple[int, int, float, str]:
        tid = str(row.get("id") or "")
        cosmetic = 0 if not _is_cosmetic_transform_id(tid) else 1
        penalty = float(row.get("_semantic_priority_penalty", 0.0))
        weight = _transform_risk_weight(
            tid,
            llm_meta=llm_meta,
            sec_entry=sec_entry,
        )
        return (cosmetic, int(penalty * 1000), int(weight * 1000), tid)

    demoted = sorted(demoted, key=_soft_rank)
    return demoted, reasons

def _semantic_avoid_region_overlap_penalty(
    *,
    llm_meta: Dict[str, Any] | None,
    sec_entry: Dict[str, Any] | None,
    selected_ids: List[str],
) -> float:
    llm_meta = llm_meta if isinstance(llm_meta, dict) else {}
    sec_entry = sec_entry if isinstance(sec_entry, dict) else {}

    sc = llm_meta.get("semantic_contract") if isinstance(llm_meta.get("semantic_contract"), dict) else {}
    ts_list = sc.get("transform_safety") if isinstance(sc.get("transform_safety"), list) else []

    transform_safety: Dict[str, Dict[str, Any]] = {}
    for row in ts_list:
        if not isinstance(row, dict):
            continue
        tid = row.get("transform_id")
        if isinstance(tid, str) and tid.strip():
            transform_safety[tid] = row

    protected_tags = set()

    for tag in sc.get("protected_region_tags") or []:
        if isinstance(tag, str) and tag.strip():
            protected_tags.add(tag)

    policy_constraints = sec_entry.get("policy_constraints") if isinstance(sec_entry.get("policy_constraints"), dict) else {}
    for tag in policy_constraints.get("protected_region_tags") or []:
        if isinstance(tag, str) and tag.strip():
            protected_tags.add(tag)

    if not protected_tags:
        return 0.0

    penalty = 0.0

    for tid in selected_ids:
        row = transform_safety.get(tid) or {}
        avoid_regions = row.get("avoid_regions") if isinstance(row.get("avoid_regions"), list) else []
        overlap = {
            tag for tag in avoid_regions
            if isinstance(tag, str) and tag.strip() and tag in protected_tags
        }
        if overlap:
            # Very large penalty so these subsets never become "preferred".
            penalty += 100.0 + (10.0 * len(overlap))

    return penalty

def _candidate_semantic_cost(candidate_plan: Dict[str, Any]) -> float:
    total = 0.0

    for fp in candidate_plan.get("plans", []) or []:
        if not isinstance(fp, dict):
            continue

        llm_meta = fp.get("llm_meta") if isinstance(fp.get("llm_meta"), dict) else {}
        sec_entry = fp.get("sec_entry") if isinstance(fp.get("sec_entry"), dict) else {}

        selected = fp.get("selected_transforms") or []
        if not isinstance(selected, list):
            selected = []

        selected_ids: List[str] = []
        for t in selected:
            if isinstance(t, dict) and isinstance(t.get("id"), str) and t.get("id").strip():
                selected_ids.append(t["id"])

        # lower is better
        for tid in selected_ids:
            total += _transform_risk_weight(tid, llm_meta=llm_meta, sec_entry=sec_entry)

        # additional penalty for bigger transform sets on semantically narrow functions
        if _narrow_semantic_contract(llm_meta, sec_entry):
            total += max(0, len(selected_ids) - 2) * 0.35

        # CRITICAL: explicit semantic-contract avoid-region overlap should make a subset
        # non-preferred, even if its generic risk score is otherwise acceptable.
        total += _semantic_avoid_region_overlap_penalty(
            llm_meta=llm_meta,
            sec_entry=sec_entry,
            selected_ids=selected_ids,
        )

    return total

def _sort_candidate_plans_by_semantic_cost(candidate_plan_objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    decorated = []
    for i, cp in enumerate(candidate_plan_objects or []):
        try:
            score = _candidate_semantic_cost(cp if isinstance(cp, dict) else {})
        except Exception:
            score = 10**9
        decorated.append((score, i, cp))

    decorated.sort(key=lambda x: (x[0], x[1]))
    return [cp for _, _, cp in decorated]

def ensure_contract_in_foundry_src(sol_path: Path) -> str:
    src_dir = FOUNDRY_ROOT / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    try:
        rel = sol_path.relative_to(FOUNDRY_ROOT)
        return rel.as_posix()
    except ValueError:
        dest = src_dir / sol_path.name
        copy2(sol_path, dest)
        print(f"[OBLIVION] Copied contract into Foundry src: {dest}")
        return f"src/{sol_path.name}"


def auto_flatten_if_needed(original_sol: Path, out_dir: Path) -> Path:
    try:
        _ = original_sol.relative_to(FOUNDRY_ROOT)
    except ValueError:
        print("[OBLIVION] Contract not under Foundry root; skipping auto-flatten.")
        return original_sol

    flat_path = out_dir / f"{original_sol.stem}_flat.sol"
    subprocess.run(
        ["forge", "flatten", str(original_sol.relative_to(FOUNDRY_ROOT)), "-o", str(flat_path)],
        cwd=str(FOUNDRY_ROOT),
    )
    if flat_path.exists():
        print(f"Flattened file written at {flat_path}")
    return flat_path if flat_path.exists() else original_sol


def run_testcrafter(ir_json_path: Path, contract_import_path: str):
    TESTCRAFTER_ROOT = ROOT / "testcrafter-mini"
    cfg_path = TESTCRAFTER_ROOT / "data" / "config.json"

    subprocess.run(
        [
            sys.executable,
            "-m",
            "testcrafter.cli",
            "--ast-json",
            str(ir_json_path),
            "--config",
            str(cfg_path),
            "--contract-import-path",
            contract_import_path,
            "--verbose-logs",
        ],
        cwd=str(TESTCRAFTER_ROOT),
        check=True,
    )

    with open(ir_json_path, "r", encoding="utf-8") as f:
        ir = json.load(f)

    cname = ir["contract"]["name"]
    harness = FOUNDRY_ROOT / "test" / f"{cname}_Harness.t.sol"
    return harness, f"{cname}_Harness"


def _extract_tests_to_run(plan_obj: dict) -> list[str]:
    tests_to_run: list[str] = []
    for p in plan_obj.get("plans", []) or []:
        tests_to_run.extend(p.get("tests_to_run", []) or [])
    return sorted(set(tests_to_run))

def _rehydrate_candidate_plan_metadata(
    base_plan_obj: Dict[str, Any],
    candidate_plan_obj: Dict[str, Any],
) -> Dict[str, Any]:
    import copy

    if not isinstance(base_plan_obj, dict) or not isinstance(candidate_plan_obj, dict):
        return candidate_plan_obj

    base_plans = base_plan_obj.get("plans")
    cand_plans = candidate_plan_obj.get("plans")

    if not isinstance(base_plans, list) or not isinstance(cand_plans, list):
        return candidate_plan_obj

    base_by_fn: Dict[str, Dict[str, Any]] = {}
    for fp in base_plans:
        if not isinstance(fp, dict):
            continue
        fn = str(fp.get("function") or "").strip()
        if fn:
            base_by_fn[fn] = fp

    for fp in cand_plans:
        if not isinstance(fp, dict):
            continue

        fn = str(fp.get("function") or "").strip()
        if not fn:
            continue

        base_fp = base_by_fn.get(fn)
        if not isinstance(base_fp, dict):
            continue

        base_sec = base_fp.get("sec_entry") if isinstance(base_fp.get("sec_entry"), dict) else {}
        cand_sec = fp.get("sec_entry") if isinstance(fp.get("sec_entry"), dict) else {}

        # Merge sec_entry from base first, then overlay candidate.
        merged_sec = copy.deepcopy(base_sec)
        merged_sec.update(copy.deepcopy(cand_sec))

        # Force critical nested sec_entry metadata from base when candidate carries
        # empty or stripped placeholders.
        base_sec_signals = base_sec.get("policy_signals") if isinstance(base_sec.get("policy_signals"), dict) else {}
        cand_sec_signals = merged_sec.get("policy_signals") if isinstance(merged_sec.get("policy_signals"), dict) else {}
        if base_sec_signals and not cand_sec_signals:
            merged_sec["policy_signals"] = copy.deepcopy(base_sec_signals)

        base_sec_regions = base_sec.get("protected_regions") if isinstance(base_sec.get("protected_regions"), list) else []
        cand_sec_regions = merged_sec.get("protected_regions") if isinstance(merged_sec.get("protected_regions"), list) else []
        if base_sec_regions and not cand_sec_regions:
            merged_sec["protected_regions"] = copy.deepcopy(base_sec_regions)

        base_sec_constraints = base_sec.get("policy_constraints")
        cand_sec_constraints = merged_sec.get("policy_constraints")
        if isinstance(base_sec_constraints, dict) and not isinstance(cand_sec_constraints, dict):
            merged_sec["policy_constraints"] = copy.deepcopy(base_sec_constraints)

        fp["sec_entry"] = merged_sec

        base_pt = base_fp.get("policy_trace") if isinstance(base_fp.get("policy_trace"), dict) else {}
        cand_pt = fp.get("policy_trace") if isinstance(fp.get("policy_trace"), dict) else {}

        merged_pt = copy.deepcopy(base_pt)
        merged_pt.update(copy.deepcopy(cand_pt))

        # Force nested policy_trace fields from base if candidate carries empty/stripped values.
        base_signals = base_pt.get("policy_signals") if isinstance(base_pt.get("policy_signals"), dict) else {}
        cand_signals = merged_pt.get("policy_signals") if isinstance(merged_pt.get("policy_signals"), dict) else {}
        if base_signals and not cand_signals:
            merged_pt["policy_signals"] = copy.deepcopy(base_signals)

        base_regions = base_pt.get("protected_regions") if isinstance(base_pt.get("protected_regions"), list) else []
        cand_regions = merged_pt.get("protected_regions") if isinstance(merged_pt.get("protected_regions"), list) else []
        if base_regions and not cand_regions:
            merged_pt["protected_regions"] = copy.deepcopy(base_regions)

        base_constraints = base_pt.get("policy_constraints")
        cand_constraints = merged_pt.get("policy_constraints")
        if isinstance(base_constraints, dict) and not isinstance(cand_constraints, dict):
            merged_pt["policy_constraints"] = copy.deepcopy(base_constraints)

        # Keep policy_trace aligned with sec_entry too.
        sec_signals = merged_sec.get("policy_signals") if isinstance(merged_sec.get("policy_signals"), dict) else {}
        if sec_signals and not (
            isinstance(merged_pt.get("policy_signals"), dict) and merged_pt.get("policy_signals")
        ):
            merged_pt["policy_signals"] = copy.deepcopy(sec_signals)

        sec_regions = merged_sec.get("protected_regions") if isinstance(merged_sec.get("protected_regions"), list) else []
        if sec_regions and not (
            isinstance(merged_pt.get("protected_regions"), list) and merged_pt.get("protected_regions")
        ):
            merged_pt["protected_regions"] = copy.deepcopy(sec_regions)

        sec_constraints = merged_sec.get("policy_constraints")
        if isinstance(sec_constraints, dict) and not isinstance(merged_pt.get("policy_constraints"), dict):
            merged_pt["policy_constraints"] = copy.deepcopy(sec_constraints)

        fp["policy_trace"] = merged_pt

        if not isinstance(fp.get("function_ir"), dict) or not fp.get("function_ir"):
            fp["function_ir"] = copy.deepcopy(base_fp.get("function_ir") or {})

        if not isinstance(fp.get("policy_context"), dict) or not fp.get("policy_context"):
            fp["policy_context"] = copy.deepcopy(base_fp.get("policy_context") or {})

        if not isinstance(fp.get("llm_meta"), dict) or not fp.get("llm_meta"):
            fp["llm_meta"] = copy.deepcopy(base_fp.get("llm_meta") or {})

        if not isinstance(fp.get("pre_engine_llm_meta"), dict) or not fp.get("pre_engine_llm_meta"):
            fp["pre_engine_llm_meta"] = copy.deepcopy(base_fp.get("pre_engine_llm_meta") or {})

        if not isinstance(fp.get("tests_to_run"), list):
            fp["tests_to_run"] = copy.deepcopy(base_fp.get("tests_to_run") or [])

    return candidate_plan_obj

def _candidate_plan_metadata_missing(
    base_plan_obj: Dict[str, Any],
    candidate_plan_obj: Dict[str, Any],
) -> List[str]:
    """
    Return a list of per-function metadata problems that should never survive
    into a persisted optimizer candidate plan.
    """
    problems: List[str] = []

    if not isinstance(base_plan_obj, dict) or not isinstance(candidate_plan_obj, dict):
        return ["plan_not_dict"]

    base_plans = base_plan_obj.get("plans") if isinstance(base_plan_obj.get("plans"), list) else []
    cand_plans = candidate_plan_obj.get("plans") if isinstance(candidate_plan_obj.get("plans"), list) else []

    base_by_fn: Dict[str, Dict[str, Any]] = {}
    for fp in base_plans:
        if not isinstance(fp, dict):
            continue
        fn_name = str(fp.get("function") or "").strip()
        if fn_name:
            base_by_fn[fn_name] = fp

    for fp in cand_plans:
        if not isinstance(fp, dict):
            continue

        fn_name = str(fp.get("function") or "").strip()
        if not fn_name:
            continue

        base_fp = base_by_fn.get(fn_name)
        if not isinstance(base_fp, dict):
            continue

        base_sec = base_fp.get("sec_entry") if isinstance(base_fp.get("sec_entry"), dict) else {}
        cand_sec = fp.get("sec_entry") if isinstance(fp.get("sec_entry"), dict) else {}

        base_trace = base_fp.get("policy_trace") if isinstance(base_fp.get("policy_trace"), dict) else {}
        cand_trace = fp.get("policy_trace") if isinstance(fp.get("policy_trace"), dict) else {}

        if base_sec and not cand_sec:
            problems.append(f"{fn_name}:missing_sec_entry")

        base_sec_signals = base_sec.get("policy_signals") if isinstance(base_sec.get("policy_signals"), dict) else {}
        cand_sec_signals = cand_sec.get("policy_signals") if isinstance(cand_sec.get("policy_signals"), dict) else {}
        if base_sec_signals and not cand_sec_signals:
            problems.append(f"{fn_name}:missing_sec_entry_policy_signals")

        base_sec_regions = base_sec.get("protected_regions") if isinstance(base_sec.get("protected_regions"), list) else []
        cand_sec_regions = cand_sec.get("protected_regions") if isinstance(cand_sec.get("protected_regions"), list) else []
        if base_sec_regions and not cand_sec_regions:
            problems.append(f"{fn_name}:missing_sec_entry_protected_regions")

        base_sec_constraints = base_sec.get("policy_constraints") if isinstance(base_sec.get("policy_constraints"), dict) else {}
        cand_sec_constraints = cand_sec.get("policy_constraints") if isinstance(cand_sec.get("policy_constraints"), dict) else {}
        if base_sec_constraints and not cand_sec_constraints:
            problems.append(f"{fn_name}:missing_sec_entry_policy_constraints")

        base_signals = base_trace.get("policy_signals") if isinstance(base_trace.get("policy_signals"), dict) else {}
        cand_signals = cand_trace.get("policy_signals") if isinstance(cand_trace.get("policy_signals"), dict) else {}
        if base_signals and not cand_signals:
            problems.append(f"{fn_name}:missing_policy_signals")

        base_regions = base_trace.get("protected_regions") if isinstance(base_trace.get("protected_regions"), list) else []
        cand_regions = cand_trace.get("protected_regions") if isinstance(cand_trace.get("protected_regions"), list) else []
        if base_regions and not cand_regions:
            problems.append(f"{fn_name}:missing_protected_regions")

        base_constraints = base_trace.get("policy_constraints") if isinstance(base_trace.get("policy_constraints"), dict) else {}
        cand_constraints = cand_trace.get("policy_constraints") if isinstance(cand_trace.get("policy_constraints"), dict) else {}
        if base_constraints and not cand_constraints:
            problems.append(f"{fn_name}:missing_policy_constraints")

        base_ir = base_fp.get("function_ir") if isinstance(base_fp.get("function_ir"), dict) else {}
        cand_ir = fp.get("function_ir") if isinstance(fp.get("function_ir"), dict) else {}
        if base_ir and not cand_ir:
            problems.append(f"{fn_name}:missing_function_ir")

        base_llm = base_fp.get("llm_meta") if isinstance(base_fp.get("llm_meta"), dict) else {}
        cand_llm = fp.get("llm_meta") if isinstance(fp.get("llm_meta"), dict) else {}
        if base_llm and not cand_llm:
            problems.append(f"{fn_name}:missing_llm_meta")

    return problems

def _ensure_plan_has_transforms(plan_obj: dict) -> dict:
    """
    Ensure the plan object has a top-level `transforms` list that the engine/optimizer can use.
    """
    if not isinstance(plan_obj, dict):
        return {"contract": "", "plans": [], "transforms": []}

    def _is_bogus_id(tid: str) -> bool:
        return isinstance(tid, str) and tid.strip().startswith("plan[")

    def _coerce_one_transform(x) -> list[dict]:
        out: list[dict] = []

        if isinstance(x, str):
            tid = x.strip()
            if not tid or _is_bogus_id(tid):
                return []
            out.append({"id": tid, "target": {}, "params": {}})
            return out

        if not isinstance(x, dict):
            return []

        if "plan" in x and isinstance(x.get("plan"), list):
            for y in x.get("plan") or []:
                out.extend(_coerce_one_transform(y))
            return out
        if "transforms" in x and isinstance(x.get("transforms"), list):
            for y in x.get("transforms") or []:
                out.extend(_coerce_one_transform(y))
            return out

        tid = x.get("id") or x.get("transform_id") or x.get("type") or x.get("transformId")
        if tid is None:
            return []

        tid = str(tid).strip()
        if not tid or _is_bogus_id(tid):
            return []

        params = x.get("params") if isinstance(x.get("params"), dict) else {}
        target = x.get("target") if isinstance(x.get("target"), dict) else {}

        out.append({"id": tid, "target": target, "params": params})
        return out

    transforms: list[dict] = []
    existing = plan_obj.get("transforms")
    if isinstance(existing, list):
        for item in existing:
            transforms.extend(_coerce_one_transform(item))

    plans = plan_obj.get("plans")
    if isinstance(plans, list):
        for fp in plans:
            if not isinstance(fp, dict):
                continue
            fn_name = (fp.get("function") or "").strip()
            sel = fp.get("selected_transforms") or []
            if not isinstance(sel, list):
                sel = []

            for item in sel:
                for t in _coerce_one_transform(item):
                    tgt = t.get("target") if isinstance(t.get("target"), dict) else {}
                    if fn_name and "function" not in tgt:
                        tgt["function"] = fn_name
                    t["target"] = tgt
                    transforms.append(t)

    normalized: list[dict] = []
    for t in transforms:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        if not isinstance(tid, str):
            continue
        tid = tid.strip()
        if not tid or _is_bogus_id(tid):
            continue

        params = t.get("params") if isinstance(t.get("params"), dict) else {}
        target = t.get("target") if isinstance(t.get("target"), dict) else {}

        normalized.append({"id": tid, "target": target, "params": params})

    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for t in normalized:
        fn = ""
        if isinstance(t.get("target"), dict):
            fn = str(t["target"].get("function") or "")
        key = (t["id"], fn)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(t)

    plan_obj2 = dict(plan_obj)
    plan_obj2["transforms"] = deduped
    if "plans" not in plan_obj2 or not isinstance(plan_obj2.get("plans"), list):
        plan_obj2["plans"] = []

    return plan_obj2

def _try_score_candidate(
    *,
    foundry_root: Path,
    contract_name: str,
    contract_import_path: str,
    harness_contract: str,
    original_sol: Path,
    obfuscated_sol: Path,
    out_dir: Path,
    validator_dir: Optional[Path] = None,
    baseline_sec_advice_json: Optional[Path] = None,
    transform_map_json: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Optional scoring hook.
    """
    try:
        from scorer.bytecode_scorer import score_contract
    except Exception:
        return {"ok": False, "skipped": True, "reason": "bytecode_scorer_not_available"}

    try:
        score = score_contract(
            foundry_root=foundry_root,
            contract_name=contract_name,
            target_relpath=contract_import_path,
            harness_contract=harness_contract,
            original_sol=original_sol,
            candidate_sol=obfuscated_sol,
            validator_dir=validator_dir,
            baseline_sec_advice_json=baseline_sec_advice_json,
            transform_map_json=transform_map_json,
            out_dir=out_dir,
        )
        if isinstance(score, dict):
            score.setdefault("ok", True)
            score.setdefault("skipped", False)
            return score
        return {"ok": True, "skipped": False, "score": score}
    except Exception as e:
        return {"ok": False, "skipped": False, "reason": f"scorer_error: {e}"}

def _summarize_validation_failure(vres, validator_out: Path) -> str:
    """
    Best-effort summarizer for rejected candidates.
    Tries:
      1) ValidationResult object attributes
      2) validation_report.json
      3) diff/gas JSON side files
    """
    parts = []

    def _add(label: str, value):
        if value is None:
            return
        parts.append(f"{label}={value}")

    def _inspect_stage(name: str, obj):
        if not isinstance(obj, dict):
            return
        if "ok" in obj:
            _add(f"{name}_ok", obj.get("ok"))
        if "reason" in obj:
            _add(f"{name}_reason", obj.get("reason"))
        if "failure_reason" in obj:
            _add(f"{name}_failure_reason", obj.get("failure_reason"))
        if "returncode" in obj:
            _add(f"{name}_returncode", obj.get("returncode"))
        if "within_budget" in obj:
            _add(f"{name}_within_budget", obj.get("within_budget"))
        if "gas_delta_pct" in obj:
            _add(f"{name}_gas_delta_pct", obj.get("gas_delta_pct"))
        if "median_delta_pct" in obj:
            _add(f"{name}_median_delta_pct", obj.get("median_delta_pct"))
        if "dropped" in obj and isinstance(obj.get("dropped"), list):
            _add(f"{name}_dropped", len(obj.get("dropped")))
        if "new_findings" in obj and isinstance(obj.get("new_findings"), list):
            _add(f"{name}_new_findings", len(obj.get("new_findings")))
        if "error_summary" in obj and obj.get("error_summary"):
            _add(f"{name}_error_summary", obj.get("error_summary"))
        if "log" in obj and obj.get("log"):
            _add(f"{name}_log", obj.get("log"))

    # 1) Read directly from ValidationResult object
    try:
        _add("accepted", getattr(vres, "accepted", None))
    except Exception:
        pass

    for attr_name, label in [
        ("compile", "compile"),
        ("tests", "tests"),
        ("fuzz", "fuzz"),
        ("semantic", "semantic"),
        ("coverage", "coverage"),
        ("security", "security"),
        ("gas", "gas"),
    ]:
        try:
            obj = getattr(vres, attr_name, None)
            _inspect_stage(label, obj)
        except Exception:
            pass

    try:
        notes = getattr(vres, "notes", None)
        if isinstance(notes, list) and notes:
            _add("notes", "; ".join(str(x) for x in notes[:4]))
    except Exception:
        pass

    # 2) Read validation_report.json if present
    report_path = validator_out / "validation_report.json"
    if report_path.exists():
        try:
            obj = json.loads(report_path.read_text(encoding="utf-8"))
            for key in [
                "status",
                "reason",
                "failure_reason",
                "compile_ok",
                "tests_ok",
                "fuzz_ok",
                "coverage_ok",
                "gas_ok",
                "security_ok",
                "accepted",
            ]:
                if key in obj:
                    _add(key, obj.get(key))

            rr = obj.get("reject_reasons") or obj.get("rejection_reasons")
            if isinstance(rr, list) and rr:
                _add("reject_reasons", ",".join(str(x) for x in rr[:8]))
        except Exception:
            _add("validation_report", "unreadable")

    # 3) Side files
    diff_path = validator_out / "diff_report.json"
    if diff_path.exists():
        try:
            obj = json.loads(diff_path.read_text(encoding="utf-8"))
            if "new_high_severity" in obj:
                _add("new_high_severity", obj.get("new_high_severity"))
            if "new_findings" in obj and isinstance(obj.get("new_findings"), list):
                _add("new_findings", len(obj.get("new_findings")))
        except Exception:
            _add("diff_report", "unreadable")

    gas_path = validator_out / "gas_diff.json"
    if gas_path.exists():
        try:
            obj = json.loads(gas_path.read_text(encoding="utf-8"))
            for key in ["gas_delta_pct", "median_delta_pct", "mean_delta_pct", "within_budget"]:
                if key in obj:
                    _add(key, obj.get(key))
        except Exception:
            _add("gas_diff", "unreadable")

    return " | ".join(parts) if parts else "no_validation_details"

# ------------------------------------------------------------
# Function / advice helpers
# ------------------------------------------------------------

def _build_plan_repair_feedback(
    *,
    failure_reason: str,
    reject_reasons: list[str],
    validator_summary: str,
) -> dict:
    return {
        "failure_reason": failure_reason or "unknown_failure",
        "reject_reasons": reject_reasons or [],
        "validator_summary": validator_summary or "no_validator_summary",
    }

def _read_json_if_exists(path: Path) -> dict:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _extract_failure_reason_from_validation_report(validator_out: Path) -> str | None:
    obj = _read_json_if_exists(validator_out / "validation_report.json")
    reason = obj.get("failure_reason")
    if isinstance(reason, str) and reason.strip():
        return reason.strip()
    reject_reasons = obj.get("reject_reasons")
    if isinstance(reject_reasons, list) and reject_reasons:
        first = reject_reasons[0]
        if isinstance(first, str) and first.strip():
            return first.strip()
    return None


def _extract_reject_reasons_from_validation_report(validator_out: Path) -> list[str]:
    obj = _read_json_if_exists(validator_out / "validation_report.json")
    rr = obj.get("reject_reasons")
    if isinstance(rr, list):
        return [str(x) for x in rr if str(x).strip()]
    return []

def _extract_explicit_function_names_from_source(source_text: str) -> set[str]:
    names = set(re.findall(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\b", source_text))
    return names


def _slice_obf_advice_for_function(obf_advice: dict, fn_name: str) -> dict:
    if not isinstance(obf_advice, dict):
        return {}
    fns = obf_advice.get("functions")
    if isinstance(fns, list):
        for item in fns:
            if isinstance(item, dict) and item.get("function") == fn_name:
                return item
    return {}


def _slice_sec_advice_for_function(sec_advice: dict, fn_name: str) -> dict:
    if not isinstance(sec_advice, dict):
        return {}
    fns = sec_advice.get("functions")
    if isinstance(fns, list):
        for item in fns:
            if isinstance(item, dict) and item.get("function") == fn_name:
                return item

    by_fn = sec_advice.get("by_function")
    if isinstance(by_fn, dict) and isinstance(by_fn.get(fn_name), dict):
        return by_fn[fn_name]

    if sec_advice.get("function") == fn_name:
        return sec_advice

    return {}

# ------------------------------------------------------------
# Safe-by-default planner expansion
# ------------------------------------------------------------
# These transforms are safe enough to be attempted broadly.
# They still pass through the normal compatibility gate, engine gate,
# validator, gas checks, and security diff later.
SAFE_BY_DEFAULT = [
    "layout_scramble_v1",
    "rename_identifiers_v2_scoped",
    "string_split_v1",
]

CONTEXT_SAFE = [
    "constant_encoding_v1",
    "dynamic_constants_v1",
    "boolean_split_v1",
    "opaque_predicate_v1",
]

RISKY = [
    "cfg_flatten_v1",
    "predicate_masking_v1",
    "loop_rewrite_v1",
    "inline_internal_v1",
    "storage_indirection_v1",
    "yul_microblock_v1",
]


def _transform_id_from_any(x: Any) -> str:
    if isinstance(x, str):
        return x.strip()
    if not isinstance(x, dict):
        return ""
    tid = x.get("id") or x.get("transform_id") or x.get("type") or x.get("transformId")
    return str(tid).strip() if tid else ""


def expand_safe_plan(
    fp: dict,
    *,
    allowed_ids_set: set[str] | None = None,
    seed: int = 1337,
    policy: dict | None = None,
) -> dict:
    """
    Add safe-by-default transforms to one per-function plan.

    This is planner-side expansion only. It does not bypass:
      - compatibility matrix
      - engine risk gate
      - validator
      - security diff
      - gas budget

    Goal:
      Ensure harmless transforms are not omitted just because the LLM/optimizer
      did not explicitly select them.
    """
    if not isinstance(fp, dict):
        return fp

    fn_name = str(fp.get("function") or "").strip()
    if not fn_name:
        return fp

    policy = policy if isinstance(policy, dict) else {}

    enabled = bool(policy.get("auto_apply_safe_transforms", True))
    if not enabled:
        return fp

    selected = fp.get("selected_transforms")
    if not isinstance(selected, list):
        selected = []

    selected = list(selected)

    existing = {
        _transform_id_from_any(x)
        for x in selected
        if _transform_id_from_any(x)
    }

    for tid in SAFE_BY_DEFAULT:
        if tid in existing:
            continue

        if allowed_ids_set is not None and tid not in allowed_ids_set:
            continue

        selected.append(
            {
                "id": tid,
                "transform_id": tid,
                "params": {
                    "seed": seed,
                    "auto_added_safe_default": True,
                },
                "target": {
                    "function": fn_name,
                },
                "auto_added": True,
                "auto_added_reason": "safe_by_default_planner_expansion",
            }
        )
        existing.add(tid)

    fp2 = dict(fp)
    fp2["selected_transforms"] = selected
    return fp2


def expand_safe_plans(
    plans: list,
    *,
    allowed_ids_set: set[str] | None = None,
    seed: int = 1337,
    policy: dict | None = None,
) -> list:
    """
    Apply expand_safe_plan() to every function plan.
    """
    out = []
    for fp in plans or []:
        if isinstance(fp, dict):
            out.append(
                expand_safe_plan(
                    fp,
                    allowed_ids_set=allowed_ids_set,
                    seed=seed,
                    policy=policy,
                )
            )
        else:
            out.append(fp)
    return out
# ------------------------------------------------------------
# LLM plan normalization / sanitization
# ------------------------------------------------------------

def _normalize_selected_transforms_for_engine(plans: list[dict]) -> list[dict]:
    """
    Normalize per-function transform selections into engine schema.
    """
    out: list[dict] = []

    def _is_bogus_id(tid: str) -> bool:
        return isinstance(tid, str) and tid.strip().startswith("plan[")

    def _as_transform_dict(x) -> dict | None:
        if isinstance(x, str):
            tid = x.strip()
            if not tid or _is_bogus_id(tid):
                return None
            return {"id": tid, "target": {}, "params": {}}

        if not isinstance(x, dict):
            return None

        if "plan" in x and isinstance(x.get("plan"), list):
            return {"__NESTED__": "plan", "items": x.get("plan")}
        if "transforms" in x and isinstance(x.get("transforms"), list):
            return {"__NESTED__": "transforms", "items": x.get("transforms")}

        tid = x.get("id") or x.get("transform_id") or x.get("type") or x.get("transformId")
        if not tid:
            return None

        tid = str(tid).strip()
        if not tid or _is_bogus_id(tid):
            return None

        params = x.get("params") if isinstance(x.get("params"), dict) else {}
        target = x.get("target") if isinstance(x.get("target"), dict) else {}

        return {"id": tid, "target": target, "params": params}

    for fp in plans or []:
        if not isinstance(fp, dict):
            continue

        fp2 = dict(fp)
        sel = fp2.get("selected_transforms") or []
        if not isinstance(sel, list):
            sel = []

        normalized: list[dict] = []
        stack = list(sel)

        while stack:
            t = stack.pop(0)
            td = _as_transform_dict(t)
            if td is None:
                continue

            if "__NESTED__" in td:
                items = td.get("items") or []
                if isinstance(items, list):
                    stack = list(items) + stack
                continue

            normalized.append(td)

        seen: set[str] = set()
        deduped: list[dict] = []
        for t in normalized:
            tid = t.get("id")
            if not isinstance(tid, str):
                continue
            if tid in seen:
                continue
            seen.add(tid)
            deduped.append(t)

        fp2["selected_transforms"] = deduped
        out.append(fp2)

    return out


def _sanitize_transform_list_for_function(
    *,
    fn_name: str,
    function_ir: dict,
    selected: list,
    allowed_ids: set[str],
    policy: dict,
) -> tuple[list[dict], list[str]]:
    """
    Returns: (sanitized_transforms, drop_reasons)
    """
    drop_reasons: list[str] = []

    tmp_plans = _normalize_selected_transforms_for_engine(
        [{"function": fn_name, "selected_transforms": selected}]
    )
    norm = tmp_plans[0].get("selected_transforms") or []

    sanitized: list[dict] = []
    for t in norm:
        if not isinstance(t, dict):
            drop_reasons.append("non_dict_transform")
            continue

        tid = t.get("id")
        if not tid or not isinstance(tid, str):
            drop_reasons.append("missing_id")
            continue

        if tid not in allowed_ids:
            drop_reasons.append(f"unknown_transform:{tid}")
            continue

        params = t.get("params") if isinstance(t.get("params"), dict) else {}
        target = t.get("target") if isinstance(t.get("target"), dict) else {}
        sanitized.append({"id": tid, "target": target, "params": params})

    return sanitized, drop_reasons

def _filter_llm_meta_to_selected_ids(
    *,
    llm_meta: dict,
    selected_ids: list[str],
) -> dict:
    llm_meta = dict(llm_meta or {})
    sc = llm_meta.get("semantic_contract") or {}
    graph = llm_meta.get("composition_graph") or {}

    by_id = {}
    for item in sc.get("transform_safety", []) or []:
        if isinstance(item, dict) and item.get("transform_id") in selected_ids:
            by_id[item["transform_id"]] = item

    llm_meta["semantic_contract"] = {
        "global_invariants": list(sc.get("global_invariants") or []),
        "protected_region_tags": list(sc.get("protected_region_tags") or []),
        "transform_safety": [by_id[tid] for tid in selected_ids if tid in by_id],
    }
    llm_meta["composition_graph"] = filter_graph_to_selected_ids(graph, selected_ids)
    return llm_meta

def _dedupe_transforms_keep_order(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for t in items or []:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        if not isinstance(tid, str) or not tid.strip():
            continue
        if tid in seen:
            continue
        seen.add(tid)
        out.append(t)
    return out

def _append_drop_audit(
    *,
    audit_log: list[dict],
    fn_name: str,
    stage: str,
    tid: str,
    reason: str,
    tier: int | None = None,
    sec_sev: str | None = None,
):
    audit_log.append(
        {
            "function": fn_name,
            "stage": stage,
            "transform_id": tid,
            "reason": reason,
            "tier": tier,
            "sec_severity": sec_sev,
        }
    )

def _semantic_filter_selected_transforms(
    selected: List[Dict[str, Any]],
    llm_meta: Dict[str, Any] | None,
    sec_entry: Dict[str, Any] | None,
    policy: Dict[str, Any] | None = None,
) -> tuple[List[Dict[str, Any]], List[str]]:
    llm_meta = llm_meta if isinstance(llm_meta, dict) else {}
    sec_entry = sec_entry if isinstance(sec_entry, dict) else {}
    policy = policy if isinstance(policy, dict) else {}

    sc = llm_meta.get("semantic_contract") if isinstance(llm_meta.get("semantic_contract"), dict) else {}
    transform_safety = sc.get("transform_safety") if isinstance(sc.get("transform_safety"), list) else []

    by_id: Dict[str, Dict[str, Any]] = {}
    for item in transform_safety:
        if isinstance(item, dict) and isinstance(item.get("transform_id"), str):
            by_id[item["transform_id"]] = item

    protected_tags = set()
    for tag in sc.get("protected_region_tags") or []:
        if isinstance(tag, str) and tag.strip():
            protected_tags.add(tag)

    for tag in (sec_entry.get("policy_constraints", {}) or {}).get("protected_region_tags", []) or []:
        if isinstance(tag, str) and tag.strip():
            protected_tags.add(tag)

    strict_tags = set(
        x for x in (policy.get("security_strict_protected_region_tags") or [])
        if isinstance(x, str) and x.strip()
    )

    reject_on_overlap = bool(policy.get("semantic_reject_on_avoid_region_overlap", True))

    out: List[Dict[str, Any]] = []
    reasons: List[str] = []

    for row in selected or []:
        if not isinstance(row, dict):
            continue

        tid = row.get("id")
        if not isinstance(tid, str) or not tid.strip():
            continue

        safety = by_id.get(tid) or {}
        avoid_regions = set(
            x for x in (safety.get("avoid_regions") or [])
            if isinstance(x, str) and x.strip()
        )

        overlap = sorted(avoid_regions & protected_tags)
        hard_overlap = sorted((avoid_regions & protected_tags) & strict_tags)

        low_risk_cosmetic_ids = {
            "rename_identifiers_sha1_v1",
            "rename_identifiers_v2_scoped",
            "layout_scramble_v1",
        }

        # Cosmetic transforms can remain advisory-only on overlap.
        is_cosmetic = tid in low_risk_cosmetic_ids

        # Align planner filtering with validator semantics:
        # for non-cosmetic transforms, ANY avoid-region overlap should be rejected.
        effective_reject_overlap = []
        if not is_cosmetic:
            effective_reject_overlap = overlap

        if reject_on_overlap and effective_reject_overlap:
            reasons.append(f"{tid}:semantic_overlap_hard:{','.join(effective_reject_overlap)}")
            continue

        # Cosmetic transforms keep overlap as advisory-only metadata.
        if overlap and is_cosmetic:
            row = dict(row)
            row.setdefault("_oblivion_warnings", [])
            row["_oblivion_warnings"] = list(row["_oblivion_warnings"]) + [
                f"semantic_overlap_soft:{','.join(overlap)}"
            ]

        out.append(row)

    return out, reasons

def _filter_transforms_with_audit(
    *,
    fn_name: str,
    transforms: list[dict],
    allowed_ids_set: set[str],
    fn_tier: int,
    sev: str,
    fn_ir: dict,
    sec_advice_fn: dict,
    policy: dict,
    stage: str,
    audit_log: list[dict],
) -> list[dict]:
    kept: list[dict] = []

    for t in transforms or []:
        if not isinstance(t, dict):
            _append_drop_audit(
                audit_log=audit_log,
                fn_name=fn_name,
                stage=stage,
                tid="",
                reason="non_dict_transform",
                tier=fn_tier,
                sec_sev=sev,
            )
            continue

        tid = t.get("id")
        if not isinstance(tid, str) or not tid.strip():
            _append_drop_audit(
                audit_log=audit_log,
                fn_name=fn_name,
                stage=stage,
                tid="",
                reason="missing_id",
                tier=fn_tier,
                sec_sev=sev,
            )
            continue

        tid = tid.strip()

        if tid not in allowed_ids_set:
            _append_drop_audit(
                audit_log=audit_log,
                fn_name=fn_name,
                stage=stage,
                tid=tid,
                reason=f"unknown_transform:{tid}",
                tier=fn_tier,
                sec_sev=sev,
            )
            continue

        ok, reason = _compat_gate_transform(
            tid=tid,
            tier=fn_tier,
            sec_sev=sev,
            fn_ir=fn_ir,
            sec_entry=sec_advice_fn,
            policy=policy,
        )
        if not ok:
            _append_drop_audit(
                audit_log=audit_log,
                fn_name=fn_name,
                stage=stage,
                tid=tid,
                reason=reason,
                tier=fn_tier,
                sec_sev=sev,
            )
            continue

        kept.append(t)

    return kept

def _compat_gate_transform(
    *,
    tid: str,
    tier: int,
    sec_sev: str,
    fn_ir: dict,
    sec_entry: dict | None,
    policy: dict | None,
) -> tuple[bool, str]:
    catalog = default_transform_catalog()
    spec = catalog.get(tid)
    if spec is None:
        return False, "unknown_transform"

    sec_signals = extract_signals(sec_entry or {})
    matrix = policy.get("transform_vulnerability_matrix") if isinstance(policy, dict) else None

    protected_regions = []
    policy_constraints = {}
    if isinstance(sec_entry, dict):
        protected_regions = sec_entry.get("protected_regions") or []
        policy_constraints = sec_entry.get("policy_constraints") or {}

    ok, reason = compat_matrix_compatible(
        spec=spec,
        tier=tier,
        signals=sec_signals,
        fn_advice=fn_ir or {},
        sec_severity_max=str(sec_sev or ""),
        protected_regions=protected_regions,
        policy_constraints=policy_constraints,
        matrix=matrix,
    )
    if not ok:
        return False, reason

    return True, ""

def _enforce_tier_transform_policy(
    *,
    fn_name: str,
    tier: int,
    sec_sev: str,
    mutability: str,
    transforms: list[dict],
    allowed_ids: set[str],
    policy: dict | None = None,
    fn_ir: dict | None = None,
    sec_entry: dict | None = None,
) -> list[dict]:
    _ = fn_name
    _ = mutability

    transforms = _dedupe_transforms_keep_order(transforms or [])
    kept: list[dict] = []

    for t in transforms:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        if not isinstance(tid, str) or not tid.strip():
            continue
        tid = tid.strip()

        if tid not in allowed_ids:
            continue

        ok, _reason = _compat_gate_transform(
            tid=tid,
            tier=tier,
            sec_sev=sec_sev,
            fn_ir=fn_ir or {},
            sec_entry=sec_entry or {},
            policy=policy,
        )
        if not ok:
            continue

        kept.append(t)

    apply_all_safe = False
    if isinstance(policy, dict):
        apply_all_safe = bool(policy.get("apply_all_safe_transforms_when_allowed", False))

    if apply_all_safe:
        return kept

    max_count = {
        1: 4,
        2: 6,
        3: 8,
    }.get(int(tier), 8)

    if isinstance(policy, dict):
        try:
            policy_max = int(policy.get("max_transforms_per_function", max_count))
            if policy_max > 0:
                max_count = min(max_count, policy_max)
        except Exception:
            pass

    return kept[:max_count]

def _restore_non_risky_transforms(
    *,
    base_selected: list[dict],
    current_selected: list[dict],
    llm_meta: dict | None,
    sec_entry: dict | None,
    policy: dict | None,
) -> tuple[list[dict], list[str]]:
    policy = policy if isinstance(policy, dict) else {}
    llm_meta = llm_meta if isinstance(llm_meta, dict) else {}
    sec_entry = sec_entry if isinstance(sec_entry, dict) else {}

    if not bool(policy.get("apply_all_safe_transforms_when_allowed", False)):
        return list(current_selected or []), []

    graph = llm_meta.get("composition_graph") if isinstance(llm_meta.get("composition_graph"), dict) else {}
    unsafe_pairs = set()
    for item in graph.get("unsafe_pairs", []) or []:
        if not isinstance(item, dict):
            continue
        pair = item.get("pair") or []
        if isinstance(pair, list) and len(pair) == 2:
            a, b = pair
            if isinstance(a, str) and isinstance(b, str):
                unsafe_pairs.add(tuple(sorted([a, b])))

    strict_tags = set(
        x for x in (policy.get("security_strict_protected_region_tags") or [])
        if isinstance(x, str) and x.strip()
    )

    sc = llm_meta.get("semantic_contract") if isinstance(llm_meta.get("semantic_contract"), dict) else {}
    transform_safety = sc.get("transform_safety") if isinstance(sc.get("transform_safety"), list) else []
    safety_by_id = {}
    for item in transform_safety:
        if isinstance(item, dict) and isinstance(item.get("transform_id"), str):
            safety_by_id[item["transform_id"]] = item

    protected_tags = set()
    for tag in sc.get("protected_region_tags") or []:
        if isinstance(tag, str) and tag.strip():
            protected_tags.add(tag)
    for tag in (sec_entry.get("policy_constraints", {}) or {}).get("protected_region_tags", []) or []:
        if isinstance(tag, str) and tag.strip():
            protected_tags.add(tag)

    out = list(current_selected or [])
    out_ids = {
        t.get("id") for t in out
        if isinstance(t, dict) and isinstance(t.get("id"), str)
    }

    restored: list[str] = []

    for row in base_selected or []:
        if not isinstance(row, dict):
            continue
        tid = row.get("id")
        if not isinstance(tid, str) or not tid.strip():
            continue
        if tid in out_ids:
            continue

        # hard semantic blocker?
        safety = safety_by_id.get(tid) or {}
        avoid_regions = set(
            x for x in (safety.get("avoid_regions") or [])
            if isinstance(x, str) and x.strip()
        )
        hard_overlap = sorted((avoid_regions & protected_tags) & strict_tags)
        if hard_overlap:
            continue

        # unsafe pair blocker?
        blocked_by_pair = False
        for existing in list(out_ids):
            if tuple(sorted([tid, existing])) in unsafe_pairs:
                blocked_by_pair = True
                break
        if blocked_by_pair:
            continue

        out.append(row)
        out_ids.add(tid)
        restored.append(tid)

    return out, restored

def _fallback_deterministic_transforms(
    *,
    fn_name: str,
    function_ir: dict,
    tier: int,
    allowed_ids: set[str],
    obf_advice_fn: dict,
    sec_advice_fn: dict,
    policy: dict,
) -> list[dict]:
    """
    Deterministic fallback plan in v2-preferred mode.
    Builds a broad-but-safe transform set, prefers v2 transforms over their
    v1 counterparts, then lets policy enforcement trim it.
    """
    _ = obf_advice_fn
    sec_sev = (
        (sec_advice_fn.get("severity_max") or sec_advice_fn.get("severity") or sec_advice_fn.get("sec_severity") or "INFO")
        if isinstance(sec_advice_fn, dict) else "INFO"
    )

    shadow_map = {
        "constant_encoding_v1": "constant_encoding_v2_layered",
        "boolean_split_v1": "boolean_split_v2_distributed",
        "opaque_predicate_v1": "opaque_predicate_v2_entangled",
        "inline_internal_v1": "inline_internal_v2_diversified",
        "cfg_flatten_v1": "cfg_flatten_v2_hybrid",
    }

    chosen: list[dict] = []
    seen_ids: set[str] = set()

    for level in (1, 2, 3):
        if tier < level:
            continue

        for tid in SAFE_BY_TIER.get(level, []):
            if tid not in allowed_ids:
                continue

            # Skip old v1 family member if its preferred v2 counterpart is available
            v2 = shadow_map.get(tid)
            if v2 and v2 in allowed_ids:
                allowed_v2, _reason_v2 = _compat_gate_transform(
                    tid=v2,
                    tier=tier,
                    sec_sev=sec_sev,
                    fn_ir=function_ir,
                    sec_entry=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
                    policy=policy,
                )
                if allowed_v2:
                    continue

            allowed, _reason = _compat_gate_transform(
                tid=tid,
                tier=tier,
                sec_sev=sec_sev,
                fn_ir=function_ir,
                sec_entry=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
                policy=policy,
            )
            if not allowed:
                continue

            if tid in seen_ids:
                continue

            chosen.append(
                {
                    "id": tid,
                    "target": {"function": fn_name},
                    "params": {},
                }
            )
            seen_ids.add(tid)

    chosen = _dedupe_transforms_keep_order(chosen)
    chosen = _drop_shadowed_v1_transforms(chosen)

    return chosen

# ------------------------------------------------------------
# Safe augmentation helpers (BiAn-parity, risk-aware)
# ------------------------------------------------------------

SAFE_BY_TIER = {
    1: [
        "rename_identifiers_sha1_v1",
        "rename_identifiers_v2_scoped",
        "layout_scramble_v1",
        "constant_encoding_v2_layered",
        "dynamic_constants_v1",
        "string_split_v1",
        "algebraic_identities_v1",
    ],
    2: [
        "rename_identifiers_sha1_v1",
        "rename_identifiers_v2_scoped",
        "layout_scramble_v1",
        "constant_encoding_v2_layered",
        "string_split_v1",
        "algebraic_identities_v1",
        "boolean_split_v2_distributed",
        "inline_internal_v2_diversified",
        "opaque_predicate_v2_entangled",
        "stack_variable_aliasing_v1",
        "public_state_accessor_indirection_v1",
    ],
    3: [
        "rename_identifiers_sha1_v1",
        "rename_identifiers_v2_scoped",
        "layout_scramble_v1",
        "constant_encoding_v2_layered",
        "string_split_v1",
        "algebraic_identities_v1",
        "boolean_split_v2_distributed",
        "inline_internal_v2_diversified",
        "opaque_predicate_v2_entangled",
        "stack_variable_aliasing_v1",
        "public_state_accessor_indirection_v1",
        "scalar_to_struct_indirection_v1",
        "cfg_flatten_v2_hybrid",
        "yul_microblock_v1",
    ],
}

def _has_id(plan: list[dict], tid: str) -> bool:
    return any((isinstance(x, dict) and x.get("id") == tid) for x in (plan or []))


def _force_add(plan: list[dict], tid: str, fn_name: str, params=None):
    if params is None:
        params = {}
    plan.append({"id": tid, "target": {"function": fn_name}, "params": params})


def _sec_ok(sec_sev: str) -> bool:
    return (sec_sev or "").upper() in ("INFO", "LOW")

def _infer_identifier_rename_candidates(fn_ir: dict) -> bool:
    params = fn_ir.get("parameters") or []
    locals_ = fn_ir.get("locals") or fn_ir.get("local_variables") or []
    returns_ = fn_ir.get("returns") or []

    candidate_count = 0
    for seq in (params, locals_, returns_):
        if isinstance(seq, list):
            for item in seq:
                if isinstance(item, dict):
                    nm = str(item.get("name") or "").strip()
                    if nm and not nm.startswith("__obf_") and not re.match(r"^v_\d+_\d+$", nm):
                        candidate_count += 1

    return candidate_count > 0

def _infer_has_external_calls(fn_ir: dict) -> bool | None:
    if "has_external_calls" in fn_ir:
        v = fn_ir.get("has_external_calls")
        if isinstance(v, bool):
            return v

    for k in ("external_calls", "calls_external", "call_sites", "calls"):
        v = fn_ir.get(k)
        if isinstance(v, list):
            if k == "calls" and any(
                isinstance(x, dict) and (x.get("kind") == "external" or x.get("type") == "external")
                for x in v
            ):
                return True
            return len(v) > 0

    return None

def _infer_public_state_candidates(fn_ir: dict) -> bool:
    for k in ("storage_reads", "reads_storage", "storage_writes", "writes_storage"):
        v = fn_ir.get(k)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    vis = str(item.get("visibility") or "").lower()
                    if vis == "public":
                        return True
    return False

def _infer_internal_call_presence(fn_ir: dict) -> bool:
    for k in ("internal_calls", "calls_internal", "function_calls", "calls"):
        v = fn_ir.get(k)
        if isinstance(v, list):
            if k in ("internal_calls", "calls_internal"):
                return len(v) > 0
            for item in v:
                if isinstance(item, dict):
                    kind = str(item.get("kind") or item.get("type") or "").lower()
                    if kind == "internal":
                        return True
    return False


def _infer_loop_count(fn_ir: dict) -> int:
    for k in ("loop_count", "loops_count", "num_loops", "n_loops"):
        if k in fn_ir:
            try:
                return int(fn_ir.get(k) or 0)
            except Exception:
                return 0
    if isinstance(fn_ir.get("loops"), list):
        return len(fn_ir.get("loops") or [])
    return 0


def _infer_storage_touch(fn_ir: dict) -> bool:
    for k in ("reads_storage", "writes_storage", "storage_reads", "storage_writes"):
        v = fn_ir.get(k)
        if isinstance(v, list) and len(v) > 0:
            return True
    return False


def _infer_modifier_presence(fn_ir: dict) -> bool:
    for k in ("modifiers", "modifier_invocations", "applied_modifiers", "modifiers_full"):
        v = fn_ir.get(k)
        if isinstance(v, list) and len(v) > 0:
            return True
    return False


def _is_viewish(fn_ir: dict) -> bool:
    mut = (fn_ir.get("state_mutability") or fn_ir.get("mutability") or "").strip().lower()
    return mut in ("view", "pure")


def _is_pure(fn_ir: dict) -> bool:
    mut = (fn_ir.get("state_mutability") or fn_ir.get("mutability") or "").strip().lower()
    return mut == "pure"


def _is_publicish(fn_ir: dict) -> bool:
    vis = (fn_ir.get("visibility") or "").strip().lower()
    return vis in ("public", "external")

def _infer_internal_call_presence(fn_ir: dict) -> bool:
    for k in ("internal_calls", "calls_internal", "function_calls", "calls"):
        v = fn_ir.get(k)
        if isinstance(v, list):
            if k in ("internal_calls", "calls_internal"):
                return len(v) > 0
            for item in v:
                if isinstance(item, dict):
                    kind = str(item.get("kind") or item.get("type") or "").lower()
                    if kind == "internal":
                        return True
    return False


def _infer_public_state_candidates(fn_ir: dict) -> bool:
    for k in ("storage_reads", "reads_storage", "storage_writes", "writes_storage"):
        v = fn_ir.get(k)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    vis = str(item.get("visibility") or "").lower()
                    if vis == "public":
                        return True
    return False

def _precond_ok(tid: str, fn_ir: dict) -> tuple[bool, str]:
    ext = _infer_has_external_calls(fn_ir)
    has_storage = _infer_storage_touch(fn_ir)
    is_viewish = _is_viewish(fn_ir)
    is_pure = _is_pure(fn_ir)
    loop_count = _infer_loop_count(fn_ir)
    has_modifiers = _infer_modifier_presence(fn_ir)

    if tid == "dispatcher_cfg_virtualization_v1":
        if ext is False:
            return True, ""
        return False, "dispatcher_cfg_virtualization_requires_no_external_calls"

    if tid == "opaque_storage_slot_indirection_v1":
        if has_storage:
            return True, ""
        return False, "opaque_storage_slot_indirection_requires_storage"

    if tid == "cfg_flatten_v1":
        if not is_viewish:
            return True, ""
        return False, "cfg_flatten_blocks_view_pure"

    if tid == "inline_internal_v1":
        if _infer_internal_call_presence(fn_ir):
            return True, ""
        return False, "inline_internal_requires_internal_calls"

    if tid == "local_to_state_lift_v1":
        if is_viewish or is_pure:
            return False, "local_to_state_lift_blocks_view_pure"
        if ext is True:
            return False, "local_to_state_lift_blocks_external_calls"
        return True, ""

    if tid == "scalar_to_struct_indirection_v1":
        if is_viewish:
            return False, "scalar_to_struct_indirection_blocks_view_pure"
        if not has_storage:
            return False, "scalar_to_struct_indirection_requires_storage"
        if ext is True:
            return False, "scalar_to_struct_indirection_blocks_external_calls"
        return True, ""

    if tid == "modifier_expand_v1":
        if has_modifiers:
            return True, ""
        return False, "modifier_expand_requires_modifier"

    if tid == "loop_rewrite_v1":
        if loop_count > 0:
            return True, ""
        return False, "loop_rewrite_requires_loops"

    if tid == "boolean_split_v1":
        return True, ""

    if tid == "dynamic_constants_v1":
        return True, ""

    if tid == "constant_encoding_v1":
        return True, ""

    if tid == "layout_scramble_v1":
        return True, ""

    if tid == "opaque_predicate_v1":
        return True, ""

    if tid == "stack_variable_aliasing_v1":
        return True, ""

    if tid == "predicate_masking_v1":
        return True, ""

    if tid == "dead_code_v1":
        return True, ""

    if tid == "yul_microblock_v1":
        if not is_viewish:
            return True, ""
        return False, "yul_microblock_blocks_view_pure"

    if tid == "public_state_accessor_indirection_v1":
        if is_pure:
            return False, "public_state_accessor_indirection_blocks_pure"
        if not has_storage:
            return False, "public_state_accessor_indirection_requires_storage"
        if _infer_public_state_candidates(fn_ir) or has_storage:
            return True, ""
        return False, "public_state_accessor_indirection_requires_public_state_candidates"

    if tid == "rename_identifiers_v2_scoped":
        if _infer_identifier_rename_candidates(fn_ir):
            return True, ""
        return False, "rename_identifiers_v2_scoped_no_identifier_candidates"

    if tid == "rename_identifiers_sha1_v1":
        if _infer_identifier_rename_candidates(fn_ir):
            return True, ""
        return False, "rename_identifiers_sha1_v1_no_identifier_candidates"

    return True, ""

def _transform_allowed_here(
    *,
    tid: str,
    tier: int,
    sec_sev: str,
    fn_ir: dict,
    allowed_ids: set[str] | None = None,
    sec_entry: dict | None = None,
    policy: dict | None = None,
) -> tuple[bool, str]:
    if allowed_ids is not None and tid not in allowed_ids:
        return False, "not_in_allowed_ids"

    ok, reason = _compat_gate_transform(
        tid=tid,
        tier=tier,
        sec_sev=sec_sev,
        fn_ir=fn_ir or {},
        sec_entry=sec_entry or {},
        policy=policy or {},
    )
    if not ok:
        return False, reason

    pre_ok, pre_reason = _precond_ok(tid, fn_ir)
    if not pre_ok:
        return False, pre_reason or "preconditions_failed"

    return True, "ok"

def _drop_shadowed_v1_transforms(transforms: list[dict]) -> list[dict]:
    shadow_map = {
        "constant_encoding_v1": "constant_encoding_v2_layered",
        "boolean_split_v1": "boolean_split_v2_distributed",
        "opaque_predicate_v1": "opaque_predicate_v2_entangled",
        "inline_internal_v1": "inline_internal_v2_diversified",
        "cfg_flatten_v1": "cfg_flatten_v2_hybrid",
    }

    present_ids = {
        t.get("id")
        for t in (transforms or [])
        if isinstance(t, dict) and isinstance(t.get("id"), str)
    }

    out: list[dict] = []
    for t in transforms or []:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        if not isinstance(tid, str):
            continue

        v2 = shadow_map.get(tid)
        if v2 and v2 in present_ids:
            continue
        out.append(t)

    return _dedupe_transforms_keep_order(out)

def augment_plan_if_safe(
    plan: list[dict],
    tier: int,
    sec_sev: str,
    fn_ir: dict,
    fn_name: str,
    allowed_ids: set[str] | None = None,
    sec_entry: dict | None = None,
    policy: dict | None = None,
) -> list[dict]:
    plan = _dedupe_transforms_keep_order(plan or [])
    existing = {p.get("id") for p in plan if isinstance(p, dict)}
    extras: list[dict] = []

    for level in (1, 2, 3):
        if tier < level:
            continue

        for tid in SAFE_BY_TIER.get(level, []):
            if tid in existing:
                continue

            allowed, _reason = _transform_allowed_here(
                tid=tid,
                tier=tier,
                sec_sev=sec_sev,
                fn_ir=fn_ir,
                allowed_ids=allowed_ids,
                sec_entry=sec_entry,
                policy=policy,
            )
            if not allowed:
                continue

            # Avoid consuming scarce transform budget with both rename families at once.
            if tid == "rename_identifiers_sha1_v1" and "rename_identifiers_v2_scoped" in existing:
                continue
            if tid == "rename_identifiers_v2_scoped" and "rename_identifiers_sha1_v1" in existing:
                continue

            extras.append(
                {
                    "id": tid,
                    "target": {"function": fn_name},
                    "params": {},
                }
            )
            existing.add(tid)

    combined = _dedupe_transforms_keep_order((plan or []) + extras)
    combined = _drop_shadowed_v1_transforms(combined)
    return combined


def augment_plan_if_safe_with_log(
    plan: list[dict],
    tier: int,
    sec_sev: str,
    fn_ir: dict,
    fn_name: str,
    allowed_ids: set[str] | None = None,
    sec_entry: dict | None = None,
    policy: dict | None = None,
) -> list[dict]:
    before = _drop_shadowed_v1_transforms(_dedupe_transforms_keep_order(plan or []))
    after = augment_plan_if_safe(
        plan=before,
        tier=tier,
        sec_sev=sec_sev,
        fn_ir=fn_ir,
        fn_name=fn_name,
        allowed_ids=allowed_ids,
        sec_entry=sec_entry,
        policy=policy,
    )
    after = _drop_shadowed_v1_transforms(_dedupe_transforms_keep_order(after))

    before_ids = [t.get("id") for t in before if isinstance(t, dict)]
    after_ids = [t.get("id") for t in after if isinstance(t, dict)]
    added = [tid for tid in after_ids if tid not in set(before_ids)]

    decisions = []
    seen = set(before_ids)

    shadow_map = {
        "constant_encoding_v1": "constant_encoding_v2_layered",
        "boolean_split_v1": "boolean_split_v2_distributed",
        "opaque_predicate_v1": "opaque_predicate_v2_entangled",
        "inline_internal_v1": "inline_internal_v2_diversified",
        "cfg_flatten_v1": "cfg_flatten_v2_hybrid",
    }

    for level in (1, 2, 3):
        if tier < level:
            continue
        for tid in SAFE_BY_TIER.get(level, []):
            v2 = shadow_map.get(tid)
            if v2 and v2 in seen:
                decisions.append(f"{tid}:shadowed_by_v2")
                continue

            if tid in seen:
                decisions.append(f"{tid}:already_present")
                continue

            allowed, reason = _transform_allowed_here(
                tid=tid,
                tier=tier,
                sec_sev=sec_sev,
                fn_ir=fn_ir,
                allowed_ids=allowed_ids,
                sec_entry=sec_entry,
                policy=policy,
            )
            decisions.append(f"{tid}:{reason}")
            if allowed:
                seen.add(tid)

    print(
        f"[AUGMENT] fn={fn_name} tier={tier} sev={sec_sev} "
        f"ran=True added={added if added else []} "
        f"final_count={len(after_ids)} decisions={'; '.join(decisions)}"
    )
    return after
# ------------------------------------------------------------
# Transform map helpers
# ------------------------------------------------------------

def _read_transform_map_counts(transform_map_path: Path) -> tuple[int, int]:
    if not transform_map_path.exists():
        return 0, 0

    try:
        obj = json.loads(transform_map_path.read_text(encoding="utf-8"))
    except Exception:
        return 0, 0

    applied = obj.get("applied")
    if not isinstance(applied, list):
        return 0, 0

    fn_set: set[str] = set()
    for a in applied:
        if not isinstance(a, dict):
            continue
        tgt = a.get("target")
        if isinstance(tgt, dict):
            fn = tgt.get("function")
            if isinstance(fn, str) and fn:
                fn_set.add(fn)

    return len(applied), len(fn_set)


def _read_transform_map_stats(transform_map_path: Path) -> tuple[int, int, int]:
    if not transform_map_path.exists():
        return 0, 0, 0
    try:
        obj = json.loads(transform_map_path.read_text(encoding="utf-8"))
    except Exception:
        return 0, 0, 0

    applied = obj.get("applied")
    if not isinstance(applied, list):
        return 0, 0, 0

    fn_set: set[str] = set()
    id_set: set[str] = set()

    for a in applied:
        if not isinstance(a, dict):
            continue
        tid = a.get("id")
        if isinstance(tid, str) and tid:
            id_set.add(tid)

        tgt = a.get("target")
        if isinstance(tgt, dict):
            fn = tgt.get("function")
            if isinstance(fn, str) and fn:
                fn_set.add(fn)

    return len(applied), len(fn_set), len(id_set)

def _read_transform_map_quality(transform_map_path: Path) -> dict:
    empty = {
        "selected": 0,
        "applied": 0,
        "selected_noop": 0,
        "distinct_ids": 0,
        "distinct_families": 0,
        "has_noncosmetic": False,
        "cosmetic_only": False,
        "selected_has_noncosmetic": False,
        "selected_cosmetic_only": False,
    }

    if not transform_map_path.exists():
        return empty

    try:
        obj = json.loads(transform_map_path.read_text(encoding="utf-8"))
    except Exception:
        return empty

    selected_rows = obj.get("selected") or []

    cosmetic_ids = {
        "rename_identifiers_v2_scoped",
        "rename_identifiers_sha1_v1",
        "rename_identifiers_v1",
        "layout_scramble_v1",
        "aggressive_layout_minify_safe_v1",
    }

    catalog = default_transform_catalog()

    selected_ids = set()
    applied_ids = set()
    applied_families = set()

    selected_count = 0
    applied_count = 0
    selected_noop = 0

    for row in selected_rows:
        if not isinstance(row, dict):
            continue

        selected_count += 1

        tid = row.get("id") or row.get("transform_id")
        if isinstance(tid, str) and tid:
            selected_ids.add(tid)

        outcome = str(row.get("final_outcome") or "").strip().lower()

        if outcome == "applied":
            applied_count += 1

            if isinstance(tid, str) and tid:
                applied_ids.add(tid)
                spec = catalog.get(tid)
                if spec is not None:
                    applied_families.add(spec.family)
                else:
                    applied_families.add(str(tid).split("_v")[0])

        elif outcome == "noop":
            selected_noop += 1

    has_noncosmetic = any(tid not in cosmetic_ids for tid in applied_ids)
    cosmetic_only = bool(applied_ids) and all(tid in cosmetic_ids for tid in applied_ids)

    selected_has_noncosmetic = any(tid not in cosmetic_ids for tid in selected_ids)
    selected_cosmetic_only = bool(selected_ids) and all(tid in cosmetic_ids for tid in selected_ids)

    return {
        "selected": selected_count,
        "applied": applied_count,
        "selected_noop": selected_noop,
        "distinct_ids": len(applied_ids),
        "distinct_families": len(applied_families),
        "has_noncosmetic": has_noncosmetic,
        "cosmetic_only": cosmetic_only,
        "selected_has_noncosmetic": selected_has_noncosmetic,
        "selected_cosmetic_only": selected_cosmetic_only,
    }

def _filter_candidates_keep_required(base_plan: dict, candidates: list[dict], required_ids: list[str]) -> list[dict]:
    base_ids = {t.get("id") for t in (base_plan.get("transforms") or []) if isinstance(t, dict)}
    must_keep = [tid for tid in required_ids if tid in base_ids]

    if not must_keep:
        return candidates

    def cand_has_all(c: dict) -> bool:
        ids = {t.get("id") for t in (c.get("transforms") or []) if isinstance(t, dict)}
        return all(tid in ids for tid in must_keep)

    kept = [c for c in candidates if cand_has_all(c)]
    return kept if kept else [base_plan]


def _obl_safe_visual_postpass(sol_path: Path, transform_map_path: Path) -> None:
    """
    BiAn-style safe visual postpass.
    Does NOT bypass validation. Existing validator still runs after this.
    """
    if os.getenv("OBLIVION_BIAN_STYLE_SAFE", "1").lower() in {"0", "false", "no"}:
        return

    src = sol_path.read_text(encoding="utf-8")
    original = src
    applied_rows = []

    src2, changed, rename_map = _obl_whole_contract_rename_safe(src)
    if changed:
        src = src2
        applied_rows.append({
            "id": "whole_contract_identifier_rename_safe_v1",
            "transform_id": "whole_contract_identifier_rename_safe_v1",
            "function": "*",
            "target": {"function": "*"},
            "params": {"abi_breaking": False},
            "details": {
                "note": "whole-contract safe identifier renaming; public/external function names preserved",
                "renamed_count": len(rename_map),
                "rename_map": rename_map,
            },
            "final_outcome": "applied",
        })

    src2, changed = _obl_encode_safe_integer_literals(src)
    if changed:
        src = src2
        applied_rows.append({
            "id": "contract_wide_constant_encoding_safe_v1",
            "transform_id": "contract_wide_constant_encoding_safe_v1",
            "function": "*",
            "target": {"function": "*"},
            "params": {},
            "details": {"note": "safe integer literals encoded contract-wide"},
            "final_outcome": "applied",
        })

    src2, changed = _obl_wrap_simple_return_functions(src)
    if changed:
        src = src2
        applied_rows.append({
            "id": "simple_return_cfg_wrap_safe_v1",
            "transform_id": "simple_return_cfg_wrap_safe_v1",
            "function": "*",
            "target": {"function": "*"},
            "params": {},
            "details": {"note": "simple pure/view return functions wrapped with dispatcher-like control flow"},
            "final_outcome": "applied",
        })

    src2, changed = _obl_minify_layout(src)
    if changed:
        src = src2
        applied_rows.append({
            "id": "aggressive_layout_minify_safe_v1",
            "transform_id": "aggressive_layout_minify_safe_v1",
            "function": "*",
            "target": {"function": "*"},
            "params": {},
            "details": {"note": "comments/extra whitespace removed"},
            "final_outcome": "applied",
        })

    if src != original:
        sol_path.write_text(src, encoding="utf-8")
        _obl_append_transform_map(transform_map_path, applied_rows)


def _obl_encode_safe_integer_literals(src: str) -> tuple[str, bool]:
    """
    Conservative literal encoding.
    Avoids strings, hex literals, decimals, pragma versions, and tiny 0/1 literals.
    """
    protected = []

    def protect(m):
        protected.append(m.group(0))
        return f"__OBL_STR_{len(protected)-1}__"

    tmp = re.sub(r'"[^"\n]*"', protect, src)
    tmp = re.sub(r"'[^'\n]*'", protect, tmp)

    def repl(m):
        n = m.group(0)

        # skip pragma versions and hex-ish contexts
        start = max(0, m.start() - 20)
        ctx = tmp[start:m.start()].lower()
        if "pragma solidity" in ctx:
            return n
        if n in {"0", "1"}:
            return n
        if n.startswith("0x"):
            return n

        return f"(uint256({n}) + uint256(1337) - uint256(1337))"

    out = re.sub(r"(?<![A-Za-z0-9_.$])\d+(?![A-Za-z0-9_.$])", repl, tmp)

    for i, val in enumerate(protected):
        out = out.replace(f"__OBL_STR_{i}__", val)

    return out, out != src


def _obl_wrap_simple_return_functions(src: str) -> tuple[str, bool]:
    """
    Wrap only very simple pure/view functions:
        function f(...) public view/pure returns (...) { return EXPR; }
    No storage writes, no external calls, no modifiers.
    """
    pattern = re.compile(
        r"(function\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^{};]*\)\s+"
        r"(?:public|external|internal|private)\s+"
        r"(?:(?:view|pure)\s+)?returns\s*\([^{};]*\)\s*)"
        r"\{\s*return\s+([^;{}]+);\s*\}",
        re.DOTALL,
    )

    def repl(m):
        header = m.group(1)
        expr = m.group(2).strip()

        # Avoid wrapping expressions with obvious side effects.
        if any(x in expr for x in ["=", "++", "--", ".call", ".transfer", ".send"]):
            return m.group(0)

        return (
            header
            + "{"
            + "uint256 __obl_state = uint256(11);"
            + "while (__obl_state != uint256(0)) {"
            + "if (__obl_state == uint256(11)) { __obl_state = uint256(7); continue; }"
            + "if (__obl_state == uint256(7)) { return "
            + expr
            + "; }"
            + "}"
            + "return "
            + expr
            + ";"
            + "}"
        )

    out = pattern.sub(repl, src)
    return out, out != src


def _obl_minify_layout(src: str) -> tuple[str, bool]:
    # Remove block comments and line comments, but keep SPDX/pragma readable enough.
    out = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    out = re.sub(r"//(?! SPDX-License-Identifier:).*", "", out)
    out = re.sub(r"\s+", " ", out)
    out = re.sub(r"\s*([{}();,+\-*/=<>\[\]])\s*", r"\1", out)
    out = out.strip() + "\n"
    return out, out != src


def _obl_append_transform_map(transform_map_path: Path, rows: list[dict]) -> None:
    if not rows:
        return

    try:
        obj = json.loads(transform_map_path.read_text(encoding="utf-8"))
    except Exception:
        obj = {}

    obj.setdefault("selected", [])
    obj.setdefault("applied", [])
    obj.setdefault("skipped", [])
    obj.setdefault("final_function_plans", [])

    obj["selected"].extend(rows)
    obj["applied"].extend(rows)

    obj["final_function_plans"].append({
        "function": "*",
        "final_transform_ids": [r["id"] for r in rows],
        "final_ordered_transform_ids": [r["id"] for r in rows],
        "final_transform_rows": rows,
    })

    transform_map_path.write_text(json.dumps(obj, indent=2), encoding="utf-8")

def _obl_whole_contract_rename_safe(src: str) -> tuple[str, bool, dict]:
    """
    Safe-ish BiAn-style renaming.
    Renames internal/private identifiers, local vars, params, state vars.
    Keeps public/external function names to avoid ABI breakage.
    """
    reserved = {
        "pragma", "solidity", "contract", "interface", "library", "function",
        "modifier", "constructor", "returns", "return", "if", "else", "while",
        "for", "break", "continue", "mapping", "address", "uint", "uint256",
        "int", "int256", "bytes32", "bytes", "string", "bool", "public",
        "private", "internal", "external", "view", "pure", "payable",
        "memory", "storage", "calldata", "require", "revert", "assert",
        "msg", "sender", "value", "block", "timestamp", "number", "gasleft",
        "abi", "encodePacked", "keccak256", "this", "unchecked", "true", "false",
    }

    # Do not rename externally visible function names.
    public_external_funcs = set(
        re.findall(
            r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*(?:public|external)",
            src,
        )
    )

    # Do not rename contract name for Foundry/import stability.
    contract_names = set(re.findall(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)", src))

    candidates = set()

    # state vars / local vars / params
    for m in re.finditer(
        r"\b(?:uint|uint256|int|int256|address|bytes32|bytes|string|bool)\s+([A-Za-z_][A-Za-z0-9_]*)",
        src,
    ):
        candidates.add(m.group(1))

    # mappings
    for m in re.finditer(r"\bmapping\s*\([^)]*\)\s*(?:public|private|internal)?\s*([A-Za-z_][A-Za-z0-9_]*)", src):
        candidates.add(m.group(1))

    # function parameters
    for params in re.findall(r"function\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)", src):
        for m in re.finditer(
            r"\b(?:uint|uint256|int|int256|address|bytes32|bytes|string|bool)\s+([A-Za-z_][A-Za-z0-9_]*)",
            params,
        ):
            candidates.add(m.group(1))

    blocked = reserved | public_external_funcs | contract_names
    candidates = sorted(x for x in candidates if x not in blocked and not x.startswith("__obl") and not x.startswith("__op") and not x.startswith("_oblv_"))

    rename_map = {}
    for i, name in enumerate(candidates):
        # Use an unambiguous, valid Solidity identifier prefix. The previous
        # value f"Ox{i:08x}" emitted tokens like `Ox00000009` (capital letter
        # O + x) which read as a hex-literal lookalike: it compiled (Solidity
        # parses it as a plain identifier) but produced malformed-looking
        # dispatcher state such as `int(Ox00000009)` and `Ox00000001=1;continue;`
        # that tripped the narrow semantic contract on every aggressive
        # candidate. `_oblv_<hex>` is a normal scoped identifier in the same
        # spirit as the `__obl`/`__op` reserved namespaces already in use.
        rename_map[name] = f"_oblv_{i:08x}"

    out = src

    # protect string literals
    strings = []

    def protect_str(m):
        strings.append(m.group(0))
        return f"__OBL_STRING_{len(strings)-1}__"

    out = re.sub(r'"[^"\n]*"', protect_str, out)
    out = re.sub(r"'[^'\n]*'", protect_str, out)

    for old, new in sorted(rename_map.items(), key=lambda x: -len(x[0])):
        out = re.sub(rf"\b{re.escape(old)}\b", new, out)

    for i, s in enumerate(strings):
        out = out.replace(f"__OBL_STRING_{i}__", s)

    return out, out != src, rename_map

def _filter_by_patch_site_precheck(*, fn_name: str, transforms: list[dict], fn_ir: dict) -> list[dict]:
    """
    Prevent obvious no-op transform selection.
    Conservative: only removes transforms when function text/body clearly lacks patch sites.
    """
    body = ""
    for key in ("body", "source", "src_text", "code", "text"):
        if isinstance(fn_ir.get(key), str):
            body = fn_ir.get(key) or ""
            break

    # If IR has no body text, do not over-filter.
    if not body:
        return transforms

    out = []

    has_int_literal = bool(re.search(r"(?<![A-Za-z0-9_.$])\d+(?![A-Za-z0-9_.$])", body))
    has_string_literal = bool(re.search(r'"[^"\n]*"', body))
    has_bool_literal = bool(re.search(r"\b(true|false)\b", body))
    has_return = "return" in body
    has_nonempty_body = bool(body.strip()) and body.strip() not in {"{}", ";"}

    for t in transforms or []:
        if not isinstance(t, dict):
            continue

        tid = t.get("id") or t.get("transform_id") or ""

        if tid in {"constant_encoding_v1", "constant_encoding_v2_layered"} and not has_int_literal:
            t = dict(t)
            t["precheck_skip_reason"] = "no_integer_literal_patch_site"
            continue

        if tid == "dynamic_constants_v1" and not (has_int_literal or has_string_literal or has_bool_literal):
            t = dict(t)
            t["precheck_skip_reason"] = "no_dynamic_constant_patch_site"
            continue

        if "cfg" in tid and not has_return:
            t = dict(t)
            t["precheck_skip_reason"] = "no_simple_return_or_cfg_patch_site"
            continue

        if tid in {"layout_scramble_v1", "rename_identifiers_v2_scoped"} and not has_nonempty_body:
            t = dict(t)
            t["precheck_skip_reason"] = "empty_body"
            continue

        out.append(t)

    return out
# ------------------------------------------------------------
# Main pipeline
# ------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} path/to/Contract.sol")
        sys.exit(1)

    sol_path = Path(sys.argv[1]).resolve()
    if not sol_path.exists():
        print(f"[ERROR] Solidity file not found: {sol_path}")
        sys.exit(1)

    contract_name = sol_path.stem

    out_dir = OBLIVION_OUT / contract_name
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[OBLIVION] Solidity file:      {sol_path}")
    print(f"[OBLIVION] Output run dir:     {out_dir}")

    contract_import_path = ensure_contract_in_foundry_src(sol_path)
    source_in_foundry = (FOUNDRY_ROOT / contract_import_path).resolve()

    # Immutable per-run original snapshot.
    source_snapshot = _snapshot_source_file(source_in_foundry, out_dir)
    _register_source_restore(source_snapshot, source_in_foundry)

    analyze_path = auto_flatten_if_needed(sol_path, out_dir)

    # ------------------------------
    # Load policy early
    # ------------------------------
    policy_path = ROOT / "configs" / "policy.json"
    policy = {}
    if policy_path.exists():
        txt = policy_path.read_text(encoding="utf-8").strip()
        if txt:
            policy = json.loads(txt)

    # ------------------------------
    # Step 1: AST Analyzer
    # ------------------------------
    ir_out = out_dir / f"{contract_name}_ir.json"
    ast_dump = out_dir / f"{contract_name}_analyzer_ast.json"
    _ = run_ast_analyzer(analyze_path, ir_out, ast_dump)

    # IMPORTANT: load IR here because test-generation now uses it
    with open(ir_out, "r", encoding="utf-8") as f:
        ir = json.load(f)

    # ------------------------------
    # Step 2: TestCrafter baseline harness generation
    # ------------------------------
    harness_path, harness_contract = run_testcrafter(ir_out, contract_import_path)

    # ------------------------------
    # Step 3: Explicit Test Generation Layer
    # ------------------------------
    testgen_out_dir = out_dir / "test_generation"
    testgen_out_dir.mkdir(parents=True, exist_ok=True)

    llm_test_generator = None
    if bool(policy.get("llm_test_generation_enabled", False)):
        llm_test_generator = build_llm_test_generator(
            model=str(policy.get("llm_model", "gpt-4.1-mini")),
            temperature=float(policy.get("llm_temperature", 0.2)),
            max_tests=int(policy.get("max_generated_tests", 6)),
            root=str(ROOT),
        )

    tg_config = TestGenerationConfig(
        forge_bin=str(policy.get("forge_bin", "forge")),
        fuzz_runs=int(policy.get("fuzz_runs", 256)),
        baseline_verbosity=str(policy.get("baseline_test_verbosity", "-vvvv")),
        merged_verbosity=str(policy.get("merged_test_verbosity", "-vv")),
        max_uncovered_targets=int(policy.get("max_uncovered_targets", 12)),
        max_generated_tests=int(policy.get("max_generated_tests", 6)),
        generated_tests_subdir=str(policy.get("generated_tests_subdir", "generated_tests")),
        traces_subdir=str(policy.get("traces_subdir", "traces")),
        llm_enabled=bool(policy.get("llm_test_generation_enabled", False)),
        keep_failed_generated_tests=bool(policy.get("keep_failed_generated_tests", False)),
        retain_only_with_gain=bool(policy.get("retain_only_with_gain", False)),
        retain_on_target_touch=bool(policy.get("retain_on_target_touch", True)),
        retain_on_semantic_value=bool(policy.get("retain_on_semantic_value", True)),
        augmentation_rounds=int(policy.get("augmentation_rounds", 2)),
    )

    print("[DEBUG TESTGEN] llm_test_generation_enabled =", bool(policy.get("llm_test_generation_enabled", False)))
    print("[DEBUG TESTGEN] llm_test_generator_is_none =", llm_test_generator is None)
    print("[DEBUG TESTGEN] tg_config.llm_enabled =", tg_config.llm_enabled)

    tg_result = run_test_generation_layer(
        foundry_root=FOUNDRY_ROOT,
        contract_source_path=FOUNDRY_ROOT / contract_import_path,
        contract_name=contract_name,
        harness_name=harness_contract,
        out_dir=testgen_out_dir,
        llm_generator=llm_test_generator,
        config=tg_config,
        ir_json=ir,
        ir_json_path=ir_out,
    )

    print(
        "[OBLIVION] Test generation layer complete: "
        f"verified_generated_tests={len(tg_result.verified_generated_tests)} "
        f"targets={len(tg_result.uncovered_targets)}"
    )

    # ------------------------------
    # Step 4: Copy unified evidence artifacts to canonical run root
    # ------------------------------
    canonical_files = [
        "coverage.json",
        "traces.json",
        "test_results.json",
        "test_summary.json",
        "uncovered_targets.json",
        "generated_tests_manifest.json",
        "retained_tests.json",
        "merged_manifest.json",
        "test_generation_summary.json",
        "coverage.lcov",
        "merged_test_stdout.txt",
        "baseline_test_stdout.txt",
    ]
    for name in canonical_files:
        src = testgen_out_dir / name
        if src.exists():
            copy2(src, out_dir / name)

    src_traces_dir = tg_result.traces_dir
    dst_traces_dir = out_dir / "traces"
    dst_traces_dir.mkdir(parents=True, exist_ok=True)
    if src_traces_dir.exists():
        for trace_file in src_traces_dir.glob("*.json"):
            copy2(trace_file, dst_traces_dir / trace_file.name)

    test_stdout = testgen_out_dir / "merged_test_stdout.txt"
    cov_lcov = testgen_out_dir / "coverage.lcov"

    if test_stdout.exists():
        copy2(test_stdout, out_dir / "forge-test.stdout.txt")
    if cov_lcov.exists():
        copy2(cov_lcov, out_dir / "coverage.lcov")

    if test_stdout.exists() and cov_lcov.exists():
        ExecutionEvidence.from_paths(
            test_stdout=test_stdout,
            coverage_lcov=cov_lcov,
        ).to_json_files(out_dir)

    # ------------------------------
    # Step 5: Security Advisor baseline
    # ------------------------------
    sec_advice_path = out_dir / "sec_advice.json"

    try:
        from security_advisor import build_sec_advice

        build_sec_advice(
            contract_name=contract_name,
            source_relpath=contract_import_path,
            target_sol=source_in_foundry,
            out_json=sec_advice_path,
            cwd=FOUNDRY_ROOT,
            coverage_json=out_dir / "coverage.json",
            traces_json=out_dir / "traces.json",
            ir_json=ir_out,
            analyzer_ast_json=ast_dump,
        )
        print(f"[OBLIVION] Security baseline: {sec_advice_path}")
    except Exception as e:
        print(f"[OBLIVION] WARNING: Security baseline failed: {e}")
        sec_advice_path = None

    # ------------------------------
    # Step 5.5: Obfuscation Advisor
    # ------------------------------
    advice_path = out_dir / "obfuscation_advice.json"
    advice = build_contract_advice(
        coverage_json=out_dir / "coverage.json",
        test_summary_json=out_dir / "test_summary.json",
        traces_json=out_dir / "traces.json",
        ir_json=ir_out,
        contract_name=contract_name,
        source_relpath=contract_import_path,
        sec_advice_json=sec_advice_path if sec_advice_path and sec_advice_path.exists() else None,
        tier_policy=policy.get("tiering", {}),
    )
    advice_path.write_text(json.dumps(advice, indent=2), encoding="utf-8")

    tier_decisions_path = out_dir / "tier_decisions.json"
    tier_decisions = {
        "contract": advice.get("contract"),
        "source_file": advice.get("source_file"),
        "meta": (advice.get("meta") or {}).get("tiering", {}),
        "functions": [
            {
                "function": fn.get("function"),
                "econ_score": fn.get("econ_score"),
                "sec_score": fn.get("sec_score"),
                "sec_severity": fn.get("sec_severity"),
                "runtime_relevance": fn.get("runtime_relevance"),
                "coverage_score": fn.get("coverage_score"),
                "exec_weight": fn.get("exec_weight"),
                "tier": fn.get("tier"),
                "tier_reason": fn.get("tier_reason"),
                "tier_inputs": fn.get("tier_inputs"),
                "policy_trace": {
                    "policy_sensitivity": fn.get("policy_sensitivity"),
                    "policy_sensitivity_band": fn.get("policy_sensitivity_band"),
                    "policy_signals": fn.get("policy_signals"),
                    "protected_regions": fn.get("protected_regions"),
                    "policy_constraints": fn.get("policy_constraints"),
                },
            }
            for fn in (advice.get("functions") or [])
        ],
    }
    tier_decisions_path.write_text(json.dumps(tier_decisions, indent=2), encoding="utf-8")
    transform_policy_audit_path = out_dir / "transform_policy_audit.json"

    # ------------------------------
    # Step 6: Decision / Planner
    # ------------------------------
    plan_path = out_dir / "variants_plan.json"

    planner = LLMPlanner(policy=policy)

    llm_schema_validator = LLMPlanValidatorV1(
        schema_path=ROOT / "schemas" / "llm_transform_plan.schema.json",
    )
    _ = llm_schema_validator

    allowed_transform_ids_sorted = sorted(list(APPLIERS.keys()))
    allowed_ids_set = set(allowed_transform_ids_sorted)

    # ------------------------------------------------------------
    # OBLIVION visual potency mode
    # Allows stronger BiAn-like obfuscation, but still keeps validator/security checks.
    # ------------------------------------------------------------
    VISUAL_POTENCY_MODE = bool(
        os.getenv("OBLIVION_VISUAL_POTENCY", "1").lower() not in {"0", "false", "no"}
    )

    if VISUAL_POTENCY_MODE:
        policy["apply_all_safe_transforms_when_allowed"] = True
        policy["respect_full_llm_plan"] = True
        policy["force_full_safe_plan"] = True
        policy["max_transforms_per_function"] = 12
        policy["max_selected_noop_ratio"] = 0.90
        policy["gas_budget_pct"] = max(float(policy.get("gas_budget_pct", 25) or 25), 45.0)

        print("[POTENCY] Visual potency mode enabled")

    allowed_transforms = {}
    for tid, fn in APPLIERS.items():
        desc = ""
        try:
            desc = (fn.__doc__ or "").strip()
        except Exception:
            desc = ""
        allowed_transforms[tid] = {"id": tid, "description": desc}

    with open(advice_path, "r", encoding="utf-8") as f:
        obf_advice = json.load(f)

    sec_advice = {}
    if sec_advice_path and sec_advice_path.exists():
        with open(sec_advice_path, "r", encoding="utf-8") as f:
            sec_advice = json.load(f)

    sec_by_function = {
        item["function"]: item
        for item in (sec_advice.get("functions") or [])
        if isinstance(item, dict) and item.get("function")
    }

    def _sec_sev_from_entry(obj: dict) -> str:
        if not isinstance(obj, dict):
            return ""
        s = (obj.get("severity_max") or "").strip().upper()
        if s:
            return s
        s = (obj.get("severity") or obj.get("sec_severity") or "").strip().upper()
        return s

    sec_contract_sev = str(sec_advice.get("contract_severity") or "").strip()
    sec_contract_score = sec_advice.get("contract_sec_score")

    if not sec_contract_sev:
        sec_contract_sev = _sec_sev_from_entry(sec_advice)

    if not sec_contract_sev:
        sec_contract_sev = "INFO"

    try:
        sec_contract_score = float(sec_contract_score)
    except Exception:
        sec_contract_score = None

    print(f"[SEC] contract_severity={sec_contract_sev}")
    if sec_contract_score is not None:
        print(f"[SEC] contract_sec_score={round(sec_contract_score, 4)}")

    source_text = source_snapshot.read_text(encoding="utf-8", errors="ignore")
    explicit_fn_names = _extract_explicit_function_names_from_source(source_text)

    plans = []
    transform_policy_audit: list[dict] = []

    for fn in ir["contract"]["functions"]:
        fn_name = fn.get("name") or ""
        if not fn_name:
            continue

        # Never plan/obfuscate framework-generated helper functions.
        if fn_name.startswith("__obf_"):
            print(f"[OBLIVION] Skipping generated helper function: {fn_name}")
            continue

        is_constructor = (fn_name == "constructor")
        if is_constructor:
            continue

        if fn_name not in explicit_fn_names:
            continue

        obf_advice_fn = _slice_obf_advice_for_function(obf_advice, fn_name)
        sec_advice_fn = _slice_sec_advice_for_function(sec_advice, fn_name)
        if sec_advice_fn:
            print(
                f"[SEC-FN] fn={fn_name} "
                f"sec_score={sec_advice_fn.get('sec_score')} "
                f"severity={sec_advice_fn.get('severity_max')} "
                f"runtime_relevance={sec_advice_fn.get('runtime_relevance')} "
                f"confidence={sec_advice_fn.get('confidence')}"
            )

        if obf_advice_fn:
            print(
                f"[OBF-ADVICE] fn={fn_name} "
                f"econ_score={obf_advice_fn.get('econ_score')} "
                f"sec_severity={obf_advice_fn.get('sec_severity')} "
                f"tier={obf_advice_fn.get('tier')} "
                f"candidates={len(obf_advice_fn.get('candidate_transforms') or [])}"
            )

        try:
            fn_tier = int(obf_advice_fn.get("tier"))
        except Exception:
            raise RuntimeError(
                f"Canonical tier missing for function '{fn_name}'. "
                "obfuscation_advisor must provide tier before planning."
            )

        sev = (
            obf_advice_fn.get("sec_severity")
            or sec_advice_fn.get("severity_max")
            or sec_advice_fn.get("severity")
            or sec_advice_fn.get("sec_severity")
            or sec_contract_sev
            or "INFO"
        ).strip().upper()

        runtime_relevance = float(
            obf_advice_fn.get("runtime_relevance")
            or sec_advice_fn.get("runtime_relevance")
            or 0.0
        )

        mut = (fn.get("state_mutability") or fn.get("mutability") or "").strip().lower()

        print(
            f"[TIER] fn={fn_name} canonical_tier={fn_tier} "
            f"reason={obf_advice_fn.get('tier_reason')} "
            f"econ={obf_advice_fn.get('econ_score')} "
            f"sec_score={obf_advice_fn.get('sec_score')} "
            f"coverage={obf_advice_fn.get('coverage_score')} "
            f"runtime_relevance={obf_advice_fn.get('runtime_relevance')}"
        )

        if fn_tier <= 0:
            print(f"[DEBUG] Tier-0 protected function {fn_name}: allowing safe cosmetic transforms only")

            import copy

            normalized_sec_entry = (
                json.loads(json.dumps(sec_advice_fn))
                if isinstance(sec_advice_fn, dict) else {}
            )

            normalized_sec_entry["sec_score"] = obf_advice_fn.get(
                "sec_score",
                normalized_sec_entry.get("sec_score"),
            )
            normalized_sec_entry["sec_severity"] = obf_advice_fn.get(
                "sec_severity",
                normalized_sec_entry.get("sec_severity"),
            )
            normalized_sec_entry["policy_sensitivity"] = obf_advice_fn.get(
                "policy_sensitivity",
                normalized_sec_entry.get("policy_sensitivity"),
            )
            normalized_sec_entry["policy_sensitivity_band"] = obf_advice_fn.get(
                "policy_sensitivity_band",
                normalized_sec_entry.get("policy_sensitivity_band"),
            )

            if isinstance(obf_advice_fn.get("policy_signals"), dict):
                normalized_sec_entry["policy_signals"] = json.loads(
                    json.dumps(obf_advice_fn["policy_signals"])
                )
            else:
                normalized_sec_entry.setdefault("policy_signals", {})

            if isinstance(obf_advice_fn.get("policy_constraints"), dict):
                normalized_sec_entry["policy_constraints"] = json.loads(
                    json.dumps(obf_advice_fn["policy_constraints"])
                )
            else:
                normalized_sec_entry.setdefault("policy_constraints", {})

            if isinstance(obf_advice_fn.get("protected_regions"), list):
                normalized_sec_entry["protected_regions"] = list(obf_advice_fn["protected_regions"])
            else:
                normalized_sec_entry.setdefault("protected_regions", [])

            tier0_selected = [
                {
                    "id": "rename_identifiers_v2_scoped",
                    "target": {"function": fn_name},
                    "params": {},
                    "tier0_safe": True,
                    "reason": "tier0_safe_scoped_identifier_rename",
                },
                {
                    "id": "layout_scramble_v1",
                    "target": {"function": fn_name},
                    "params": {},
                    "tier0_safe": True,
                    "reason": "tier0_safe_layout_only",
                },
            ]

            tier0_policy_signals = normalized_sec_entry.get("policy_signals", {})
            if not isinstance(tier0_policy_signals, dict):
                tier0_policy_signals = {}

            tier0_access = bool(tier0_policy_signals.get("access_control_sensitive"))
            tier0_revert = bool(tier0_policy_signals.get("revert_semantics_sensitive"))
            tier0_external = bool(tier0_policy_signals.get("external_call_sensitive"))

            if not (tier0_access or tier0_revert or tier0_external):
                for tid in ["constant_encoding_v1", "opaque_predicate_v2_entangled"]:
                    if tid in allowed_ids_set:
                        tier0_selected.append(
                            {
                                "id": tid,
                                "target": {"function": fn_name},
                                "params": {
                                    "tier0_safe": True,
                                    "validator_must_pass": True,
                                },
                                "reason": "tier0_extra_safe_visual_transform",
                            }
                        )

            tier0_selected = _filter_transforms_with_audit(
                fn_name=fn_name,
                transforms=tier0_selected,
                allowed_ids_set=allowed_ids_set,
                fn_tier=1,  # compatibility gate needs light-transform permission
                sev=sev,
                fn_ir=fn if isinstance(fn, dict) else {},
                sec_advice_fn=normalized_sec_entry,
                policy=policy if isinstance(policy, dict) else {},
                stage="tier0_safe_transform_gate",
                audit_log=transform_policy_audit,
            )

            if not tier0_selected:
                tier0_selected = [
                    {
                        "id": "layout_scramble_v1",
                        "target": {"function": fn_name},
                        "params": {},
                        "tier0_safe": True,
                        "reason": "tier0_safe_fallback_layout_only",
                    }
                ]

            llm_meta = {
                "rationale": "Tier-0 protected function: only scoped-safe/cosmetic transforms allowed",
                "semantic_contract": {
                    "global_invariants": [
                        "preserve external behavior",
                        "preserve revert behavior",
                        "preserve storage writes",
                        "preserve access-control semantics",
                    ],
                    "protected_region_tags": list(normalized_sec_entry.get("protected_regions", []) or []),
                    "transform_safety": [
                        {
                            "transform_id": t.get("id"),
                            "risk": "low",
                            "avoid_regions": [],
                            "allowed_on_tier0": True,
                        }
                        for t in tier0_selected
                        if isinstance(t, dict)
                    ],
                },
                "composition_graph": {
                    "nodes": [
                        {"transform_id": t.get("id")}
                        for t in tier0_selected
                        if isinstance(t, dict)
                    ],
                    "unsafe_pairs": [],
                },
                "composition_audit": [],
            }

            plans.append(
                {
                    "function": fn_name,
                    "tier": 0,
                    "sec_severity_max": sev or "UNKNOWN",
                    "sec_entry": copy.deepcopy(normalized_sec_entry),
                    "function_ir": copy.deepcopy(fn if isinstance(fn, dict) else {}),
                    "policy_context": {
                        "transform_vulnerability_matrix": (
                            policy.get("transform_vulnerability_matrix", {})
                            if isinstance(policy, dict) else {}
                        ),
                        "tier0_safe_mode": True,
                    },
                    "policy_trace": {
                        "sec_score": normalized_sec_entry.get("sec_score"),
                        "sec_severity": normalized_sec_entry.get("sec_severity") or sev or "UNKNOWN",
                        "policy_sensitivity": normalized_sec_entry.get("policy_sensitivity"),
                        "policy_sensitivity_band": normalized_sec_entry.get("policy_sensitivity_band", "INFO"),
                        "policy_signals": copy.deepcopy(normalized_sec_entry.get("policy_signals", {}) or {}),
                        "protected_regions": copy.deepcopy(normalized_sec_entry.get("protected_regions", []) or []),
                        "policy_constraints": copy.deepcopy(normalized_sec_entry.get("policy_constraints", {}) or {}),
                        "tier_reason": "tier0_safe_cosmetic_only",
                    },
                    "pre_engine_llm_meta": copy.deepcopy(llm_meta),
                    "llm_meta": copy.deepcopy(llm_meta),
                    "selected_transforms": tier0_selected,
                    "tests_to_run": [],
                }
            )
            continue

        selected = []
        drop_reasons: list[str] = []

        max_llm_repair_rounds = int(policy.get("max_llm_repair_rounds", 2))
        repair_feedback = None
        llm_plan = None
        llm_meta = {
            "rationale": "",
            "semantic_contract": {},
            "composition_graph": {},
            "composition_audit": [],
        }

        for repair_round in range(max_llm_repair_rounds + 1):
            try:
                if repair_round == 0:
                    llm_plan = planner.propose_plan(
                        contract_name=contract_name,
                        function_name=fn_name,
                        function_ir=fn,
                        obf_advice=obf_advice_fn,
                        sec_advice=sec_advice_fn,
                        tier=fn_tier,
                        allowed_transforms=allowed_transforms,
                    )
                else:
                    llm_plan = planner.repair_plan(
                        contract_name=contract_name,
                        function_name=fn_name,
                        function_ir=fn,
                        obf_advice=obf_advice_fn,
                        sec_advice=sec_advice_fn,
                        tier=fn_tier,
                        allowed_transforms=allowed_transforms,
                        previous_plan=selected,
                        previous_semantic_contract=llm_meta.get("semantic_contract", {}),
                        previous_composition_graph=llm_meta.get("composition_graph", {}),
                        failure_reason=repair_feedback.get("failure_reason", "unknown_failure"),
                        reject_reasons=repair_feedback.get("reject_reasons", []),
                        validator_summary=repair_feedback.get("validator_summary", "no_validator_summary"),
                    )

                if isinstance(llm_plan, dict):
                    print(f"[DEBUG] LLM raw keys for {fn_name}: {list(llm_plan.keys())}")
                    if "plan" in llm_plan:
                        print(f"[DEBUG] LLM 'plan' length for {fn_name}: {len(llm_plan.get('plan') or [])}")
                    if "transforms" in llm_plan:
                        print(f"[DEBUG] LLM 'transforms' length for {fn_name}: {len(llm_plan.get('transforms') or [])}")

                    selected = llm_plan.get("plan") or llm_plan.get("transforms") or []
                    llm_meta = {
                        "rationale": llm_plan.get("rationale", ""),
                        "semantic_contract": llm_plan.get("semantic_contract", {}),
                        "composition_graph": llm_plan.get("composition_graph", {}),
                        "composition_audit": llm_plan.get("composition_audit", []),
                    }
                else:
                    print(f"[DEBUG] LLM returned non-dict for {fn_name}: {type(llm_plan)}")
                    selected = []
                    llm_meta = {
                        "rationale": "",
                        "semantic_contract": {},
                        "composition_graph": {},
                        "composition_audit": [],
                    }

            except Exception as e:
                print(f"[OBLIVION] LLM plan failed for function={fn_name} round={repair_round}: {e}")
                selected = []
                llm_meta = {
                    "rationale": "",
                    "semantic_contract": {},
                    "composition_graph": {},
                    "composition_audit": [],
                }

                repair_feedback = _build_plan_repair_feedback(
                    failure_reason=str(e),
                    reject_reasons=[],
                    validator_summary=f"Planner failure for function={fn_name} round={repair_round}",
                )
            
            sanitized, drop_reasons = _sanitize_transform_list_for_function(
                fn_name=fn_name,
                function_ir=fn,
                selected=selected,
                allowed_ids=allowed_ids_set,
                policy=policy,
            )

            if sanitized:
                selected = sanitized
                break

            llm_meta = {
                "rationale": llm_meta.get("rationale", ""),
                "semantic_contract": {},
                "composition_graph": {},
                "composition_audit": list(llm_meta.get("composition_audit", [])),
            }

            repair_feedback = _build_plan_repair_feedback(
                failure_reason=repair_feedback.get("failure_reason", "plan_sanitized_to_empty") if repair_feedback else "plan_sanitized_to_empty",
                reject_reasons=drop_reasons,
                validator_summary=f"Sanitization removed all transforms for function={fn_name}",
            )

            print(
                f"[REPAIR-PLAN] fn={fn_name} round={repair_round} "
                f"failure_reason={repair_feedback['failure_reason']} "
                f"reject_reasons={repair_feedback['reject_reasons']}"
            )

            selected = []

        sanitized, drop_reasons = _sanitize_transform_list_for_function(
            fn_name=fn_name,
            function_ir=fn,
            selected=selected,
            allowed_ids=allowed_ids_set,
            policy=policy,
        )

        # If LLM output is empty after sanitization, fall back first to advisor-provided candidates
        if not sanitized:
            advisor_candidates = obf_advice_fn.get("candidate_transforms") or []
            if isinstance(advisor_candidates, list):
                advisor_selected = []
                for item in advisor_candidates:
                    if not isinstance(item, dict):
                        continue
                    if not item.get("enabled", True):
                        continue
                    tid = item.get("id")
                    if not isinstance(tid, str) or not tid.strip():
                        continue
                    advisor_selected.append(
                        {
                            "id": tid.strip(),
                            "target": {"function": fn_name},
                            "params": {},
                        }
                    )

                sanitized, advisor_drop_reasons = _sanitize_transform_list_for_function(
                    fn_name=fn_name,
                    function_ir=fn,
                    selected=advisor_selected,
                    allowed_ids=allowed_ids_set,
                    policy=policy,
                )
                if advisor_drop_reasons:
                    print(f"[DEBUG] Advisor candidate drops for {fn_name}: {advisor_drop_reasons}")

        if sev in ("HIGH", "CRITICAL"):
            risky = {
                "dispatcher_cfg_virtualization_v1",
                "opaque_storage_slot_indirection_v1",
            }
            sanitized = [t for t in sanitized if t.get("id") not in risky]

        if drop_reasons:
            print(f"[DEBUG] Dropped/trimmed transforms for {fn_name}: {drop_reasons}")

        sanitized = augment_plan_if_safe_with_log(
            plan=sanitized,
            tier=fn_tier,
            sec_sev=sev or "UNKNOWN",
            fn_ir=fn,
            fn_name=fn_name,
            allowed_ids=allowed_ids_set,
            sec_entry=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
            policy=policy if isinstance(policy, dict) else {},
        )

        sanitized = _filter_transforms_with_audit(
            fn_name=fn_name,
            transforms=sanitized,
            allowed_ids_set=allowed_ids_set,
            fn_tier=fn_tier,
            sev=sev or "UNKNOWN",
            fn_ir=fn,
            sec_advice_fn=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
            policy=policy,
            stage="post_augment_compat_filter",
            audit_log=transform_policy_audit,
        )

        before_ids = [t.get("id") for t in sanitized if isinstance(t, dict) and isinstance(t.get("id"), str)]
        sanitized_after_policy = _enforce_tier_transform_policy(
            fn_name=fn_name,
            tier=fn_tier,
            sec_sev=sev or "UNKNOWN",
            mutability=mut,
            transforms=sanitized,
            allowed_ids=allowed_ids_set,
            policy=policy,
            fn_ir=fn,
            sec_entry=sec_advice_fn,
        )
        after_ids = {t.get("id") for t in sanitized_after_policy if isinstance(t, dict) and isinstance(t.get("id"), str)}
        for tid in before_ids:
            if tid not in after_ids:
                _append_drop_audit(
                    audit_log=transform_policy_audit,
                    fn_name=fn_name,
                    stage="tier_policy_trim",
                    tid=tid,
                    reason="tier_policy_trimmed",
                    tier=fn_tier,
                    sec_sev=sev or "UNKNOWN",
                )
        sanitized = sanitized_after_policy

        print(f"[DEBUG] Post-augment/policy transforms count for {fn_name}: {len(sanitized)}")

        if not sanitized:
            sanitized = _fallback_deterministic_transforms(
                fn_name=fn_name,
                function_ir=fn,
                tier=fn_tier,
                allowed_ids=allowed_ids_set,
                obf_advice_fn=obf_advice_fn,
                sec_advice_fn=sec_advice_fn,
                policy=policy,
            )

            sanitized = augment_plan_if_safe_with_log(
                plan=sanitized,
                tier=fn_tier,
                sec_sev=sev or "UNKNOWN",
                fn_ir=fn,
                fn_name=fn_name,
                allowed_ids=allowed_ids_set,
                sec_entry=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
                policy=policy if isinstance(policy, dict) else {},
            )

            sanitized = _filter_transforms_with_audit(
                fn_name=fn_name,
                transforms=sanitized,
                allowed_ids_set=allowed_ids_set,
                fn_tier=fn_tier,
                sev=sev or "UNKNOWN",
                fn_ir=fn,
                sec_advice_fn=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
                policy=policy,
                stage="fallback_compat_filter",
                audit_log=transform_policy_audit,
            )

            sanitized = _enforce_tier_transform_policy(
                fn_name=fn_name,
                tier=fn_tier,
                sec_sev=sev or "UNKNOWN",
                mutability=mut,
                transforms=sanitized,
                allowed_ids=allowed_ids_set,
                policy=policy,
                fn_ir=fn,
                sec_entry=sec_advice_fn,
            )
            print(f"[DEBUG] Fallback transforms count for {fn_name}: {len(sanitized)}")

        for t in sanitized:
            tgt = t.get("target")
            if not isinstance(tgt, dict):
                tgt = {}
            tgt.setdefault("function", fn_name)
            t["target"] = tgt

        final_ids = [
            t["id"]
            for t in sanitized
            if isinstance(t, dict) and isinstance(t.get("id"), str)
        ]

        det_sc = build_deterministic_semantic_contract(
            selected_ids=final_ids,
            function_ir=fn,
            sec_advice=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
        )
        det_graph = build_deterministic_composition_graph(
            selected_ids=final_ids,
            function_ir=fn,
            sec_advice=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
        )

        llm_meta = dict(llm_meta or {})
        llm_meta["semantic_contract"] = merge_semantic_contracts(
            llm_meta.get("semantic_contract", {}),
            det_sc,
            final_ids,
        )
        llm_meta["composition_graph"] = merge_composition_graphs(
            llm_meta.get("composition_graph", {}),
            det_graph,
        )
        llm_meta = _filter_llm_meta_to_selected_ids(
            llm_meta=llm_meta,
            selected_ids=final_ids,
        )

        semantic_filtered, semantic_filter_reasons = _semantic_filter_selected_transforms(
            sanitized,
            llm_meta if isinstance(llm_meta, dict) else {},
            sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
            policy if isinstance(policy, dict) else {},
        )

        if semantic_filter_reasons:
            print(
                f"[SEM-FILTER] fn={fn_name} removed={semantic_filter_reasons} "
                f"before={len(sanitized)} after={len(semantic_filtered)}"
            )

        sanitized = semantic_filtered

        pair_pruned, pair_prune_reasons = _prune_unsafe_pairs_from_selected(
            sanitized,
            llm_meta if isinstance(llm_meta, dict) else {},
            sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
        )

        if pair_prune_reasons:
            print(
                f"[SEM-PAIR-PRUNE] fn={fn_name} reasons={pair_prune_reasons} "
                f"before={len(sanitized)} after={len(pair_pruned)}"
            )

        sanitized = pair_pruned

        print(
            f"[DEMOTE-CONTEXT] fn={fn_name} "
            f"tier={fn_tier} sec_severity={sev} runtime_relevance={runtime_relevance}"
        )

        demoted_selected, demote_reasons = _demote_aggressive_transforms_for_narrow_contract(
            sanitized,
            llm_meta=llm_meta if isinstance(llm_meta, dict) else {},
            sec_entry=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
            policy=policy if isinstance(policy, dict) else {},
            fn_entry={
                "tier": fn_tier,
                "sec_severity": sev,
                "runtime_relevance": float(
                    obf_advice_fn.get("runtime_relevance")
                    or sec_advice_fn.get("runtime_relevance")
                    or 0.0
                ),
            },
        )

        if demote_reasons:
            print(
                f"[SEM-DEMOTE] fn={fn_name} reasons={demote_reasons} "
                f"before={len(sanitized)} after={len(demoted_selected)}"
            )

        sanitized = demoted_selected

        restored_selected, restored_ids = _restore_non_risky_transforms(
            base_selected=sanitized_after_policy,
            current_selected=demoted_selected,
            llm_meta=llm_meta if isinstance(llm_meta, dict) else {},
            sec_entry=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
            policy=policy if isinstance(policy, dict) else {},
        )

        if restored_ids:
            print(
                f"[SAFE-CLOSURE] fn={fn_name} restored={restored_ids} "
                f"before={len(demoted_selected)} after={len(restored_selected)}"
            )

        sanitized = restored_selected

        # Recompute the deterministic graph from the FINAL selected transform set,
        # then merge it with the LLM graph so ordering uses the same graph contract
        # that downstream validation expects.
        selected_ids_for_graph = [
            t["id"]
            for t in sanitized
            if isinstance(t, dict) and isinstance(t.get("id"), str) and t["id"].strip()
        ]

        llm_graph = (
            llm_meta.get("composition_graph")
            if isinstance(llm_meta.get("composition_graph"), dict)
            else {}
        )

        det_graph = build_deterministic_composition_graph(
            selected_ids=selected_ids_for_graph,
            function_ir=fn if isinstance(fn, dict) else {},
            sec_advice=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
        )

        merged_graph = merge_composition_graphs(llm_graph, det_graph)

        # Persist the merged graph back into llm_meta so the plan object carries
        # the same composition contract used for ordering.
        llm_meta["composition_graph"] = merged_graph

        ordered = order_plan_steps(
            [
                {
                    "transform_id": t["id"],
                    "params": t.get("params", {}),
                }
                for t in sanitized
                if isinstance(t, dict) and isinstance(t.get("id"), str)
            ],
            merged_graph,
        )

        print(
            f"[ORDER-BEFORE] fn={fn_name} "
            f"sanitized={[t.get('id') for t in sanitized if isinstance(t, dict)]}"
        )

        ordered_ids = [
            x.get("transform_id")
            for x in ordered or []
            if isinstance(x, dict) and isinstance(x.get("transform_id"), str) and x.get("transform_id").strip()
        ]

        print(f"[ORDER-AFTER] fn={fn_name} ordered_ids={ordered_ids}")

        ordered_ids = [
            x.get("transform_id")
            for x in ordered or []
            if isinstance(x, dict) and isinstance(x.get("transform_id"), str) and x.get("transform_id").strip()
        ]

        if ordered_ids:
            by_id = {}
            for t in sanitized:
                if not isinstance(t, dict):
                    continue
                tid = t.get("id")
                if isinstance(tid, str) and tid.strip():
                    by_id[tid] = t

            reordered_sanitized: List[Dict[str, Any]] = []
            seen = set()

            for tid in ordered_ids:
                row = by_id.get(tid)
                if row is None or tid in seen:
                    continue
                seen.add(tid)
                reordered_sanitized.append(row)

            for t in sanitized:
                if not isinstance(t, dict):
                    continue
                tid = t.get("id")
                if not isinstance(tid, str) or not tid.strip() or tid in seen:
                    continue
                seen.add(tid)
                reordered_sanitized.append(t)

            sanitized = reordered_sanitized

            print(
                f"[ORDER-APPLIED] fn={fn_name} "
                f"sanitized={[t.get('id') for t in sanitized if isinstance(t, dict)]}"
            )

        final_ids = [
            t["id"]
            for t in sanitized
            if isinstance(t, dict) and isinstance(t.get("id"), str) and t["id"].strip()
        ]

        llm_meta = _filter_llm_meta_to_selected_ids(
            llm_meta=llm_meta,
            selected_ids=final_ids,
        )

        # Rebuild once more after final filtering so the carried graph is guaranteed
        # to match the final transform set written into the plan.
        det_graph_final = build_deterministic_composition_graph(
            selected_ids=final_ids,
            function_ir=fn if isinstance(fn, dict) else {},
            sec_advice=sec_advice_fn if isinstance(sec_advice_fn, dict) else {},
        )

        llm_graph_final = (
            llm_meta.get("composition_graph")
            if isinstance(llm_meta.get("composition_graph"), dict)
            else {}
        )

        llm_meta["composition_graph"] = merge_composition_graphs(
            llm_graph_final,
            det_graph_final,
        )

        order_idx = {
            step["transform_id"]: i
            for i, step in enumerate(ordered)
            if isinstance(step, dict) and isinstance(step.get("transform_id"), str)
        }
        sanitized = sorted(
            sanitized,
            key=lambda t: order_idx.get(t.get("id"), 10**9) if isinstance(t, dict) else 10**9,
        )

        if VISUAL_POTENCY_MODE:
            before_visual = [t.get("id") for t in selected if isinstance(t, dict)]
            selected = _append_visual_potency_transforms(
                fn_name=fn_name,
                tier=fn_tier,
                sev=sev,
                selected=selected,
                allowed_ids_set=allowed_ids_set,
                sec_entry=normalized_sec_entry if isinstance(normalized_sec_entry, dict) else {},
            )

            selected = _dedupe_transforms_keep_order(selected)

            selected = _filter_by_patch_site_precheck(
                fn_name=fn_name,
                transforms=selected,
                fn_ir=fn if isinstance(fn, dict) else {},
            )

            selected = _filter_transforms_with_audit(
                fn_name=fn_name,
                transforms=selected,
                allowed_ids_set=allowed_ids_set,
                fn_tier=max(1, int(fn_tier)),
                sev=sev,
                fn_ir=fn if isinstance(fn, dict) else {},
                sec_advice_fn=normalized_sec_entry if isinstance(normalized_sec_entry, dict) else {},
                policy=policy if isinstance(policy, dict) else {},
                stage="visual_potency_gate",
                audit_log=transform_policy_audit,
            )

            selected = _dedupe_transforms_keep_order(selected)

            # IMPORTANT: visual potency was modifying `selected`,
            # but final plan writes `sanitized`.
            # Without this line, stronger transforms are logged but not emitted.
            sanitized = selected

            after_visual = [t.get("id") for t in selected if isinstance(t, dict)]

            print(
                f"[POTENCY] fn={fn_name} before={before_visual} after={after_visual}"
            )

        print(f"[DEBUG] Final selected_transforms count for {fn_name}: {len(sanitized)}")

        print(
            f"[PLAN-APPEND] fn={fn_name} selected_transforms="
            f"{[t.get('id') for t in sanitized if isinstance(t, dict)]}"
        )

        normalized_sec_entry = (
            json.loads(json.dumps(sec_advice_fn))
            if isinstance(sec_advice_fn, dict) else {}
        )

        # Backfill the fields that downstream semantic/risk logic expects to live
        # inside sec_entry, even when the raw sec_advice_fn is sparse.
        normalized_sec_entry["sec_score"] = obf_advice_fn.get(
            "sec_score",
            normalized_sec_entry.get("sec_score"),
        )
        normalized_sec_entry["sec_severity"] = obf_advice_fn.get(
            "sec_severity",
            normalized_sec_entry.get("sec_severity"),
        )
        normalized_sec_entry["policy_sensitivity"] = obf_advice_fn.get(
            "policy_sensitivity",
            normalized_sec_entry.get("policy_sensitivity"),
        )
        normalized_sec_entry["policy_sensitivity_band"] = obf_advice_fn.get(
            "policy_sensitivity_band",
            normalized_sec_entry.get("policy_sensitivity_band"),
        )

        if isinstance(obf_advice_fn.get("policy_signals"), dict):
            normalized_sec_entry["policy_signals"] = json.loads(
                json.dumps(obf_advice_fn["policy_signals"])
            )
        else:
            normalized_sec_entry.setdefault("policy_signals", {})

        if isinstance(obf_advice_fn.get("policy_constraints"), dict):
            normalized_sec_entry["policy_constraints"] = json.loads(
                json.dumps(obf_advice_fn["policy_constraints"])
            )
        else:
            normalized_sec_entry.setdefault("policy_constraints", {})

        if isinstance(obf_advice_fn.get("protected_regions"), list):
            normalized_sec_entry["protected_regions"] = list(obf_advice_fn["protected_regions"])
        else:
            normalized_sec_entry.setdefault("protected_regions", [])

        plans.append(
            {
                "function": fn_name,
                "tier": fn_tier,
                "sec_severity_max": sev or "UNKNOWN",
                "sec_entry": normalized_sec_entry,
                "function_ir": fn if isinstance(fn, dict) else {},
                "policy_context": {
                    "transform_vulnerability_matrix": (
                        policy.get("transform_vulnerability_matrix", {})
                        if isinstance(policy, dict) else {}
                    )
                },
                "policy_trace": {
                    "sec_score": normalized_sec_entry.get("sec_score"),
                    "sec_severity": normalized_sec_entry.get("sec_severity"),
                    "policy_sensitivity": normalized_sec_entry.get("policy_sensitivity"),
                    "policy_sensitivity_band": normalized_sec_entry.get("policy_sensitivity_band"),
                    "policy_signals": normalized_sec_entry.get("policy_signals"),
                    "protected_regions": normalized_sec_entry.get("protected_regions"),
                    "policy_constraints": normalized_sec_entry.get("policy_constraints"),
                    "tier_reason": obf_advice_fn.get("tier_reason"),
                },
                "pre_engine_llm_meta": llm_meta,
                "llm_meta": llm_meta,
                "selected_transforms": sanitized,
                "tests_to_run": [],
            }
        )

    # --------------------------------------------------
    # Safe-by-default planner expansion
    # --------------------------------------------------
    # This happens AFTER LLM/planner sanitization and BEFORE variants_plan.json
    # is written. It increases visual obfuscation density while keeping the
    # final risk gate in the engine/validator.
    safe_expand_seed = (
        int(policy.get("safe_expand_seed", policy.get("seed", 1337)))
        if isinstance(policy, dict)
        else 1337
    )

    plans = expand_safe_plans(
        plans,
        allowed_ids_set=allowed_ids_set,
        seed=safe_expand_seed,
        policy=policy if isinstance(policy, dict) else {},
    )

    plans = _normalize_selected_transforms_for_engine(plans)

    base_plan_obj = {
        "contract": contract_name,
        "plans": plans,
        "policy": policy if isinstance(policy, dict) else {},
    }
    base_plan_obj = _ensure_plan_has_transforms(base_plan_obj)

    base_tests_to_run = _extract_tests_to_run(base_plan_obj)

    (out_dir / "variants_plan.base.json").write_text(
        json.dumps(base_plan_obj, indent=2), encoding="utf-8"
    )
    plan_path.write_text(json.dumps(base_plan_obj, indent=2), encoding="utf-8")

    # ------------------------------
    # Step 6.5: Optimizer/Search
    # ------------------------------
    try:
        from optimizer.variant_generator import generate_candidate_plans
        optimizer_available = True
    except Exception:
        optimizer_available = False

    search_max_subset_size = int(policy.get("search_max_subset_size", 2))
    search_max_candidates = int(policy.get("search_max_candidates", 12))
    search_enable_param_mutation = bool(policy.get("search_enable_param_mutation", False))

    validator_policy = dict(policy) if isinstance(policy, dict) else {}

    apply_all_safe = bool(policy.get("apply_all_safe_transforms_when_allowed", False))
    respect_full = bool(policy.get("respect_full_llm_plan", False))
    force_full_safe_plan = bool(policy.get("force_full_safe_plan", False))

    if os.getenv("OBLIVION_VISUAL_POTENCY", "1").lower() not in {"0", "false", "no"}:
        apply_all_safe = True
        respect_full = True
        force_full_safe_plan = True

        policy["apply_all_safe_transforms_when_allowed"] = True
        policy["respect_full_llm_plan"] = True
        policy["force_full_safe_plan"] = True

        validator_policy["apply_all_safe_transforms_when_allowed"] = True
        validator_policy["respect_full_llm_plan"] = True
        validator_policy["force_full_safe_plan"] = True

    print(
        f"[OPT-DEBUG] apply_all_safe= {apply_all_safe} "
        f"respect_full= {respect_full} "
        f"force_full_safe_plan= {force_full_safe_plan}"
    )

    if bool(validator_policy.get("experiment_mode", True)):
        validator_policy["strict_gas_budget_pct"] = validator_policy.get("gas_budget_pct", 25)
        validator_policy["gas_budget_pct"] = max(
            float(validator_policy.get("gas_budget_pct", 25) or 25),
            35.0,
        )

    validator_policy.update({
        "search_max_subset_size": search_max_subset_size,
        "search_enable_param_mutation": search_enable_param_mutation,
        "search_max_candidates": search_max_candidates,
    })

    candidate_plan_objects: list[dict] = []

    if optimizer_available:
        if "transforms" not in base_plan_obj or not isinstance(base_plan_obj.get("transforms"), list):
            print("[OBLIVION] WARNING: optimizer enabled but base plan has no usable 'transforms'. Falling back to single plan.")
            candidate_plan_objects = [base_plan_obj]
        else:
            candidate_plan_objects = generate_candidate_plans(
                base_plan=base_plan_obj,
                max_subset_size=search_max_subset_size,
                max_tier=None,
                enable_param_mutation=search_enable_param_mutation,
                min_subset_size=int(
                    policy.get("search_min_subset_size", policy.get("optimizer_min_subset_size", 1))
                ),
                include_full_plan_first=True,
                max_candidates=search_max_candidates,
            ) or [base_plan_obj]
    else:
        candidate_plan_objects = [base_plan_obj]

    # Rehydrate per-function semantic/security metadata that optimizer-emitted
    # candidate subsets may have dropped.
    candidate_plan_objects = [
        _rehydrate_candidate_plan_metadata(base_plan_obj, cp if isinstance(cp, dict) else {})
        for cp in (candidate_plan_objects or [])
        if isinstance(cp, dict)
    ] or [base_plan_obj]

    # Normalize transforms again after rehydration so downstream engine/validator
    # see consistent top-level transform lists.
    candidate_plan_objects = [
        _ensure_plan_has_transforms(cp)
        for cp in candidate_plan_objects
        if isinstance(cp, dict)
    ] or [base_plan_obj]

    # ------------------------------------------------------------
    # If optimizer emitted the locked full-safe plan, use ONLY that.
    # This is the end-to-end enforcement point for:
    # "all non-risky transforms must be applied".
    # ------------------------------------------------------------
    locked_only = [
        p for p in (candidate_plan_objects or [])
        if isinstance(p, dict) and str(p.get("id", "")).strip() == "full_plan_locked"
    ]
    if locked_only:
        candidate_plan_objects = locked_only
        print(
            "[OPT-DEBUG] using_locked_full_plan_only ids=",
            [str(p.get("id", "")) for p in candidate_plan_objects]
        )

    locked_mode_active = any(
        isinstance(cp, dict) and str(cp.get("id", "")).strip() == "full_plan_locked"
        for cp in (candidate_plan_objects or [])
    )

    if not locked_mode_active:
        candidate_plan_objects = _sort_candidate_plans_by_semantic_cost(candidate_plan_objects)

    for rank, cp in enumerate(candidate_plan_objects):
        if not isinstance(cp, dict):
            continue
        cp.setdefault("optimizer_meta", {})
        cp["optimizer_meta"]["semantic_cost"] = _candidate_semantic_cost(cp)
        cp["optimizer_meta"]["semantic_rank"] = rank

    def _make_ultra_safe_candidate(base_plan: dict) -> dict:
        keep = {
            "rename_identifiers_v2_scoped",
            "rename_identifiers_sha1_v1",
            "layout_scramble_v1",
            "constant_encoding_v1",
            "opaque_predicate_v1",
        }

        downgrade = {
            "constant_encoding_v2_layered": "constant_encoding_v1",
            "opaque_predicate_v2_entangled": "opaque_predicate_v1",
        }

        out = json.loads(json.dumps(base_plan))
        out["id"] = "ultra_safe_semantic_fallback"
        out["candidate_id"] = "ultra_safe_semantic_fallback"

        # CRITICAL: remove old aggressive top-level transforms.
        out["transforms"] = []

        for fp in out.get("plans", []) or []:
            if not isinstance(fp, dict):
                continue

            fn = str(fp.get("function") or "").strip()
            selected = fp.get("selected_transforms") or []
            fixed = []

            for tr in selected:
                if not isinstance(tr, dict):
                    continue

                old_tid = str(tr.get("id") or tr.get("transform_id") or "").strip()
                tid = downgrade.get(old_tid, old_tid)

                if tid not in keep:
                    continue

                tr2 = dict(tr)
                tr2["id"] = tid
                tr2["transform_id"] = tid

                target = tr2.get("target") if isinstance(tr2.get("target"), dict) else {}
                if fn:
                    target["function"] = fn
                tr2["target"] = target

                fixed.append(tr2)
                out["transforms"].append({
                    "id": tid,
                    "target": target,
                    "params": tr2.get("params") if isinstance(tr2.get("params"), dict) else {},
                })

            fp["selected_transforms"] = fixed

        out["optimizer_meta"] = {
            "ultra_safe_semantic_fallback": True,
            "allowed_ids": sorted(keep),
        }

        return out

    if candidate_plan_objects:
        candidate_plan_objects.append(
            _make_ultra_safe_candidate(base_plan_obj)
        )

    required_keep = policy.get(
        "optimizer_keep_transform_ids",
        [
            "layout_scramble_v1",
            "rename_identifiers_v2_scoped",
            "string_split_v1",
            "stack_variable_aliasing_v1",
            "opaque_predicate_v1",
        ],
    )

    all_candidate_plan_objects = list(candidate_plan_objects)

    # Preferred candidates should be more conservative than the full pool.
    preferred_candidate_plan_objects: List[Dict[str, Any]] = []

    if locked_mode_active:
        preferred_candidate_plan_objects = list(candidate_plan_objects)
    else:
        semantic_cost_threshold = float(
            policy.get("preferred_candidate_semantic_cost_threshold", 3.25)
        )

        for cp in candidate_plan_objects:
            if not isinstance(cp, dict):
                continue

            score = _candidate_semantic_cost(cp)
            if score > semantic_cost_threshold:
                continue

            preferred_candidate_plan_objects.append(cp)

        if isinstance(required_keep, list) and required_keep and preferred_candidate_plan_objects:
            preferred_candidate_plan_objects = _filter_candidates_keep_required(
                base_plan_obj, preferred_candidate_plan_objects, required_keep
            )

        if not preferred_candidate_plan_objects:
            preferred_candidate_plan_objects = candidate_plan_objects[: min(3, len(candidate_plan_objects))]

    # ------------------------------
    # Step 7/8 Loop: transform -> validate -> score
    # ------------------------------
    validator_out_root = out_dir / "validator"
    validator_out_root.mkdir(parents=True, exist_ok=True)

    best = None
    any_valid = False
    all_candidate_dirs: list[Path] = []

    repair_trace_path = out_dir / "repair_trace.json"
    repair_trace = {
        "kind": "repair_trace",
        "version": "v1_observability_only",
        "contract": contract_name,
        "run_dir": str(out_dir),
        "bounded": True,
        "repair_capability_present": True,
        "actual_plan_repair_applied": False,
        "repair_needed": False,
        "note": (
            "This artifact makes retry/repair rounds observable in runner outputs. "
            "It does not claim that a full centralized repair manager is active."
        ),
        "rounds": [],
        "summary": {
            "accepted": False,
            "accepted_round": None,
            "accepted_candidate_tag": None,
            "accepted_plan_path": None,
            "accepted_on_initial_round": None,
            "repair_needed": False,
            "repair_attempted": False,
            "actual_plan_repair_applied": False,
            "total_rounds": 0,
        },
    }
    repair_round_index = 0

    min_applied_transforms = int(policy.get("min_applied_transforms", 1))
    min_applied_functions = int(policy.get("min_applied_functions", 1))

    SEMANTIC_FAILURE_DOWNGRADE_MAP = {
        "constant_encoding_v2_layered": "constant_encoding_v1",
        "boolean_split_v2_distributed": "boolean_split_v1",
        "opaque_predicate_v2_entangled": "opaque_predicate_v1",
        "cfg_flatten_v2_hybrid": "cfg_flatten_v1",
    }

    SEMANTIC_FAILURE_REMOVE_IDS = {
        "cfg_flatten_v1",
        "dynamic_constants_v1",
        "stack_variable_aliasing_v1",
        "local_to_state_lift_v1",
        "scalar_to_struct_indirection_v1",
        "storage_indirection_v1",
        "opaque_storage_slot_indirection_v1",
        "dispatcher_cfg_virtualization_v1",
        "yul_microblock_v1",
    }

    def _tid_local(tr: dict) -> str:
        if not isinstance(tr, dict):
            return ""
        return str(tr.get("id") or tr.get("transform_id") or tr.get("type") or "").strip()

    def _semantic_safe_repair_plan(plan_obj: dict, failed_tag: str = "") -> dict:
        """
        Build a safer repaired plan after semantic_contract_failed.

        It preserves risk-aware safe transforms, downgrades aggressive v2 transforms,
        and removes transforms that commonly break semantic equivalence.
        """
        if not isinstance(plan_obj, dict):
            return plan_obj

        repaired = json.loads(json.dumps(plan_obj))

        repaired["id"] = f"semantic_safe_repair_{failed_tag or repaired.get('id', 'candidate')}"
        repaired["candidate_id"] = repaired["id"]

        meta = repaired.setdefault("optimizer_meta", {})
        meta["semantic_repaired"] = True
        meta["semantic_repair_source"] = failed_tag
        meta["semantic_repair_policy"] = {
            "downgraded": SEMANTIC_FAILURE_DOWNGRADE_MAP,
            "removed": sorted(SEMANTIC_FAILURE_REMOVE_IDS),
        }

        def repair_transform_list(items: list) -> list:
            out = []
            seen = set()

            SEMANTIC_REPAIR_ALLOWLIST = {
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
                "layout_scramble_v1",
                "constant_encoding_v1",
                "opaque_predicate_v1",
            }

            for tr in items or []:
                if not isinstance(tr, dict):
                    continue

                old_tid = _tid_local(tr)
                if not old_tid:
                    continue

                if old_tid in SEMANTIC_FAILURE_REMOVE_IDS:
                    continue

                new_tid = SEMANTIC_FAILURE_DOWNGRADE_MAP.get(old_tid, old_tid)

                if new_tid not in SEMANTIC_REPAIR_ALLOWLIST:
                    continue

                fixed = dict(tr)
                fixed["id"] = new_tid
                fixed["transform_id"] = new_tid
                fixed.pop("type", None)

                key = (
                    new_tid,
                    json.dumps(fixed.get("target", {}), sort_keys=True, default=str),
                )
                if key in seen:
                    continue
                seen.add(key)

                out.append(fixed)

            return out

        if isinstance(repaired.get("transforms"), list):
            repaired["transforms"] = repair_transform_list(repaired.get("transforms") or [])

        for fp in repaired.get("plans", []) or []:
            if not isinstance(fp, dict):
                continue

            selected = fp.get("selected_transforms")
            if isinstance(selected, list):
                fp["selected_transforms"] = repair_transform_list(selected)

        return repaired

    def _force_ultra_safe_candidate(plan_obj: dict) -> dict:
        if not isinstance(plan_obj, dict):
            return plan_obj

        meta = plan_obj.get("optimizer_meta")
        is_ultra = (
            isinstance(meta, dict)
            and bool(meta.get("ultra_safe_semantic_fallback"))
        ) or str(plan_obj.get("candidate_id") or plan_obj.get("id") or "") == "ultra_safe_semantic_fallback"

        if not is_ultra:
            return plan_obj

        keep = {
            "rename_identifiers_v2_scoped",
            "rename_identifiers_sha1_v1",
            "layout_scramble_v1",
            "constant_encoding_v1",
            "opaque_predicate_v1",
        }

        downgrade = {
            "constant_encoding_v2_layered": "constant_encoding_v1",
            "opaque_predicate_v2_entangled": "opaque_predicate_v1",
        }

        rebuilt_top = []

        for fp in plan_obj.get("plans", []) or []:
            if not isinstance(fp, dict):
                continue

            fn = str(fp.get("function") or "").strip()
            fixed = []

            for tr in fp.get("selected_transforms", []) or []:
                if not isinstance(tr, dict):
                    continue

                old_tid = str(tr.get("id") or tr.get("transform_id") or "").strip()
                tid = downgrade.get(old_tid, old_tid)

                if tid not in keep:
                    continue

                tr2 = dict(tr)
                tr2["id"] = tid
                tr2["transform_id"] = tid
                tr2["params"] = {}
                tr2["params"]["disable_safe_refill"] = True

                target = tr2.get("target") if isinstance(tr2.get("target"), dict) else {}
                if fn:
                    target["function"] = fn
                tr2["target"] = target

                fixed.append(tr2)
                rebuilt_top.append({
                    "id": tid,
                    "target": target,
                    "params": tr2.get("params") if isinstance(tr2.get("params"), dict) else {},
                })

            fp["selected_transforms"] = fixed

            kept_ids = {t["id"] for t in fixed if isinstance(t, dict) and t.get("id")}

            llm_meta = fp.setdefault("llm_meta", {})
            if isinstance(llm_meta, dict):
                sc = llm_meta.setdefault("semantic_contract", {})
                if isinstance(sc, dict):
                    existing = {
                        row.get("transform_id")
                        for row in sc.get("transform_safety", [])
                        if isinstance(row, dict)
                    }

                    rows = [
                        row for row in sc.get("transform_safety", [])
                        if isinstance(row, dict) and row.get("transform_id") in kept_ids
                    ]

                    for tid in sorted(kept_ids):
                        if tid not in existing:
                            rows.append({
                                "transform_id": tid,
                                "risk": "low",
                                "avoid_regions": [],
                                "allowed_on_tier0": True,
                            })

                    sc["transform_safety"] = rows

                cg = llm_meta.setdefault("composition_graph", {})
                if isinstance(cg, dict):
                    cg["ordering_constraints"] = []
                    cg["unsafe_pairs"] = []
                    cg["safe_pairs"] = []

        plan_obj["transforms"] = rebuilt_top
        plan_obj.setdefault("optimizer_meta", {})
        plan_obj["optimizer_meta"]["ultra_safe_final_sanitized"] = True

        return plan_obj

    def _run_candidates(candidate_list: list[dict], pass_tag: str):
        nonlocal best, any_valid, repair_round_index

        for idx, cand_plan_obj in enumerate(candidate_list):
            cand_plan_obj = _rehydrate_candidate_plan_metadata(
                base_plan_obj,
                cand_plan_obj if isinstance(cand_plan_obj, dict) else {},
            )
            cand_plan_obj = _ensure_plan_has_transforms(cand_plan_obj)

            # Re-apply once more after normalization so the final in-memory object
            # still carries the base planner's semantic/security metadata.
            cand_plan_obj = _rehydrate_candidate_plan_metadata(base_plan_obj, cand_plan_obj)

            # Build a short, filesystem-safe candidate tag.
            fallback_tag = f"{pass_tag}_cand_{idx:02d}"
            run_tag = _safe_candidate_dir_name(
                cand_plan_obj,
                fallback_prefix=fallback_tag,
            )

            # Persist a stable short id back into the candidate object so
            # downstream artifacts/logs do not accidentally stringify the whole object.
            if isinstance(cand_plan_obj, dict):
                cand_plan_obj = dict(cand_plan_obj)
                cand_plan_obj.setdefault("candidate_id", run_tag)

            cand_dir = out_dir / "optimizer_runs" / run_tag
            cand_dir.mkdir(parents=True, exist_ok=True)
            all_candidate_dirs.append(cand_dir)

            cand_plan_obj = _rehydrate_candidate_plan_metadata(base_plan_obj, cand_plan_obj)

            if isinstance(cand_plan_obj, dict) and isinstance(cand_plan_obj.get("plans"), list):
                safe_expand_seed = (
                    int(policy.get("safe_expand_seed", policy.get("seed", 1337)))
                    if isinstance(policy, dict)
                    else 1337
                )
                cand_plan_obj["plans"] = expand_safe_plans(
                    cand_plan_obj["plans"],
                    allowed_ids_set=allowed_ids_set,
                    seed=safe_expand_seed,
                    policy=policy if isinstance(policy, dict) else {},
                )

            cand_plan_obj = _ensure_plan_has_transforms(cand_plan_obj)
            cand_plan_obj = _force_ultra_safe_candidate(cand_plan_obj)

            if isinstance(cand_plan_obj, dict) and isinstance(cand_plan_obj.get("plans"), list):
                safe_expand_seed = (
                    int(policy.get("safe_expand_seed", policy.get("seed", 1337)))
                    if isinstance(policy, dict)
                    else 1337
                )
                cand_plan_obj["plans"] = expand_safe_plans(
                    cand_plan_obj["plans"],
                    allowed_ids_set=allowed_ids_set,
                    seed=safe_expand_seed,
                    policy=policy if isinstance(policy, dict) else {},
                )
                cand_plan_obj = _ensure_plan_has_transforms(cand_plan_obj)

            # 🔴 DEBUG PRINT (INSERT HERE)
            for fp in cand_plan_obj.get("plans", []):
                print(
                    "[DEBUG BEFORE WRITE]",
                    fp.get("function"),
                    "sec_entry_keys=",
                    list((fp.get("sec_entry") or {}).keys()),
                    "policy_trace_keys=",
                    list((fp.get("policy_trace") or {}).keys()) if isinstance(fp.get("policy_trace"), dict) else [],
                )

            metadata_problems = _candidate_plan_metadata_missing(base_plan_obj, cand_plan_obj)
            if metadata_problems:
                raise RuntimeError(
                    "Candidate plan metadata still missing before write: "
                    + ", ".join(metadata_problems)
                )

            cand_plan_path = cand_dir / "variants_plan.json"
            write_ok = _write_json(cand_plan_path, cand_plan_obj)
            if not write_ok:
                raise RuntimeError(f"Failed to write candidate plan to {cand_plan_path}")

            # Read back from disk and verify the persisted file still has the metadata.
            persisted_plan_obj = _read_json_if_exists(cand_plan_path)
            if not isinstance(persisted_plan_obj, dict):
                raise RuntimeError(f"Failed to read back candidate plan from {cand_plan_path}")

            persisted_plan_obj = _rehydrate_candidate_plan_metadata(base_plan_obj, persisted_plan_obj)
            persisted_problems = _candidate_plan_metadata_missing(base_plan_obj, persisted_plan_obj)
            if persisted_problems:
                raise RuntimeError(
                    "Persisted candidate plan metadata still missing after write: "
                    + ", ".join(persisted_problems)
                )

            # Re-write once more with the verified persisted object so downstream stages
            # definitely consume the rehydrated version from disk.
            write_ok = _write_json(cand_plan_path, persisted_plan_obj)
            if not write_ok:
                raise RuntimeError(f"Failed to rewrite verified candidate plan to {cand_plan_path}")

            current_round = repair_round_index
            repair_round_index += 1

            round_entry = {
                "round": current_round,
                "pass_tag": pass_tag,
                "candidate_tag": run_tag,
                "plan_path": str(cand_plan_path),
                "status": "started",
                "repair_attempted": current_round > 0,
                "actual_plan_repair_applied": False,
                "failure_reason": None,
                "reject_reasons": [],
                "validator_report_path": None,
                "validator_summary": None,
            }
            repair_trace["rounds"].append(round_entry)

            print(
                f"[REPAIR] round={current_round} "
                f"candidate={run_tag} "
                f"status=started"
            )

            obf_out_dir = cand_dir / "obfuscation_engine"
            obf_out_dir.mkdir(parents=True, exist_ok=True)

            try:
                engine_res = apply_variants_plan(
                    source_path=source_snapshot,
                    plan_path=cand_plan_path,
                    out_dir=obf_out_dir,
                    sec_by_function=sec_by_function,
                )
            except Exception as e:
                repair_trace["repair_needed"] = True
                repair_trace["summary"]["repair_needed"] = True
                repair_trace["summary"]["repair_attempted"] = True

                round_entry["status"] = "rejected"
                round_entry["failure_reason"] = "transform_failed"
                round_entry["validator_summary"] = f"transform_failed: {e}"

                print(
                    f"[REPAIR] round={current_round} "
                    f"candidate={run_tag} "
                    f"status=rejected "
                    f"failure_reason=transform_failed"
                )
                print(f"[OBLIVION] Candidate {run_tag} transform failed: {e}")
                continue

            obfuscated_sol = Path(engine_res["obfuscated_sol"])
            transform_map = Path(engine_res["transform_map"])

            _obl_safe_visual_postpass(obfuscated_sol, transform_map)

            transform_quality = _read_transform_map_quality(transform_map)

            min_distinct_ids = int(policy.get("min_distinct_transform_ids", 1))

            applied_cnt, applied_fn_cnt, distinct_id_cnt = _read_transform_map_stats(transform_map)
            quality = _read_transform_map_quality(transform_map)

            print(
                f"[TRANSFORM-QUALITY] candidate={run_tag} "
                f"selected={quality.get('selected')} "
                f"applied={quality.get('applied')} "
                f"selected_noop={quality.get('selected_noop')} "
                f"distinct_ids={quality.get('distinct_ids')} "
                f"distinct_families={quality.get('distinct_families')} "
                f"has_noncosmetic={quality.get('has_noncosmetic')} "
                f"cosmetic_only={quality.get('cosmetic_only')} "
                f"selected_has_noncosmetic={quality.get('selected_has_noncosmetic')} "
                f"selected_cosmetic_only={quality.get('selected_cosmetic_only')}"
            )
            quality = _read_transform_map_quality(transform_map)

            selected_cnt = int(quality.get("selected") or 0)
            selected_noop_cnt = int(quality.get("selected_noop") or 0)
            applied_quality_cnt = int(quality.get("applied") or 0)

            if selected_cnt > 0 and applied_quality_cnt == 0:
                repair_trace["repair_needed"] = True
                repair_trace["summary"]["repair_needed"] = True
                repair_trace["summary"]["repair_attempted"] = True

                round_entry["status"] = "rejected"
                round_entry["failure_reason"] = "all_selected_transforms_noop"
                round_entry["validator_summary"] = (
                    f"selected={selected_cnt}, applied={applied_quality_cnt}, selected_noop={selected_noop_cnt}"
                )

                print(
                    f"[REPAIR] round={current_round} "
                    f"candidate={run_tag} "
                    f"status=rejected "
                    f"failure_reason=all_selected_transforms_noop"
                )
                continue

            max_noop_ratio = float(policy.get("max_selected_noop_ratio", 0.75))
            noop_ratio = (selected_noop_cnt / selected_cnt) if selected_cnt > 0 else 0.0

            if selected_cnt >= 3 and noop_ratio > max_noop_ratio:
                repair_trace["repair_needed"] = True
                repair_trace["summary"]["repair_needed"] = True
                repair_trace["summary"]["repair_attempted"] = True

                round_entry["status"] = "rejected"
                round_entry["failure_reason"] = "too_many_noop_transforms"
                round_entry["validator_summary"] = (
                    f"selected={selected_cnt}, applied={applied_quality_cnt}, "
                    f"selected_noop={selected_noop_cnt}, noop_ratio={noop_ratio:.3f}"
                )

                print(
                    f"[REPAIR] round={current_round} "
                    f"candidate={run_tag} "
                    f"status=rejected "
                    f"failure_reason=too_many_noop_transforms "
                    f"noop_ratio={noop_ratio:.3f}"
                )
                continue

            if (
                applied_cnt < min_applied_transforms
                or applied_fn_cnt < min_applied_functions
                or distinct_id_cnt < min_distinct_ids
            ):
                repair_trace["repair_needed"] = True
                repair_trace["summary"]["repair_needed"] = True
                repair_trace["summary"]["repair_attempted"] = True

                round_entry["status"] = "rejected"
                round_entry["failure_reason"] = "too_little_obfuscation"
                round_entry["validator_summary"] = (
                    f"applied={applied_cnt}, functions={applied_fn_cnt}, distinct_ids={distinct_id_cnt}"
                )

                print(
                    f"[REPAIR] round={current_round} "
                    f"candidate={run_tag} "
                    f"status=rejected "
                    f"failure_reason=too_little_obfuscation"
                )
                print(
                    f"[OBLIVION] Candidate {run_tag} rejected early: too little obfuscation "
                    f"(applied={applied_cnt} < {min_applied_transforms} OR "
                    f"functions={applied_fn_cnt} < {min_applied_functions} OR "
                    f"distinct_ids={distinct_id_cnt} < {min_distinct_ids})"
                )
                continue

            if bool(policy.get("optimizer_require_noncosmetic_transform", True)):
                min_noncosmetic = int(policy.get("optimizer_min_noncosmetic_transforms", 1))

                selected_has_noncosmetic = bool(quality.get("selected_has_noncosmetic"))
                selected_cosmetic_only = bool(quality.get("selected_cosmetic_only"))

                # Early rejection must use the selected plan, not applied transforms,
                # because validation has not run yet.
                if min_noncosmetic > 0 and selected_cosmetic_only and not selected_has_noncosmetic:
                    repair_trace["repair_needed"] = True
                    repair_trace["summary"]["repair_needed"] = True
                    repair_trace["summary"]["repair_attempted"] = True

                    round_entry["status"] = "rejected"
                    round_entry["failure_reason"] = "cosmetic_only_obfuscation"
                    round_entry["validator_summary"] = (
                        f"selected={quality.get('selected')} "
                        f"applied={quality.get('applied')} "
                        f"distinct_ids={quality.get('distinct_ids')} "
                        f"distinct_families={quality.get('distinct_families')} "
                        f"selected_noop={quality.get('selected_noop')} "
                        f"selected_has_noncosmetic={quality.get('selected_has_noncosmetic')} "
                        f"selected_cosmetic_only={quality.get('selected_cosmetic_only')}"
                    )

                    print(
                        f"[REPAIR] round={current_round} "
                        f"candidate={run_tag} "
                        f"status=rejected "
                        f"failure_reason=cosmetic_only_obfuscation"
                    )
                    print(
                        f"[OBLIVION] Candidate {run_tag} rejected early: cosmetic-only obfuscation "
                        f"(selected={quality.get('selected')}, "
                        f"applied={quality.get('applied')}, "
                        f"distinct_ids={quality.get('distinct_ids')}, "
                        f"distinct_families={quality.get('distinct_families')}, "
                        f"selected_noop={quality.get('selected_noop')}, "
                        f"selected_has_noncosmetic={quality.get('selected_has_noncosmetic')}, "
                        f"selected_cosmetic_only={quality.get('selected_cosmetic_only')})"
                    )
                    continue

            validator_out = cand_dir / "validator"
            validator_out.mkdir(parents=True, exist_ok=True)

            tests_to_run = _extract_tests_to_run(cand_plan_obj) or base_tests_to_run

            # 🔴 CRITICAL FIX: ensure validator sees fully rehydrated metadata
            cand_plan_obj = _rehydrate_candidate_plan_metadata(base_plan_obj, cand_plan_obj)

            validation_metadata_problems = _candidate_plan_metadata_missing(base_plan_obj, cand_plan_obj)
            if validation_metadata_problems:
                raise RuntimeError(
                    "Candidate plan metadata still missing before validation: "
                    + ", ".join(validation_metadata_problems)
                )

            # 🔴 ALSO ensure the on-disk plan is correct (validator may read from disk indirectly)
            cand_plan_path = cand_dir / "variants_plan.json"
            persisted_plan_obj = _read_json_if_exists(cand_plan_path)

            if isinstance(persisted_plan_obj, dict):
                persisted_plan_obj = _rehydrate_candidate_plan_metadata(base_plan_obj, persisted_plan_obj)

                persisted_problems = _candidate_plan_metadata_missing(base_plan_obj, persisted_plan_obj)
                if persisted_problems:
                    raise RuntimeError(
                        "Persisted candidate plan metadata still missing before validation: "
                        + ", ".join(persisted_problems)
                    )

                # rewrite to guarantee validator sees correct version
                _write_json(cand_plan_path, persisted_plan_obj)

                # sync memory with disk (important)
                cand_plan_obj = persisted_plan_obj

            try:
                vres = validate_candidate(
                    original_src=source_snapshot,
                    obfuscated_src=obfuscated_sol,
                    foundry_root=FOUNDRY_ROOT,
                    target_relpath=contract_import_path,
                    tests_to_run=tests_to_run,
                    baseline_coverage_json=out_dir / "coverage.lcov",
                    baseline_sec_advice_json=sec_advice_path if sec_advice_path else None,
                    contract_name=contract_name,
                    source_relpath=contract_import_path,
                    candidate_plan=cand_plan_obj,
                    policy=validator_policy,
                    out_dir=validator_out,
                    force_full_suite=True,
                )
            except Exception as e:
                repair_trace["repair_needed"] = True
                repair_trace["summary"]["repair_needed"] = True
                repair_trace["summary"]["repair_attempted"] = True

                round_entry["status"] = "rejected"
                round_entry["failure_reason"] = "validator_crashed"
                round_entry["validator_summary"] = f"validator_crashed: {e}"

                print(
                    f"[REPAIR] round={current_round} "
                    f"candidate={run_tag} "
                    f"status=rejected "
                    f"failure_reason=validator_crashed"
                )
                print(f"[OBLIVION] Candidate {run_tag} validator crashed: {e}")
                continue

            if not vres.accepted:
                repair_trace["repair_needed"] = True
                repair_trace["summary"]["repair_needed"] = True
                repair_trace["summary"]["repair_attempted"] = True

                failure_reason = (
                    _extract_failure_reason_from_validation_report(validator_out)
                    or "validator_rejected"
                )
                reject_reasons = _extract_reject_reasons_from_validation_report(validator_out)
                why = _summarize_validation_failure(vres, validator_out)

                round_entry["status"] = "rejected"
                round_entry["failure_reason"] = failure_reason
                round_entry["reject_reasons"] = reject_reasons
                round_entry["validator_report_path"] = str(validator_out / "validation_report.json")
                round_entry["validator_summary"] = why

                print(
                    f"[REPAIR] round={current_round} "
                    f"candidate={run_tag} "
                    f"status=rejected "
                    f"failure_reason={failure_reason}"
                )
                print(f"[OBLIVION] Candidate {run_tag} rejected. {why}")

                # ------------------------------------------------------------
                # NEW: semantic-contract repair
                # If a potent candidate compiles/tests but violates semantic contract,
                # immediately enqueue a safer downgraded version.
                # ------------------------------------------------------------
                if failure_reason == "semantic_contract_failed":
                    opt_meta = cand_plan_obj.get("optimizer_meta") if isinstance(cand_plan_obj.get("optimizer_meta"), dict) else {}

                    if not bool(opt_meta.get("semantic_repaired")):
                        repaired_plan = _semantic_safe_repair_plan(
                            cand_plan_obj,
                            failed_tag=run_tag,
                        )

                        repaired_transforms = repaired_plan.get("transforms") if isinstance(repaired_plan, dict) else []
                        if isinstance(repaired_transforms, list) and repaired_transforms:
                            candidate_list.append(repaired_plan)

                            round_entry["actual_plan_repair_applied"] = True
                            repair_trace["actual_plan_repair_applied"] = True
                            repair_trace["summary"]["actual_plan_repair_applied"] = True

                            print(
                                f"[REPAIR] round={current_round} "
                                f"candidate={run_tag} "
                                f"semantic_safe_repair_enqueued={repaired_plan.get('candidate_id')}"
                            )

                continue

            score_report = {
                "ok": False,
                "skipped": True,
                "reason": "score_not_run",
                "score": 0.0,
            }
            try:
                score_report = _try_score_candidate(
                    foundry_root=FOUNDRY_ROOT,
                    contract_name=contract_name,
                    contract_import_path=contract_import_path,
                    harness_contract=harness_contract,
                    original_sol=source_snapshot,
                    obfuscated_sol=obfuscated_sol,
                    out_dir=cand_dir,
                    validator_dir=validator_out,
                    baseline_sec_advice_json=sec_advice_path if sec_advice_path else None,
                    transform_map_json=transform_map,
                )
            except Exception as e:
                print(f"[OBLIVION] Candidate {run_tag} scorer failed: {e}")

            round_entry["status"] = "accepted"
            round_entry["validator_report_path"] = str(validator_out / "validation_report.json")
            round_entry["validator_summary"] = "accepted"

            print(
                f"[REPAIR] round={current_round} "
                f"candidate={run_tag} "
                f"status=accepted"
            )

            any_valid = True

            score_value = 0.0
            if isinstance(score_report, dict) and score_report.get("ok") and not score_report.get("skipped"):
                if "objective_score" in score_report and isinstance(score_report["objective_score"], (int, float)):
                    score_value = float(score_report["objective_score"])
                elif "score" in score_report and isinstance(score_report["score"], (int, float)):
                    score_value = float(score_report["score"])
                elif "total" in score_report and isinstance(score_report["total"], (int, float)):
                    score_value = float(score_report["total"])

            effective_score = score_value

            if bool(policy.get("optimizer_penalize_noop_selected", True)):
                noop_penalty = float(policy.get("optimizer_noop_penalty", 0.08))
                effective_score -= noop_penalty * float(transform_quality.get("selected_noop", 0))

            if bool(policy.get("optimizer_penalize_cosmetic_only", True)):
                if bool(transform_quality.get("selected_cosmetic_only", False)):
                    effective_score -= float(policy.get("optimizer_cosmetic_only_penalty", 0.12))

            if bool(policy.get("optimizer_require_noncosmetic_transform", True)):
                min_noncosmetic = int(policy.get("optimizer_min_noncosmetic_transforms", 1))
                selected_has_noncosmetic = bool(transform_quality.get("selected_has_noncosmetic", False))
                selected_cosmetic_only = bool(transform_quality.get("selected_cosmetic_only", False))

                # Scoring-time gate must use the selected plan view, not applied-only view,
                # because many candidates have not yet materialized applied transforms here.
                if min_noncosmetic > 0 and selected_cosmetic_only and not selected_has_noncosmetic:
                    effective_score -= 0.20

            if bool(policy.get("optimizer_reward_distinct_families", True)):
                fam_bonus = float(policy.get("optimizer_family_diversity_bonus", 0.06))
                effective_score += fam_bonus * max(0, int(transform_quality.get("distinct_families", 0)) - 1)

            if bool(policy.get("optimizer_reward_control_or_data_transform", True)):
                applied_obj = json.loads(transform_map.read_text(encoding="utf-8"))
                applied_rows = applied_obj.get("applied") or []
                selected_rows = applied_obj.get("selected") or []
                catalog = default_transform_catalog()

                has_control_or_data = False

                # Prefer applied rows when present.
                for row in applied_rows:
                    if not isinstance(row, dict):
                        continue
                    tid = row.get("id") or row.get("transform_id")
                    if not isinstance(tid, str):
                        continue
                    spec = catalog.get(tid)
                    if spec and spec.family in {"control", "data"}:
                        has_control_or_data = True
                        break

                # Fallback to selected rows if applied rows are still empty at this stage.
                if not has_control_or_data:
                    for row in selected_rows:
                        if not isinstance(row, dict):
                            continue
                        tid = row.get("id") or row.get("transform_id")
                        if not isinstance(tid, str):
                            continue
                        spec = catalog.get(tid)
                        if spec and spec.family in {"control", "data"}:
                            has_control_or_data = True
                            break

                if has_control_or_data:
                    effective_score += float(policy.get("optimizer_control_data_bonus", 0.08))

            if best is None or effective_score > best["score_value"]:
                best = {
                    "raw_score_value": score_value,
                    "score_value": effective_score,
                    "transform_quality": transform_quality,
                    "objective_score": float(score_report.get("objective_score", score_value)) if isinstance(score_report, dict) else score_value,
                    "potency_score": float(score_report.get("potency_score", 0.0)) if isinstance(score_report, dict) else 0.0,
                    "overhead_score": float(score_report.get("overhead_score", 0.0)) if isinstance(score_report, dict) else 0.0,
                    "risk_score": float(score_report.get("risk_score", 0.0)) if isinstance(score_report, dict) else 0.0,
                    "plan_obj": cand_plan_obj,
                    "plan_path": cand_plan_path,
                    "obfuscated_sol": obfuscated_sol,
                    "transform_map": transform_map,
                    "validation_result": vres,
                    "score_report": score_report,
                    "run_dir": cand_dir,
                    "repair_round": current_round,
                    "run_tag": run_tag,
                }

    _run_candidates(preferred_candidate_plan_objects, pass_tag="pref")

    if not any_valid:
        print("[OBLIVION] No preferred candidate validated; falling back to full optimizer candidate set.")
        _run_candidates(all_candidate_plan_objects, pass_tag="all")

    if not any_valid or best is None:
        repair_trace["summary"] = {
            "accepted": False,
            "accepted_round": None,
            "accepted_candidate_tag": None,
            "accepted_plan_path": None,
            "accepted_on_initial_round": None,
            "repair_needed": bool(repair_trace.get("repair_needed", False)),
            "repair_attempted": bool(repair_trace.get("repair_needed", False)),
            "actual_plan_repair_applied": False,
            "total_rounds": len(repair_trace["rounds"]),
        }
        _write_json(repair_trace_path, repair_trace)

        print("[OBLIVION] ❌ No candidate passed validation")
        print(f"[OBLIVION] Base plan: {plan_path}")
        print(f"[OBLIVION] Repair trace: {repair_trace_path}")
        sys.exit(1)

    # ------------------------------
    # Finalize: copy best artifacts to canonical locations
    # ------------------------------
    final_obf_dir = out_dir / "obfuscation_engine"
    final_val_dir = out_dir / "validator"
    final_obf_dir.mkdir(parents=True, exist_ok=True)
    final_val_dir.mkdir(parents=True, exist_ok=True)

    plan_path.write_text(json.dumps(best["plan_obj"], indent=2), encoding="utf-8")

    copy2(best["obfuscated_sol"], final_obf_dir / "obfuscated.sol")
    copy2(best["transform_map"], final_obf_dir / "transform_map.json")

    best_val_dir = best["run_dir"] / "validator"
    if (best_val_dir / "validation_report.json").exists():
        copy2(best_val_dir / "validation_report.json", final_val_dir / "validation_report.json")
    if (best_val_dir / "diff_report.json").exists():
        copy2(best_val_dir / "diff_report.json", final_val_dir / "diff_report.json")
    if (best_val_dir / "gas_diff.json").exists():
        copy2(best_val_dir / "gas_diff.json", final_val_dir / "gas_diff.json")
    if (best["run_dir"] / "adversarial_proxy_score.json").exists():
        copy2(best["run_dir"] / "adversarial_proxy_score.json", out_dir / "adversarial_proxy_score.json")
    if (best["run_dir"] / "original_artifact.json").exists():
        copy2(best["run_dir"] / "original_artifact.json", out_dir / "original_artifact.json")
    if (best["run_dir"] / "candidate_artifact.json").exists():
        copy2(best["run_dir"] / "candidate_artifact.json", out_dir / "candidate_artifact.json")

    print("[OBLIVION] ✅ Candidate validated successfully")
    print(f"[OBLIVION] Best run dir:      {best['run_dir']}")
    print(f"[OBLIVION] Validation report: {final_val_dir / 'validation_report.json'}")
    print(f"[OBLIVION] Security diff:     {final_val_dir / 'diff_report.json'}")

    accepted_round = best.get("repair_round")
    accepted_on_initial_round = (accepted_round == 0)

    repair_trace["summary"] = {
        "accepted": True,
        "accepted_round": accepted_round,
        "accepted_candidate_tag": best.get("run_tag"),
        "accepted_plan_path": str(best["plan_path"]),
        "accepted_on_initial_round": accepted_on_initial_round,
        "repair_needed": bool(repair_trace.get("repair_needed", False)),
        "repair_attempted": bool(repair_trace.get("repair_needed", False)),
        "actual_plan_repair_applied": False,
        "total_rounds": len(repair_trace["rounds"]),
    }
    _write_json(repair_trace_path, repair_trace)
    print(f"[OBLIVION] Repair trace:      {repair_trace_path}")
    if repair_trace["summary"]["accepted_on_initial_round"]:
        print("[REPAIR] accepted_on_initial_round=True repair_needed=False")
    else:
        print(
            f"[REPAIR] accepted_on_initial_round=False "
            f"repair_needed={repair_trace['summary']['repair_needed']}"
        )

    validation_report_path = final_val_dir / "validation_report.json"

    try:
        vr_path = Path(validation_report_path)
        print(f"[OBLIVION] Debug: reading validator report from {vr_path}")

        raw = vr_path.read_text(encoding="utf-8")
        vr = json.loads(raw)

        fuzz = vr.get("fuzz", {}) or {}
        print(
            "[OBLIVION] Short fuzz: "
            f"ok={fuzz.get('ok')} "
            f"skipped={fuzz.get('skipped')} "
            f"reason={fuzz.get('reason')} "
            f"executed_count={fuzz.get('executed_count', 0)}"
        )
    except Exception as e:
        print(f"[OBLIVION] Short fuzz summary unavailable: {e}")

    optimizer_summary_path = out_dir / "optimizer_summary.json"
    try:
        optimizer_summary = {
            "search_strategy": "bounded_candidate_subset_search",
            "objective": "w1*potency_score - w2*overhead_score - w3*risk_score",
            "best_candidate": {
                "objective_score": best.get("objective_score", best["score_value"]),
                "potency_score": best.get("potency_score", 0.0),
                "overhead_score": best.get("overhead_score", 0.0),
                "risk_score": best.get("risk_score", 0.0),
                "run_dir": str(best["run_dir"]),
                "plan_path": str(best["plan_path"]),
            },
        }
        optimizer_summary_path.write_text(
            json.dumps(optimizer_summary, indent=2),
            encoding="utf-8",
        )
        print(f"[OBLIVION] Optimizer summary: {optimizer_summary_path}")
    except Exception as e:
        print(f"[OBLIVION] Failed to write optimizer summary: {e}")

    transform_coverage_summary_path = out_dir / "transform_coverage_summary.json"
    try:
        implemented_transform_ids = sorted(APPLIERS.keys())
        transform_coverage_summary = _aggregate_transform_coverage_for_run(
            candidate_dirs=all_candidate_dirs,
            implemented_transform_ids=implemented_transform_ids,
        )
        transform_coverage_summary_path.write_text(
            json.dumps(transform_coverage_summary, indent=2),
            encoding="utf-8",
        )
        print(f"[OBLIVION] Transform coverage summary: {transform_coverage_summary_path}")
    except Exception as e:
        print(f"[OBLIVION] Failed to write transform_coverage_summary.json: {e}")

    try:
        transform_policy_audit_path.write_text(
            json.dumps(
                {
                    "contract": contract_name,
                    "source_file": contract_import_path,
                    "entries": transform_policy_audit,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"[OBLIVION] Transform policy audit: {transform_policy_audit_path}")
    except Exception as e:
        print(f"[OBLIVION] Failed to write transform_policy_audit.json: {e}")

    exported_artifacts = {}

    exported_artifacts["coverage.json"] = (out_dir / "coverage.json").exists()
    exported_artifacts["sec_advice.json"] = (out_dir / "sec_advice.json").exists()

    exported_artifacts["obf_candidates.json"] = _copy_if_exists(
        out_dir / "obfuscation_advice.json",
        out_dir / "obf_candidates.json"
    )

    exported_artifacts["variants.json"] = _copy_if_exists(
        out_dir / "variants_plan.json",
        out_dir / "variants.json"
    )

    exported_artifacts["validation_report.json"] = _copy_if_exists(
        final_val_dir / "validation_report.json",
        out_dir / "validation_report.json"
    )

    exported_artifacts["diff_report.json"] = _copy_if_exists(
        final_val_dir / "diff_report.json",
        out_dir / "diff_report.json"
    )

    exported_artifacts["adversarial_score.json"] = _copy_if_exists(
        out_dir / "adversarial_proxy_score.json",
        out_dir / "adversarial_score.json"
    )

    exported_artifacts["repair_trace.json"] = repair_trace_path.exists()
    exported_artifacts["optimizer_summary.json"] = optimizer_summary_path.exists()
    exported_artifacts["transform_coverage_summary.json"] = transform_coverage_summary_path.exists()
    exported_artifacts["transform_policy_audit.json"] = transform_policy_audit_path.exists()

    print("[OBLIVION] Canonical artifact export:")
    for name, ok in exported_artifacts.items():
        print(f"  - {name}: {'ok' if ok else 'missing'}")

    final_report_path = out_dir / "final_report.json"
    try:
        final_report = {
            "contract": {
                "input_solidity_file": str(sol_path),
                "run_dir": str(out_dir),
            },
            "artifacts": {
                "coverage.json": str(out_dir / "coverage.json"),
                "sec_advice.json": str(out_dir / "sec_advice.json"),
                "obf_candidates.json": str(out_dir / "obf_candidates.json"),
                "variants.json": str(out_dir / "variants.json"),
                "validation_report.json": str(out_dir / "validation_report.json"),
                "diff_report.json": str(out_dir / "diff_report.json"),
                "adversarial_score.json": str(out_dir / "adversarial_score.json"),
                "repair_trace.json": str(out_dir / "repair_trace.json"),
                "optimizer_summary.json": str(out_dir / "optimizer_summary.json"),
                "transform_coverage_summary.json": str(out_dir / "transform_coverage_summary.json"),
                "transform_policy_audit.json": str(out_dir / "transform_policy_audit.json"),
            },
            "best_candidate": {
                "run_dir": str(best["run_dir"]),
                "plan_path": str(best["plan_path"]),
                "obfuscated_sol": str(best["obfuscated_sol"]),
                "transform_map": str(best["transform_map"]),
                "objective_score": best.get("objective_score", best["score_value"]),
                "potency_score": best.get("potency_score", 0.0),
                "overhead_score": best.get("overhead_score", 0.0),
                "risk_score": best.get("risk_score", 0.0),
                "repair_round": best.get("repair_round"),
                "candidate_tag": best.get("run_tag"),
            },
            "validation": {
                "validation_report": str(out_dir / "validation_report.json"),
                "diff_report": str(out_dir / "diff_report.json"),
            },
            "repair_loop": {
                "artifact": str(out_dir / "repair_trace.json"),
                "mode": "observability_only",
                "repair_capability_present": True,
                "actual_plan_repair_applied": False,
                "repair_needed": repair_trace.get("summary", {}).get("repair_needed"),
                "repair_attempted": repair_trace.get("summary", {}).get("repair_attempted"),
                "accepted_round": repair_trace.get("summary", {}).get("accepted_round"),
                "accepted_on_initial_round": repair_trace.get("summary", {}).get("accepted_on_initial_round"),
                "total_rounds": repair_trace.get("summary", {}).get("total_rounds"),
            },
            "status": {
                "validated": True,
                "canonical_artifacts_exported": exported_artifacts,
            },
        }


        final_report_path.write_text(
            json.dumps(final_report, indent=2),
            encoding="utf-8",
        )
        print(f"[OBLIVION] Final report: {final_report_path}")
    except Exception as e:
        print(f"[OBLIVION] Failed to write final_report.json: {e}")

    restored = _restore_source_file(source_snapshot, source_in_foundry)
    if restored:
        print(f"[OBLIVION] Restored canonical source file: {source_in_foundry}")

    print("\n[OBLIVION] Done.")
    print(f"  IR JSON:                 {ir_out}")
    print(f"  AST Dump:                {ast_dump}")
    print(f"  Harness:                 {harness_path}")
    print(f"  TestGen dir:             {testgen_out_dir}")
    print(f"  Coverage LCOV:           {cov_lcov}")
    print(f"  Coverage JSON:           {out_dir / 'coverage.json'}")
    print(f"  Test results JSON:       {out_dir / 'test_results.json'}")
    print(f"  Uncovered targets:       {out_dir / 'uncovered_targets.json'}")
    print(f"  Generated manifest:      {out_dir / 'generated_tests_manifest.json'}")
    print(f"  Obfuscation advice:      {advice_path}")
    print(f"  Security advice:         {sec_advice_path if sec_advice_path else 'DISABLED'}")
    print(f"  Variants plan:           {plan_path}")
    print(f"  Obfuscated sol:          {final_obf_dir / 'obfuscated.sol'}")
    print(f"  Transform map:           {final_obf_dir / 'transform_map.json'}")
    print(f"  Validator report:        {final_val_dir / 'validation_report.json'}")
    print(f"  Security diff:           {final_val_dir / 'diff_report.json'}")
    print(f"  Obf candidates JSON:     {out_dir / 'obf_candidates.json'}")
    print(f"  Variants JSON:           {out_dir / 'variants.json'}")
    print(f"  Adversarial proxy JSON:  {out_dir / 'adversarial_proxy_score.json'}")
    print(f"  Adversarial score JSON:  {out_dir / 'adversarial_score.json'}")
    print(f"  Repair trace JSON:       {out_dir / 'repair_trace.json'}")
    print(f"  Optimizer summary JSON:  {out_dir / 'optimizer_summary.json'}")
    print(f"  Final report JSON:       {out_dir / 'final_report.json'}")
    print(f"  Transform policy audit:   {out_dir / 'transform_policy_audit.json'}")
    if isinstance(best.get("score_report"), dict):
        print(f"  Adversarial proxy score: {best['score_report']}")
    print(f"  Tier decisions JSON:     {tier_decisions_path}")

    print(
            f"[POLICY] fn={fn_name} "
            f"policy_sensitivity={obf_advice_fn.get('policy_sensitivity')} "
            f"band={obf_advice_fn.get('policy_sensitivity_band')} "
            f"protected_regions={len(obf_advice_fn.get('protected_regions') or [])} "
            f"forbid_ids={len((obf_advice_fn.get('policy_constraints') or {}).get('forbid_transform_ids') or [])}"
        )

if __name__ == "__main__":
    main()