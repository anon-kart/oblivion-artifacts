import json
from pathlib import Path
from .models import ValidationResult


def summarize_transform_map(transform_map_obj: dict, *, validation_accepted: bool | None = None) -> dict:
    selected = transform_map_obj.get("selected", []) if isinstance(transform_map_obj, dict) else []
    applied = transform_map_obj.get("applied", []) if isinstance(transform_map_obj, dict) else []
    skipped = transform_map_obj.get("skipped", []) if isinstance(transform_map_obj, dict) else []
    implemented_transform_ids = (
        transform_map_obj.get("implemented_transform_ids", [])
        if isinstance(transform_map_obj, dict)
        else []
    )

    coverage: dict[str, dict] = {}

    def _ensure_row(tid: str) -> dict:
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

    for tid in implemented_transform_ids or []:
        row = _ensure_row(str(tid))
        row["implemented"] = True

    selected_ids_in_candidate: set[str] = set()

    # Primary source of truth: selected rows with terminal outcome stamped by engine.py
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
        elif outcome in {"noop", "selected_noop", "noop_no_eligible_site"}:
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
    # that do not yet include selected[].final_outcome.
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
            changed = bool(row_obj.get("changed", True))

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

            if cat == "skipped_by_risk" or "engine gate blocked" in reason or "risk" in reason:
                row["skipped_by_risk"] += 1
            elif cat == "skipped_by_conflict" or "conflict" in reason:
                row["skipped_by_conflict"] += 1
            elif cat == "skipped_no_handler" or "no transform handler registered" in reason:
                row["skipped_no_handler"] += 1
            elif cat == "skipped_unimplemented" or "not implemented" in reason:
                row["skipped_unimplemented"] += 1
            elif cat == "transform_failed" or "transform failed" in reason or "runtime_failed" in reason:
                row["transform_failed"] += 1
            elif "selected_noop" in reason or "source_unchanged" in reason or "noop" in reason:
                row["selected_noop"] += 1

    if validation_accepted is False:
        for tid in selected_ids_in_candidate:
            row = _ensure_row(tid)
            row["rejected_on_validation"] += 1

    fns = sorted(
        {
            a.get("function")
            for a in applied
            if isinstance(a, dict) and isinstance(a.get("function"), str) and a.get("function")
        }
    )

    tids = sorted(coverage.keys())

    return {
        "mapping_kind": transform_map_obj.get("mapping_kind"),
        "engine_kind": transform_map_obj.get("engine_kind"),
        "implemented_transform_count": len(implemented_transform_ids or []),
        "selected_count": len(selected),
        "applied_count": len(applied),
        "skipped_count": len(skipped),
        "functions_touched": fns,
        "transform_ids": tids,
        "per_transform": coverage,
    }


def transform_quality_gate(summary: dict, *, max_noop_ratio: float = 0.40) -> dict:
    """
    Hard quality gate against selected-transform inflation.

    Purpose:
      Prevent OBLIVION from claiming potency based on transforms that were
      selected by planner/LLM/optimizer but then became no-op, inapplicable,
      unimplemented, or otherwise not actually applied.

    This does NOT decide semantic/security acceptance by itself.
    It is a reporting/optimizer-quality signal.

    Expected input:
      summary = summarize_transform_map(...)

    Output:
      {
        "ok": bool,
        "selected": int,
        "applied": int,
        "selected_noop": int,
        "noop_ratio": float,
        "reasons": list[str]
      }
    """
    selected = int(summary.get("selected_count") or 0)
    applied = int(summary.get("applied_count") or 0)

    noop = 0
    skipped_by_risk = 0
    skipped_by_conflict = 0
    skipped_no_handler = 0
    skipped_unimplemented = 0
    transform_failed = 0
    dropped_before_execution = 0
    rejected_on_validation = 0

    per_transform = summary.get("per_transform") or {}

    if isinstance(per_transform, dict):
        for row in per_transform.values():
            if not isinstance(row, dict):
                continue

            noop += int(row.get("selected_noop") or 0)
            skipped_by_risk += int(row.get("skipped_by_risk") or 0)
            skipped_by_conflict += int(row.get("skipped_by_conflict") or 0)
            skipped_no_handler += int(row.get("skipped_no_handler") or 0)
            skipped_unimplemented += int(row.get("skipped_unimplemented") or 0)
            transform_failed += int(row.get("transform_failed") or 0)
            dropped_before_execution += int(row.get("dropped_before_execution") or 0)
            rejected_on_validation += int(row.get("rejected_on_validation") or 0)

    noop_ratio = float(noop) / float(max(selected, 1))
    applied_ratio = float(applied) / float(max(selected, 1))

    ok = True
    reasons: list[str] = []

    if selected > 0 and noop_ratio > max_noop_ratio:
        ok = False
        reasons.append(f"too_many_noop_transforms:{noop_ratio:.2f}")

    if selected > 0 and applied == 0:
        ok = False
        reasons.append("no_applied_transforms")

    if skipped_no_handler > 0:
        ok = False
        reasons.append(f"missing_transform_handlers:{skipped_no_handler}")

    if skipped_unimplemented > 0:
        ok = False
        reasons.append(f"unimplemented_transforms:{skipped_unimplemented}")

    if transform_failed > 0:
        ok = False
        reasons.append(f"transform_runtime_failures:{transform_failed}")

    return {
        "ok": ok,
        "selected": selected,
        "applied": applied,
        "selected_noop": noop,
        "noop_ratio": noop_ratio,
        "applied_ratio": applied_ratio,
        "max_noop_ratio": float(max_noop_ratio),
        "skipped_by_risk": skipped_by_risk,
        "skipped_by_conflict": skipped_by_conflict,
        "skipped_no_handler": skipped_no_handler,
        "skipped_unimplemented": skipped_unimplemented,
        "transform_failed": transform_failed,
        "dropped_before_execution": dropped_before_execution,
        "rejected_on_validation": rejected_on_validation,
        "reasons": reasons,
    }


def write_report(*, out_dir: Path, result: ValidationResult) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "validation_report.json"

    # Original structured report
    data = result.to_dict()

    # --------------------------------------------------
    # Backward-compatibility + optimizer glue
    # --------------------------------------------------
    accepted = data.get("accepted")
    if accepted is None:
        accepted = bool(
            data.get("compile", {}).get("ok", False)
            and data.get("tests", {}).get("ok", False)
            and data.get("fuzz", {}).get("ok", True)
            and data.get("semantic", {}).get("ok", True)
            and data.get("security", {}).get("ok", False)
        )

    data["accepted"] = bool(accepted)
    data["ok"] = bool(accepted)
    data.setdefault("reason", "ok" if accepted else "rejected")
    data.setdefault("stage", "validator")

    # --------------------------------------------------
    # Optional transform provenance summary
    # --------------------------------------------------
    transform_map_path = out_dir.parent / "obfuscation_engine" / "transform_map.json"

    if transform_map_path.exists():
        try:
            transform_map_obj = json.loads(transform_map_path.read_text(encoding="utf-8"))

            summary = summarize_transform_map(
                transform_map_obj,
                validation_accepted=bool(accepted),
            )

            quality_gate = transform_quality_gate(summary)

            data["transform_summary"] = summary
            data["transform_quality_gate"] = quality_gate
            data["transform_map_path"] = str(transform_map_path)

            # Do not override compile/test/security acceptance here.
            # This flag is separate so your optimizer/report can reject
            # no-op-inflated candidates without confusing semantic validation.
            data["transform_quality_ok"] = bool(quality_gate.get("ok", False))

        except Exception as exc:
            data["transform_summary"] = {
                "error": f"failed_to_read_transform_map: {type(exc).__name__}: {exc}"
            }
            data["transform_quality_gate"] = {
                "ok": False,
                "selected": 0,
                "applied": 0,
                "selected_noop": 0,
                "noop_ratio": 0.0,
                "reasons": [f"failed_to_read_transform_map:{type(exc).__name__}"],
            }
            data["transform_quality_ok"] = False
            data["transform_map_path"] = str(transform_map_path)

    report_path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )