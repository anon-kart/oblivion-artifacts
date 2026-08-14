from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from decision.composition_graph import order_plan_steps
from decision.semantic_rules import (
    build_deterministic_composition_graph,
    merge_composition_graphs,
)


# Deterministic, engine-owned transforms that the augment/potency stage may
# inject AFTER the LLM has produced its plan. Because the LLM never saw these,
# it cannot list them in its `semantic_contract.transform_safety`. Their absence
# from that list is therefore expected and NOT evidence of a hallucinated or
# unsafe plan — these modules exist in obfuscation_engine/transforms/ and are
# applied by the engine itself under its own policy/compat gating. A selected
# transform whose id is NOT in this set and is also missing a safety entry is a
# genuine anomaly (e.g. an LLM-hallucinated transform id) and still hard-rejects.
_ENGINE_OWNED_TRANSFORM_IDS: frozenset[str] = frozenset(
    {
        "algebraic_identities_v1",
        "boolean_split_v1",
        "boolean_split_v2_distributed",
        "cfg_flatten_v1",
        "cfg_flatten_v2_hybrid",
        "chaotic_opaque_predicate_v1",
        "constant_encoding_v1",
        "constant_encoding_v2_layered",
        "dead_code_v1",
        "dispatcher_cfg_virtualization_v1",
        "dynamic_constants_v1",
        "inline_internal_v1",
        "inline_internal_v2_diversified",
        "layout_scramble_v1",
        "local_to_state_lift_v1",
        "loop_rewrite_v1",
        "modifier_expand_v1",
        "opaque_predicate_v1",
        "opaque_predicate_v2_entangled",
        "opaque_storage_slot_indirection_v1",
        "predicate_masking_v1",
        "public_state_accessor_indirection_v1",
        "rename_identifiers_sha1_v1",
        "rename_identifiers_v1",
        "rename_identifiers_v2_scoped",
        "scalar_to_struct_indirection_v1",
        "stack_variable_aliasing_v1",
        "storage_indirection_v1",
        "string_split_v1",
        "yul_microblock_v1",
    }
)


def _read_json_if_exists(path: Path | None) -> Dict[str, Any]:
    try:
        if path is None or not Path(path).exists():
            return {}
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}


def _extract_selected_ids_from_transform_map(function_name: str, tm: Dict[str, Any]) -> List[str]:
    # Preferred source of truth: final_function_plans
    fplans = tm.get("final_function_plans") or []
    if isinstance(fplans, list):
        for fp in fplans:
            if not isinstance(fp, dict):
                continue
            if fp.get("function") != function_name:
                continue

            ordered_ids = fp.get("final_ordered_transform_ids") or []
            if isinstance(ordered_ids, list):
                out: List[str] = []
                seen = set()
                for tid in ordered_ids:
                    if isinstance(tid, str) and tid.strip() and tid not in seen:
                        seen.add(tid)
                        out.append(tid)
                if out:
                    return out

            final_ids = fp.get("final_transform_ids") or []
            if isinstance(final_ids, list):
                out = []
                seen = set()
                for tid in final_ids:
                    if isinstance(tid, str) and tid.strip() and tid not in seen:
                        seen.add(tid)
                        out.append(tid)
                if out:
                    return out

    # Backward-compatible fallback
    selected_ids: List[str] = []

    def _maybe_add_from_rows(rows: Any) -> None:
        nonlocal selected_ids
        for row in rows or []:
            if not isinstance(row, dict):
                continue

            target = row.get("target") if isinstance(row.get("target"), dict) else {}
            fn = target.get("function") or row.get("function")
            if fn != function_name:
                continue

            tid = row.get("id") or row.get("transform_id")
            if not isinstance(tid, str) or not tid.strip():
                continue

            selected_ids.append(tid)

    _maybe_add_from_rows(tm.get("selected"))
    _maybe_add_from_rows(tm.get("applied"))
    _maybe_add_from_rows(tm.get("skipped"))

    out: List[str] = []
    seen = set()
    for tid in selected_ids:
        if tid in seen:
            continue
        seen.add(tid)
        out.append(tid)

    return out


def check_semantic_contract(
    *,
    candidate_plan: Dict[str, Any] | None,
    policy: Dict[str, Any] | None,
    out_dir: Path,
    transform_map_json: Path | None = None,
) -> Dict[str, Any]:
    policy = policy or {}
    out_dir.mkdir(parents=True, exist_ok=True)

    if not bool(policy.get("semantic_validation_enabled", True)):
        result = {
            "ok": True,
            "skipped": True,
            "reason": "semantic_validation_disabled",
            "reject_reasons": [],
            "per_function_results": [],
            "transform_map_used": False,
            "transform_map_json": str(transform_map_json) if transform_map_json else None,
        }
        (out_dir / "semantic_report.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    if not candidate_plan or not isinstance(candidate_plan.get("plans"), list):
        result = {
            "ok": True,
            "skipped": True,
            "reason": "no_candidate_plan",
            "reject_reasons": [],
            "per_function_results": [],
            "transform_map_used": False,
            "transform_map_json": str(transform_map_json) if transform_map_json else None,
        }
        (out_dir / "semantic_report.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    reject_reasons: List[str] = []
    per_function_results: List[Dict[str, Any]] = []
    tm = _read_json_if_exists(transform_map_json)

    for fp in candidate_plan.get("plans", []) or []:
        if not isinstance(fp, dict):
            continue

        fn = fp.get("function", "<unknown>")
        llm_meta = fp.get("llm_meta") or {}
        semantic_contract = llm_meta.get("semantic_contract") or {}
        graph = llm_meta.get("composition_graph") or {}
        sec_entry = fp.get("sec_entry") or {}

        selected_ids: List[str] = []

        if tm:
            selected_ids = _extract_selected_ids_from_transform_map(fn, tm)

        if not selected_ids:
            for t in fp.get("selected_transforms", []) or []:
                if isinstance(t, dict) and isinstance(t.get("id"), str):
                    selected_ids.append(t["id"])

        # de-dup preserve order
        dedup_selected_ids: List[str] = []
        seen_selected = set()
        for tid in selected_ids:
            if not isinstance(tid, str) or not tid.strip():
                continue
            if tid in seen_selected:
                continue
            seen_selected.add(tid)
            dedup_selected_ids.append(tid)
        selected_ids = dedup_selected_ids

        det_graph = build_deterministic_composition_graph(
            selected_ids=selected_ids,
            function_ir=fp.get("function_ir", {}) if isinstance(fp.get("function_ir"), dict) else {},
            sec_advice=sec_entry if isinstance(sec_entry, dict) else {},
        )
        graph = merge_composition_graphs(graph, det_graph)

        fn_reasons: List[str] = []
        engine_added_observed: List[str] = []

        by_id: Dict[str, Dict[str, Any]] = {}
        for item in semantic_contract.get("transform_safety", []) or []:
            if isinstance(item, dict) and isinstance(item.get("transform_id"), str):
                by_id[item["transform_id"]] = item

        # Transforms the engine's augment/potency stage may add after the LLM
        # plan. Operators can override the default allowlist via policy if they
        # register custom transforms.
        engine_owned = _ENGINE_OWNED_TRANSFORM_IDS
        extra_owned = policy.get("engine_owned_transform_ids")
        if isinstance(extra_owned, list):
            engine_owned = engine_owned | frozenset(
                x for x in extra_owned if isinstance(x, str) and x.strip()
            )

        for tid in selected_ids:
            if tid in by_id:
                continue
            # Missing a safety entry. Only a real violation if this is NOT a
            # known engine-owned transform — i.e. it looks like a hallucinated
            # or unregistered transform id. Engine-injected transforms are
            # deterministically safe by construction; record them as an
            # observation so the decision stays auditable, but do not veto.
            if tid in engine_owned:
                engine_added_observed.append(tid)
                continue
            msg = f"{fn}:missing_transform_safety:{tid}"
            reject_reasons.append(msg)
            fn_reasons.append(msg)

        protected_tags = set()

        ptr = semantic_contract.get("protected_region_tags") or []
        if isinstance(ptr, list):
            protected_tags.update(x for x in ptr if isinstance(x, str) and x.strip())

        sec_tags = (sec_entry.get("policy_constraints", {}) or {}).get("protected_region_tags", []) or []
        if isinstance(sec_tags, list):
            protected_tags.update(x for x in sec_tags if isinstance(x, str) and x.strip())

        if bool(policy.get("semantic_reject_on_avoid_region_overlap", True)):
            for tid in selected_ids:
                item = by_id.get(tid) or {}
                avoid = item.get("avoid_regions") or []
                avoid_set = set(x for x in avoid if isinstance(x, str) and x.strip())
                overlap = sorted(avoid_set & protected_tags)
                if overlap:
                    msg = f"{fn}:avoid_region_overlap:{tid}:{','.join(overlap)}"
                    reject_reasons.append(msg)
                    fn_reasons.append(msg)

        unsafe_pairs = set()
        for item in graph.get("unsafe_pairs", []) or []:
            if not isinstance(item, dict):
                continue
            pair = item.get("pair") or []
            if isinstance(pair, list) and len(pair) == 2:
                a, b = pair[0], pair[1]
                if isinstance(a, str) and a.strip() and isinstance(b, str) and b.strip():
                    unsafe_pairs.add("|".join(sorted([a, b])))

        if bool(policy.get("semantic_reject_on_unsafe_composition", True)):
            for i in range(len(selected_ids)):
                for j in range(i + 1, len(selected_ids)):
                    pair_key = "|".join(sorted([selected_ids[i], selected_ids[j]]))
                    if pair_key in unsafe_pairs:
                        msg = f"{fn}:unsafe_pair:{selected_ids[i]}|{selected_ids[j]}"
                        reject_reasons.append(msg)
                        fn_reasons.append(msg)

        engine_ordered_ids = selected_ids
        fplans = tm.get("final_function_plans") or []
        if isinstance(fplans, list):
            for fp2 in fplans:
                if not isinstance(fp2, dict):
                    continue
                if fp2.get("function") != fn:
                    continue
                candidate_ids = fp2.get("final_ordered_transform_ids") or []
                if isinstance(candidate_ids, list) and candidate_ids:
                    engine_ordered_ids = [
                        tid for tid in candidate_ids
                        if isinstance(tid, str) and tid.strip()
                    ]
                    break

        # de-dup preserve order on engine ordering too
        dedup_engine_ordered_ids: List[str] = []
        seen_engine = set()
        for tid in engine_ordered_ids:
            if tid in seen_engine:
                continue
            seen_engine.add(tid)
            dedup_engine_ordered_ids.append(tid)
        engine_ordered_ids = dedup_engine_ordered_ids

        if bool(policy.get("semantic_reject_on_order_violation", True)):
            ordered = order_plan_steps(
                [{"transform_id": tid} for tid in engine_ordered_ids],
                graph,
            )
            ordered_ids = [
                x["transform_id"]
                for x in ordered
                if isinstance(x, dict) and x.get("transform_id")
            ]

            if ordered_ids != engine_ordered_ids:
                msg = f"{fn}:ordering_violation:{engine_ordered_ids}->{ordered_ids}"
                reject_reasons.append(msg)
                fn_reasons.append(msg)

        per_function_results.append(
            {
                "function": fn,
                "selected_ids": selected_ids,
                "engine_ordered_ids": engine_ordered_ids,
                "engine_added_transforms": engine_added_observed,
                "llm_semantic_contract": semantic_contract if isinstance(semantic_contract, dict) else {},
                "composition_graph": graph if isinstance(graph, dict) else {},
                "sec_entry": sec_entry if isinstance(sec_entry, dict) else {},
                "violations": fn_reasons,
                "ok": len(fn_reasons) == 0,
            }
        )

    result = {
        "ok": len(reject_reasons) == 0,
        "skipped": False,
        "reason": "ok" if len(reject_reasons) == 0 else "semantic_contract_violation",
        "reject_reasons": reject_reasons,
        "per_function_results": per_function_results,
        "transform_map_used": bool(tm),
        "transform_map_json": str(transform_map_json) if transform_map_json else None,
    }
    (out_dir / "semantic_report.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result