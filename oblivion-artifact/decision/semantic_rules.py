from __future__ import annotations

from typing import Any, Dict, List, Tuple

from decision_planner.catalog import default_transform_catalog


def _pair_key(a: str, b: str) -> str:
    x, y = sorted([str(a), str(b)])
    return f"{x}|{y}"


def infer_base_invariants(function_ir: Dict[str, Any], sec_advice: Dict[str, Any]) -> List[str]:
    invariants: List[str] = [
        "return_values_preserved",
        "observable_side_effects_preserved",
    ]

    if (function_ir.get("visibility") or "").lower() in {"public", "external"}:
        invariants.append("abi_surface_preserved")

    if function_ir.get("writes_storage"):
        invariants.append("storage_effects_preserved")

    if function_ir.get("returns"):
        invariants.append("return_arity_and_meaning_preserved")

    protected = {
        str(x.get("tag") or "").strip()
        for x in (sec_advice.get("protected_regions") or [])
        if isinstance(x, dict)
    }

    if "access_control_guard" in protected:
        invariants.append("access_control_behavior_preserved")
    if "revert_semantics_region" in protected:
        invariants.append("revert_behavior_preserved")
    if "arithmetic_region" in protected:
        invariants.append("arithmetic_semantics_preserved")
    if "loop_region" in protected:
        invariants.append("loop_termination_preserved")
    if "external_call_site" in protected:
        invariants.append("external_call_order_preserved")

    return sorted(set(invariants))


def build_deterministic_semantic_contract(
    *,
    selected_ids: List[str],
    function_ir: Dict[str, Any],
    sec_advice: Dict[str, Any],
) -> Dict[str, Any]:
    catalog = default_transform_catalog()
    global_invariants = infer_base_invariants(function_ir, sec_advice)

    protected_tags = sorted(
        {
            str(x.get("tag") or "").strip()
            for x in (sec_advice.get("protected_regions") or [])
            if isinstance(x, dict) and x.get("tag")
        }
    )

    transform_safety = []
    for tid in selected_ids:
        spec = catalog.get(tid)
        if not spec:
            continue

        avoid_regions = list(spec.protected_region_conflicts or [])
        why_safe = (
            f"{tid} is only safe if it preserves "
            f"{', '.join(spec.semantic_preserves or ['core semantics'])} "
            f"and avoids {', '.join(avoid_regions or ['no protected regions'])}."
        )

        preserve_invariants = sorted(set(global_invariants + [
            f"{x}_preserved" for x in (spec.semantic_preserves or [])
        ]))

        transform_safety.append(
            {
                "transform_id": tid,
                "why_safe": why_safe,
                "preserve_invariants": preserve_invariants,
                "avoid_regions": avoid_regions,
            }
        )

    return {
        "global_invariants": global_invariants,
        "protected_region_tags": protected_tags,
        "transform_safety": transform_safety,
    }


def build_deterministic_composition_graph(
    *,
    selected_ids: List[str],
    function_ir: Dict[str, Any],
    sec_advice: Dict[str, Any],
) -> Dict[str, Any]:
    catalog = default_transform_catalog()
    safe_pairs: List[List[str]] = []
    unsafe_pairs: List[Dict[str, Any]] = []
    ordering_constraints: List[Dict[str, Any]] = []
    pair_scores: Dict[str, float] = {}

    protected_tags = {
        str(x.get("tag") or "").strip()
        for x in (sec_advice.get("protected_regions") or [])
        if isinstance(x, dict)
    }

    loop_sensitive_transforms = {
        "cfg_flatten_v1",
        "cfg_flatten_v2_hybrid",
        "predicate_masking_v1",
        "loop_rewrite_v1",
    }

    arithmetic_sensitive_transforms = {
        "predicate_masking_v1",
        "constant_encoding_v1",
        "constant_encoding_v2_layered",
        "dynamic_constants_v1",
        "boolean_split_v2_distributed",
    }

    for i in range(len(selected_ids)):
        for j in range(i + 1, len(selected_ids)):
            a = selected_ids[i]
            b = selected_ids[j]
            sa = catalog.get(a)
            sb = catalog.get(b)
            if not sa or not sb:
                continue

            reason = None
            if b in (sa.compose_unsafe_with or {}):
                reason = sa.compose_unsafe_with[b]
            elif a in (sb.compose_unsafe_with or {}):
                reason = sb.compose_unsafe_with[a]

            # First-pass explicit v2 guardrails
            if not reason:
                if {a, b} == {"opaque_predicate_v2_entangled", "predicate_masking_v1"}:
                    reason = "entangled opaque predicates should not be combined with predicate masking in first-pass composition"
                elif {a, b} == {"cfg_flatten_v2_hybrid", "dispatcher_cfg_virtualization_v1"}:
                    reason = "hybrid flattening should not be combined with dispatcher virtualization in first-pass composition"
                elif {a, b} == {"constant_encoding_v2_layered", "dynamic_constants_v1"}:
                    reason = "layered constant virtualization should not be combined with dynamic constants in first-pass composition"
                elif {a, b} == {"constant_encoding_v2_layered", "algebraic_identities_v1"}:
                    reason = "layered constant virtualization should not be combined with algebraic identities in first-pass composition"
                elif {a, b} == {"boolean_split_v2_distributed", "predicate_masking_v1"}:
                    reason = "distributed predicate encoding should not be combined with predicate masking in first-pass composition"
                elif {a, b} == {"boolean_split_v2_distributed", "opaque_predicate_v2_entangled"}:
                    reason = "distributed predicate encoding should not be combined with entangled opaque predicates in first-pass composition"
                elif {a, b} == {"cfg_flatten_v2_hybrid", "cfg_flatten_v1"}:
                    reason = "two flattening transforms should not be combined"
                elif {a, b} == {"inline_internal_v2_diversified", "cfg_flatten_v2_hybrid"}:
                    reason = "diversified inlining should not be combined with hybrid flattening in first-pass composition"

            if not reason and "loop_region" in protected_tags:
                if len({a, b} & loop_sensitive_transforms) >= 2:
                    reason = "pair may interfere with loop termination semantics"

            if not reason and "arithmetic_region" in protected_tags:
                if len({a, b} & arithmetic_sensitive_transforms) >= 2:
                    reason = "pair may interfere with arithmetic guard semantics"

            if reason:
                unsafe_pairs.append(
                    {
                        "pair": [a, b],
                        "reason": reason,
                        "risk": 0.9,
                    }
                )
                pair_scores[_pair_key(a, b)] = -1.0
            else:
                safe_pairs.append([a, b])
                pair_scores[_pair_key(a, b)] = 0.25

    for tid in selected_ids:
        spec = catalog.get(tid)
        if not spec:
            continue

        for before in (spec.must_run_after or []):
            if before in selected_ids:
                ordering_constraints.append(
                    {
                        "before": before,
                        "after": tid,
                        "reason": f"{before} should run before {tid}",
                    }
                )

        for after in (spec.must_run_before or []):
            if after in selected_ids:
                ordering_constraints.append(
                    {
                        "before": tid,
                        "after": after,
                        "reason": f"{tid} should run before {after}",
                    }
                )

    return {
        "safe_pairs": safe_pairs,
        "unsafe_pairs": unsafe_pairs,
        "ordering_constraints": ordering_constraints,
        "pair_scores": pair_scores,
    }


def merge_semantic_contracts(
    llm_sc: Dict[str, Any],
    det_sc: Dict[str, Any],
    selected_ids: List[str],
) -> Dict[str, Any]:
    llm_sc = llm_sc or {}
    det_sc = det_sc or {}

    merged = {
        "global_invariants": sorted(set((llm_sc.get("global_invariants") or []) + (det_sc.get("global_invariants") or []))),
        "protected_region_tags": sorted(set((llm_sc.get("protected_region_tags") or []) + (det_sc.get("protected_region_tags") or []))),
        "transform_safety": [],
    }

    by_id: Dict[str, Dict[str, Any]] = {}
    for src in [det_sc.get("transform_safety") or [], llm_sc.get("transform_safety") or []]:
        for item in src:
            if not isinstance(item, dict):
                continue
            tid = item.get("transform_id")
            if not isinstance(tid, str) or tid not in selected_ids:
                continue
            cur = by_id.get(tid, {"transform_id": tid, "why_safe": "", "preserve_invariants": [], "avoid_regions": []})
            if item.get("why_safe"):
                cur["why_safe"] = item["why_safe"]
            cur["preserve_invariants"] = sorted(set(cur["preserve_invariants"] + list(item.get("preserve_invariants") or [])))
            cur["avoid_regions"] = sorted(set(cur["avoid_regions"] + list(item.get("avoid_regions") or [])))
            by_id[tid] = cur

    merged["transform_safety"] = [by_id[tid] for tid in selected_ids if tid in by_id]
    return merged


def merge_composition_graphs(llm_graph: Dict[str, Any], det_graph: Dict[str, Any]) -> Dict[str, Any]:
    llm_graph = llm_graph or {}
    det_graph = det_graph or {}

    safe_pairs = list(det_graph.get("safe_pairs") or [])
    for p in (llm_graph.get("safe_pairs") or []):
        if p not in safe_pairs:
            safe_pairs.append(p)

    unsafe_pairs = list(det_graph.get("unsafe_pairs") or [])
    seen_unsafe = {tuple(sorted(x.get("pair") or [])) for x in unsafe_pairs if isinstance(x, dict)}
    for item in (llm_graph.get("unsafe_pairs") or []):
        pair = tuple(sorted((item.get("pair") or []))) if isinstance(item, dict) else ()
        if pair and pair not in seen_unsafe:
            unsafe_pairs.append(item)
            seen_unsafe.add(pair)

    ordering_constraints = list(det_graph.get("ordering_constraints") or [])
    for item in (llm_graph.get("ordering_constraints") or []):
        if item not in ordering_constraints:
            ordering_constraints.append(item)

    pair_scores = dict(det_graph.get("pair_scores") or {})
    pair_scores.update(llm_graph.get("pair_scores") or {})

    return {
        "safe_pairs": safe_pairs,
        "unsafe_pairs": unsafe_pairs,
        "ordering_constraints": ordering_constraints,
        "pair_scores": pair_scores,
    }