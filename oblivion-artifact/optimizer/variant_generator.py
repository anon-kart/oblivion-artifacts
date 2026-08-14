# optimizer/variant_generator.py
"""
Variant plan generator (v1.5)  ✅ UPDATED for DISTINCT-ID subset generation + caps/weights support

Purpose
-------
Generate multiple candidate obfuscation plans from a base variants_plan.json
for use by the optimizer/search layer.

Supports BOTH plan styles:
  A) "flat" engine plan:
      plan["transforms"] = [ {id,target,params}, ... ]
  B) per-function planner plan (DecisionPlanner output):
      plan["plans"][i]["selected_transforms"] = [ {id,target,params}, ... ]

✅ LLM integration (kept from v1.2)
----------------------------------
This module can accept LLM-generated candidate plans and include them
as search candidates alongside combinatorial subsets.

LLM candidates may be provided in either form:
  - function-style (preferred): plan["plans"][i]["selected_transforms"]
  - flat-style: plan["transforms"]

We normalize them so that they work with your current engine:
  - if base plan is function-style, LLM flat plans are pushed back into
    plan["plans"][i]["selected_transforms"] (using target.function)
  - if base plan is flat-style, LLM function plans are flattened into
    plan["transforms"]

✅ NEW in v1.3 (fixes "tiny subsets" issue)
-----------------------------------------------
- Always includes the FULL base plan as an early candidate ("candidate_kind": "full")
- Generates subsets in "largest-first" order (k=max ... 1)

✅ NEW in v1.4 (fixes OOM / supports max_candidates)
-------------------------------------------------------------
- Streaming subset enumeration (no giant subsets list in RAM)
- Hard-cap candidate generation via max_candidates (stop early)

✅ NEW in v1.5 (fixes "1 unique transform id" collapse)
------------------------------------------------------
- Subsets are generated over DISTINCT transform IDs (not raw entries)
- Candidate materialization picks multiple entries per chosen ID, spread across functions
- Honors policy knobs if present inside base_plan:
    - min_distinct_transform_ids
    - transform_caps
    - transform_weights
    - seed
"""

from __future__ import annotations

import copy
import itertools
import json
import random
from collections import defaultdict
from typing import Any, Dict, List, Optional, Sequence, Tuple
from decision.composition_graph import composition_bonus_for_ids

Plan = Dict[str, Any]
Transform = Dict[str, Any]


# -----------------------------
# Helpers: IDs + copying
# -----------------------------

def _transform_id(t: Transform) -> str:
    if "id" in t:
        return str(t["id"])
    if "type" in t:
        return str(t["type"])
    return json.dumps(t, sort_keys=True)


def _plan_id_from_transforms(transforms: Sequence[Transform]) -> str:
    # ✅ Keep ORIGINAL v1.2 behavior (order-preserving)
    ids = [_transform_id(t) for t in transforms]
    return "plan[" + ",".join(ids) + "]"


def _stable_plan_fingerprint(plan: Plan) -> str:
    try:
        blob = json.dumps(plan, sort_keys=True)
    except Exception:
        blob = str(plan)
    return "plan:" + str(abs(hash(blob)))


def _copy_plan_base(base_plan: Plan) -> Plan:
    """
    Copy everything except transforms (which may be replaced).
    For per-function plans, we keep "llm/meta/plans" and will edit selected_transforms inside.
    """
    out: Plan = {}
    for k, v in base_plan.items():
        if k == "transforms":
            continue
        out[k] = copy.deepcopy(v)
    return out


def _group_transforms_by_id(base_transforms: List[Transform]) -> Dict[str, List[Transform]]:
    by_id: Dict[str, List[Transform]] = defaultdict(list)
    for t in base_transforms or []:
        if not isinstance(t, dict):
            continue
        tid = t.get("id") or t.get("type")
        if not tid:
            continue
        by_id[str(tid)].append(t)
    return dict(by_id)


def _weighted_choice_no_replace(ids: List[str], weights: Dict[str, float], k: int, rng: random.Random) -> List[str]:
    # simple no-replacement weighted sampling
    pool = ids[:]
    chosen: List[str] = []
    for _ in range(min(k, len(pool))):
        total = sum(float(weights.get(i, 1.0)) for i in pool)
        r = rng.random() * total
        acc = 0.0
        pick = pool[-1]
        for i in pool:
            acc += float(weights.get(i, 1.0))
            if acc >= r:
                pick = i
                break
        chosen.append(pick)
        pool.remove(pick)
    return chosen


def _get_policy_from_base_plan(base_plan: Plan) -> Dict[str, Any]:
    """
    Try to read policy from common places without requiring a signature change.
    """
    # 1) base_plan["policy"]
    if isinstance(base_plan.get("policy"), dict):
        return dict(base_plan["policy"])  # shallow copy ok

    # 2) base_plan["meta"]["policy"]
    meta = base_plan.get("meta")
    if isinstance(meta, dict) and isinstance(meta.get("policy"), dict):
        return dict(meta["policy"])

    # 3) fallback empty
    return {}

def _function_composition_graphs(base_plan: Plan) -> Dict[str, Dict[str, Any]]:
    out = {}
    for fp in base_plan.get("plans", []) or []:
        if not isinstance(fp, dict):
            continue
        fn = fp.get("function")
        llm_meta = fp.get("llm_meta") or {}
        graph = llm_meta.get("composition_graph") or {}
        if isinstance(fn, str) and isinstance(graph, dict):
            out[fn] = graph
    return out


def _candidate_composition_bonus(base_plan: Plan, plan: Plan) -> float:
    graphs = _function_composition_graphs(base_plan)
    bonus = 0.0

    # function-style plan
    if isinstance(plan.get("plans"), list):
        for fp in plan.get("plans", []) or []:
            if not isinstance(fp, dict):
                continue
            fn = fp.get("function")
            if not isinstance(fn, str):
                continue
            graph = graphs.get(fn) or {}
            ids = []
            for t in fp.get("selected_transforms", []) or []:
                if isinstance(t, dict):
                    tid = t.get("id") or t.get("type")
                    if isinstance(tid, str):
                        ids.append(tid)
            bonus += composition_bonus_for_ids(ids, graph)
        return bonus

    return 0.0


def _candidate_violates_unsafe_pairs(base_plan: Plan, plan: Plan) -> bool:
    graphs = _function_composition_graphs(base_plan)

    if isinstance(plan.get("plans"), list):
        for fp in plan.get("plans", []) or []:
            if not isinstance(fp, dict):
                continue
            fn = fp.get("function")
            graph = graphs.get(fn) or {}
            unsafe = set()
            for item in graph.get("unsafe_pairs", []) or []:
                if isinstance(item, dict):
                    pair = item.get("pair") or []
                    if isinstance(pair, list) and len(pair) == 2:
                        unsafe.add("|".join(sorted(pair)))

            ids = []
            for t in fp.get("selected_transforms", []) or []:
                if isinstance(t, dict):
                    tid = t.get("id") or t.get("type")
                    if isinstance(tid, str):
                        ids.append(tid)

            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    if "|".join(sorted([ids[i], ids[j]])) in unsafe:
                        return True
    return False


def _spread_pick(entries: List[Transform], cap: int) -> List[Transform]:
    """
    Pick up to `cap` entries, trying to spread across different target.functions first.
    """
    if cap <= 0:
        return []
    seen_fns: set[str] = set()
    picked: List[Transform] = []
    # prefer unique functions first
    for t in entries:
        target = t.get("target") if isinstance(t.get("target"), dict) else {}
        fn = str(target.get("function") or "")
        if fn and fn in seen_fns:
            continue
        picked.append(t)
        if fn:
            seen_fns.add(fn)
        if len(picked) >= cap:
            return picked
    # if still under cap, just fill
    if len(picked) < cap:
        for t in entries:
            if t in picked:
                continue
            picked.append(t)
            if len(picked) >= cap:
                break
    return picked


# -----------------------------
# Flatten / Unflatten
# -----------------------------

def _extract_flat_transforms_from_function_plans(plan: Plan) -> List[Transform]:
    """
    If plan came from DecisionPlanner, transforms live under:
      plan["plans"][i]["selected_transforms"]

    We flatten them into a single list, attaching function info so the engine can scope.
    Output transform schema:
      {
        "id": "...",
        "target": {..., "function": "<fn>"},
        "params": {...}
      }
    """
    out: List[Transform] = []
    for fp in plan.get("plans", []) or []:
        fn = fp.get("function") or fp.get("full_name") or ""
        for t in fp.get("selected_transforms", []) or []:
            if not isinstance(t, dict):
                continue
            tid = t.get("id") or t.get("type")
            if not tid:
                continue
            target = t.get("target") if isinstance(t.get("target"), dict) else {}
            target2 = dict(target)
            if fn:
                target2.setdefault("function", fn)
            params = t.get("params") if isinstance(t.get("params"), dict) else {}
            out.append({"id": str(tid), "target": target2, "params": params})
    return out


def _base_plan_is_function_style(plan: Plan) -> bool:
    return isinstance(plan.get("plans"), list) and len(plan.get("plans") or []) > 0


def _get_base_transforms(plan: Plan) -> List[Transform]:
    """
    Prefer top-level plan["transforms"] if present; otherwise derive from function plans.
    """
    t = plan.get("transforms")
    if isinstance(t, list) and t:
        return list(t)
    if _base_plan_is_function_style(plan):
        return _extract_flat_transforms_from_function_plans(plan)
    return []


def _apply_flat_transforms_back_into_plan(base_plan: Plan, flat_transforms: List[Transform]) -> Plan:
    """
    If base plan is function-style, we MUST put transforms back into each function's selected_transforms
    so your obfuscation_engine/engine.py will apply them (it reads plan["plans"][i]["selected_transforms"]).

    If base plan is already flat-style, we just set plan["transforms"].
    """
    out = _copy_plan_base(base_plan)

    if not _base_plan_is_function_style(base_plan):
        out["transforms"] = copy.deepcopy(flat_transforms)
        return out

    # function-style: clear selected_transforms and reassign by target.function
    plans = out.get("plans", []) or []
    for fp in plans:
        fp["selected_transforms"] = []

    # index by function name for fast assignment
    by_fn: Dict[str, Dict[str, Any]] = {}
    for fp in plans:
        fn = fp.get("function") or fp.get("full_name") or ""
        if fn:
            by_fn[fn] = fp

    for t in flat_transforms:
        tid = t.get("id") or t.get("type")
        if not tid:
            continue
        target = t.get("target") if isinstance(t.get("target"), dict) else {}
        fn = target.get("function") or ""
        params = t.get("params") if isinstance(t.get("params"), dict) else {}

        # if missing function, just skip (cannot safely attach)
        if not fn or fn not in by_fn:
            continue

        # store in original planner schema
        by_fn[fn]["selected_transforms"].append(
            {"id": str(tid), "target": {k: v for k, v in target.items() if k != "function"}, "params": params}
        )

    out["plans"] = plans
    return out


def _normalize_candidate_plan_to_base_style(base_plan: Plan, cand: Plan) -> Plan:
    """
    Normalize a candidate plan (possibly LLM-generated) to match the base plan style
    so your engine can apply it reliably.
    """
    base_is_fn = _base_plan_is_function_style(base_plan)
    cand_is_fn = _base_plan_is_function_style(cand)

    # Candidate already matches base style: keep (but deep copy)
    if base_is_fn == cand_is_fn:
        out = copy.deepcopy(cand)
        return out

    # Base is function-style, candidate is flat-style => push flat transforms into selected_transforms
    if base_is_fn and not cand_is_fn:
        flat = _get_base_transforms(cand)
        out = _apply_flat_transforms_back_into_plan(base_plan, flat)
        # ✅ KEEP v1.2 meta merge behavior
        if isinstance(cand.get("meta"), dict):
            out.setdefault("meta", {})
            if isinstance(out["meta"], dict):
                out["meta"] = {**out["meta"], **cand["meta"]}
        return out

    # Base is flat-style, candidate is function-style => flatten into transforms
    if not base_is_fn and cand_is_fn:
        flat = _extract_flat_transforms_from_function_plans(cand)
        out = _copy_plan_base(base_plan)
        out["transforms"] = copy.deepcopy(flat)
        # ✅ KEEP v1.2 meta merge behavior
        if isinstance(cand.get("meta"), dict):
            out.setdefault("meta", {})
            if isinstance(out["meta"], dict):
                out["meta"] = {**out["meta"], **cand["meta"]}
        return out

    return copy.deepcopy(cand)


# -----------------------------
# Potency scoring (heuristic)
# -----------------------------

# These weights are a search PRIORITY only (not acceptance).
# Validator still decides pass/fail with security+tests+gas.
_POTENCY_WEIGHTS: Dict[str, int] = {
    # heavy / BiAn-like
    "cfg_flatten_v1": 100,
    "storage_indirection_v1": 90,
    "yul_microblock_v1": 80,

    "chaotic_opaque_predicate_v1": 70,
    "scalar_to_struct_indirection_v1": 75,

    # strong control/data
    "opaque_predicate_v1": 60,
    "dead_code_v1": 55,
    "predicate_masking_v1": 50,
    "loop_rewrite_v1": 45,
    "inline_internal_v1": 35,

    # data
    "dynamic_constants_v1": 30,
    "constant_encoding_v1": 25,
    "boolean_split_v1": 20,

    # layout (low potency alone)
    "rename_identifiers_v2_scoped": 15,
    "rename_identifiers_sha1_v1": 12,
    "rename_identifiers_v1": 5,
    "layout_scramble_v1": 3,
}


def _potency_key(t: Transform) -> Tuple[int, str]:
    tid = _transform_id(t)
    return (-int(_POTENCY_WEIGHTS.get(tid, 0)), tid)


def _potency_for_id(tid: str, *, fallback: int = 0) -> int:
    return int(_POTENCY_WEIGHTS.get(tid, fallback))


# -----------------------------
# Subset generation (STREAMING)
# -----------------------------

def iter_id_subsets(
    ids: Sequence[str],
    *,
    max_size: Optional[int] = None,
    include_empty: bool = False,
    min_size: int = 1,
):
    """
    Yield subsets of DISTINCT ids, largest-first. Streaming generator.
    """
    n = len(ids)
    max_k = max_size if max_size is not None else n

    start_k = 0 if include_empty else max(1, int(min_size))

    for k in range(min(max_k, n), start_k - 1, -1):
        if k < 0:
            continue
        for combo in itertools.combinations(ids, k):
            yield list(combo)


# -----------------------------
# Parameter mutation (v1.1)
# -----------------------------

def mutate_transform_params(
    transform: Transform,
    *,
    numeric_jitter_pct: float = 0.2,
) -> List[Transform]:
    """
    Mutate numeric values inside transform["params"] (NOT top-level keys),
    because engine.py passes params dict to transforms.

    If no numeric params exist, returns [transform].
    """
    base = copy.deepcopy(transform)
    params = base.get("params")
    if not isinstance(params, dict) or not params:
        return [transform]

    variants: List[Transform] = [base]

    for k, v in list(params.items()):
        if isinstance(v, (int, float)) and k not in ("tier",):
            if isinstance(v, int):
                delta = max(1, int(abs(v) * numeric_jitter_pct))
                candidates = {v, v - delta, v + delta}
            else:
                delta = abs(v) * numeric_jitter_pct
                candidates = {v, v - delta, v + delta}

            new_variants: List[Transform] = []
            for tv in variants:
                for c in candidates:
                    if isinstance(c, (int, float)) and c < 0:
                        continue
                    t2 = copy.deepcopy(tv)
                    if "params" not in t2 or not isinstance(t2["params"], dict):
                        t2["params"] = {}
                    t2["params"][k] = c
                    new_variants.append(t2)
            variants = new_variants

    # Deduplicate
    uniq: Dict[str, Transform] = {}
    for t in variants:
        uniq[json.dumps(t, sort_keys=True)] = t
    return list(uniq.values())


# -----------------------------
# Tier filtering
# -----------------------------

def _get_transform_tier(t: Transform) -> Optional[int]:
    """
    Best-effort tier detection:
      - t["tier"]
      - t["params"]["tier"]
    """
    if isinstance(t.get("tier"), int):
        return int(t["tier"])
    params = t.get("params")
    if isinstance(params, dict) and isinstance(params.get("tier"), int):
        return int(params["tier"])
    return None


def filter_transforms_by_tier(
    transforms: Sequence[Transform],
    *,
    max_tier: Optional[int] = None,
) -> List[Transform]:
    """
    Drop transforms whose declared tier exceeds max_tier.
    If no tier exists, treat as allowed.
    """
    if max_tier is None:
        return list(transforms)

    out: List[Transform] = []
    for t in transforms:
        tier = _get_transform_tier(t)
        if tier is None or tier <= max_tier:
            out.append(t)
    return out


# -----------------------------
# ✅ LLM candidate ingestion
# -----------------------------

def _ensure_plan_has_id(plan: Plan, *, prefix: str = "llm") -> Plan:
    out = copy.deepcopy(plan)
    pid = out.get("id")
    if isinstance(pid, str) and pid.strip():
        return out
    out["id"] = f"{prefix}:{_stable_plan_fingerprint(out)}"
    return out


def normalize_llm_candidate_plans(
    *,
    base_plan: Plan,
    llm_candidate_plans: Sequence[Plan],
) -> List[Plan]:
    """
    Normalize LLM-generated plans to the base plan style, add IDs, and tag meta.
    """
    out: List[Plan] = []
    for i, cand in enumerate(llm_candidate_plans or []):
        if not isinstance(cand, dict):
            continue
        norm = _normalize_candidate_plan_to_base_style(base_plan, cand)
        norm = _ensure_plan_has_id(norm, prefix=f"llm{i:02d}")
        norm.setdefault("meta", {})
        if isinstance(norm["meta"], dict):
            norm["meta"] = {**norm["meta"], "generated_by": "LLM", "candidate_kind": "llm"}
        out.append(norm)
    return out


# -----------------------------
# Main entry point
# -----------------------------

def generate_candidate_plans(
    *,
    base_plan: Plan,
    max_subset_size: int = 3,
    max_tier: Optional[int] = None,
    enable_param_mutation: bool = False,
    llm_candidate_plans: Optional[Sequence[Plan]] = None,
    min_subset_size: int = 1,
    include_full_plan_first: bool = True,
    # ✅ hard cap to prevent OOM + supports oblivion_run.py call
    max_candidates: Optional[int] = None,
) -> List[Plan]:
    """
    Generate candidate plans from a base plan.

    Strategy:
      A) Include normalized LLM candidate plans first (if provided)
      B) Deterministic candidate exploration:
         0) Extract base transforms (flat or derived-from-function)
         1) Filter by tier
         2) Group transforms by DISTINCT id
         3) Optionally include FULL plan first
         4) Generate DISTINCT-ID subsets (largest-first) STREAMING
         5) Materialize each id-subset into transform entries using caps + function spreading
         6) Optionally mutate parameters (inside params dict)
         7) Emit full plan objects (preserve base schema style)

    Returns:
      List[Plan dicts]
    """
    candidate_plans: List[Plan] = []
    emitted = 0

    policy = _get_policy_from_base_plan(base_plan)
    seed = int(policy.get("seed", 1337))
    rng = random.Random(seed)

    transform_caps: Dict[str, int] = {}
    if isinstance(policy.get("transform_caps"), dict):
        transform_caps = {str(k): int(v) for k, v in policy["transform_caps"].items() if v is not None}

    transform_weights: Dict[str, float] = {}
    if isinstance(policy.get("transform_weights"), dict):
        transform_weights = {str(k): float(v) for k, v in policy["transform_weights"].items() if v is not None}

    min_distinct_transform_ids = int(policy.get("min_distinct_transform_ids", 1))

    def _maybe_add(p: Plan) -> bool:
        nonlocal emitted

        if _candidate_violates_unsafe_pairs(base_plan, p):
            return True

        p.setdefault("meta", {})
        if isinstance(p["meta"], dict):
            p["meta"]["composition_bonus"] = _candidate_composition_bonus(base_plan, p)

        candidate_plans.append(p)
        emitted += 1

        if max_candidates is not None and emitted >= max_candidates:
            return False

        return True

    # ✅ A) LLM candidates (already full plans)
    if llm_candidate_plans:
        for p in normalize_llm_candidate_plans(base_plan=base_plan, llm_candidate_plans=llm_candidate_plans):
            if not _maybe_add(p):
                return candidate_plans

    # ✅ B) Base transforms
    base_transforms = _get_base_transforms(base_plan)
    base_transforms = filter_transforms_by_tier(base_transforms, max_tier=max_tier)

    # If nothing to do, return whatever we have (possibly LLM)
    if not base_transforms:
        uniq: Dict[str, Plan] = {}
        for p in candidate_plans:
            pid = str(p.get("id", "")).strip()
            if not pid:
                pid = json.dumps(p, sort_keys=True)
                p["id"] = pid
            uniq[pid] = p

        final_plans = list(uniq.values())
        final_plans.sort(
            key=lambda p: float((p.get("meta") or {}).get("composition_bonus", 0.0)),
            reverse=True,
        )

        return final_plans

    # Group by id
    by_id = _group_transforms_by_id(list(base_transforms))
    all_ids = sorted(by_id.keys())

    # Order ids by potency (descending), tie-breaker by id
    all_ids = sorted(all_ids, key=lambda tid: (-_potency_for_id(tid), tid))

    # ------------------------------------------------------------
    # HARD MODE: if the pipeline is in "apply all safe transforms"
    # mode, the optimizer is NOT allowed to search subsets.
    # It must emit exactly one candidate: the full compatible plan.
    # ------------------------------------------------------------
    force_full_safe_plan = bool(
        policy.get("apply_all_safe_transforms_when_allowed", False)
    ) and bool(
        policy.get("optimizer_respect_full_safe_plan", True)
    )

    print(
        "[OPT-DEBUG] apply_all_safe=",
        bool(policy.get("apply_all_safe_transforms_when_allowed", False)),
        "respect_full=",
        bool(policy.get("optimizer_respect_full_safe_plan", False)),
        "force_full_safe_plan=",
        force_full_safe_plan,
    )

    if force_full_safe_plan:
        full_entries: List[Transform] = []
        for tid in all_ids:
            entries = by_id.get(tid, [])
            cap = int(transform_caps.get(tid, 999999))
            full_entries.extend(_spread_pick(entries, cap))

        full_plan = _apply_flat_transforms_back_into_plan(base_plan, list(full_entries))
        full_plan["id"] = "full_plan_locked"
        full_plan.setdefault("meta", {})
        if isinstance(full_plan["meta"], dict):
            full_plan["meta"] = {
                **full_plan["meta"],
                "candidate_kind": "full_locked",
                "optimization_mode": "apply_all_safe_locked",
                "distinct_ids": len(set(all_ids)),
            }

        _maybe_add(full_plan)

        uniq: Dict[str, Plan] = {}
        for p in candidate_plans:
            pid = str(p.get("id", "")).strip()
            if not pid:
                pid = json.dumps(p, sort_keys=True)
                p["id"] = pid
            uniq[pid] = p

        print(
            f"[OPT-DEBUG] locked_full_plan_emitted id={full_plan['id']} "
            f"distinct_ids={len(set(all_ids))} total_entries={len(full_entries)}"
        )

        return list(uniq.values())

    # ✅ full-plan candidate first (materialize all ids with caps)
    if include_full_plan_first and all_ids:
        full_entries: List[Transform] = []
        for tid in all_ids:
            entries = by_id.get(tid, [])
            cap = int(transform_caps.get(tid, 999999))
            full_entries.extend(_spread_pick(entries, cap))
        full_plan = _apply_flat_transforms_back_into_plan(base_plan, list(full_entries))
        full_plan["id"] = "full_plan"
        full_plan.setdefault("meta", {})
        if isinstance(full_plan["meta"], dict):
            full_plan["meta"] = {**full_plan["meta"], "candidate_kind": "full"}
        if not _maybe_add(full_plan):
            return candidate_plans
        
    # Dedicated BiAn-parity bundle candidate
    parity_bundle_ids = [
        tid for tid in (
            "chaotic_opaque_predicate_v1",
            "cfg_flatten_v1",
            "scalar_to_struct_indirection_v1",
        )
        if tid in by_id
    ]

    if parity_bundle_ids:
        parity_entries: List[Transform] = []
        for tid in parity_bundle_ids:
            entries = by_id.get(tid, [])
            cap = int(transform_caps.get(tid, 999999))
            parity_entries.extend(_spread_pick(entries, cap))

        if parity_entries:
            parity_plan = _apply_flat_transforms_back_into_plan(base_plan, parity_entries)
            parity_plan["id"] = "bian_parity_bundle"
            parity_plan.setdefault("meta", {})
            if isinstance(parity_plan["meta"], dict):
                parity_plan["meta"] = {
                    **parity_plan["meta"],
                    "candidate_kind": "bian_parity_bundle",
                    "distinct_ids": len(set(parity_bundle_ids)),
                }
            if not _maybe_add(parity_plan):
                return candidate_plans

    # Decide subset size range over DISTINCT IDs
    # Ensure min_size respects policy min_distinct_transform_ids
    eff_min = max(int(min_subset_size), int(min_distinct_transform_ids), 1)
    eff_max = max(int(max_subset_size), eff_min)

    # If user provided transform_weights, do a few weighted samples first (good diversity fast),
    # then fall back to combinational largest-first for coverage.
    weighted_rounds = int(policy.get("optimizer_weighted_rounds", 8))
    for _ in range(max(0, weighted_rounds)):
        k = min(eff_max, len(all_ids))
        if k <= 0:
            break
        chosen_ids = _weighted_choice_no_replace(all_ids, transform_weights, k, rng)
        if len(chosen_ids) < eff_min:
            continue

        subset_entries: List[Transform] = []
        for tid in chosen_ids:
            entries = by_id.get(tid, [])
            cap = int(transform_caps.get(tid, 999999))
            subset_entries.extend(_spread_pick(entries, cap))

        # parameter mutation (optional)
        transform_variants: List[List[Transform]] = [[]]
        for t in subset_entries:
            muts = mutate_transform_params(t) if enable_param_mutation else [t]
            transform_variants = [prev + [m] for prev in transform_variants for m in muts]

        for tv in transform_variants:
            plan = _apply_flat_transforms_back_into_plan(base_plan, tv)
            plan["plan_id"] = _plan_id_from_transforms(tv)
            plan.pop("id", None)
            plan.setdefault("meta", {})
            if isinstance(plan["meta"], dict):
                plan["meta"] = {**plan["meta"], "candidate_kind": "subset_weighted", "distinct_ids": len(set(chosen_ids))}
            if not _maybe_add(plan):
                return candidate_plans

    # DISTINCT-ID subsets (STREAMING, largest-first)
    for id_subset in iter_id_subsets(
        all_ids,
        max_size=eff_max,
        include_empty=False,
        min_size=eff_min,
    ):
        # Materialize ids -> entries (caps + spreading)
        subset_entries: List[Transform] = []
        for tid in id_subset:
            entries = by_id.get(tid, [])
            cap = int(transform_caps.get(tid, 999999))
            subset_entries.extend(_spread_pick(entries, cap))

        # parameter mutation (optional)
        transform_variants: List[List[Transform]] = [[]]
        for t in subset_entries:
            muts = mutate_transform_params(t) if enable_param_mutation else [t]
            transform_variants = [prev + [m] for prev in transform_variants for m in muts]

        # build plans (preserve function-style if needed)
        for tv in transform_variants:
            plan = _apply_flat_transforms_back_into_plan(base_plan, tv)
            plan["plan_id"] = _plan_id_from_transforms(tv)
            plan.pop("id", None)
            plan.setdefault("meta", {})
            if isinstance(plan["meta"], dict):
                plan["meta"] = {**plan["meta"], "candidate_kind": "subset", "distinct_ids": len(set(id_subset))}
            if not _maybe_add(plan):
                return candidate_plans

    uniq: Dict[str, Plan] = {}
    for p in candidate_plans:
        pid = str(p.get("id", "")).strip()
        if not pid:
            pid = json.dumps(p, sort_keys=True)
            p["id"] = pid
        uniq[pid] = p

    final_plans = list(uniq.values())
    final_plans.sort(
        key=lambda p: float((p.get("meta") or {}).get("composition_bonus", 0.0)),
        reverse=True,
    )

    return final_plans


# -----------------------------
# Convenience wrappers
# -----------------------------

def generate_simple_variants(
    base_plan: Plan,
    *,
    k: int = 3,
) -> List[Plan]:
    """
    Simplest helper:
      - pick up to k DISTINCT ids (materialized into entries)
      - no mutation
      - no tier logic
    """
    return generate_candidate_plans(
        base_plan=base_plan,
        max_subset_size=k,
        max_tier=None,
        enable_param_mutation=False,
        llm_candidate_plans=None,
        min_subset_size=1,
        include_full_plan_first=True,
        max_candidates=None,
    )