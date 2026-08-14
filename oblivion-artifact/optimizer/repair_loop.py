from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class RepairPolicy:
    """
    Deterministic reject/repair policy.

    Rules:
    - if compile fails -> drop the last transform, retry
    - if tests fail    -> drop newest CONTROL-FLOW transform first, else drop last, retry
    - if security diff adds HIGH/CRITICAL -> drop transforms with risk_tags: touches_storage|touches_calls, retry
    """
    max_attempts: int = 8
    control_flow_ids: Tuple[str, ...] = (
        "opaque_predicate_v1",
        "cfg_flatten_partial_v1",
        "cfg_flatten_v1",
        "loop_rewrite_v1",
        "predicate_masking_v1",
        "yul_microblock_v1",
    )
    risky_tags: Tuple[str, ...] = ("touches_storage", "touches_calls")


@dataclass
class RepairOutcome:
    ok: bool
    attempts: int
    final_transforms: List[Dict[str, Any]]
    reason: str
    history: List[Dict[str, Any]]


# These runner callbacks make this module usable without importing your whole pipeline.
# You wire them from your orchestrator/validator.
CompileFn = Callable[[List[Dict[str, Any]]], Tuple[bool, str]]
TestsFn = Callable[[List[Dict[str, Any]]], Tuple[bool, str]]
SecDiffFn = Callable[[List[Dict[str, Any]]], Tuple[bool, Dict[str, Any]]]
# SecDiffFn returns: (ok, diff_json), where ok indicates the scan succeeded,
# and diff_json contains at least: {"counts":{"new_high_or_critical": <int>}, ...}


def _drop_last(transforms: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
    if not transforms:
        return transforms, "no_transforms_to_drop"
    dropped = transforms[-1].get("id", "<unknown>")
    return transforms[:-1], f"dropped_last:{dropped}"


def _drop_newest_control_flow(policy: RepairPolicy, transforms: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
    if not transforms:
        return transforms, "no_transforms_to_drop"

    # drop newest (last in list) whose id is in control_flow_ids
    for i in range(len(transforms) - 1, -1, -1):
        tid = transforms[i].get("id", "")
        if tid in policy.control_flow_ids:
            out = transforms[:i] + transforms[i + 1 :]
            return out, f"dropped_control_flow:{tid}"

    # fallback
    return _drop_last(transforms)


def _drop_by_risk_tags(transforms: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
    """
    Deterministic: remove any transform whose params contains risk_tags hitting touches_storage|touches_calls.
    This supports a "defense in depth" drop if your planner/engine annotates params with risk_tags.

    Expected shape (optional):
      {"id": "...", "params": {"risk_tags": ["touches_storage"]}}
    """
    if not transforms:
        return transforms, "no_transforms_to_drop"

    keep: List[Dict[str, Any]] = []
    dropped: List[str] = []
    for tr in transforms:
        tags = ((tr.get("params") or {}).get("risk_tags") or [])
        tagset = set(str(t) for t in tags)
        if "touches_storage" in tagset or "touches_calls" in tagset:
            dropped.append(tr.get("id", "<unknown>"))
        else:
            keep.append(tr)

    if dropped:
        return keep, f"dropped_risky_tags:{','.join(dropped)}"

    # if none tagged, fall back to dropping last
    return _drop_last(transforms)


def repair_loop(
    *,
    initial_transforms: List[Dict[str, Any]],
    compile_fn: CompileFn,
    tests_fn: TestsFn,
    secdiff_fn: Optional[SecDiffFn] = None,
    policy: Optional[RepairPolicy] = None,
) -> RepairOutcome:
    """
    Deterministic reject/repair loop.

    You pass in functions that run *your* pipeline steps on a candidate defined
    only by its transform list.

    Minimal behavior if secdiff_fn is None:
      compile -> tests -> accept/reject with drop rules (compile/tests only).
    """
    pol = policy or RepairPolicy()
    transforms = list(initial_transforms)
    hist: List[Dict[str, Any]] = []

    for attempt in range(1, pol.max_attempts + 1):
        # 1) compile gate
        ok_c, msg_c = compile_fn(transforms)
        hist.append({"attempt": attempt, "phase": "compile", "ok": ok_c, "msg": msg_c, "transforms": [t.get("id") for t in transforms]})
        if not ok_c:
            transforms, action = _drop_last(transforms)
            hist.append({"attempt": attempt, "action": action})
            if not transforms:
                return RepairOutcome(False, attempt, transforms, "compile_failed_and_no_more_transforms", hist)
            continue

        # 2) tests gate
        ok_t, msg_t = tests_fn(transforms)
        hist.append({"attempt": attempt, "phase": "tests", "ok": ok_t, "msg": msg_t})
        if not ok_t:
            transforms, action = _drop_newest_control_flow(pol, transforms)
            hist.append({"attempt": attempt, "action": action})
            if not transforms:
                return RepairOutcome(False, attempt, transforms, "tests_failed_and_no_more_transforms", hist)
            continue

        # 3) security diff gate (optional)
        if secdiff_fn is not None:
            ok_s, diff = secdiff_fn(transforms)
            nh = int((((diff or {}).get("counts") or {}).get("new_high_or_critical") or 0))
            hist.append({"attempt": attempt, "phase": "secdiff", "ok": ok_s, "new_high_or_critical": nh})
            if not ok_s:
                # conservative: drop last on scan failure
                transforms, action = _drop_last(transforms)
                hist.append({"attempt": attempt, "action": action})
                if not transforms:
                    return RepairOutcome(False, attempt, transforms, "secdiff_failed_and_no_more_transforms", hist)
                continue

            if nh > 0:
                transforms, action = _drop_by_risk_tags(transforms)
                hist.append({"attempt": attempt, "action": action})
                if not transforms:
                    return RepairOutcome(False, attempt, transforms, "new_high_or_critical_and_no_more_transforms", hist)
                continue

        # all gates passed
        return RepairOutcome(True, attempt, transforms, "ok", hist)

    return RepairOutcome(False, pol.max_attempts, transforms, "max_attempts_exhausted", hist)
