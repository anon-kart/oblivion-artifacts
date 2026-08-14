# optimizer/search.py
"""
Variant search / optimizer (v1)

Goal
----
Given a set of available obfuscation "plans" (each plan = list of transforms),
search for the best candidate under your validator gates.

This module is intentionally generic and does NOT assume a particular
variants_plan.json schema beyond:
  - a "candidate plan" can be represented as a dict with enough info for your
    obfuscation engine to apply it.

You wire it up from your runner like:
  1) generate base plan(s) from decision_planner
  2) expand into candidate plans (different combinations/tiers)
  3) for each candidate:
        - apply_variants_plan(...)
        - validate_candidate(...)
        - score with adversarial scorer (bytecode/opcode metrics, etc.)
  4) pick best passing candidate (or best overall if none pass)

This file provides:
  - greedy_search: iteratively add transforms that improve score while passing
  - beam_search: keep top-K partial plans at each depth
  - small utilities to combine plans and rank results

Key design choice:
------------------
We treat "apply + validate + score" as a callback (EvaluateFn) that you provide.
So this module stays pure-Python and independent of Foundry/forge.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


# -----------------------------
# Types
# -----------------------------

Plan = Dict[str, Any]

# EvaluateFn returns an EvaluationResult for a given plan.
# You implement this elsewhere (likely in oblivion_runner.py).
EvaluateFn = Callable[[Plan], "EvaluationResult"]

@dataclass(frozen=True)
class EvaluationResult:
    """
    One evaluation of a plan.

    objective_score: weighted optimizer objective
    potency_score: obfuscation potency proxy
    overhead_score: deployment/runtime overhead proxy
    risk_score: security / detector-surface risk proxy

    score is kept as a compatibility alias for objective_score.
    """
    plan: Plan
    score: float
    accepted: bool
    reason: str = ""
    artifacts: Dict[str, Any] = None  # type: ignore
    potency_score: float = 0.0
    overhead_score: float = 0.0
    risk_score: float = 0.0
    objective_score: float = 0.0

@dataclass(frozen=True)
class SearchResult:
    """
    Output of a search run.
    """
    best: Optional[EvaluationResult]
    best_accepted: Optional[EvaluationResult]
    evaluated: Tuple[EvaluationResult, ...]
    note: str = ""


# -----------------------------
# Utilities
# -----------------------------

def _plan_id(plan: Plan) -> str:
    """
    Produce a stable-ish identifier for deduping.
    Prefer an explicit plan id if present; else fall back to repr.
    """
    if isinstance(plan, dict):
        if "id" in plan and isinstance(plan["id"], str):
            return plan["id"]
        if "name" in plan and isinstance(plan["name"], str):
            return plan["name"]
    return repr(plan)


def _dedupe(plans: Sequence[Plan]) -> List[Plan]:
    seen = set()
    out: List[Plan] = []
    for p in plans:
        pid = _plan_id(p)
        if pid in seen:
            continue
        seen.add(pid)
        out.append(p)
    return out


def _topk(results: Sequence[EvaluationResult], k: int) -> List[EvaluationResult]:
    if k <= 0:
        return []
    return sorted(results, key=lambda r: r.score, reverse=True)[:k]


def _choose_best(results: Sequence[EvaluationResult]) -> Optional[EvaluationResult]:
    if not results:
        return None
    return max(results, key=lambda r: r.score)


def _choose_best_accepted(results: Sequence[EvaluationResult]) -> Optional[EvaluationResult]:
    accepted = [r for r in results if r.accepted]
    return _choose_best(accepted)


def combine_plans(base: Plan, delta: Plan) -> Plan:
    """
    Combine two plan dicts.

    Convention (recommended for your pipeline):
      base = {"transforms": [...], "meta": {...}}
      delta = {"transforms": [...], "meta": {...}}

    This function:
      - concatenates transforms if both have list "transforms"
      - shallow-merges other keys (delta overrides base)
      - keeps a composite "id" if none exists

    If your schema is different, adjust here (single choke point).
    """
    out = dict(base)

    # merge transforms
    bt = out.get("transforms")
    dt = delta.get("transforms")
    if isinstance(bt, list) and isinstance(dt, list):
        out["transforms"] = list(bt) + list(dt)
    elif isinstance(dt, list):
        out["transforms"] = list(dt)

    # merge other keys
    for k, v in delta.items():
        if k == "transforms":
            continue
        out[k] = v

    # id
    if "id" not in out:
        out["id"] = f"{_plan_id(base)}+{_plan_id(delta)}"

    return out


def make_incremental_candidates(
    *,
    base_plan: Plan,
    transform_options: Sequence[Plan],
) -> List[Plan]:
    """
    Build candidate plans = base + each option.
    """
    cands = [combine_plans(base_plan, opt) for opt in transform_options]
    return _dedupe(cands)


# -----------------------------
# Greedy search
# -----------------------------

def greedy_search(
    *,
    base_plan: Plan,
    transform_options: Sequence[Plan],
    evaluate: EvaluateFn,
    max_steps: int = 8,
    require_acceptance: bool = True,
) -> SearchResult:
    """
    Greedy hill-climb:
      Start from base_plan.
      At each step, try adding ONE transform option that most improves score.
      Keep it if it (a) improves score and (b) passes validator (if require_acceptance).

    Notes:
      - Works well when transforms are "mostly independent".
      - Not guaranteed optimal.
    """
    evaluated: List[EvaluationResult] = []

    current = evaluate(base_plan)
    evaluated.append(current)

    used_ids = set()
    used_ids.add(_plan_id(base_plan))

    steps = 0
    remaining = list(_dedupe(transform_options))

    while steps < max_steps and remaining:
        steps += 1

        # Evaluate each single-step extension
        best_next: Optional[EvaluationResult] = None
        best_next_idx: Optional[int] = None

        for idx, opt in enumerate(remaining):
            cand = combine_plans(current.plan, opt)
            pid = _plan_id(cand)
            if pid in used_ids:
                continue

            res = evaluate(cand)
            evaluated.append(res)

            ok = res.accepted or not require_acceptance
            improves = res.score > current.score

            if ok and improves:
                if best_next is None or res.score > best_next.score:
                    best_next = res
                    best_next_idx = idx

        if best_next is None:
            break

        # Commit best improvement
        current = best_next
        used_ids.add(_plan_id(current.plan))

        # Remove the chosen option so we don't re-add it endlessly
        if best_next_idx is not None and 0 <= best_next_idx < len(remaining):
            remaining.pop(best_next_idx)

    return SearchResult(
        best=_choose_best(evaluated),
        best_accepted=_choose_best_accepted(evaluated),
        evaluated=tuple(evaluated),
        note="greedy_search",
    )


# -----------------------------
# Beam search
# -----------------------------

def beam_search(
    *,
    base_plan: Plan,
    transform_options: Sequence[Plan],
    evaluate: EvaluateFn,
    beam_width: int = 5,
    max_depth: int = 4,
    require_acceptance: bool = True,
) -> SearchResult:
    """
    Beam search over combinations.

    At each depth:
      - expand each plan in the beam by adding each transform option once
      - evaluate all expanded plans
      - keep top-K by score (optionally only accepted ones)

    Compared to greedy:
      - explores multiple branches
      - still bounded (beam_width * options * depth)
    """
    evaluated: List[EvaluationResult] = []

    # Evaluate base
    base_eval = evaluate(base_plan)
    evaluated.append(base_eval)

    beam: List[EvaluationResult] = [base_eval]
    options = list(_dedupe(transform_options))

    seen = set()
    seen.add(_plan_id(base_plan))

    for depth in range(1, max_depth + 1):
        expanded: List[EvaluationResult] = []

        for parent in beam:
            for opt in options:
                cand = combine_plans(parent.plan, opt)
                pid = _plan_id(cand)
                if pid in seen:
                    continue
                seen.add(pid)

                res = evaluate(cand)
                evaluated.append(res)
                expanded.append(res)

        if not expanded:
            break

        if require_acceptance:
            expanded_ok = [r for r in expanded if r.accepted]
            # If nothing accepted, keep *something* so search can continue,
            # otherwise we stop early (useful when constraints are tight).
            if expanded_ok:
                beam = _topk(expanded_ok, beam_width)
            else:
                beam = _topk(expanded, beam_width)
        else:
            beam = _topk(expanded, beam_width)

    return SearchResult(
        best=_choose_best(evaluated),
        best_accepted=_choose_best_accepted(evaluated),
        evaluated=tuple(evaluated),
        note=f"beam_search(beam_width={beam_width}, max_depth={max_depth})",
    )


# -----------------------------
# Exhaustive search (bounded)
# -----------------------------

def exhaustive_search(
    *,
    base_plan: Plan,
    candidate_plans: Sequence[Plan],
    evaluate: EvaluateFn,
) -> SearchResult:
    """
    Evaluate a fixed list of candidate plans (no generation).

    Useful if your decision_planner already emits a list of complete plans.
    """
    evaluated: List[EvaluationResult] = []
    for p in _dedupe([base_plan] + list(candidate_plans)):
        evaluated.append(evaluate(p))

    return SearchResult(
        best=_choose_best(evaluated),
        best_accepted=_choose_best_accepted(evaluated),
        evaluated=tuple(evaluated),
        note=f"exhaustive_search(n={len(evaluated)})",
    )


# -----------------------------
# Result formatting helpers
# -----------------------------

def summarize_search_result(sr: SearchResult) -> Dict[str, Any]:
    """
    Turn SearchResult into a JSON-friendly summary.
    """
    best = sr.best
    best_acc = sr.best_accepted

    def pack(r: Optional[EvaluationResult]) -> Optional[Dict[str, Any]]:
        if r is None:
            return None
        return {
            "score": r.score,
            "objective_score": r.objective_score if r.objective_score else r.score,
            "potency_score": r.potency_score,
            "overhead_score": r.overhead_score,
            "risk_score": r.risk_score,
            "accepted": r.accepted,
            "reason": r.reason,
            "plan_id": _plan_id(r.plan),
            "artifacts": r.artifacts or {},
        }

    return {
        "note": sr.note,
        "best": pack(best),
        "best_accepted": pack(best_acc),
        "evaluated_count": len(sr.evaluated),
        "accepted_count": sum(1 for r in sr.evaluated if r.accepted),
    }
