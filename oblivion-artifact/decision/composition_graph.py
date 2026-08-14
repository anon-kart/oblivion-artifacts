from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Dict, List, Tuple


def _pair_key(a: str, b: str) -> str:
    x, y = sorted([str(a), str(b)])
    return f"{x}|{y}"


def normalize_composition_graph(graph: Dict[str, Any] | None) -> Dict[str, Any]:
    graph = graph or {}
    return {
        "safe_pairs": list(graph.get("safe_pairs") or []),
        "unsafe_pairs": list(graph.get("unsafe_pairs") or []),
        "ordering_constraints": list(graph.get("ordering_constraints") or []),
        "pair_scores": dict(graph.get("pair_scores") or {}),
    }


def filter_graph_to_selected_ids(graph: Dict[str, Any], selected_ids: List[str]) -> Dict[str, Any]:
    selected = set(selected_ids)

    safe_pairs = []
    for pair in graph.get("safe_pairs", []):
        if isinstance(pair, list) and len(pair) == 2 and pair[0] in selected and pair[1] in selected:
            safe_pairs.append(pair)

    unsafe_pairs = []
    for item in graph.get("unsafe_pairs", []):
        pair = item.get("pair") if isinstance(item, dict) else None
        if isinstance(pair, list) and len(pair) == 2 and pair[0] in selected and pair[1] in selected:
            unsafe_pairs.append(item)

    ordering_constraints = []
    for item in graph.get("ordering_constraints", []):
        if not isinstance(item, dict):
            continue
        before = item.get("before")
        after = item.get("after")
        if before in selected and after in selected:
            ordering_constraints.append(item)

    pair_scores = {}
    for k, v in (graph.get("pair_scores") or {}).items():
        try:
            a, b = str(k).split("|", 1)
        except Exception:
            continue
        if a in selected and b in selected:
            pair_scores[k] = v

    return {
        "safe_pairs": safe_pairs,
        "unsafe_pairs": unsafe_pairs,
        "ordering_constraints": ordering_constraints,
        "pair_scores": pair_scores,
    }


def prune_unsafe_plan_steps(plan_steps: List[Dict[str, Any]], graph: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    unsafe = set()
    for item in graph.get("unsafe_pairs", []):
        if not isinstance(item, dict):
            continue
        pair = item.get("pair") or []
        if isinstance(pair, list) and len(pair) == 2:
            unsafe.add(_pair_key(pair[0], pair[1]))

    kept = []
    kept_ids = []
    drops = []

    for step in plan_steps or []:
        tid = step.get("transform_id") if isinstance(step, dict) else None
        if not isinstance(tid, str):
            continue

        blocked = False
        for prev in kept_ids:
            if _pair_key(prev, tid) in unsafe:
                blocked = True
                drops.append(f"composition_unsafe_pair:{prev}|{tid}")
                break

        if not blocked:
            kept.append(step)
            kept_ids.append(tid)

    return kept, drops


def order_plan_steps(plan_steps: List[Dict[str, Any]], graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    id_to_step = {}
    original_order = []
    for step in plan_steps or []:
        tid = step.get("transform_id") if isinstance(step, dict) else None
        if isinstance(tid, str) and tid not in id_to_step:
            id_to_step[tid] = step
            original_order.append(tid)

    indeg = defaultdict(int)
    edges = defaultdict(list)

    for item in graph.get("ordering_constraints", []):
        if not isinstance(item, dict):
            continue
        a = item.get("before")
        b = item.get("after")
        if a in id_to_step and b in id_to_step and b not in edges[a]:
            edges[a].append(b)
            indeg[b] += 1
            indeg[a] += 0

    q = deque([tid for tid in original_order if indeg[tid] == 0])
    out_ids = []

    while q:
        cur = q.popleft()
        out_ids.append(cur)
        for nxt in edges[cur]:
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                q.append(nxt)

    if len(out_ids) != len(id_to_step):
        return [id_to_step[tid] for tid in original_order]

    return [id_to_step[tid] for tid in out_ids]


def composition_bonus_for_ids(ids: List[str], graph: Dict[str, Any]) -> float:
    ids = list(dict.fromkeys(ids))
    pair_scores = dict(graph.get("pair_scores") or {})
    unsafe = set()
    for item in graph.get("unsafe_pairs", []):
        pair = item.get("pair") if isinstance(item, dict) else None
        if isinstance(pair, list) and len(pair) == 2:
            unsafe.add(_pair_key(pair[0], pair[1]))

    score = 0.0
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            k = _pair_key(ids[i], ids[j])
            if k in unsafe:
                score -= 1.0
            score += float(pair_scores.get(k, 0.0))
    return score