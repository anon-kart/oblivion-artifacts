from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


def discover_uncovered_targets(
    *,
    coverage: Dict[str, Any],
    contract_source_path: Path,
    contract_name: str,
    max_targets: int = 12,
    ir_json: Optional[Dict[str, Any]] = None,
    ir_json_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """
    Compute uncovered functions / low-hit functions / cold line clusters.
    Optionally enrich using IR.

    Output entries are designed to feed directly into the LLM augmentation stage.
    """
    normalized_contract_path = normalize_contract_key(contract_source_path)
    file_cov = best_matching_coverage_entry(coverage, normalized_contract_path)

    if ir_json is None and ir_json_path is not None and Path(ir_json_path).exists():
        try:
            ir_json = json.loads(Path(ir_json_path).read_text(encoding="utf-8"))
        except Exception:
            ir_json = None

    function_meta = _extract_ir_function_meta(ir_json, contract_name)
    line_to_function = _build_line_to_function_map(function_meta)

    targets: List[Dict[str, Any]] = []

    if not file_cov:
        fallback = {
            "target_type": "contract",
            "contract": contract_name,
            "source": normalized_contract_path,
            "reason": "no_coverage_entry_found",
            "priority": 1.0,
            "target_id": f"{contract_name}:contract:no_coverage_entry_found",
            "semantic_tags": ["general_behavior_target"],
            "constructor_context_required": bool(_contract_has_constructor(ir_json, contract_name)),
            "suggested_test_intent": ["constructor_smoke", "public_function_smoke"],
        }
        return [fallback]

    fn_hits_raw = file_cov.get("functions", {}) or {}
    fn_hits: Dict[str, int] = {}
    for raw_name, hits in fn_hits_raw.items():
        short_name = _normalize_cov_function_name(raw_name)
        if not short_name or short_name == "constructor":
            continue
        fn_hits[short_name] = max(_safe_int(hits, default=0) or 0, fn_hits.get(short_name, 0))

    line_hits = file_cov.get("lines", {}) or {}

    # 1) Function targets from LCOV function counts
    for fn_name, hits in fn_hits.items():
        if str(fn_name).strip() == "constructor":
            continue

        h = _safe_int(hits, default=0) or 0
        meta = function_meta.get(fn_name, {})

        reason = None
        priority = 0.0
        if h <= 0:
            reason = "function_uncovered"
            priority = 1.0
        elif h <= 2:
            reason = "function_low_hit"
            priority = 0.85
        elif h <= 5:
            reason = "function_lightly_hit"
            priority = 0.65

        if not reason:
            continue

        targets.append(
            _build_function_target(
                contract_name=contract_name,
                source=normalized_contract_path,
                fn_name=fn_name,
                hits=h,
                reason=reason,
                priority=priority,
                meta=meta,
            )
        )

    # 2) IR functions not seen in LCOV
    for fn_name, meta in function_meta.items():
        if str(fn_name).strip() == "constructor":
            continue
        if fn_name in fn_hits:
            continue
        if str(meta.get("visibility") or "").lower() not in {"public", "external"}:
            continue

        line_start = meta.get("line_start")
        line_end = meta.get("line_end")
        if not isinstance(line_start, int) or not isinstance(line_end, int):
            continue
        if line_start <= 0 or line_end < line_start:
            continue

        targets.append(
            _build_function_target(
                contract_name=contract_name,
                source=normalized_contract_path,
                fn_name=fn_name,
                hits=0,
                reason="function_missing_from_coverage",
                priority=0.9,
                meta=meta,
            )
        )

    # 3) Cold and low-hit lines
    cold_lines: List[int] = []
    low_lines: List[int] = []
    for line_no, hits in line_hits.items():
        ln = _safe_int(line_no, default=-1)
        h = _safe_int(hits, default=-1)
        if ln is None or h is None or ln <= 0 or h < 0:
            continue
        if h == 0:
            cold_lines.append(ln)
        elif h <= 1:
            low_lines.append(ln)

    cold_clusters = _cluster_lines(sorted(cold_lines))
    low_clusters = _cluster_lines(sorted(low_lines))

    for cluster in cold_clusters[:4]:
        owner = _dominant_function_for_lines(cluster, line_to_function)
        intents = _cluster_test_intents(owner, function_meta)
        targets.append(
            {
                "target_type": "line_cluster",
                "contract": contract_name,
                "source": normalized_contract_path,
                "lines": cluster,
                "owner_function": owner,
                "reason": "cold_lines_detected",
                "priority": 0.8,
                "target_id": f"{contract_name}:cluster:{cluster[0]}-{cluster[-1]}:cold",
                "semantic_tags": ["cold_cluster_target"] + intents,
                "constructor_context_required": bool(_contract_has_constructor(ir_json, contract_name)),
                "suggested_test_intent": intents,
            }
        )

    for cluster in low_clusters[:4]:
        owner = _dominant_function_for_lines(cluster, line_to_function)
        intents = _cluster_test_intents(owner, function_meta)
        targets.append(
            {
                "target_type": "line_cluster",
                "contract": contract_name,
                "source": normalized_contract_path,
                "lines": cluster,
                "owner_function": owner,
                "reason": "low_hit_lines_detected",
                "priority": 0.65,
                "target_id": f"{contract_name}:cluster:{cluster[0]}-{cluster[-1]}:low",
                "semantic_tags": ["low_hit_cluster_target"] + intents,
                "constructor_context_required": bool(_contract_has_constructor(ir_json, contract_name)),
                "suggested_test_intent": intents,
            }
        )

    # 4) Dedup and sort
    deduped = _dedupe_targets(targets)
    deduped.sort(key=lambda x: float(x.get("priority", 0.0)), reverse=True)
    return deduped[:max_targets]


def normalize_contract_key(contract_source_path: Path) -> str:
    p = Path(contract_source_path)
    parts = p.parts
    if "src" in parts:
        idx = parts.index("src")
        return "/".join(parts[idx:])
    return p.as_posix()


def best_matching_coverage_entry(
    coverage: Dict[str, Any],
    normalized_contract_path: str,
) -> Dict[str, Any]:
    if normalized_contract_path in coverage:
        return coverage[normalized_contract_path]

    basename = Path(normalized_contract_path).name
    for key, value in coverage.items():
        if Path(str(key)).name == basename and isinstance(value, dict):
            return value
    return {}


def _normalize_cov_function_name(name: str) -> str:
    s = str(name or "").strip()
    if not s:
        return s
    return s.split(".")[-1]


def _build_function_target(
    *,
    contract_name: str,
    source: str,
    fn_name: str,
    hits: int,
    reason: str,
    priority: float,
    meta: Dict[str, Any],
) -> Dict[str, Any]:
    visibility = str(meta.get("visibility") or "unknown")
    mutability = str(meta.get("state_mutability") or "nonpayable")
    params = list(meta.get("params") or [])
    loop_count = _safe_int(meta.get("loop_count"), default=0) or 0
    require_count = _safe_int(meta.get("require_count"), default=0) or 0
    storage_writes = list(meta.get("storage_writes") or [])
    external_calls = list(meta.get("external_calls") or [])

    semantic_tags = _semantic_tags_for_function(
        params=params,
        mutability=mutability,
        loop_count=loop_count,
        require_count=require_count,
        storage_write_count=len(storage_writes),
        external_call_count=len(external_calls),
    )

    return {
        "target_type": "function",
        "contract": contract_name,
        "source": source,
        "function": fn_name,
        "signature": _function_signature(fn_name, params),
        "visibility": visibility,
        "state_mutability": mutability,
        "hits": hits,
        "reason": reason,
        "priority": priority,
        "target_id": f"{contract_name}:{fn_name}:{reason}",
        "semantic_tags": semantic_tags,
        "constructor_context_required": bool(meta.get("constructor_context_required", False)),
        "loop_count": loop_count,
        "require_count": require_count,
        "storage_write_count": len(storage_writes),
        "external_call_count": len(external_calls),
        "suggested_test_intent": _function_test_intents(
            fn_name=fn_name,
            params=params,
            mutability=mutability,
            loop_count=loop_count,
            require_count=require_count,
            storage_write_count=len(storage_writes),
            external_call_count=len(external_calls),
        ),
    }


def _semantic_tags_for_function(
    *,
    params: Sequence[Dict[str, Any]],
    mutability: str,
    loop_count: int,
    require_count: int,
    storage_write_count: int,
    external_call_count: int,
) -> List[str]:
    tags: List[str] = []

    if loop_count > 0:
        tags.append("loop_bound_target")
    if require_count > 0:
        tags.append("revert_guard_target")
    if storage_write_count > 0:
        tags.append("storage_write_target")
    if external_call_count > 0:
        tags.append("external_call_target")
    if str(mutability).lower() == "payable":
        tags.append("payable_flow_target")

    for p in params:
        typ = str((p or {}).get("type") or "")
        if "[]" in typ:
            tags.append("array_edge_target")
            break

    if not tags:
        tags.append("general_behavior_target")

    return sorted(set(tags))


def _extract_ir_function_meta(ir_json: Optional[Dict[str, Any]], contract_name: str) -> Dict[str, Dict[str, Any]]:
    if not isinstance(ir_json, dict):
        return {}

    candidates: List[Dict[str, Any]] = []

    contract = ir_json.get("contract")
    if isinstance(contract, dict):
        if str(contract.get("name") or "") == contract_name:
            candidates.append(contract)

    contracts = ir_json.get("contracts")
    if isinstance(contracts, list):
        for c in contracts:
            if isinstance(c, dict) and str(c.get("name") or "") == contract_name:
                candidates.append(c)

    for c in candidates:
        functions = c.get("functions")
        if isinstance(functions, list):
            out: Dict[str, Dict[str, Any]] = {}
            has_ctor = bool(c.get("constructor"))
            for fn in functions:
                if not isinstance(fn, dict):
                    continue
                name = str(fn.get("name") or "").strip()
                if not name or name == "constructor":
                    continue
                out[name] = {
                    "name": name,
                    "visibility": fn.get("visibility"),
                    "state_mutability": fn.get("state_mutability"),
                    "params": fn.get("params") or [],
                    "line_start": _extract_line_start(fn),
                    "line_end": _extract_line_end(fn),
                    "loop_count": _extract_loop_count(fn),
                    "require_count": _extract_require_count(fn),
                    "storage_writes": fn.get("storage_writes") or [],
                    "external_calls": fn.get("external_calls") or [],
                    "constructor_context_required": has_ctor,
                }
            if out:
                return out

    contract_top = ir_json.get("contract")
    if isinstance(contract_top, dict):
        functions = contract_top.get("functions")
        if isinstance(functions, list):
            out: Dict[str, Dict[str, Any]] = {}
            has_ctor = bool(contract_top.get("constructor"))
            for fn in functions:
                if not isinstance(fn, dict):
                    continue
                name = str(fn.get("name") or "").strip()
                if not name or name == "constructor":
                    continue
                out[name] = {
                    "name": name,
                    "visibility": fn.get("visibility"),
                    "state_mutability": fn.get("state_mutability"),
                    "params": fn.get("params") or [],
                    "line_start": _extract_line_start(fn),
                    "line_end": _extract_line_end(fn),
                    "loop_count": _extract_loop_count(fn),
                    "require_count": _extract_require_count(fn),
                    "storage_writes": fn.get("storage_writes") or [],
                    "external_calls": fn.get("external_calls") or [],
                    "constructor_context_required": has_ctor,
                }
            return out

    return {}


def _contract_has_constructor(ir_json: Optional[Dict[str, Any]], contract_name: str) -> bool:
    if not isinstance(ir_json, dict):
        return False

    contract = ir_json.get("contract")
    if isinstance(contract, dict) and str(contract.get("name") or "") == contract_name:
        return bool(contract.get("constructor"))

    contracts = ir_json.get("contracts")
    if isinstance(contracts, list):
        for c in contracts:
            if isinstance(c, dict) and str(c.get("name") or "") == contract_name:
                return bool(c.get("constructor"))

    return False


def _extract_line_start(fn: Dict[str, Any]) -> Optional[int]:
    loc = fn.get("loc") or {}
    if isinstance(loc, dict):
        start = loc.get("start") or {}
        if isinstance(start, dict):
            line = start.get("line")
            if line is not None:
                return _safe_int(line, default=None)
    line = fn.get("line_start")
    if line is not None:
        return _safe_int(line, default=None)
    return None


def _extract_line_end(fn: Dict[str, Any]) -> Optional[int]:
    loc = fn.get("loc") or {}
    if isinstance(loc, dict):
        end = loc.get("end") or {}
        if isinstance(end, dict):
            line = end.get("line")
            if line is not None:
                return _safe_int(line, default=None)
    line = fn.get("line_end")
    if line is not None:
        return _safe_int(line, default=None)
    return None


def _extract_loop_count(fn: Dict[str, Any]) -> int:
    loops = fn.get("loops")
    if isinstance(loops, list):
        return len(loops)
    loop_count = fn.get("loop_count")
    return _safe_int(loop_count, default=0) or 0


def _extract_require_count(fn: Dict[str, Any]) -> int:
    reqs = fn.get("requires")
    if isinstance(reqs, list):
        return len(reqs)
    req_count = fn.get("require_count")
    return _safe_int(req_count, default=0) or 0


def _build_line_to_function_map(
    function_meta: Dict[str, Dict[str, Any]]
) -> Dict[int, str]:
    mapping: Dict[int, str] = {}
    for fn_name, meta in function_meta.items():
        start = meta.get("line_start")
        end = meta.get("line_end")
        if isinstance(start, int) and isinstance(end, int) and start > 0 and end >= start:
            for line in range(start, end + 1):
                mapping[line] = fn_name
    return mapping


def _dominant_function_for_lines(
    lines: Sequence[int],
    line_to_function: Dict[int, str],
) -> Optional[str]:
    counts: Dict[str, int] = {}
    for ln in lines:
        owner = line_to_function.get(ln)
        if owner:
            counts[owner] = counts.get(owner, 0) + 1
    if not counts:
        return None
    return max(counts.items(), key=lambda kv: kv[1])[0]


def _cluster_lines(lines: Sequence[int], gap: int = 2, min_cluster_len: int = 2) -> List[List[int]]:
    if not lines:
        return []

    clusters: List[List[int]] = []
    current: List[int] = [int(lines[0])]

    for ln in lines[1:]:
        ln = int(ln)
        if ln - current[-1] <= gap:
            current.append(ln)
        else:
            if len(current) >= min_cluster_len:
                clusters.append(current)
            current = [ln]

    if len(current) >= min_cluster_len:
        clusters.append(current)

    return clusters


def _function_signature(fn_name: str, params: Sequence[Dict[str, Any]]) -> str:
    types = []
    for p in params:
        if isinstance(p, dict):
            types.append(str(p.get("type") or "unknown"))
        else:
            types.append("unknown")
    return f"{fn_name}({', '.join(types)})"


def _function_test_intents(
    *,
    fn_name: str,
    params: Sequence[Dict[str, Any]],
    mutability: str,
    loop_count: int,
    require_count: int,
    storage_write_count: int,
    external_call_count: int,
) -> List[str]:
    intents: List[str] = []

    if loop_count > 0:
        intents.extend([
            "small_bound_case",
            "zero_or_empty_case",
            "upper_bound_case",
        ])

    if require_count > 0:
        intents.extend([
            "guard_revert_case",
            "guard_success_case",
        ])

    if storage_write_count > 0:
        intents.append("state_mutation_invariant_case")

    if external_call_count > 0:
        intents.append("external_interaction_smoke_case")

    if str(mutability).lower() == "payable":
        intents.append("payable_value_case")

    if not intents:
        intents.append("smoke_case")

    if any("[]" in str((p or {}).get("type") or "") for p in params if isinstance(p, dict)):
        intents.extend([
            "empty_array_case",
            "single_element_array_case",
            "small_array_fuzz_case",
        ])

    lname = fn_name.lower()
    if "sort" in lname:
        intents.extend(["already_sorted_case", "reverse_sorted_case"])
    if "sum" in lname or "accumulate" in lname:
        intents.extend(["zero_input_case", "small_input_case"])
    if "deposit" in lname:
        intents.extend(["first_deposit_case", "repeat_deposit_case"])

    return _stable_unique(intents)


def _cluster_test_intents(
    owner_function: Optional[str],
    function_meta: Dict[str, Dict[str, Any]],
) -> List[str]:
    if not owner_function or owner_function not in function_meta:
        return ["smoke_case", "line_cluster_probe_case"]
    meta = function_meta[owner_function]
    return _function_test_intents(
        fn_name=owner_function,
        params=meta.get("params") or [],
        mutability=str(meta.get("state_mutability") or "nonpayable"),
        loop_count=_safe_int(meta.get("loop_count"), default=0) or 0,
        require_count=_safe_int(meta.get("require_count"), default=0) or 0,
        storage_write_count=len(meta.get("storage_writes") or []),
        external_call_count=len(meta.get("external_calls") or []),
    )


def _dedupe_targets(targets: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []

    for t in targets:
        if t.get("target_type") == "function":
            key = ("function", t.get("function"), t.get("reason"))
        elif t.get("target_type") == "line_cluster":
            key = ("line_cluster", tuple(t.get("lines") or []), t.get("reason"))
        else:
            key = ("other", t.get("reason"), t.get("source"))

        if key in seen:
            continue
        seen.add(key)
        out.append(dict(t))

    return out


def _stable_unique(items: Sequence[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out


def _safe_int(value: Any, default: Optional[int] = 0) -> Optional[int]:
    try:
        return int(value)
    except Exception:
        return default