"""
Lightweight semantic consistency checks for the IR.

These are best-effort guards (not a replacement for formal validation).
Return a list of problems, or raise ValidationError in strict mode.
"""

from __future__ import annotations
from typing import Any, Dict, List, Set

from ..utils.errors import ValidationError


# ------------------------
# Helpers
# ------------------------

def _is_str_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)

def _is_storage_touch_list(v: Any) -> bool:
    """
    Accept:
      { "var": <str>, "key": <str> }            # indexed storage
      { "var": <str>, "key": null }             # scalar getter/writer encoded with explicit null
      { "var": <str> }                          # scalar getter/writer without key field
    """
    return isinstance(v, list) and all(
        isinstance(x, dict)
        and isinstance(x.get("var"), str) and x.get("var")
        and (
            ("key" not in x) or (x.get("key") is None) or isinstance(x.get("key"), str)
        )
        for x in v
    )

def _is_return_list(v: Any) -> bool:
    """
    Returns should be a list of objects with at least {"type": <str>}.
    Name is optional in our IR.
    """
    return isinstance(v, list) and all(
        isinstance(x, dict) and isinstance(x.get("type"), str) and x.get("type")
        for x in v
    )

def _collect_function_names(ir: Dict[str, Any]) -> Set[str]:
    names: Set[str] = set()
    for f in ir.get("contract", {}).get("functions", []):
        n = (f.get("name") or "").strip()
        if n:
            names.add(n)
    return names


# ------------------------
# Core checks
# ------------------------

def _check_ir_version(ir: Dict[str, Any], allowed: List[str] = None) -> List[str]:
    problems: List[str] = []
    allowed = allowed or ["0.1"]
    ver = str(ir.get("ir_version", "")).strip()
    if not ver:
        problems.append("Missing 'ir_version'.")
    elif ver not in allowed:
        problems.append(f"Unexpected ir_version='{ver}' (allowed: {allowed}).")
    return problems


def _check_functions(ir: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    funcs = ir.get("contract", {}).get("functions", [])
    if not isinstance(funcs, list):
        return ["'contract.functions' must be a list."]
    seen = set()

    for f in funcs:
        if not isinstance(f, dict):
            problems.append("Function entry must be an object.")
            continue

        key = (f.get("contract") or "", f.get("name") or "")
        if key in seen:
            problems.append(f"Duplicate function entry: {key}.")
        else:
            seen.add(key)

        # Required basics
        if not f.get("name"):
            problems.append("Function missing 'name'.")
        if not f.get("visibility"):
            problems.append(f"Function '{f.get('name')}' is missing visibility.")
        if f.get("modifiers") is None or not isinstance(f.get("modifiers"), list):
            problems.append(f"Function '{f.get('name')}' has invalid 'modifiers' (expected list).")
        if f.get("params") is None or not isinstance(f.get("params"), list):
            problems.append(f"Function '{f.get('name')}' has invalid 'params' (expected list).")

        # Optional 'synthetic' must be boolean if present
        if "synthetic" in f and not isinstance(f.get("synthetic"), bool):
            problems.append(f"Function '{f.get('name')}' has non-boolean 'synthetic' flag.")

        # Returns list (objects with 'type': str)
        if "returns" not in f:
            problems.append(f"Function '{f.get('name')}' missing 'returns' (expected list).")
        elif not _is_return_list(f.get("returns")):
            problems.append(f"Function '{f.get('name')}' has invalid 'returns' (expected list[{{type:str}}]).")

        # Effects fields (lists of strings)
        for fld in ("reads", "writes", "member_accesses", "internal_calls", "external_calls", "events_emitted"):
            if fld not in f:
                problems.append(f"Function '{f.get('name')}' missing '{fld}' (expected list).")
            elif not _is_str_list(f.get(fld)):
                problems.append(f"Function '{f.get('name')}' has invalid '{fld}' (expected list[str]).")

        # Storage touches (list of {var, key?})
        if "storage_reads" not in f or not _is_storage_touch_list(f.get("storage_reads")):
            problems.append(f"Function '{f.get('name')}' has invalid 'storage_reads' (expected list[{{var,key?}}]).")
        if "storage_writes" not in f or not _is_storage_touch_list(f.get("storage_writes")):
            problems.append(f"Function '{f.get('name')}' has invalid 'storage_writes' (expected list[{{var,key?}}]).")

        # Loops shape
        loops = f.get("loops", [])
        if not isinstance(loops, list):
            problems.append(f"Function '{f.get('name')}' has invalid 'loops' (expected list).")
            continue

        for lp in loops:
            if not isinstance(lp, dict):
                problems.append(f"Function '{f.get('name')}' loop entry is not an object.")
                continue
            lt = lp.get("type")
            if lt not in {"for", "while", "loop"}:
                problems.append(f"Function '{f.get('name')}' loop has invalid type: {lt}.")

            # Optional body_summary should be an object if present
            if "body_summary" in lp and not isinstance(lp.get("body_summary"), dict):
                problems.append(f"Function '{f.get('name')}' loop 'body_summary' must be an object if present.")

            # Optional bounds object check
            b = lp.get("bounds")
            if b is not None:
                if not isinstance(b, dict):
                    problems.append(f"Function '{f.get('name')}' loop 'bounds' must be an object.")
                else:
                    idx = b.get("index")
                    if idx is not None and not isinstance(idx, str):
                        problems.append(f"Function '{f.get('name')}' loop 'bounds.index' must be a string.")
                    if "inclusive_upper" in b and not isinstance(b.get("inclusive_upper"), (bool, type(None))):
                        problems.append(f"Function '{f.get('name')}' loop 'bounds.inclusive_upper' must be bool or null.")

    return problems


def _check_loops_reference_declared_functions(ir: Dict[str, Any]) -> List[str]:
    """
    build_ir groups loops under functions, so this is mostly shape check.
    """
    problems: List[str] = []
    funcs = {f.get("name"): f for f in ir.get("contract", {}).get("functions", []) if isinstance(f, dict)}
    for f in funcs.values():
        for lp in f.get("loops", []):
            if not isinstance(lp, dict) or not lp.get("type"):
                problems.append(f"Function '{f.get('name')}' has a malformed loop entry.")
            # If bounds.index exists and body_summary.indices exists, ensure membership
            b = lp.get("bounds")
            bs = lp.get("body_summary", {})
            if isinstance(b, dict) and isinstance(bs, dict):
                idx = b.get("index")
                indices = bs.get("indices", [])
                if idx and isinstance(indices, list) and idx not in indices:
                    problems.append(
                        f"Function '{f.get('name')}' loop bounds index '{idx}' not present in body_summary.indices."
                    )
    return problems


def _check_requires_are_strings(ir: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    for f in ir.get("contract", {}).get("functions", []):
        reqs = f.get("requires", [])
        if not isinstance(reqs, list) or any(not isinstance(r, str) for r in reqs):
            problems.append(f"Function '{f.get('name')}' has non-string 'requires' entries.")
    return problems


def _check_state(ir: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    state = ir.get("contract", {}).get("state", {})
    for v in state.get("variables", []):
        if not v.get("name") or not v.get("type"):
            problems.append("State variable missing 'name' or 'type'.")
    for m in state.get("mappings", []):
        if not (m.get("name") and m.get("key") and m.get("value")):
            problems.append("Mapping missing 'name', 'key' or 'value'.")
    return problems


def _check_access_control(ir: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    acl = ir.get("contract", {}).get("access_control", [])
    if not isinstance(acl, list):
        problems.append("'contract.access_control' must be a list.")
        return problems
    for e in acl:
        if not isinstance(e, dict):
            problems.append("Access control entry must be an object.")
            continue
        if not all(k in e and isinstance(e[k], str) and e[k] for k in ("function", "modifier", "role")):
            problems.append("Access control edge has missing/invalid 'function', 'modifier', or 'role'.")
    return problems


def _check_access_dependencies(ir: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    deps = ir.get("contract", {}).get("access_dependencies", [])
    if deps is None:
        return problems  # optional
    if not isinstance(deps, list):
        problems.append("'contract.access_dependencies' must be a list if present.")
        return problems
    for d in deps:
        if not isinstance(d, dict):
            problems.append("Access dependency entry must be an object.")
            continue
        if not isinstance(d.get("function"), str):
            problems.append("Access dependency missing/invalid 'function' (str).")
        if not isinstance(d.get("source"), str):
            problems.append("Access dependency missing/invalid 'source' (str).")
        # condition may be empty but must be a string if present
        if "condition" in d and not isinstance(d.get("condition"), str):
            problems.append("Access dependency 'condition' must be a string.")
        if "role" in d and d.get("role") is not None and not isinstance(d.get("role"), str):
            problems.append("Access dependency 'role' must be a string or null.")
    return problems


# ------------------------
# Entry point
# ------------------------

def check(ir: Dict[str, Any], *, strict: bool = False) -> List[str]:
    """
    Run all consistency checks and return a list of problems.
    If strict=True, raise ValidationError on any problems.
    """
    problems: List[str] = []
    problems += _check_ir_version(ir)
    problems += _check_functions(ir)
    problems += _check_loops_reference_declared_functions(ir)
    problems += _check_requires_are_strings(ir)
    problems += _check_state(ir)
    problems += _check_access_control(ir)
    problems += _check_access_dependencies(ir)

    if strict and problems:
        raise ValidationError("IR consistency checks failed:\n- " + "\n- ".join(problems))
    return problems
