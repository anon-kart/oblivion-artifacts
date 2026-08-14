from __future__ import annotations
from typing import Any, Dict, List, Tuple

from .extractor_core import find_by_type, find_parent_function
from .extractor_loops import _render_expr
from typing import Any, Dict, List
from .extractor_core import find_by_type


def _has_revert(node: Dict[str, Any]) -> bool:
    """Detect a revert in a subtree: either an explicit RevertStatement or a FunctionCall named 'revert' (custom errors)."""
    # Explicit revert statement
    for _ in find_by_type(node, "RevertStatement"):
        return True
    # Custom error or bare revert call
    for fc in find_by_type(node, "FunctionCall"):
        expr = fc.get("expression") or {}
        callee = expr.get("name") or expr.get("memberName") or ""
        if callee == "revert":
            return True
    return False


def _extract_revert_condition(ifs: Dict[str, Any]) -> str:
    """
    Handle the common pattern:
        if (!cond) revert ...;
    Return the rendered 'cond' if matched, else "".
    """
    cond = ifs.get("condition") or {}
    if cond.get("nodeType") == "UnaryOperation" and cond.get("operator") == "!":
        then_body = ifs.get("trueBody") or {}
        if _has_revert(then_body):
            return _render_expr(cond.get("subExpression"))
    return ""


def extract_requires(norm_ast: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Collect precondition-like constraints that appear inside FUNCTION bodies.
    - require(cond)
    - assert(cond)
    - if (!cond) revert ...;
    Returns a list of dicts: {contract, function, condition, node_id} (extra keys may be present).
    """
    reqs: List[Dict[str, Any]] = []

    for contract in norm_ast.get("contracts", []):
        cname = contract.get("name") or ""

        # require(...) and assert(...)
        for call in find_by_type(contract, "FunctionCall"):
            expr = call.get("expression") or {}
            callee = expr.get("name") or expr.get("memberName") or ""
            if callee not in {"require", "assert"}:
                continue
            args = call.get("arguments") or []
            cond = _render_expr(args[0]) if args else ""
            fn = find_parent_function(contract, call)
            fn_name = (fn or {}).get("name") or (fn or {}).get("kind") or "unknown"
            entry = {
                "contract": cname,
                "function": fn_name,
                "condition": cond,
                "node_id": call.get("id"),
            }
            # keep a hint of origin (doesn't affect downstream)
            entry["kind"] = callee  # "require" | "assert"
            reqs.append(entry)

        # if (!cond) revert ...
        for ifs in find_by_type(contract, "IfStatement"):
            cond_str = _extract_revert_condition(ifs)
            if not cond_str:
                continue
            fn = find_parent_function(contract, ifs)
            fn_name = (fn or {}).get("name") or (fn or {}).get("kind") or "unknown"
            reqs.append({
                "contract": cname,
                "function": fn_name,
                "condition": cond_str,
                "node_id": ifs.get("id"),
                "kind": "revert_guard",
            })

    return reqs


def extract_modifier_requires(norm_ast: Dict[str, Any]) -> Dict[Tuple[str, str], List[str]]:
    """
    Collect precondition-like constraints that appear inside MODIFIER bodies.
    Recognizes:
      - require(cond)
      - assert(cond)
      - if (!cond) revert ...;
    Returns a mapping: {(contract_name, modifier_name): [cond_str, ...], ...}
    """
    mod_reqs: Dict[Tuple[str, str], List[str]] = {}

    for contract in norm_ast.get("contracts", []):
        c_name = contract.get("name") or ""

        for md in find_by_type(contract, "ModifierDefinition"):
            mname = md.get("name") or ""
            if not mname:
                continue

            conds: List[str] = []

            # require(...) and assert(...)
            for call in find_by_type(md, "FunctionCall"):
                expr = call.get("expression") or {}
                callee = expr.get("name") or expr.get("memberName") or ""
                if callee not in {"require", "assert"}:
                    continue
                args = call.get("arguments") or []
                conds.append(_render_expr(args[0]) if args else "")

            # if (!cond) revert ...;
            for ifs in find_by_type(md, "IfStatement"):
                cond_str = _extract_revert_condition(ifs)
                if cond_str:
                    conds.append(cond_str)

            # de-duplicate and store
            conds = [c for c in {c for c in conds if c}]
            if conds:
                mod_reqs[(c_name, mname)] = sorted(conds)

    return mod_reqs

def _render_expr_min(e: Any) -> str:
    if not isinstance(e, dict):
        return ""
    nt = e.get("nodeType")
    if nt == "Identifier":
        return e.get("name") or ""
    if nt == "Literal":
        v = e.get("value") or e.get("hexValue") or e.get("number")
        return str(v) if v is not None else "literal"
    if nt == "BinaryOperation":
        op = e.get("operator") or "?"
        return f"({_render_expr_min(e.get('leftExpression'))} {op} {_render_expr_min(e.get('rightExpression'))})"
    if nt == "MemberAccess":
        b = _render_expr_min(e.get("expression"))
        m = e.get("memberName") or ""
        return f"{b}.{m}" if b and m else m or b
    if nt == "IndexAccess":
        a = _render_expr_min(e.get("baseExpression"))
        i = _render_expr_min(e.get("indexExpression"))
        return f"{a}[{i}]"
    if nt == "FunctionCall":
        fn = e.get("expression") or {}
        name = fn.get("name") or fn.get("memberName") or "call"
        args = e.get("arguments") or []
        return f"{name}(" + ", ".join(_render_expr_min(a) for a in args) + ")"
    return nt or "expr"

def extract_modifier_requires(norm_ast: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Return { 'onlyOwner': ['(msg.sender == owner)'], 'AssetTransfer.onlyOwner': [...] }
    """
    out: Dict[str, List[str]] = {}
    for contract in norm_ast.get("contracts", []):
        cname = contract.get("name") or ""
        for md in find_by_type(contract, "ModifierDefinition"):
            mname = md.get("name") or ""
            if not mname:
                continue
            conds: List[str] = []
            # find require(...) calls inside modifier body
            for call in find_by_type(md, "FunctionCall"):
                expr = call.get("expression") or {}
                callee = expr.get("name") or expr.get("memberName")
                if callee == "require":
                    args = call.get("arguments") or []
                    if args:
                        conds.append(_render_expr_min(args[0]))
            if not conds:
                continue
            # store under plain and qualified keys
            out.setdefault(mname, []).extend(conds)
            if cname:
                out.setdefault(f"{cname}.{mname}", []).extend(conds)
    return out
