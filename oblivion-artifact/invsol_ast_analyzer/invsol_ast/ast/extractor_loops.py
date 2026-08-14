from typing import Any, Dict, List
from .extractor_core import find_by_type, find_parent_function
from .extractor_effects import summarize_loop_body  # uses its own renderer (no circular import)


def _render_expr(e: Any) -> str:
    if not isinstance(e, dict):
        return ""
    nt = e.get("nodeType")
    if nt == "Identifier":
        return e.get("name") or ""
    if nt == "Literal":
        val = e.get("value")
        if val is None:
            val = e.get("hexValue") or e.get("number")
        return str(val)
    if nt == "BinaryOperation":
        op = e.get("operator") or "?"
        return f"({_render_expr(e.get('leftExpression'))} {op} {_render_expr(e.get('rightExpression'))})"
    if nt == "UnaryOperation":
        op = e.get("operator") or "?"
        sub = _render_expr(e.get("subExpression"))
        if e.get("prefix") is False:
            return f"({sub}{op})"
        return f"({op}{sub})"
    if nt == "Assignment":
        op = e.get("operator") or "="
        return f"({_render_expr(e.get('leftHandSide'))} {op} {_render_expr(e.get('rightHandSide'))})"
    if nt == "FunctionCall":
        fn = e.get("expression") or {}
        fn_name = fn.get("name") or fn.get("memberName") or _render_expr(fn) or "call"
        args = e.get("arguments") or []
        args_s = ", ".join(_render_expr(a) for a in args)
        return f"{fn_name}({args_s})"
    if nt == "IndexAccess":
        a = _render_expr(e.get("baseExpression"))
        i = _render_expr(e.get("indexExpression"))
        return f"{a}[{i}]"
    if nt == "MemberAccess":
        b = _render_expr(e.get("expression"))
        n = e.get("memberName") or ""
        return f"{b}.{n}"
    if nt == "TupleExpression":
        comps = e.get("components") or []
        return "(" + ", ".join(_render_expr(c) for c in comps) + ")"
    return nt or "expr"


def _type_string(node: Dict[str, Any]) -> str:
    if not isinstance(node, dict):
        return ""
    td = node.get("typeDescriptions") or {}
    ts = td.get("typeString")
    if ts:
        return ts
    tn = node.get("typeName") or {}
    return tn.get("name") or ""


def _render_statement(s: Any) -> str:
    if not isinstance(s, dict):
        return ""
    nt = s.get("nodeType")
    if nt == "VariableDeclarationStatement":
        decls = s.get("declarations") or []
        names: List[str] = []
        for d in decls:
            n = d.get("name") or ""
            if not n:
                t = (d.get("typeName") or {}).get("name") or ""
                if t:
                    n = t
            if n:
                names.append(n)
        left = ", ".join(names)
        init_s = _render_expr(s.get("initialValue"))
        t0 = _type_string(decls[0]) if decls else ""
        if left and init_s:
            return f"{left} = {init_s}"
        if t0 and left:
            return f"{t0} {left}"
        return left or "VariableDeclarationStatement"
    if nt == "ExpressionStatement":
        return _render_expr(s.get("expression"))
    return _render_expr(s)


def _parse_loop_bounds(guard: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Recognize patterns like:
      i < N, i <= N, i < arr.length, 0 <= i && i < N
    Returns: {"index":"i","lower":"0","upper":"payees.length","inclusive_upper":False}
    """
    def is_id(n): return isinstance(n, dict) and n.get("nodeType") == "Identifier"
    def is_lit(n): return isinstance(n, dict) and n.get("nodeType") == "Literal"
    def render(n): return _render_expr(n)

    if not isinstance(guard, dict):
        return None

    if guard.get("nodeType") == "BinaryOperation":
        op = guard.get("operator")
        L = guard.get("leftExpression")
        R = guard.get("rightExpression")

        # i < N / i <= N
        if is_id(L) and op in ("<", "<="):
            return {"index": L["name"], "lower": None, "upper": render(R), "inclusive_upper": op == "<="}

        # 0 < i / 0 <= i  (lower bound)
        if (is_lit(L) and is_id(R)) and op in ("<", "<="):
            return {"index": R["name"], "lower": render(L), "upper": None, "inclusive_upper": None}

        # compound: lower && upper
        if op == "&&":
            left = _parse_loop_bounds(L) or {}
            right = _parse_loop_bounds(R) or {}
            if left.get("index") and left.get("index") == right.get("index"):
                return {
                    "index": left["index"],
                    "lower": left.get("lower") or right.get("lower"),
                    "upper": left.get("upper") or right.get("upper"),
                    "inclusive_upper": left.get("inclusive_upper") if left.get("upper") else right.get("inclusive_upper"),
                }
            return left or right

    return None


# NEW: derive lower bound from init when possible (e.g., uint i = 0;  or  i = 0;)
def _lower_from_init(init_node: Dict[str, Any]) -> tuple[str, str] | None:
    # VariableDeclarationStatement: uint i = 0;
    if isinstance(init_node, dict) and init_node.get("nodeType") == "VariableDeclarationStatement":
        decls = init_node.get("declarations") or []
        if decls:
            name = (decls[0] or {}).get("name")
            init = init_node.get("initialValue")
            if name and isinstance(init, dict) and init.get("nodeType") == "Literal":
                val = init.get("value") or init.get("number") or init.get("hexValue")
                if val is not None:
                    return name, str(val)

    # ExpressionStatement(Assignment): i = 0;
    if isinstance(init_node, dict) and init_node.get("nodeType") == "ExpressionStatement":
        expr = init_node.get("expression") or {}
        if expr.get("nodeType") == "Assignment" and (expr.get("operator") in (None, "=", "+=", "-=")):
            lhs = expr.get("leftHandSide") or {}
            rhs = expr.get("rightHandSide") or {}
            if lhs.get("nodeType") == "Identifier" and rhs.get("nodeType") == "Literal":
                name = lhs.get("name")
                val = rhs.get("value") or rhs.get("number") or rhs.get("hexValue")
                if name and val is not None:
                    return name, str(val)

    return None


def _ensure_loop_index_in_summary(summary: Dict[str, Any], bounds: Dict[str, Any] | None) -> Dict[str, Any]:
    """
    Keep body_summary.indices consistent with bounds.index.

    This is especially important for normalized/obfuscated while-loops where:
      - the guard still clearly identifies the loop index, but
      - the body summary may miss it because the original for-loop init/update
        was lowered into surrounding block statements or unchecked blocks.
    """
    if not isinstance(summary, dict):
        summary = {}

    indices = summary.get("indices")
    if not isinstance(indices, list):
        indices = []

    idx = None
    if isinstance(bounds, dict):
        idx = bounds.get("index")

    if isinstance(idx, str) and idx and idx not in indices:
        indices.append(idx)

    summary["indices"] = sorted(set(x for x in indices if isinstance(x, str) and x))
    return summary


def _loop_sig(loop: Dict[str, Any], state_index: Dict[str, str]) -> Dict[str, Any]:
    if loop.get("nodeType") == "ForStatement":
        init_node = loop.get("initializationExpression")
        update_node = loop.get("loopExpression")
        sig = {
            "type": "for",
            "init": _render_statement(init_node) if isinstance(init_node, dict) else _render_expr(init_node),
            "guard": _render_expr(loop.get("condition")),
            "update": _render_statement(update_node) if isinstance(update_node, dict) else _render_expr(update_node),
        }
    elif loop.get("nodeType") == "WhileStatement":
        sig = {
            "type": "while",
            "init": "",
            "guard": _render_expr(loop.get("condition")),
            "update": "",
        }
    else:
        sig = {"type": loop.get("nodeType", "loop")}

    # Attach loop body summary (indices/accumulators/updates/external-call flag)
    body_summary = summarize_loop_body(loop, state_index)

    # Parse guard to extract explicit bounds (index, lower, upper, inclusive_upper)
    b = _parse_loop_bounds(loop.get("condition"))
    if b:
        sig["bounds"] = b

    # Ensure the body summary is consistent with the derived loop bounds.
    # This fixes normalized/obfuscated while-loops where bounds.index is known
    # but body_summary.indices misses it.
    sig["body_summary"] = _ensure_loop_index_in_summary(body_summary, b)

    # NEW: If lower bound not known (or no bounds at all), try to infer from init
    lb = _lower_from_init(loop.get("initializationExpression"))
    if lb:
        idx_from_init, lower_val = lb
        if "bounds" not in sig:
            sig["bounds"] = {"index": idx_from_init, "lower": lower_val, "upper": None, "inclusive_upper": None}
        else:
            # only fill lower if missing and index matches (or index not yet set)
            if not sig["bounds"].get("lower") and (not sig["bounds"].get("index") or sig["bounds"]["index"] == idx_from_init):
                sig["bounds"]["lower"] = lower_val
                if not sig["bounds"].get("index"):
                    sig["bounds"]["index"] = idx_from_init

        # Re-sync body_summary in case bounds were just created or completed from init.
        sig["body_summary"] = _ensure_loop_index_in_summary(sig.get("body_summary"), sig.get("bounds"))

    return sig


def extract_loops(norm_ast: Dict[str, Any], state_index: Dict[str, str]) -> List[Dict[str, Any]]:
    loops: List[Dict[str, Any]] = []
    for contract in norm_ast.get("contracts", []):
        for lp in list(find_by_type(contract, "ForStatement")) + list(find_by_type(contract, "WhileStatement")):
            sig = _loop_sig(lp, state_index)
            fn = find_parent_function(contract, lp)
            fn_name = (fn or {}).get("name") or (fn or {}).get("kind") or "unknown"
            loops.append({
                "contract": contract.get("name") or "",
                "function": fn_name,
                "signature": sig,
                "node_id": lp.get("id"),
            })
    return loops