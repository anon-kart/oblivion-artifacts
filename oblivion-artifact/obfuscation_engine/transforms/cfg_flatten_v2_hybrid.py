from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Tuple, List, Optional


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


def _find_matching_brace(src: str, open_idx: int) -> int:
    assert src[open_idx] == "{"
    i = open_idx + 1
    depth = 1
    in_squote = False
    in_dquote = False
    in_line_comment = False
    in_block_comment = False

    while i < len(src):
        ch = src[i]
        nxt = src[i + 1] if i + 1 < len(src) else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        if not in_squote and not in_dquote:
            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue

        if not in_dquote and ch == "'" and (i == 0 or src[i - 1] != "\\"):
            in_squote = not in_squote
            i += 1
            continue
        if not in_squote and ch == '"' and (i == 0 or src[i - 1] != "\\"):
            in_dquote = not in_dquote
            i += 1
            continue

        if in_squote or in_dquote:
            i += 1
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1

    raise ValueError("Unmatched '{' in Solidity source.")


def _find_function_body_span(src: str, fn_name: str) -> Tuple[int, int, int, str]:
    pat = re.compile(rf"\bfunction\s+{re.escape(fn_name)}\b")
    m = pat.search(src)
    if not m:
        raise ValueError(f"Function '{fn_name}' not found in source.")

    open_idx = src.find("{", m.end())
    if open_idx == -1:
        raise ValueError(f"Function '{fn_name}' has no body '{{'.")

    close_idx = _find_matching_brace(src, open_idx)
    signature = src[m.start():open_idx]
    return open_idx, close_idx, open_idx + 1, signature


def _compute_base_indent(body: str) -> str:
    for ln in body.splitlines():
        if ln.strip():
            return ln[: len(ln) - len(ln.lstrip(" \t"))]
    return "    "


def _extract_return_expr(stmt: str) -> str:
    m = re.match(r"\s*return\b(.*?);\s*$", stmt, flags=re.DOTALL)
    if not m:
        return ""
    return (m.group(1) or "").strip()


def _split_top_level_statements(body: str) -> List[Tuple[int, int, str]]:
    out: List[Tuple[int, int, str]] = []
    i = 0
    start = 0
    depth_brace = 0
    depth_paren = 0
    depth_brack = 0
    in_squote = False
    in_dquote = False
    in_line_comment = False
    in_block_comment = False

    while i < len(body):
        ch = body[i]
        nxt = body[i + 1] if i + 1 < len(body) else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        if not in_squote and not in_dquote:
            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue

        if not in_dquote and ch == "'" and (i == 0 or body[i - 1] != "\\"):
            in_squote = not in_squote
            i += 1
            continue
        if not in_squote and ch == '"' and (i == 0 or body[i - 1] != "\\"):
            in_dquote = not in_dquote
            i += 1
            continue

        if in_squote or in_dquote:
            i += 1
            continue

        if ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace -= 1
            if depth_brace == 0 and depth_paren == 0 and depth_brack == 0:
                stmt = body[start:i + 1]
                if stmt.strip():
                    out.append((start, i + 1, stmt))
                start = i + 1
        elif ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren -= 1
        elif ch == "[":
            depth_brack += 1
        elif ch == "]":
            depth_brack -= 1
        elif ch == ";" and depth_brace == 0 and depth_paren == 0 and depth_brack == 0:
            stmt = body[start:i + 1]
            if stmt.strip():
                out.append((start, i + 1, stmt))
            start = i + 1

        i += 1

    tail = body[start:]
    if tail.strip():
        out.append((start, len(body), tail))
    return out


def _partition_statements(
    stmts: List[Tuple[int, int, str]]
) -> Tuple[Optional[List[Tuple[int, int, str]]], Optional[List[Tuple[int, int, str]]], Optional[List[Tuple[int, int, str]]]]:
    if len(stmts) < 4:
        return None, None, None
    head = stmts[:1]
    tail = stmts[-1:]
    core = stmts[1:-1]
    return head, core, tail


def _count_top_level_return_statements(body: str) -> int:
    count = 0
    for _a, _b, stmt in _split_top_level_statements(body):
        if re.match(r"\s*return\b", stmt):
            count += 1
    return count


def _rewrite_single_top_level_return(body: str, ret_slot: str) -> Tuple[str, bool]:
    stmts = _split_top_level_statements(body)
    return_stmt_idx = -1
    for idx, (_a, _b, stmt) in enumerate(stmts):
        if re.match(r"\s*return\b", stmt):
            return_stmt_idx = idx
            break
    if return_stmt_idx < 0:
        return body, False

    a, b, stmt = stmts[return_stmt_idx]
    ret_expr = _extract_return_expr(stmt)
    indent_match = re.match(r"^([ \t]*)", stmt)
    indent = indent_match.group(1) if indent_match else ""

    if ret_expr:
        replacement = (
            f"{indent}{ret_slot} = {ret_expr};\n"
            f"{indent}__cfg_h_state0 = 0;\n"
            f"{indent}__cfg_h_state1 = 0;\n"
            f"{indent}continue;"
        )
    else:
        replacement = (
            f"{indent}__cfg_h_state0 = 0;\n"
            f"{indent}__cfg_h_state1 = 0;\n"
            f"{indent}continue;"
        )
    return body[:a] + replacement + body[b:], True


def _signature_has_returns(signature: str) -> bool:
    return re.search(r"\breturns\s*\(", signature) is not None


def apply_cfg_flatten_v2_hybrid(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **kwargs: Any,
) -> TransformResult:
    _ = (contract_name, kwargs)

    open_idx, close_idx, insert_idx, signature = _find_function_body_span(source, fn_name)
    original_body = source[insert_idx:close_idx]

    if re.search(r"\bassembly\b", original_body):
        return TransformResult(new_source=source, details={"seed": seed, "note": "cfg_flatten_v2_hybrid skipped: assembly"})
    if re.search(r"\brevert\b|\bthrow\b", original_body):
        return TransformResult(new_source=source, details={"seed": seed, "note": "cfg_flatten_v2_hybrid skipped: revert/throw"})

    sig = " ".join(signature.split())
    is_pure = (" pure " in f" {sig} ") or sig.endswith(" pure")
    has_returns_clause = _signature_has_returns(signature)
    return_count = _count_top_level_return_statements(original_body)

    rewritten_body = original_body
    uses_ret_slot = False
    ret_slot_name = "__cfg_h_ret"
    if return_count > 0:
        if not has_returns_clause:
            return TransformResult(new_source=source, details={"seed": seed, "note": "cfg_flatten_v2_hybrid skipped: top-level return but no returns-clause"})
        if return_count > 1:
            return TransformResult(new_source=source, details={"seed": seed, "note": "cfg_flatten_v2_hybrid skipped: multiple top-level returns"})
        rewritten_body, ok = _rewrite_single_top_level_return(original_body, ret_slot_name)
        if not ok:
            return TransformResult(new_source=source, details={"seed": seed, "note": "cfg_flatten_v2_hybrid skipped: failed to rewrite top-level return"})
        uses_ret_slot = True

    stmts = _split_top_level_statements(rewritten_body)
    head, core, tail = _partition_statements(stmts)
    if core is None or len(core) < 2:
        return TransformResult(new_source=source, details={"seed": seed, "note": "cfg_flatten_v2_hybrid skipped: insufficient top-level statements"})

    base_indent = _compute_base_indent(original_body)
    inner = base_indent + "    "
    inner2 = inner + "    "
    inner3 = inner2 + "    "

    def _indent_stmt(stmt: str, indent: str) -> str:
        lines = stmt.splitlines(True)
        out: List[str] = []
        for ln in lines:
            if ln.strip():
                out.append(indent + ln.lstrip("\r\n"))
            else:
                out.append(ln)
        txt = "".join(out)
        return txt if txt.endswith("\n") else txt + "\n"

    flat_parts: List[str] = []
    if uses_ret_slot:
        flat_parts.append(f"{base_indent}uint256 {ret_slot_name};\n")

    flat_parts.append(f"{base_indent}uint256 __cfg_h_salt = (uint256({seed}) ^ uint256({seed}));\n")
    flat_parts.append(f"{base_indent}uint256 __cfg_h_state0 = __cfg_h_salt;\n")
    flat_parts.append(f"{base_indent}uint256 __cfg_h_state1 = 1;\n")

    for _a, _b, stmt in head or []:
        flat_parts.append(_indent_stmt(stmt, base_indent))

    flat_parts.append(f"{base_indent}while (true) {{\n")
    flat_parts.append(f"{inner}uint256 __cfg_h_sel = (__cfg_h_state0 ^ __cfg_h_state1);\n")

    state_pairs: List[Tuple[int, int]] = []
    for idx in range(len(core or [])):
        target_id = idx + 1
        if idx == 0:
            state_pairs.append((0, target_id))
        else:
            state_pairs.append((target_id + 1, 1))

    for idx, ((_a, _b, stmt), (s0, s1)) in enumerate(zip(core or [], state_pairs)):
        target_id = idx + 1
        flat_parts.append(f"{inner}if (__cfg_h_sel == {target_id}) {{\n")
        flat_parts.append(_indent_stmt(stmt, inner2))

        if idx + 1 < len(state_pairs):
            ns0, ns1 = state_pairs[idx + 1]
            flat_parts.append(f"{inner2}__cfg_h_state0 = {ns0};\n")
            flat_parts.append(f"{inner2}__cfg_h_state1 = {ns1};\n")
            if idx % 2 == 1:
                flat_parts.append(f"{inner2}if (__cfg_h_sel == 99) {{\n")
                flat_parts.append(f"{inner3}__cfg_h_state0 = __cfg_h_state0 ^ 0;\n")
                flat_parts.append(f"{inner3}__cfg_h_state1 = __cfg_h_state1 ^ 0;\n")
                flat_parts.append(f"{inner3}break;\n")
                flat_parts.append(f"{inner2}}}\n")
            flat_parts.append(f"{inner2}continue;\n")
        else:
            flat_parts.append(f"{inner2}break;\n")
        flat_parts.append(f"{inner}}}\n")

    flat_parts.append(f"{inner}break;\n")
    flat_parts.append(f"{base_indent}}}\n")

    for _a, _b, stmt in tail or []:
        flat_parts.append(_indent_stmt(stmt, base_indent))

    if uses_ret_slot:
        flat_parts.append(f"{base_indent}return {ret_slot_name};\n")

    wrapper = "\n" + "".join(flat_parts)
    new_source = source[:insert_idx] + wrapper + source[close_idx:]

    return TransformResult(
        new_source=new_source,
        details={
            "seed": seed,
            "note": "cfg_flatten_v2_hybrid applied (selective core flattening with split dispatcher states)",
            "pure_safe": is_pure,
            "rewrote_single_top_level_return": uses_ret_slot,
            "top_level_return_count": return_count,
            "flattened_core_statements": len(core or []),
        },
    )