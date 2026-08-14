from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Tuple, List


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


def _find_matching_paren(src: str, open_idx: int) -> int:
    assert src[open_idx] == "("
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

        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i

        i += 1

    raise ValueError("Unmatched '(' in Solidity source.")


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


def _is_single_simple_return_body(body: str) -> Tuple[bool, str]:
    """
    Detect the strongest safe case:
      body == return <expr>;

    This catches functions like:
      return address(this);
      return uint256(1);
      return (((a) ^ b) ^ b);

    It intentionally rejects bodies with declarations/statements before return.
    """
    m = re.fullmatch(
        r"\s*return\s+(.+?)\s*;\s*",
        body,
        flags=re.DOTALL,
    )
    if not m:
        return False, ""
    return True, m.group(1).strip()


def _split_top_level_statements(body: str) -> List[Tuple[int, int, str]]:
    """
    Best-effort splitter of top-level function-body statements.
    Returns (start, end, text) slices relative to body.
    Only splits at depth-0 ';' and balanced '{...}' blocks.
    """
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
            f"{indent}__cfg_state = 1;\n"
            f"{indent}continue;"
        )
    else:
        replacement = (
            f"{indent}__cfg_state = 1;\n"
            f"{indent}continue;"
        )

    new_body = body[:a] + replacement + body[b:]
    return new_body, True


def _signature_has_returns(signature: str) -> bool:
    return re.search(r"\breturns\s*\(", signature) is not None


def _signature_returns_type(signature: str) -> str:
    """
    Best-effort extraction of the first return type.

    Supports common cases:
      returns (uint)
      returns (address)
      returns (uint256 z)

    If extraction fails, return uint256 as a safe fallback for older behavior.
    """
    m = re.search(r"\breturns\s*\((.*?)\)", signature, flags=re.DOTALL)
    if not m:
        return "uint256"

    raw = " ".join((m.group(1) or "").split()).strip()
    if not raw:
        return "uint256"

    # If multiple return values exist, do not try to slot-rewrite.
    if "," in raw:
        return ""

    parts = raw.split()
    if not parts:
        return "uint256"

    # returns (uint256 z) -> uint256
    # returns (address guy) -> address
    return parts[0]


def apply_cfg_flatten_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **kwargs: Any,
) -> TransformResult:
    """
    Conservative CFG/state-machine wrapper.

    Safety policy:
    - assembly -> skip
    - revert/throw -> skip
    - simple body `return <expr>;` -> apply direct state-machine return wrapper
    - single top-level return inside a larger function -> rewrite through temp return slot
    - multiple/complex returns -> skip

    This gives stronger obfuscation for functions like:
      upgradedAddress()
      balanceOf()
    while keeping risky functions conservative.
    """
    _ = (contract_name, kwargs)

    open_idx, close_idx, insert_idx, signature = _find_function_body_span(source, fn_name)
    original_body = source[insert_idx:close_idx]

    if re.search(r"\bassembly\b", original_body):
        return TransformResult(
            new_source=source,
            details={"seed": seed, "note": "cfg_flatten_v1 skipped: assembly"},
        )

    if re.search(r"\brevert\b|\bthrow\b", original_body):
        return TransformResult(
            new_source=source,
            details={"seed": seed, "note": "cfg_flatten_v1 skipped: revert/throw"},
        )

    base_indent = _compute_base_indent(original_body)
    inner = base_indent + "    "

    # ------------------------------------------------------------------
    # NEW STRONG SAFE PATH:
    # If the whole function body is exactly `return <expr>;`,
    # generate the compact OBLIVION state-machine wrapper.
    # This is the safest return-aware CFG flattening case.
    # ------------------------------------------------------------------
    is_simple_return, ret_expr = _is_single_simple_return_body(original_body)

    if is_simple_return:
        wrapper = (
            "\n"
            f"{base_indent}uint256 __obl_state = uint256(11);\n"
            f"{base_indent}while (__obl_state != uint256(0)) {{\n"
            f"{inner}if (__obl_state == uint256(11)) {{\n"
            f"{inner}    __obl_state = uint256(7);\n"
            f"{inner}    continue;\n"
            f"{inner}}}\n"
            f"{inner}if (__obl_state == uint256(7)) {{\n"
            f"{inner}    return {ret_expr};\n"
            f"{inner}}}\n"
            f"{base_indent}}}\n"
            f"{base_indent}return {ret_expr};\n"
        )

        new_source = source[:insert_idx] + wrapper + source[close_idx:]

        return TransformResult(
            new_source=new_source,
            details={
                "seed": seed,
                "note": "cfg_flatten_v1 applied to simple-return function",
                "simple_return": True,
                "ret_expr_preview": ret_expr[:120],
            },
        )

    # ------------------------------------------------------------------
    # Existing conservative dispatcher path.
    # This preserves your uploaded implementation's more general behavior.
    # ------------------------------------------------------------------
    sig = " ".join(signature.split())
    is_pure = (" pure " in f" {sig} ") or sig.endswith(" pure")
    has_returns_clause = _signature_has_returns(signature)
    return_count = _count_top_level_return_statements(original_body)

    rewritten_body = original_body
    uses_ret_slot = False
    ret_slot_name = "__cfg_ret"

    if return_count > 0:
        if not has_returns_clause:
            return TransformResult(
                new_source=source,
                details={
                    "seed": seed,
                    "note": "cfg_flatten_v1 skipped: top-level return but no returns-clause",
                },
            )

        if return_count > 1:
            return TransformResult(
                new_source=source,
                details={
                    "seed": seed,
                    "note": "cfg_flatten_v1 skipped: multiple top-level returns",
                },
            )

        ret_type = _signature_returns_type(signature)
        if not ret_type:
            return TransformResult(
                new_source=source,
                details={
                    "seed": seed,
                    "note": "cfg_flatten_v1 skipped: multiple return values unsupported",
                },
            )

        rewritten_body, ok = _rewrite_single_top_level_return(original_body, ret_slot_name)
        if not ok:
            return TransformResult(
                new_source=source,
                details={
                    "seed": seed,
                    "note": "cfg_flatten_v1 skipped: failed to rewrite top-level return",
                },
            )
        uses_ret_slot = True
    else:
        ret_type = "uint256"

    salt_expr = f"(uint256({seed}) * uint256({seed}) - uint256({seed}) * uint256({seed}))"
    if not is_pure:
        salt_expr = salt_expr

    wrapper = "\n"

    if uses_ret_slot:
        wrapper += f"{base_indent}{ret_type} {ret_slot_name};\n"

    wrapper += (
        f"{base_indent}uint256 __cfg_salt = {salt_expr};\n"
        f"{base_indent}uint256 __cfg_state = (__cfg_salt ^ __cfg_salt); // always 0\n"
        f"{base_indent}while (true) {{\n"
        f"{inner}if (__cfg_state == 0) {{\n"
    )

    body_lines = rewritten_body.splitlines(True)
    indented_body: List[str] = []

    for ln in body_lines:
        if ln.strip():
            indented_body.append(inner + "    " + ln.lstrip("\r\n"))
        else:
            indented_body.append(ln)

    wrapper += "".join(indented_body)

    wrapper += (
        f"\n{inner}    __cfg_state = 1;\n"
        f"{inner}    continue;\n"
        f"{inner}}}\n"
        f"{inner}if (__cfg_state == 1) {{\n"
        f"{inner}    break;\n"
        f"{inner}}}\n"
        f"{inner}// unreachable noise\n"
        f"{inner}__cfg_state = 1;\n"
        f"{base_indent}}}\n"
    )

    if uses_ret_slot:
        wrapper += f"{base_indent}return {ret_slot_name};\n"

    new_source = source[:insert_idx] + wrapper + source[close_idx:]

    return TransformResult(
        new_source=new_source,
        details={
            "seed": seed,
            "note": "cfg_flatten_v1 applied (conservative dispatcher wrapper, early-return aware)",
            "pure_safe": is_pure,
            "simple_return": False,
            "rewrote_single_top_level_return": uses_ret_slot,
            "top_level_return_count": return_count,
        },
    )