from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Optional
import re


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


@dataclass
class PublicStateVar:
    name: str
    kind: str  # "array1", "array2", "mapping"
    elem_type: str = ""
    key_type: str = ""
    value_type: str = ""


def _find_contract_span(source: str, contract_name: str) -> Tuple[int, int, int]:
    m = re.search(rf"\bcontract\s+{re.escape(contract_name)}\b", source)
    if not m:
        raise ValueError(f"public_state_accessor_indirection_v1: contract {contract_name} not found")

    brace_open = source.find("{", m.end())
    if brace_open < 0:
        raise ValueError("public_state_accessor_indirection_v1: cannot find contract body open brace")

    depth = 0
    j = brace_open
    while j < len(source):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return m.start(), brace_open, j + 1
        j += 1

    raise ValueError("public_state_accessor_indirection_v1: cannot match contract braces")


def _find_function_span(source: str, fn_name: str) -> Tuple[int, int, int, int]:
    if fn_name == "constructor":
        m = re.search(r"\bconstructor\s*\(", source)
    else:
        m = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", source)

    if not m:
        raise ValueError(f"public_state_accessor_indirection_v1: function {fn_name} not found")

    body_open = source.find("{", m.end())
    if body_open < 0:
        raise ValueError(f"public_state_accessor_indirection_v1: cannot find body open brace for {fn_name}")

    depth = 0
    j = body_open
    while j < len(source):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return m.start(), body_open, j + 1, body_open
        j += 1

    raise ValueError(f"public_state_accessor_indirection_v1: cannot match braces for {fn_name}")


def _strip_strings_and_comments_keep_len(s: str) -> str:
    out = list(s)
    i = 0
    n = len(s)
    in_line = False
    in_block = False
    in_str = False
    quote = ""

    while i < n:
        ch = s[i]
        nxt = s[i + 1] if i + 1 < n else ""

        if in_line:
            if ch != "\n":
                out[i] = " "
            else:
                in_line = False
            i += 1
            continue

        if in_block:
            out[i] = " "
            if ch == "*" and nxt == "/":
                out[i + 1] = " "
                i += 2
                in_block = False
            else:
                i += 1
            continue

        if in_str:
            out[i] = " "
            if ch == "\\" and i + 1 < n:
                out[i + 1] = " "
                i += 2
                continue
            if ch == quote:
                in_str = False
                quote = ""
            i += 1
            continue

        if ch == "/" and nxt == "/":
            out[i] = out[i + 1] = " "
            i += 2
            in_line = True
            continue

        if ch == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            i += 2
            in_block = True
            continue

        if ch in ("'", '"'):
            out[i] = " "
            in_str = True
            quote = ch
            i += 1
            continue

        i += 1

    return "".join(out)


def _split_top_level_csv(s: str) -> List[str]:
    parts: List[str] = []
    cur: List[str] = []
    depth_paren = 0
    depth_brack = 0
    depth_brace = 0
    in_str = False
    quote = ""
    i = 0

    while i < len(s):
        ch = s[i]

        if in_str:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if ch == quote:
                in_str = False
                quote = ""
            i += 1
            continue

        if ch in ("'", '"'):
            in_str = True
            quote = ch
            cur.append(ch)
            i += 1
            continue

        if ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren -= 1
        elif ch == "[":
            depth_brack += 1
        elif ch == "]":
            depth_brack -= 1
        elif ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace -= 1
        elif ch == "," and depth_paren == 0 and depth_brack == 0 and depth_brace == 0:
            parts.append("".join(cur).strip())
            cur = []
            i += 1
            continue

        cur.append(ch)
        i += 1

    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _find_matching_bracket(s: str, open_idx: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    i = open_idx
    in_str = False
    quote = ""

    while i < len(s):
        ch = s[i]

        if in_str:
            if ch == "\\" and i + 1 < len(s):
                i += 2
                continue
            if ch == quote:
                in_str = False
                quote = ""
            i += 1
            continue

        if ch in ("'", '"'):
            in_str = True
            quote = ch
            i += 1
            continue

        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1

    return -1


def _find_matching_square(s: str, open_idx: int) -> int:
    return _find_matching_bracket(s, open_idx, "[", "]")


def _sanitize_type_name(t: str) -> str:
    return " ".join((t or "").split())


def _parse_public_state_vars(contract_body: str) -> List[PublicStateVar]:
    out: List[PublicStateVar] = []
    masked = _strip_strings_and_comments_keep_len(contract_body)
    depth = 0
    line_start = 0
    i = 0
    n = len(masked)

    while i <= n:
        if i == n or masked[i] == "\n":
            raw_line = contract_body[line_start:i].strip()
            if depth == 0 and raw_line:
                # array 2D
                m2 = re.match(
                    r"^(?P<elem>[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)?)\s*\[\]\s*\[\]\s+public\s+(?P<name>[A-Za-z_]\w*)\s*;$",
                    raw_line,
                )
                if m2:
                    out.append(
                        PublicStateVar(
                            name=m2.group("name"),
                            kind="array2",
                            elem_type=_sanitize_type_name(m2.group("elem")),
                        )
                    )
                else:
                    # array 1D
                    m1 = re.match(
                        r"^(?P<elem>[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)?)\s*\[\]\s+public\s+(?P<name>[A-Za-z_]\w*)\s*;$",
                        raw_line,
                    )
                    if m1:
                        out.append(
                            PublicStateVar(
                                name=m1.group("name"),
                                kind="array1",
                                elem_type=_sanitize_type_name(m1.group("elem")),
                            )
                        )
                    else:
                        # mapping
                        mm = re.match(
                            r"^mapping\s*\(\s*(?P<key>[^=]+?)\s*=>\s*(?P<val>[^)]+?)\s*\)\s+public\s+(?P<name>[A-Za-z_]\w*)\s*;$",
                            raw_line,
                        )
                        if mm:
                            out.append(
                                PublicStateVar(
                                    name=mm.group("name"),
                                    kind="mapping",
                                    key_type=_sanitize_type_name(mm.group("key")),
                                    value_type=_sanitize_type_name(mm.group("val")),
                                )
                            )
            line_start = i + 1

        if i < n:
            ch = masked[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        i += 1

    return out


def _helper_names(var_name: str) -> Dict[str, str]:
    return {
        "len": f"__obf_{var_name}_len",
        "at": f"__obf_{var_name}_at",
        "at2": f"__obf_{var_name}_at2",
        "get": f"__obf_{var_name}_get",
    }


def _helper_exists(source: str, helper_name: str) -> bool:
    return re.search(rf"\bfunction\s+{re.escape(helper_name)}\b", source) is not None


def _build_helper_block(vars_: List[PublicStateVar]) -> str:
    lines: List[str] = []
    lines.append("    // --- OBLIVION public-state accessor indirection (generated) ---")

    for v in vars_:
        names = _helper_names(v.name)

        if v.kind == "array1":
            lines.append(f"    function {names['len']}() internal view returns (uint256) {{")
            lines.append(f"        return {v.name}.length;")
            lines.append("    }")
            lines.append(f"    function {names['at']}(uint256 i) internal view returns ({v.elem_type}) {{")
            lines.append(f"        return {v.name}[i];")
            lines.append("    }")

        elif v.kind == "array2":
            lines.append(f"    function {names['len']}() internal view returns (uint256) {{")
            lines.append(f"        return {v.name}.length;")
            lines.append("    }")
            lines.append(f"    function {names['at2']}(uint256 i, uint256 j) internal view returns ({v.elem_type}) {{")
            lines.append(f"        return {v.name}[i][j];")
            lines.append("    }")

        elif v.kind == "mapping":
            lines.append(f"    function {names['get']}({v.key_type} k) internal view returns ({v.value_type}) {{")
            lines.append(f"        return {v.name}[k];")
            lines.append("    }")

        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _needed_helper_names_for_vars(vars_: List[PublicStateVar]) -> List[str]:
    needed: List[str] = []
    for v in vars_:
        names = _helper_names(v.name)
        if v.kind == "array1":
            needed.extend([names["len"], names["at"]])
        elif v.kind == "array2":
            needed.extend([names["len"], names["at2"]])
        elif v.kind == "mapping":
            needed.extend([names["get"]])
    return needed


def _inject_helper_block(
    source: str,
    contract_name: str,
    helper_block: str,
    helper_vars: List[PublicStateVar],
) -> Tuple[str, bool]:
    if not helper_block.strip():
        return source, False

    needed_helpers = _needed_helper_names_for_vars(helper_vars)
    missing_helpers = [name for name in needed_helpers if not _helper_exists(source, name)]

    if not missing_helpers:
        return source, False

    _, brace_open, _ = _find_contract_span(source, contract_name)
    insert_at = brace_open + 1
    new_source = source[:insert_at] + "\n" + helper_block + "\n" + source[insert_at:]
    return new_source, True


def _is_write_context(src: str, end_idx: int) -> bool:
    """
    Conservative write-context check for indexed access replacements.
    If immediately followed by =, +=, -=, *=, /=, %=, |=, &=, ^=, ++, --, skip.
    """
    j = end_idx
    while j < len(src) and src[j].isspace():
        j += 1

    for op in ("+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "++", "--", "="):
        if src.startswith(op, j):
            return True
    return False


def _collect_replacements_for_var(body_inner: str, var: PublicStateVar) -> List[Tuple[int, int, str, str]]:
    """
    Returns list of (start, end, replacement, kind)
    """
    out: List[Tuple[int, int, str, str]] = []
    masked = _strip_strings_and_comments_keep_len(body_inner)
    names = _helper_names(var.name)

    # name.length
    for m in re.finditer(rf"\b{re.escape(var.name)}\s*\.\s*length\b", masked):
        out.append((m.start(), m.end(), f"{names['len']}()", "length"))

    # name[idx] or name[i][j]
    search_pos = 0
    while True:
        m = re.search(rf"\b{re.escape(var.name)}\b", masked[search_pos:])
        if not m:
            break
        start = search_pos + m.start()
        pos = search_pos + m.end()

        while pos < len(masked) and masked[pos].isspace():
            pos += 1

        if pos < len(masked) and masked[pos] == "[":
            close1 = _find_matching_square(masked, pos)
            if close1 < 0:
                search_pos = pos + 1
                continue

            idx1_expr = body_inner[pos + 1:close1].strip()
            pos2 = close1 + 1
            while pos2 < len(masked) and masked[pos2].isspace():
                pos2 += 1

            # 2D array access
            if var.kind == "array2" and pos2 < len(masked) and masked[pos2] == "[":
                close2 = _find_matching_square(masked, pos2)
                if close2 < 0:
                    search_pos = close1 + 1
                    continue

                if not _is_write_context(body_inner, close2 + 1):
                    idx2_expr = body_inner[pos2 + 1:close2].strip()
                    rep = f"{names['at2']}({idx1_expr}, {idx2_expr})"
                    out.append((start, close2 + 1, rep, "index2"))
                search_pos = close2 + 1
                continue

            # 1D array / mapping access
            if not _is_write_context(body_inner, close1 + 1):
                if var.kind == "array1":
                    rep = f"{names['at']}({idx1_expr})"
                    out.append((start, close1 + 1, rep, "index1"))
                elif var.kind == "mapping":
                    rep = f"{names['get']}({idx1_expr})"
                    out.append((start, close1 + 1, rep, "mapping_get"))

            search_pos = close1 + 1
            continue

        search_pos = pos

    return out


def _apply_replacements(src: str, replacements: List[Tuple[int, int, str, str]]) -> Tuple[str, int]:
    if not replacements:
        return src, 0

    # Prefer longer spans first, then right-to-left.
    replacements = sorted(
        replacements,
        key=lambda x: (x[0], x[1] - x[0]),
        reverse=True,
    )

    out = src
    seen_ranges = set()
    changed = 0

    for a, b, rep, _kind in replacements:
        if (a, b) in seen_ranges:
            continue
        seen_ranges.add((a, b))
        out = out[:a] + rep + out[b:]
        changed += 1

    return out, changed


def apply_public_state_accessor_indirection_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    max_rewrites: int = 12,
    enable_lengths: bool = True,
    enable_index_reads: bool = True,
    **_: Any,
) -> TransformResult:
    """
    Conservative public-state use-site indirection.

    Goal:
      Obfuscate public array / mapping reads without rewriting declarations or ABI getters.

    Supports:
      - arr.length           -> __obf_arr_len()
      - arr[i]              -> __obf_arr_at(i)
      - grid[i][j]          -> __obf_grid_at2(i, j)
      - balances[a]         -> __obf_balances_get(a)

    Safety:
      - only rewrites read contexts, not writes
      - only for top-level public arrays / mappings
      - helper functions are internal view
      - does not mutate declarations / ABI
    """
    _ = seed

    if int(max_rewrites) <= 0:
        return TransformResult(
            new_source=source,
            details={"note": "public_state_accessor_indirection_v1 skipped: max_rewrites <= 0", "rewrites": []},
        )

    contract_start, contract_open, contract_close = _find_contract_span(source, contract_name)
    contract_body = source[contract_open + 1:contract_close - 1]

    vars_ = _parse_public_state_vars(contract_body)
    if not vars_:
        return TransformResult(
            new_source=source,
            details={"note": "public_state_accessor_indirection_v1: no eligible public arrays/mappings found", "rewrites": []},
        )

    sig_start, body_open, body_close, sig_end = _find_function_span(source, fn_name)
    body_text = source[body_open:body_close]
    body_inner = body_text[1:-1]

    replacements: List[Tuple[int, int, str, str]] = []
    touched_vars: List[str] = []

    for var in vars_:
        var_repls = _collect_replacements_for_var(body_inner, var)

        if not enable_lengths:
            var_repls = [x for x in var_repls if x[3] != "length"]
        if not enable_index_reads:
            var_repls = [x for x in var_repls if x[3] == "length"]

        if var_repls:
            touched_vars.append(var.name)
            replacements.extend(var_repls)

    if not replacements:
        return TransformResult(
            new_source=source,
            details={
                "note": "public_state_accessor_indirection_v1: no eligible public-state read sites found",
                "candidates": [v.name for v in vars_],
                "rewrites": [],
            },
        )

    replacements = replacements[: int(max_rewrites)]
    rewritten_body_inner, changed = _apply_replacements(body_inner, replacements)

    if changed <= 0:
        return TransformResult(
            new_source=source,
            details={
                "note": "public_state_accessor_indirection_v1: replacement pass produced no changes",
                "rewrites": [],
            },
        )

    helper_vars = [v for v in vars_ if v.name in set(touched_vars)]
    helper_block = _build_helper_block(helper_vars)
    src2, injected = _inject_helper_block(source, contract_name, helper_block, helper_vars)

    # re-find function body after helper injection
    _, new_body_open, new_body_close, _ = _find_function_span(src2, fn_name)
    new_body_text = "{" + rewritten_body_inner + "}"
    new_source = src2[:new_body_open] + new_body_text + src2[new_body_close:]

    return TransformResult(
        new_source=new_source,
        details={
            "note": "public_state_accessor_indirection_v1 applied",
            "injected_helpers": injected,
            "helper_vars": [v.name for v in helper_vars],
            "rewrite_count": changed,
            "rewrites": [
                {
                    "kind": kind,
                    "replacement": rep,
                }
                for (_a, _b, rep, kind) in replacements
            ],
        },
    )