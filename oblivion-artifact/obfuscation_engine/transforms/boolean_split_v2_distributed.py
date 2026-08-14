from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


def _find_function_span(src: str, fn_name: str) -> Tuple[int, int]:
    fm = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", src)
    if not fm:
        raise ValueError(f"boolean_split_v2_distributed: function '{fn_name}' not found")

    brace_open = src.find("{", fm.end())
    if brace_open < 0:
        raise ValueError(f"boolean_split_v2_distributed: cannot find body open brace for {fn_name}")

    depth = 0
    j = brace_open
    while j < len(src):
        c = src[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return brace_open, j + 1
        j += 1

    raise ValueError(f"boolean_split_v2_distributed: cannot match braces for {fn_name}")


def _find_if_condition_spans(src: str, fn_name: str, limit: int = 2) -> List[Tuple[int, int, int, int]]:
    body_open, body_close = _find_function_span(src, fn_name)
    spans: List[Tuple[int, int, int, int]] = []
    i = body_open + 1

    in_squote = False
    in_dquote = False
    in_line_comment = False
    in_block_comment = False
    depth_brace = 0

    while i < body_close and len(spans) < limit:
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
            depth_brace += 1
            i += 1
            continue
        if ch == "}":
            depth_brace = max(0, depth_brace - 1)
            i += 1
            continue

        if depth_brace == 0 and src.startswith("if", i):
            prev_ok = i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")
            after_idx = i + 2
            after_ok = after_idx >= len(src) or not (src[after_idx].isalnum() or src[after_idx] == "_")
            if prev_ok and after_ok:
                j = after_idx
                while j < body_close and src[j].isspace():
                    j += 1
                if j < body_close and src[j] == "(":
                    cond_lparen = j
                    depthp = 0
                    k = j
                    while k < body_close:
                        if src[k] == "(":
                            depthp += 1
                        elif src[k] == ")":
                            depthp -= 1
                            if depthp == 0:
                                spans.append((cond_lparen + 1, k, i, body_open))
                                i = k + 1
                                break
                        k += 1
                    else:
                        break
                    continue
        i += 1
    return spans


def _compute_base_indent(fn_body: str) -> str:
    for ln in fn_body.splitlines():
        if ln.strip():
            return ln[: len(ln) - len(ln.lstrip(" \t"))]
    return "    "


def _line_start(src: str, idx: int) -> int:
    pos = src.rfind("\n", 0, idx)
    return 0 if pos < 0 else pos + 1


def _line_indent(src: str, idx: int, fallback: str) -> str:
    ls = _line_start(src, idx)
    i = ls
    while i < len(src) and src[i] in " \t":
        i += 1
    return src[ls:i] or fallback


def apply_boolean_split_v2_distributed(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    max_conditions: int = 2,
    **_: Any,
) -> TransformResult:
    _ = contract_name

    body_open, body_close = _find_function_span(source, fn_name)
    fn_body = source[body_open:body_close]
    fallback_indent = _compute_base_indent(fn_body)

    spans = _find_if_condition_spans(source, fn_name, limit=int(max_conditions))
    if not spans:
        return TransformResult(
            new_source=source,
            details={"rewritten": 0, "note": "boolean_split_v2_distributed: no eligible if-conditions found"},
        )

    new_source = source
    rewritten = 0

    for cond_start, cond_end, if_start, _fn_body_open in reversed(spans):
        cond = new_source[cond_start:cond_end].strip()
        suffix = f"{seed}_{rewritten}"
        indent = _line_indent(new_source, if_start, fallback_indent)

        prelude = (
            f"{indent}uint256 __bp_a_{suffix} = (({cond}) ? 7 : 3);\n"
            f"{indent}uint256 __bp_b_{suffix} = (__bp_a_{suffix} ^ 4);\n"
            f"{indent}bool __bp_t_{suffix} = (__bp_b_{suffix} == 3);\n"
        )
        new_cond = f"((__bp_t_{suffix} ? 1 : 0) == 1)"

        new_source = new_source[:if_start] + prelude + new_source[if_start:]
        delta = len(prelude)
        cond_start += delta
        cond_end += delta
        new_source = new_source[:cond_start] + new_cond + new_source[cond_end:]
        rewritten += 1

    return TransformResult(
        new_source=new_source,
        details={
            "rewritten": rewritten,
            "seed": seed,
            "note": "boolean_split_v2_distributed applied to real if-conditions using distributed carriers",
        },
    )