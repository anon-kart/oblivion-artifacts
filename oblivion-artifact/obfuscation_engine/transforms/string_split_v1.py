from __future__ import annotations

import re
import random
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List


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

    raise ValueError("string_split_v1: unmatched '{'")


def _find_function_body_span(src: str, fn_name: str) -> Optional[Tuple[int, int]]:
    if fn_name == "constructor":
        m = re.search(r"\bconstructor\s*\(", src)
    else:
        m = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", src)
    if not m:
        return None
    lbrace = src.find("{", m.end())
    if lbrace < 0:
        return None
    rbrace = _find_matching_brace(src, lbrace)
    return lbrace + 1, rbrace


def _split_points(s: str, rnd: random.Random) -> List[str]:
    if len(s) < 8:
        return [s]

    if len(s) < 14:
        cuts = 2
    else:
        cuts = 3

    pts = sorted(set(rnd.randint(2, len(s) - 2) for _ in range(cuts - 1)))
    if not pts:
        return [s]

    out = []
    last = 0
    for p in pts:
        out.append(s[last:p])
        last = p
    out.append(s[last:])
    return [x for x in out if x]


def _is_probably_require_or_revert(body: str, lit_start: int) -> bool:
    window = body[max(0, lit_start - 48):lit_start]
    return bool(re.search(r"\b(require|revert|assert)\s*\([^)]*$", window))


def apply_string_split_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    min_len: int = 8,
    max_literals: int = 4,
    **_: Any,
) -> TransformResult:
    _ = contract_name
    span = _find_function_body_span(source, fn_name)
    if not span:
        return TransformResult(new_source=source, details={"note": f"string_split_v1: function {fn_name} not found"})

    body_l, body_r = span
    body = source[body_l:body_r]
    rnd = random.Random(int(seed))

    out: List[str] = []
    i = 0
    changed = 0
    n = len(body)

    in_line_comment = False
    in_block_comment = False
    in_squote = False

    while i < n:
        ch = body[i]
        nxt = body[i + 1] if i + 1 < n else ""

        if in_line_comment:
            out.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            out.append(ch)
            if ch == "*" and nxt == "/":
                out.append(nxt)
                i += 2
                in_block_comment = False
            else:
                i += 1
            continue

        if in_squote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(body[i + 1])
                i += 2
                continue
            if ch == "'":
                in_squote = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            out.append(ch)
            out.append(nxt)
            i += 2
            in_line_comment = True
            continue

        if ch == "/" and nxt == "*":
            out.append(ch)
            out.append(nxt)
            i += 2
            in_block_comment = True
            continue

        if ch == "'":
            in_squote = True
            out.append(ch)
            i += 1
            continue

        if ch == '"' and changed < int(max_literals):
            j = i + 1
            literal_chars: List[str] = []
            escaped = False
            while j < n:
                cj = body[j]
                literal_chars.append(cj)
                if escaped:
                    escaped = False
                elif cj == "\\":
                    escaped = True
                elif cj == '"':
                    break
                j += 1

            if j < n and literal_chars and literal_chars[-1] == '"':
                raw = "".join(literal_chars[:-1])

                if (
                    len(raw) >= int(min_len)
                    and not _is_probably_require_or_revert(body, i)
                    and "\\x" not in raw
                    and "\\u" not in raw
                ):
                    parts = _split_points(raw, rnd)
                    if len(parts) > 1:
                        repl = "string.concat(" + ", ".join(f"\"{p}\"" for p in parts) + ")"
                        out.append(repl)
                        changed += 1
                        i = j + 1
                        continue

            out.append(ch)
            i += 1
            continue

        out.append(ch)
        i += 1

    new_body = "".join(out)
    if new_body == body:
        return TransformResult(new_source=source, details={"note": "string_split_v1: no eligible string literals found", "changed": 0})

    new_source = source[:body_l] + new_body + source[body_r:]
    return TransformResult(
        new_source=new_source,
        details={
            "note": "string_split_v1 split string literals into string.concat(...) fragments",
            "changed": changed,
            "seed": seed,
        },
    )