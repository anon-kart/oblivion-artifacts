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

    raise ValueError("algebraic_identities_v1: unmatched '{'")


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


def _skip_context(line: str) -> bool:
    return bool(
        re.search(r"\b(require|revert|assert)\s*\(", line)
        or re.search(r"\bfor\s*\(", line)
        or "unchecked" in line
    )


_INT_RE = re.compile(r"(?<![A-Za-z0-9_])([1-9][0-9]{0,6})(?![A-Za-z0-9_])")


def _rewrite_literal(n: int, rnd: random.Random) -> str:
    # keep it very safe: identity rewrites only
    choice = rnd.choice([0, 1, 2])

    if choice == 0:
        k = rnd.randint(1, 7)
        return f"(({n} + {k}) - {k})"

    if choice == 1:
        m = rnd.randint(1, 15)
        return f"(({n} ^ {m}) ^ {m})"

    k = rnd.randint(2, 5)
    return f"((({n} * {k}) + {k}) - ((({k} - 1) * {n}) + {k}))"


def apply_algebraic_identities_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    max_rewrites: int = 6,
    **_: Any,
) -> TransformResult:
    _ = contract_name
    span = _find_function_body_span(source, fn_name)
    if not span:
        return TransformResult(new_source=source, details={"note": f"algebraic_identities_v1: function {fn_name} not found"})

    body_l, body_r = span
    body = source[body_l:body_r]
    rnd = random.Random(int(seed))
    rewrites = 0

    new_lines: List[str] = []
    for line in body.splitlines(True):
        if rewrites >= int(max_rewrites) or _skip_context(line):
            new_lines.append(line)
            continue

        def repl(m: re.Match) -> str:
            nonlocal rewrites
            if rewrites >= int(max_rewrites):
                return m.group(0)

            lit = int(m.group(1))
            # skip tiny literals; they are too common/noisy
            if lit <= 1:
                return m.group(0)

            rewrites += 1
            return _rewrite_literal(lit, rnd)

        new_lines.append(_INT_RE.sub(repl, line))

    new_body = "".join(new_lines)
    if new_body == body:
        return TransformResult(new_source=source, details={"note": "algebraic_identities_v1: no eligible arithmetic literals found", "changed": 0})

    new_source = source[:body_l] + new_body + source[body_r:]
    return TransformResult(
        new_source=new_source,
        details={
            "note": "algebraic_identities_v1 rewrote integer literals using safe algebraic identities",
            "changed": rewrites,
            "seed": seed,
        },
    )