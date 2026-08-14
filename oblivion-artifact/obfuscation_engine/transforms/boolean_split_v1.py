# obfuscation_engine/transforms/boolean_split_v1.py
from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Any, Dict, Tuple


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


_SOL_KEYWORDS = {
    "function", "contract", "if", "else", "for", "while", "do", "break", "continue",
    "return", "emit", "revert", "require", "assert", "unchecked", "try", "catch",
    "new", "delete", "mapping", "memory", "storage", "calldata", "view", "pure",
    "payable", "external", "public", "internal", "private", "constant", "immutable",
    "pragma", "import", "event", "error", "modifier", "struct", "enum",
    "true", "false",
}


def _find_function_span(source: str, fn_name: str) -> Tuple[int, int]:
    """
    Best-effort: find 'function <fn_name>' and match braces for the body.
    Returns (start_idx_of_body_open_brace, end_idx_exclusive_of_body_close_brace).
    """
    needle = f"function {fn_name}"
    i = source.find(needle)
    if i < 0:
        # Sometimes signature can be: function\n<name>
        needle2 = f"function\n{fn_name}"
        i = source.find(needle2)
    if i < 0:
        raise ValueError(f"boolean_split_v1: function {fn_name} not found")

    brace_open = source.find("{", i)
    if brace_open < 0:
        raise ValueError(f"boolean_split_v1: cannot find body open brace for {fn_name}")

    depth = 0
    j = brace_open
    while j < len(source):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return brace_open, j + 1
        j += 1

    raise ValueError(f"boolean_split_v1: cannot match braces for {fn_name}")


def _split_bools_in_code(code: str, rnd: random.Random) -> Tuple[str, int]:
    """
    Replace true/false tokens outside strings/comments with equivalent boolean expressions.
    """
    out = []
    i = 0
    n = len(code)

    in_line_comment = False
    in_block_comment = False
    in_str = False
    str_quote = ""

    replaced = 0

    def is_ident_char(ch: str) -> bool:
        return ch.isalnum() or ch == "_"

    while i < n:
        ch = code[i]
        nxt = code[i + 1] if i + 1 < n else ""

        # handle comment/string state transitions
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

        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(code[i + 1])
                i += 2
                continue
            if ch == str_quote:
                in_str = False
                str_quote = ""
            i += 1
            continue

        # entering comment
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

        # entering string
        if ch in ("'", '"'):
            in_str = True
            str_quote = ch
            out.append(ch)
            i += 1
            continue

        # token check
        if ch.isalpha() or ch == "_":
            start = i
            i += 1
            while i < n and is_ident_char(code[i]):
                i += 1
            tok = code[start:i]

            if tok == "true":
                # a few equivalent expansions
                choices = [
                    "(true || false)",
                    "(!false)",
                    "((1 == 1) && true)",
                    "(true && (0 == 0))",
                ]
                out.append(rnd.choice(choices))
                replaced += 1
            elif tok == "false":
                choices = [
                    "(false && true)",
                    "(!true)",
                    "((1 != 1) || false)",
                    "(false || (0 == 1))",
                ]
                out.append(rnd.choice(choices))
                replaced += 1
            else:
                out.append(tok)
            continue

        out.append(ch)
        i += 1

    return "".join(out), replaced


def apply_boolean_split_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    max_replacements: int = 1000,
    **_: Any,
) -> TransformResult:
    rnd = random.Random(int(seed))

    body_open, body_close = _find_function_span(source, fn_name)
    body = source[body_open:body_close]

    new_body, replaced = _split_bools_in_code(body, rnd)
    if replaced > max_replacements:
        replaced = max_replacements

    if new_body == body:
        return TransformResult(new_source=source, details={"replaced": 0, "note": "no bool literals found"})

    new_source = source[:body_open] + new_body + source[body_close:]
    return TransformResult(
        new_source=new_source,
        details={
            "replaced": replaced,
            "seed": seed,
            "note": "boolean_split_v1 applied to bool literals (outside comments/strings)",
        },
    )
