# obfuscation_engine/transforms/layout_scramble_v1.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class TransformResult:
    new_source: str
    details: Dict


def _strip_line_comments(line: str) -> str:
    """
    Best-effort removal of // comments while preserving strings.
    This avoids deleting URLs or // inside quoted Solidity strings.
    """
    out = []
    i = 0
    n = len(line)
    in_str = False
    quote = ""

    while i < n:
        ch = line[i]

        if in_str:
            out.append(ch)

            if ch == "\\" and i + 1 < n:
                out.append(line[i + 1])
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
            out.append(ch)
            i += 1
            continue

        if ch == "/" and i + 1 < n and line[i + 1] == "/":
            break

        out.append(ch)
        i += 1

    return "".join(out)


def _remove_block_comments(src: str) -> str:
    """
    Remove /* ... */ comments while preserving quoted strings.
    """
    out = []
    i = 0
    n = len(src)
    in_str = False
    quote = ""

    while i < n:
        ch = src[i]

        if in_str:
            out.append(ch)

            if ch == "\\" and i + 1 < n:
                out.append(src[i + 1])
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
            out.append(ch)
            i += 1
            continue

        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                i += 1
            i += 2
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _find_function_span(source: str, fn_name: str) -> Tuple[int, int]:
    """
    Find the full source span of a function body including signature and closing brace.
    Best-effort textual locator, compatible with your current transform style.
    """
    needle = f"function {fn_name}"
    i = source.find(needle)

    if i < 0:
        # More flexible fallback for irregular spacing:
        m = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", source)
        if not m:
            raise ValueError(f"function {fn_name} not found")
        i = m.start()

    brace_open = source.find("{", i)
    if brace_open < 0:
        raise ValueError(f"body open brace not found for {fn_name}")

    depth = 0
    j = brace_open

    in_str = False
    quote = ""

    while j < len(source):
        c = source[j]

        if in_str:
            if c == "\\" and j + 1 < len(source):
                j += 2
                continue

            if c == quote:
                in_str = False
                quote = ""

            j += 1
            continue

        if c in ("'", '"'):
            in_str = True
            quote = c
            j += 1
            continue

        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i, j + 1

        j += 1

    raise ValueError(f"unbalanced braces for {fn_name}")


def _minify_safe(src: str) -> str:
    """
    Token-preserving minifier.

    Goals:
      - remove excess whitespace
      - remove spaces around punctuation/operators where safe
      - preserve string contents exactly
      - avoid merging adjacent identifiers/numbers into one token

    This is intentionally conservative. It gives stronger Bian-like compactness
    than the old layout pass without changing Solidity semantics.
    """
    out = []
    i = 0
    n = len(src)

    in_str = False
    quote = ""

    def _last_char() -> str:
        return out[-1] if out else ""

    def _is_word_char(ch: str) -> bool:
        return ch.isalnum() or ch == "_" or ch == "$"

    punctuation_no_space = set("{}();,+-*/%=<>!&|[]:?.,")

    while i < n:
        ch = src[i]

        if in_str:
            out.append(ch)

            if ch == "\\" and i + 1 < n:
                out.append(src[i + 1])
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
            out.append(ch)
            i += 1
            continue

        if ch.isspace():
            j = i
            while j < n and src[j].isspace():
                j += 1

            prev = _last_char()
            nxt = src[j] if j < n else ""

            # Keep a single space only when removing it could merge two tokens.
            if prev and nxt and _is_word_char(prev) and _is_word_char(nxt):
                if prev != " ":
                    out.append(" ")

            i = j
            continue

        if ch in punctuation_no_space:
            # Remove previous space before punctuation.
            if out and out[-1] == " ":
                out.pop()

            out.append(ch)
            i += 1

            # Skip spaces after punctuation unless needed before identifier after certain tokens.
            while i < n and src[i].isspace():
                i += 1

            continue

        out.append(ch)
        i += 1

    return "".join(out).strip() + "\n"


def _normalize_blank_lines(src: str) -> str:
    """
    Light cleanup fallback. Kept for safety/debuggability.
    """
    lines = src.splitlines()
    out_lines = []
    blank = 0

    for ln in lines:
        if ln.strip() == "":
            blank += 1
            if blank <= 1:
                out_lines.append("")
        else:
            blank = 0
            out_lines.append(ln.rstrip())

    new_src = "\n".join(out_lines)
    if not new_src.endswith("\n"):
        new_src += "\n"

    return new_src


def apply_layout_scramble_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    mode: str = "function_minify",
) -> TransformResult:
    """
    Function-scoped layout scrambling/minification.

    Supported modes:
      - function_minify: remove comments + compact only the target function
      - function_cleanup: old-style whitespace cleanup only

    This transform is intended to be Tier-0 safe:
      - no condition rewriting
      - no statement reordering
      - no arithmetic mutation
      - no external-call mutation
      - no storage write mutation
    """
    _ = (contract_name, seed)

    try:
        f0, f1 = _find_function_span(source, fn_name)
    except Exception as e:
        return TransformResult(
            new_source=source,
            details={
                "note": "layout_scramble_v1: function not found (noop)",
                "reason": str(e),
                "seed": seed,
                "mode": mode,
                "changed": False,
            },
        )

    fn_src = source[f0:f1]

    without_blocks = _remove_block_comments(fn_src)
    lines = without_blocks.splitlines()
    without_line_comments = "\n".join(_strip_line_comments(ln) for ln in lines)

    if mode == "function_cleanup":
        new_fn = _normalize_blank_lines(without_line_comments)
        applied_mode = "function_cleanup"
    else:
        new_fn = _minify_safe(without_line_comments)
        applied_mode = "function_minify"

    if new_fn == fn_src:
        return TransformResult(
            new_source=source,
            details={
                "note": "layout_scramble_v1: nothing to scramble in target function",
                "seed": seed,
                "mode": applied_mode,
                "changed": False,
            },
        )

    new_src = source[:f0] + new_fn + source[f1:]

    return TransformResult(
        new_source=new_src,
        details={
            "note": "layout_scramble_v1 applied (function-scoped token-safe minification)",
            "seed": seed,
            "mode": applied_mode,
            "changed": True,
            "old_len": len(fn_src),
            "new_len": len(new_fn),
            "delta_len": len(new_fn) - len(fn_src),
        },
    )