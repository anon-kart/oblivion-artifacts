# obfuscation_engine/transforms/loop_rewrite_v1.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class TransformResult:
    new_source: str
    details: Dict


def _find_first_for_loop_span(src: str, fn_name: str) -> Optional[tuple[int, int]]:
    """
    Best-effort: locate first "for (" in function body and rewrite the header only.
    """
    fm = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", src)
    if not fm:
        return None
    i = fm.start()
    brace_open = src.find("{", i)
    if brace_open == -1:
        return None

    depth = 0
    end = None
    for j in range(brace_open, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                end = j
                break
    if end is None:
        return None

    body = src[brace_open:end]
    m = re.search(r"\bfor\s*\(", body)
    if not m:
        return None

    p0 = brace_open + m.end() - 1  # '('
    depthp = 0
    for k in range(p0, end):
        if src[k] == "(":
            depthp += 1
        elif src[k] == ")":
            depthp -= 1
            if depthp == 0:
                return p0, k
    return None


def apply_loop_rewrite_v1(*, source: str, contract_name: str, fn_name: str, seed: int = 1337) -> TransformResult:
    """
    Rewrite the first for-loop header:

      for (init; cond; inc) { ... }

    into

      { init; while (cond) { ...; inc; } }

    NOTE: This is a best-effort text rewrite. It will NOT handle all patterns.
    It only rewrites the first for-loop it finds.
    """
    span = _find_first_for_loop_span(source, fn_name)
    if not span:
        return TransformResult(new_source=source, details={"note": "loop_rewrite_v1: no for-loop found"})

    p0, p1 = span
    header = source[p0 + 1 : p1]  # inside (...)
    parts = [p.strip() for p in header.split(";")]
    if len(parts) != 3:
        return TransformResult(new_source=source, details={"note": "loop_rewrite_v1: unsupported for header"})

    init, cond, inc = parts
    if init == "":
        init = ""
    if cond == "":
        cond = "true"
    if inc == "":
        inc = ""

    # Find the body block start after the for-header
    after = source[p1 + 1 :]
    m = re.search(r"\{", after)
    if not m:
        return TransformResult(new_source=source, details={"note": "loop_rewrite_v1: no block after for"})

    body_lbrace = p1 + 1 + m.start()
    # match that block
    depth = 0
    body_rbrace = None
    for i in range(body_lbrace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                body_rbrace = i
                break
    if body_rbrace is None:
        return TransformResult(new_source=source, details={"note": "loop_rewrite_v1: unmatched braces"})

    body_inner = source[body_lbrace + 1 : body_rbrace]

    if re.search(r"\bcontinue\s*;", body_inner):
        return TransformResult(
            new_source=source,
            details={
                "note": "loop_rewrite_v1: skipped because continue would change semantics in for->while rewrite"
            },
        )

    # build rewritten block
    init_stmt = (init + ";") if init else ""
    inc_stmt = (inc + ";") if inc else ""
    rewritten = "{\n"
    if init_stmt:
        rewritten += f"                {init_stmt}\n"
    rewritten += f"                while ({cond}) {{\n"
    rewritten += body_inner
    if inc_stmt:
        rewritten += f"\n                {inc_stmt}\n"
    rewritten += "                }\n"
    rewritten += "            }"

    # replace "for(<header>)<bodyblock>" with rewritten
    # find start of 'for' keyword
    for_kw = source.rfind("for", 0, p0)
    if for_kw == -1:
        return TransformResult(new_source=source, details={"note": "loop_rewrite_v1: cannot locate for keyword"})

    new_source = source[:for_kw] + rewritten + source[body_rbrace + 1 :]

    return TransformResult(
        new_source=new_source,
        details={"seed": seed, "note": "loop_rewrite_v1 rewrote first for-loop to while"},
    )
