# obfuscation_engine/transforms/yul_microblock_v1.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


def _find_function_body_span(src: str, fn_name: str) -> Optional[tuple[int, int, str]]:
    m = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", src)
    if not m:
        return None
    i = m.start()
    brace_open = src.find("{", i)
    if brace_open == -1:
        return None

    # capture a bit of signature (to detect pure/view if needed)
    sig = src[m.start():brace_open]

    depth = 0
    for j in range(brace_open, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return brace_open, j, sig
    return None


def apply_yul_microblock_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **kwargs: Any,
) -> TransformResult:
    """
    Insert a tiny Yul assembly block that is semantics-preserving.

    Notes:
    - Safe for view/pure (no env reads, no state writes; only local temp)
    - Planner/engine should gate this to tier3 and low-risk contexts.
    """
    _ = (contract_name, kwargs)

    span = _find_function_body_span(source, fn_name)
    if not span:
        raise ValueError(f"yul_microblock_v1: could not locate function body for {fn_name}")

    lbrace, rbrace, sig = span
    body = source[lbrace + 1 : rbrace]

    # Avoid injecting if body already contains assembly blocks (keeps it stable)
    if re.search(r"\bassembly\s*\{", body):
        return TransformResult(
            new_source=source,
            details={"seed": seed, "note": "yul_microblock_v1 skipped: existing assembly"},
        )

    sig_norm = " ".join(sig.split()).lower()
    is_pure = (" pure " in f" {sig_norm} ") or sig_norm.endswith(" pure")
    is_view = (" view " in f" {sig_norm} ") or sig_norm.endswith(" view")

    k = (seed * 1337) & 0xFFFFFFFFFFFFFFFF

    inject = f"""
        {{
            uint256 __obf_y_{seed} = {k};
            assembly {{
                // yul microblock (semantics-preserving)
                let t := xor(__obf_y_{seed}, __obf_y_{seed})
                t := add(t, 0)
            }}
        }}
"""

    new_source = source[: lbrace + 1] + inject + body + source[rbrace:]

    return TransformResult(
        new_source=new_source,
        details={
            "seed": seed,
            "note": "yul_microblock_v1 inserted tiny assembly block",
            "pure": is_pure,
            "view": is_view,
        },
    )