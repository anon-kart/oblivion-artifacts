# obfuscation_engine/transforms/predicate_masking_v1.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


def _find_first_if_condition_span(src: str, fn_name: str) -> Optional[tuple[int, int, int]]:
    """
    Find the first "if (<cond>)" inside function body. Returns (cond_start, cond_end, fn_body_start)
    """
    fm = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", src)
    if not fm:
        return None

    brace_open = src.find("{", fm.start())
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
    m = re.search(r"\bif\s*\(", body)
    if not m:
        return None

    p0 = brace_open + m.end() - 1  # points to '('
    depthp = 0
    cond_start = p0 + 1
    for k in range(p0, end):
        if src[k] == "(":
            depthp += 1
        elif src[k] == ")":
            depthp -= 1
            if depthp == 0:
                cond_end = k
                return cond_start, cond_end, brace_open
    return None


def apply_predicate_masking_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **kwargs: Any,
) -> TransformResult:
    """
    Rewrite the first if-condition in the function into a masked equivalent.

      if (COND)  ==> if (((((COND ? 1 : 0) ^ m) ^ m) == 1))

    where:
      m is a *constant* (0 or 1) derived from a hash of a constant tag.
      XOR-ing with the same value twice cancels out, so semantics are preserved exactly.
    """
    _ = (contract_name, kwargs)

    span = _find_first_if_condition_span(source, fn_name)
    if not span:
        return TransformResult(
            new_source=source,
            details={"seed": seed, "note": "predicate_masking_v1: no if found"},
        )

    cond_start, cond_end, _ = span
    cond = source[cond_start:cond_end].strip()

    tag = f"oblivion-mask:{seed}"
    m_expr = f"(uint256(keccak256(abi.encodePacked(\"{tag}\"))) >> 255)"  # 0 or 1, constant

    masked = f"(((((({cond}) ? 1 : 0) ^ {m_expr}) ^ {m_expr}) == 1))"

    new_source = source[:cond_start] + masked + source[cond_end:]

    return TransformResult(
        new_source=new_source,
        details={"seed": seed, "note": "predicate_masking_v1 applied to first if-condition (double-xor mask)"},
    )
