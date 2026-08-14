# obfuscation_engine/transforms/dead_code_v1.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class TransformResult:
    new_source: str
    details: Dict


def _find_function_body_span(src: str, fn_name: str) -> Optional[tuple[int, int]]:
    """
    Best-effort: find "function <fn_name>" then match braces to get body span.
    Works for typical Solidity formatting; not an AST parser.
    """
    m = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", src)
    if not m:
        return None
    i = m.start()
    brace_open = src.find("{", i)
    if brace_open == -1:
        return None
    depth = 0
    for j in range(brace_open, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return brace_open, j
    return None


def _compute_base_indent(body: str) -> str:
    for ln in body.splitlines():
        if ln.strip():
            return ln[: len(ln) - len(ln.lstrip(" \t"))]
    return "    "


def apply_dead_code_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    nops: int = 2,
) -> TransformResult:
    """
    Insert semantically-dead code guarded by an opaque-false predicate.

    Improvements vs previous version:
      - Uses a stronger opaque-false predicate that is not a trivial constant fold like `k ^ k`.
      - Respects function indentation instead of hardcoding spaces.
      - Does NOT wrap or restructure existing control-flow; just injects a block.

    Safety:
      - No storage writes (locals only).
      - No external calls.
      - No revert paths.
    """
    _ = contract_name

    span = _find_function_body_span(source, fn_name)
    if not span:
        raise ValueError(f"dead_code_v1: could not locate function body for {fn_name}")

    lbrace, rbrace = span
    body = source[lbrace + 1 : rbrace]
    base_indent = _compute_base_indent(body)

    # Strong opaque-false predicate:
    #   d = keccak("X") - keccak("X")  => 0, but not trivially obvious without evaluating hashes.
    #   if (d != 0) { ... } is unreachable.
    tag = "oblivion_dead_tag"
    dead.append(
        f"uint256 __obf_dead_{seed} = "
        f"uint256(keccak256(abi.encodePacked(\"{tag}\"))) - "
        f"uint256(keccak256(abi.encodePacked(\"{tag}\")));"
    )
    dead: list[str] = []
    dead.append(f"uint256 __obf_dead_{seed} = uint256(keccak256(abi.encodePacked(\"{tag}\"))) - uint256(keccak256(abi.encodePacked(\"{tag}\")));")
    dead.append(f"if (__obf_dead_{seed} != 0) {{")
    for i in range(max(1, int(nops))):
        dead.append(f"    uint256 __obf_t_{seed}_{i} = (uint256(keccak256(abi.encodePacked(__obf_dead_{seed}, uint256({i}), uint256({seed})))));")
        dead.append(f"    __obf_t_{seed}_{i} = (__obf_t_{seed}_{i} ^ (__obf_t_{seed}_{i} >> 3));")
        dead.append(f"    __obf_t_{seed}_{i} = (__obf_t_{seed}_{i} & 0xFFFFFFFFFFFFFFFF);")
    dead.append("}")

    inject = "\n" + "\n".join(f"{base_indent}{ln}" for ln in dead) + "\n"

    new_body = inject + body
    new_source = source[: lbrace + 1] + new_body + source[rbrace:]

    return TransformResult(
        new_source=new_source,
        details={"seed": seed, "nops": nops, "note": "dead_code_v1 injected opaque-false block (hash-delta)"},
    )
