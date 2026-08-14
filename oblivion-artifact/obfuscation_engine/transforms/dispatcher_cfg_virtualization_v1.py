# obfuscation_engine/transforms/dispatcher_cfg_virtualization_v1.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
import re


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


def _find_function_body_span(source: str, fn_name: str) -> Optional[Tuple[int, int, int]]:
    """
    Returns (body_lbrace_index, body_rbrace_index, header_start_index) for function/constructor.
    Best-effort. Assumes braces are balanced.
    """
    if fn_name == "constructor":
        pat = r"\bconstructor\s*\("
    else:
        pat = rf"\bfunction\s+{re.escape(fn_name)}\b\s*\("

    m = re.search(pat, source)
    if not m:
        return None

    header_start = m.start()

    # Find first '{' after header
    after = source[m.end():]
    m2 = re.search(r"\{", after)
    if not m2:
        return None

    body_lbrace = m.end() + m2.start()

    depth = 0
    body_rbrace = None
    for i in range(body_lbrace, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                body_rbrace = i
                break

    if body_rbrace is None:
        return None

    return (body_lbrace, body_rbrace, header_start)


def apply_dispatcher_cfg_virtualization_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **params: Any,
) -> TransformResult:
    """
    Dispatcher-based CFG virtualization (very lightweight).

    Wraps the function body in:
      uint256 __obf_state = 0;
      while (true) {
        if (__obf_state == 0) { __obf_state = 1; }
        else if (__obf_state == 1) { <original body>; __obf_state = 2; }
        else { break; }
      }

    Adds one bogus edge using an opaque-ish predicate so decompilers see extra CFG noise.
    """
    span = _find_function_body_span(source, fn_name)
    if not span:
        return TransformResult(new_source=source, details={"note": "dispatcher_cfg_virtualization_v1: function not found"})

    body_l, body_r, _ = span
    body_inner = source[body_l + 1 : body_r]

    # Heuristic: avoid double-wrapping if already virtualized
    if "__obf_state" in body_inner and "while (true)" in body_inner:
        return TransformResult(new_source=source, details={"note": "dispatcher_cfg_virtualization_v1: already virtualized"})

    indent = "        "  # best-effort indentation
    state_var = "__obf_state_1337"
    dead_var = "__obf_dead_1337"

    virt = []
    virt.append("\n")
    virt.append(f"{indent}uint256 {state_var} = 0;\n")
    virt.append(f"{indent}uint256 {dead_var} = uint256(keccak256(abi.encodePacked(\"oblivion:{seed}\"))) - uint256(keccak256(abi.encodePacked(\"oblivion:{seed}\")));\n")
    virt.append(f"{indent}while (true) {{\n")
    virt.append(f"{indent}    if ({state_var} == 0) {{\n")
    virt.append(f"{indent}        {state_var} = 1;\n")
    virt.append(f"{indent}        // bogus edge\n")
    virt.append(f"{indent}        if ((({dead_var} ^ uint256(keccak256(abi.encodePacked(\"mask:{seed}\")))) & 1) == 2) {{ {state_var} = 99; }}\n")
    virt.append(f"{indent}    }} else if ({state_var} == 1) {{\n")
    virt.append(body_inner)
    if not body_inner.endswith("\n"):
        virt.append("\n")
    virt.append(f"{indent}        {state_var} = 2;\n")
    virt.append(f"{indent}    }} else if ({state_var} == 99) {{\n")
    virt.append(f"{indent}        // unreachable-ish junk block\n")
    virt.append(f"{indent}        {state_var} = 2;\n")
    virt.append(f"{indent}    }} else {{\n")
    virt.append(f"{indent}        break;\n")
    virt.append(f"{indent}    }}\n")
    virt.append(f"{indent}}}\n")

    new_body = "{" + "".join(virt) + "    }"
    new_source = source[:body_l] + new_body + source[body_r + 1 :]

    return TransformResult(
        new_source=new_source,
        details={"seed": seed, "note": "dispatcher_cfg_virtualization_v1 wrapped body into a state machine"},
    )