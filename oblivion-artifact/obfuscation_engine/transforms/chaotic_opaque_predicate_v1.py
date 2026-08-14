from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Tuple


@dataclass
class ApplyResult:
    changed: bool
    new_source: str
    meta: Dict[str, Any]


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

    raise ValueError("Unmatched '{' in Solidity source.")


def _find_contract_span(src: str, contract_name: str) -> Tuple[int, int, int]:
    m = re.search(rf"\bcontract\s+{re.escape(contract_name)}\b", src)
    if not m:
        raise ValueError(f"Contract '{contract_name}' not found.")
    open_idx = src.find("{", m.end())
    if open_idx < 0:
        raise ValueError(f"Contract '{contract_name}' has no body.")
    close_idx = _find_matching_brace(src, open_idx)
    return m.start(), open_idx, close_idx


def _find_function_body_span(src: str, fn_name: str) -> Tuple[int, int, int, str]:
    if fn_name == "constructor":
        m = re.search(r"\bconstructor\s*\(", src)
    else:
        m = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", src)
    if not m:
        raise ValueError(f"Function '{fn_name}' not found.")

    open_idx = src.find("{", m.end())
    if open_idx < 0:
        raise ValueError(f"Function '{fn_name}' has no body.")

    close_idx = _find_matching_brace(src, open_idx)
    signature = src[m.start():open_idx]
    return open_idx, close_idx, open_idx + 1, signature


def _compute_base_indent(body: str) -> str:
    for ln in body.splitlines():
        if ln.strip():
            return ln[: len(ln) - len(ln.lstrip(" \t"))]
    return "    "


def _ensure_helper_once(source: str, contract_name: str, helper_name: str, helper_code: str) -> str:
    if helper_name in source:
        return source

    _cstart, copen, cclose = _find_contract_span(source, contract_name)
    contract_body = source[copen + 1:cclose]
    contract_body = contract_body + "\n" + helper_code + "\n"
    return source[:copen + 1] + contract_body + source[cclose:]


def apply_chaotic_opaque_predicate_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **kwargs: Any,
) -> ApplyResult:
    _ = kwargs

    open_idx, close_idx, insert_idx, signature = _find_function_body_span(source, fn_name)
    original_body = source[insert_idx:close_idx]
    base_indent = _compute_base_indent(original_body)

    # pure/view-safe deterministic chaotic-style mixer
    helper_name = f"__obf_cpm_mix_{seed}"
    helper_code = f"""
    function {helper_name}(uint256 x) internal pure returns (uint256) {{
        unchecked {{
            uint256 p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
            x = addmod(mulmod(x, x + 0x9E3779B97F4A7C15, p), 0x85EBCA6B, p);
            x = addmod(mulmod(x, x + 0xC2B2AE3D27D4EB4F, p), 0x165667B19E3779F9, p);
            x = addmod(mulmod(x, x + 0x27D4EB2F165667C5, p), 0x94D049BB133111EB, p);
            return x;
        }}
    }}
""".rstrip()

    src_with_helper = _ensure_helper_once(source, contract_name, helper_name, helper_code)

    # Re-find function span after helper insertion
    open_idx, close_idx, insert_idx, _signature = _find_function_body_span(src_with_helper, fn_name)
    original_body = src_with_helper[insert_idx:close_idx]
    base_indent = _compute_base_indent(original_body)

    inj_lines = [
        f"uint256 __cpm_seed_{seed} = uint256(keccak256(abi.encodePacked(uint256({seed}), bytes32(\"oblivion.cpm\"))));",
        f"uint256 __cpm_a_{seed} = {helper_name}(__cpm_seed_{seed});",
        f"uint256 __cpm_l_{seed} = {helper_name}(__cpm_a_{seed} ^ uint256(0x9E3779B97F4A7C15));",
        f"uint256 __cpm_r_{seed} = {helper_name}((__cpm_a_{seed} ^ uint256(0x9E3779B97F4A7C15)) + 0);",
        f"bool __cpm_pred_{seed} = (__cpm_l_{seed} == __cpm_r_{seed});",
        f"if (!__cpm_pred_{seed}) {{",
        f"    uint256 __junk_{seed} = (__cpm_l_{seed} ^ __cpm_r_{seed});",
        f"    __junk_{seed} = (__junk_{seed} + uint256(1)) - uint256(1);",
        f"}} else {{",
        f"    uint256 __cpm_nop_{seed} = (__cpm_a_{seed} ^ uint256(0));",
        f"    __cpm_nop_{seed} = (__cpm_nop_{seed} + uint256(0));",
        f"}}",
    ]

    inject = "\n" + "\n".join(f"{base_indent}{ln}" for ln in inj_lines) + "\n"
    new_source = src_with_helper[:insert_idx] + inject + src_with_helper[insert_idx:]

    return ApplyResult(
        changed=True,
        new_source=new_source,
        meta={
            "transform": "chaotic_opaque_predicate_v1",
            "function": fn_name,
            "seed": seed,
            "mode": "cpm_style_deterministic",
        },
    )