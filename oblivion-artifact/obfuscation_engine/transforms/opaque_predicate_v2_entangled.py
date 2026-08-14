from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Tuple


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


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


def apply_opaque_predicate_v2_entangled(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **kwargs: Any,
) -> TransformResult:
    _ = kwargs

    helper_name = f"__obf_ent_mix_{seed}"
    helper_code = f"""
    function {helper_name}(uint256 x, uint256 y) internal pure returns (uint256) {{
        unchecked {{
            uint256 a = uint256(keccak256(abi.encodePacked(x, y, bytes32("oblivion.ent"))));
            uint256 b = ((a << 7) | (a >> 249));
            return a ^ b ^ uint256(0x9E3779B97F4A7C15);
        }}
    }}
""".rstrip()

    src_with_helper = _ensure_helper_once(source, contract_name, helper_name, helper_code)

    open_idx, close_idx, insert_idx, signature = _find_function_body_span(src_with_helper, fn_name)
    body = src_with_helper[insert_idx:close_idx]
    base_indent = _compute_base_indent(body)

    sig = " ".join(signature.split())
    is_pure = (" pure " in f" {sig} ") or sig.endswith(" pure")
    is_view = (" view " in f" {sig} ") or sig.endswith(" view")
    is_viewish = is_pure or is_view

    if is_viewish:
        seed_expr = f'uint256(keccak256(abi.encodePacked(uint256({seed}), bytes32("obl.ent"))))'
    else:
        seed_expr = f'uint256(keccak256(abi.encodePacked(msg.sender, address(this), uint256({seed}), bytes32("obl.ent"))))'

    top_lines = [
        f"uint256 __op_seed_{seed} = {seed_expr};",
        f"uint256 __op_a_{seed} = {helper_name}(__op_seed_{seed}, uint256({seed}));",
        f"uint256 __op_b_{seed} = {helper_name}(__op_seed_{seed}, uint256({seed})) ^ uint256(0);",
        f"bool __op_guard0_{seed} = (((__op_a_{seed} ^ __op_b_{seed}) + 0) != 0);",
        f"if (__op_guard0_{seed}) {{",
        f"    uint256 __op_j0_{seed} = (__op_a_{seed} & __op_b_{seed}) ^ (__op_a_{seed} | __op_b_{seed});",
        f"    __op_j0_{seed} = __op_j0_{seed} ^ __op_j0_{seed};",
        f"}}",
    ]

    bottom_lines = [
        f"uint256 __op_c_{seed} = (__op_a_{seed} ^ uint256(0xA5A5)) ^ (__op_b_{seed} ^ uint256(0xA5A5));",
        f"if ((__op_c_{seed} | 0) == 1) {{",
        f"    uint256 __op_j1_{seed} = __op_c_{seed} + 17;",
        f"    __op_j1_{seed} = __op_j1_{seed} - 17;",
        f"}}",
    ]

    top_inject = "\n" + "\n".join(f"{base_indent}{ln}" for ln in top_lines) + "\n"
    bottom_inject = "\n" + "\n".join(f"{base_indent}{ln}" for ln in bottom_lines) + "\n"

    new_source = (
        src_with_helper[:insert_idx]
        + top_inject
        + src_with_helper[insert_idx:close_idx]
        + bottom_inject
        + src_with_helper[close_idx:]
    )

    return TransformResult(
        new_source=new_source,
        details={
            "seed": seed,
            "helper": helper_name,
            "viewish": is_viewish,
            "note": "opaque_predicate_v2_entangled applied (multi-stage entangled opaque predicates)",
        },
    )


def apply(*, source: str, function: str, params: Dict[str, Any] | None = None) -> ApplyResult:
    params = params or {}
    seed = int(params.get("seed", 1337))
    contract_name = params.get("contract_name")
    if not contract_name:
        raise ValueError("opaque_predicate_v2_entangled requires contract_name in params")
    res = apply_opaque_predicate_v2_entangled(
        source=source,
        contract_name=str(contract_name),
        fn_name=function,
        seed=seed,
    )
    return ApplyResult(
        changed=(res.new_source != source),
        new_source=res.new_source,
        meta=res.details,
    )