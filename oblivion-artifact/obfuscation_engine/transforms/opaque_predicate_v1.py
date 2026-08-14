# obfuscation_engine/transforms/opaque_predicate_v1.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Tuple


@dataclass(frozen=True)
class ApplyResult:
    changed: bool
    new_source: str
    meta: Dict[str, Any]


def _find_matching_brace(src: str, open_idx: int) -> int:
    """
    Given index of a '{', return index of its matching '}'.
    Minimal brace matcher that skips over strings and // and /* */ comments.
    """
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


def _find_function_body_span(src: str, fn_name: str) -> Tuple[int, int, int, str]:
    pat = re.compile(rf"\bfunction\s+{re.escape(fn_name)}\b")
    m = pat.search(src)
    if not m:
        raise ValueError(f"Function '{fn_name}' not found in source.")

    open_idx = src.find("{", m.end())
    if open_idx == -1:
        raise ValueError(f"Function '{fn_name}' has no body '{{'.")

    close_idx = _find_matching_brace(src, open_idx)
    signature = src[m.start():open_idx]
    return open_idx, close_idx, open_idx + 1, signature


def _compute_base_indent(body: str) -> str:
    for ln in body.splitlines():
        if ln.strip():
            return ln[: len(ln) - len(ln.lstrip(" \t"))]
    return "    "


def apply(*, source: str, function: str, params: Dict[str, Any] | None = None) -> ApplyResult:
    """
    Insert an opaque predicate *without* wrapping the whole function body.

    Why:
      - Wrapping the entire body in `if (always_true)` can accidentally create "missing return"
        paths for view/pure functions and confuses downstream tooling.
      - This transform instead injects a small always-unreachable branch near the top of the body.

    Safety properties:
      - No storage writes introduced (locals only).
      - No external calls introduced.
      - No new revert paths introduced.
      - The injected branch is provably unreachable.
    """
    params = params or {}
    seed = int(params.get("seed", 1337))

    _open_idx, close_idx, insert_idx, signature = _find_function_body_span(source, function)
    original_body = source[insert_idx:close_idx]
    base_indent = _compute_base_indent(original_body)

    # Determine mutability (pure / view / non-view)
    sig = " ".join(signature.split())
    is_pure = (" pure " in f" {sig} ") or sig.endswith(" pure")
    is_view = (" view " in f" {sig} ") or sig.endswith(" view")
    is_viewish = is_pure or is_view

    # A stronger (but still constant) opaque condition:
    #   Let a = uint256(keccak256(abi.encodePacked(<constant stuff>)))
    #   Let hi = a >> 128, lo = uint128(a)
    #   Then ((hi<<128)|lo) == a is ALWAYS true.
    #
    # We then negate it so the branch is ALWAYS false.
    #
    # Note: for pure/view we avoid msg.sender/address(this) to keep tool expectations clean.
    if is_viewish:
        a_expr = f"uint256(keccak256(abi.encodePacked(uint256({seed}), bytes32(\"oblivion\"))))"
    else:
        a_expr = f"uint256(keccak256(abi.encodePacked(msg.sender, address(this), uint256({seed}), bytes32(\"oblivion\"))))"

    inj_lines = [
        f"uint256 __op_{seed} = {a_expr};",
        f"uint256 __hi_{seed} = (__op_{seed} >> 128);",
        f"uint256 __lo_{seed} = uint256(uint128(__op_{seed}));",
        f"if ((((__hi_{seed} << 128) | __lo_{seed}) != __op_{seed})) {{",
        f"    uint256 __junk_{seed} = (__op_{seed} + 7) * 3;",
        f"    __junk_{seed} = (__junk_{seed} ^ (__junk_{seed} >> 1));",
        f"}}",
    ]

    inject = "\n" + "\n".join(f"{base_indent}{ln}" for ln in inj_lines) + "\n"

    # Insert right after '{' (insert_idx)
    new_source = source[:insert_idx] + inject + source[insert_idx:]

    return ApplyResult(
        changed=True,
        new_source=new_source,
        meta={
            "transform": "opaque_predicate_v1",
            "function": function,
            "seed": seed,
            "viewish": is_viewish,
            "mode": "inject_unreachable_branch",
        },
    )


# -------------------------------------------------------------------
# REQUIRED adapter for your engine (it expects apply_opaque_predicate_v1)
# -------------------------------------------------------------------
def apply_opaque_predicate_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **kwargs: Any,
) -> ApplyResult:
    _ = (contract_name, kwargs)
    return apply(source=source, function=fn_name, params={"seed": seed})
