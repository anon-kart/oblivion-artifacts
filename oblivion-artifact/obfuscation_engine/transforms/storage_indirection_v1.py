# obfuscation_engine/transforms/storage_indirection_v1.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


def _find_contract_span(src: str) -> Optional[Tuple[int, int, str]]:
    """
    Best-effort: find first `contract X { ... }` span and return (lbrace, rbrace, contract_name).
    """
    m = re.search(r"\bcontract\s+([A-Za-z_]\w*)\b", src)
    if not m:
        return None
    cname = m.group(1)
    lbrace = src.find("{", m.end())
    if lbrace < 0:
        return None

    depth = 0
    for j in range(lbrace, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return (lbrace, j, cname)
    return None


def _find_function_body_span(src: str, fn_name: str) -> Optional[Tuple[int, int]]:
    m = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", src)
    if not m:
        return None
    lbrace = src.find("{", m.end())
    if lbrace < 0:
        return None
    depth = 0
    for j in range(lbrace, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return (lbrace, j)
    return None


def _detect_storage_symbols(contract_src: str) -> Dict[str, str]:
    """
    Very small detector for state vars:
      - uint256[] public numbers;
      - mapping(address => uint256) public deposits;
      - uint256[][] public grid;
    Returns {name: kind} where kind in {"array1","array2","mapping"}.
    """
    out: Dict[str, str] = {}

    # mapping(...)
    for m in re.finditer(r"\bmapping\s*\([^)]*\)\s*(?:public|private|internal|external)?\s*([A-Za-z_]\w*)\s*;", contract_src):
        out[m.group(1)] = "mapping"

    # 2D arrays: type[][]
    for m in re.finditer(r"\b[A-Za-z_]\w*\s*\[\s*\]\s*\[\s*\]\s*(?:public|private|internal|external)?\s*([A-Za-z_]\w*)\s*;", contract_src):
        out[m.group(1)] = "array2"

    # 1D arrays: type[]
    for m in re.finditer(r"\b[A-Za-z_]\w*\s*\[\s*\]\s*(?:public|private|internal|external)?\s*([A-Za-z_]\w*)\s*;", contract_src):
        name = m.group(1)
        if name not in out:
            out[name] = "array1"

    return out


def _ensure_helper_once(contract_body: str, helper_sig_fragment: str, helper_code: str) -> Tuple[str, bool]:
    """
    Insert helper_code before final '}' if helper_sig_fragment not found.
    """
    if helper_sig_fragment in contract_body:
        return contract_body, False
    # insert before last brace (contract body has no outer braces here; caller controls insertion)
    return contract_body + "\n" + helper_code + "\n", True


def apply_storage_indirection_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **kwargs: Any,
) -> TransformResult:
    """
    DATA-FLOW strength transform:
      - Replace direct storage reads/writes with indirection helpers.
      - Adds internal helper functions at contract scope if needed.

    Supported (best-effort):
      - mapping[K] reads and simple assignments: m[k], m[k] = expr, m[k] += expr, m[k] -= expr
      - 1D array reads/writes: a[i], a[i] = expr
    Not attempted:
      - nested indices (a[i][j]) rewriting
      - complex LHS patterns
      - inline assembly / yul
    """
    _ = (contract_name, seed, kwargs)

    cspan = _find_contract_span(source)
    if not cspan:
        return TransformResult(new_source=source, details={"note": "storage_indirection_v1: no contract found"})

    contract_lbrace, contract_rbrace, detected_cname = cspan
    # If caller passed contract_name and it doesn't match first contract, we still operate on first contract (best-effort)
    _ = detected_cname

    contract_body = source[contract_lbrace + 1 : contract_rbrace]
    symbols = _detect_storage_symbols(contract_body)
    if not symbols:
        return TransformResult(new_source=source, details={"note": "storage_indirection_v1: no storage symbols detected"})

    fspan = _find_function_body_span(source, fn_name)
    if not fspan:
        return TransformResult(new_source=source, details={"note": f"storage_indirection_v1: function {fn_name} not found"})

    fl, fr = fspan
    fn_body = source[fl + 1 : fr]

    if re.search(r"\bassembly\b", fn_body):
        return TransformResult(new_source=source, details={"note": "storage_indirection_v1 skipped: assembly present"})

    changed = False
    helpers_added: List[str] = []
    rewrites: List[Dict[str, Any]] = []

    # ---- mapping rewrites ----
    # LHS assignment: m[k] = expr;
    for name, kind in symbols.items():
        if kind != "mapping":
            continue

        get_name = f"__obf_get_{name}"
        set_name = f"__obf_set_{name}"

        # Add helpers if needed later
        get_sig_frag = f"function {get_name}("
        set_sig_frag = f"function {set_name}("

        # Replace "+=" and "-=" first (so "=" doesn't eat them)
        def repl_plus_eq(m: re.Match) -> str:
            nonlocal changed
            key = m.group("key").strip()
            rhs = m.group("rhs").strip()
            changed = True
            rewrites.append({"kind": "mapping+=", "name": name})
            return f"{set_name}({key}, {get_name}({key}) + ({rhs}));"

        def repl_minus_eq(m: re.Match) -> str:
            nonlocal changed
            key = m.group("key").strip()
            rhs = m.group("rhs").strip()
            changed = True
            rewrites.append({"kind": "mapping-=", "name": name})
            return f"{set_name}({key}, {get_name}({key}) - ({rhs}));"

        def repl_assign(m: re.Match) -> str:
            nonlocal changed
            key = m.group("key").strip()
            rhs = m.group("rhs").strip()
            changed = True
            rewrites.append({"kind": "mapping=", "name": name})
            return f"{set_name}({key}, ({rhs}));"

        plus_pat = re.compile(rf"\b{re.escape(name)}\s*\[\s*(?P<key>[^\]]+?)\s*\]\s*\+\=\s*(?P<rhs>[^;]+);")
        minus_pat = re.compile(rf"\b{re.escape(name)}\s*\[\s*(?P<key>[^\]]+?)\s*\]\s*\-\=\s*(?P<rhs>[^;]+);")
        assign_pat = re.compile(rf"\b{re.escape(name)}\s*\[\s*(?P<key>[^\]]+?)\s*\]\s*\=\s*(?P<rhs>[^;]+);")

        fn_body2 = plus_pat.sub(repl_plus_eq, fn_body)
        fn_body2 = minus_pat.sub(repl_minus_eq, fn_body2)
        fn_body2 = assign_pat.sub(repl_assign, fn_body2)

        fn_body = fn_body2

        # Replace remaining reads: m[k] -> __obf_get_m(k)
        # Avoid touching the ones we just converted (they no longer look like m[...])
        read_pat = re.compile(rf"\b{re.escape(name)}\s*\[\s*([^\]]+?)\s*\]")
        if read_pat.search(fn_body):
            fn_body = read_pat.sub(lambda mm: f"{get_name}({mm.group(1).strip()})", fn_body)
            changed = True
            rewrites.append({"kind": "mapping_read", "name": name})

        if changed:
            # Add helpers at contract scope (idempotent)
            helper_get = f"""
    function {get_name}(address __k) internal view returns (uint256 __v) {{
        // storage indirection (read)
        return {name}[__k];
    }}
""".rstrip()

            helper_set = f"""
    function {set_name}(address __k, uint256 __v) internal {{
        // storage indirection (write)
        {name}[__k] = __v;
    }}
""".rstrip()

            contract_body, added1 = _ensure_helper_once(contract_body, get_sig_frag, helper_get)
            contract_body, added2 = _ensure_helper_once(contract_body, set_sig_frag, helper_set)

            if added1:
                helpers_added.append(get_name)
            if added2:
                helpers_added.append(set_name)

    # ---- 1D array rewrites ----
    for name, kind in symbols.items():
        if kind != "array1":
            continue

        get_name = f"__obf_get_{name}"
        set_name = f"__obf_set_{name}"
        get_sig_frag = f"function {get_name}("
        set_sig_frag = f"function {set_name}("

        # a[i] = rhs;
        assign_pat = re.compile(rf"\b{re.escape(name)}\s*\[\s*(?P<idx>[^\]]+?)\s*\]\s*\=\s*(?P<rhs>[^;]+);")

        def repl_arr_assign(m: re.Match) -> str:
            nonlocal changed
            idx = m.group("idx").strip()
            rhs = m.group("rhs").strip()
            changed = True
            rewrites.append({"kind": "array1=", "name": name})
            return f"{set_name}({idx}, ({rhs}));"

        fn_body2 = assign_pat.sub(repl_arr_assign, fn_body)
        fn_body = fn_body2

        # remaining reads a[i] -> get(i)
        read_pat = re.compile(rf"\b{re.escape(name)}\s*\[\s*([^\]]+?)\s*\]")
        if read_pat.search(fn_body):
            fn_body = read_pat.sub(lambda mm: f"{get_name}({mm.group(1).strip()})", fn_body)
            changed = True
            rewrites.append({"kind": "array1_read", "name": name})

        if changed:
            helper_get = f"""
    function {get_name}(uint256 __i) internal view returns (uint256 __v) {{
        // storage indirection (read)
        return {name}[__i];
    }}
""".rstrip()

            helper_set = f"""
    function {set_name}(uint256 __i, uint256 __v) internal {{
        // storage indirection (write)
        {name}[__i] = __v;
    }}
""".rstrip()

            contract_body, added1 = _ensure_helper_once(contract_body, get_sig_frag, helper_get)
            contract_body, added2 = _ensure_helper_once(contract_body, set_sig_frag, helper_set)

            if added1:
                helpers_added.append(get_name)
            if added2:
                helpers_added.append(set_name)

    if not changed:
        return TransformResult(new_source=source, details={"note": "storage_indirection_v1: no eligible patterns found"})

    # Rebuild source:
    # 1) replace function body slice
    new_source = source[: fl + 1] + fn_body + source[fr:]

    # 2) replace contract body slice (helpers)
    # Recompute contract span on the updated source may shift indices; use original indices carefully:
    # safest: re-find contract span and replace body there.
    cspan2 = _find_contract_span(new_source)
    if cspan2:
        cl2, cr2, _ = cspan2
        new_source = new_source[: cl2 + 1] + contract_body + new_source[cr2:]

    return TransformResult(
        new_source=new_source,
        details={
            "note": "storage_indirection_v1 applied (storage reads/writes routed via helpers)",
            "helpers_added": helpers_added,
            "rewrites": rewrites[:50],  # keep it bounded
        },
    )
