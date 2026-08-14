from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


def build_fallback_test_candidates(
    *,
    contract_name: str,
    contract_source_path: Path,
    uncovered_targets: Sequence[Dict[str, Any]],
    max_generated_tests: int = 6,
    ir_json: Optional[Dict[str, Any]] = None,
    abi: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """
    Deterministic constructor-aware fallback synthesis.

    Returns list[spec]:
      {
        "name": str,
        "filename": str,
        "kind": "fallback_generated",
        "target": dict,
        "code": str
      }
    """
    contract_source_path = Path(contract_source_path).resolve()
    source_text = contract_source_path.read_text(encoding="utf-8", errors="replace")
    source_meta = _extract_source_metadata(
        contract_name=contract_name,
        source_text=source_text,
        ir_json=ir_json,
        abi=abi,
    )

    raw_targets = list(uncovered_targets) if uncovered_targets else []
    chosen_targets: List[Dict[str, Any]] = []

    for target in raw_targets:
        fn_name = str((target or {}).get("function") or "").strip()

        if fn_name.startswith("__obf_"):
            continue

        if fn_name in {"obf_u", "obf_b", "obf_s", "obf_x", "_requireBound"}:
            continue

        chosen_targets.append(dict(target))
        if len(chosen_targets) >= max_generated_tests:
            break

    if not chosen_targets:
        chosen_targets = [
            {
                "target_type": "contract",
                "contract": contract_name,
                "reason": "fallback_no_targets",
                "priority": 0.1,
                "suggested_test_intent": ["constructor_smoke", "public_function_smoke"],
            }
        ]

    specs: List[Dict[str, Any]] = []
    for idx, target in enumerate(chosen_targets, start=1):
        fn_name = str(target.get("function") or target.get("reason") or f"target_{idx}")
        name = _sanitize_identifier(f"autogen_{fn_name}_{idx}")
        filename = f"{contract_name}_AutoGen_{idx}.t.sol"
        code = _build_constructor_aware_test_file(
            contract_name=contract_name,
            contract_source_path=contract_source_path,
            source_meta=source_meta,
            synthetic_test_name=name,
            target=target,
            unique_suffix=str(idx),
        )
        specs.append(
            {
                "name": name,
                "filename": filename,
                "kind": "fallback_generated",
                "target": dict(target),
                "code": code,
            }
        )

    return specs


def build_single_fallback_candidate(
    *,
    contract_name: str,
    contract_source_path: Path,
    target: Dict[str, Any],
    unique_suffix: str = "1",
    ir_json: Optional[Dict[str, Any]] = None,
    abi: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    contract_source_path = Path(contract_source_path).resolve()
    source_text = contract_source_path.read_text(encoding="utf-8", errors="replace")
    source_meta = _extract_source_metadata(
        contract_name=contract_name,
        source_text=source_text,
        ir_json=ir_json,
        abi=abi,
    )

    fn_name = str(target.get("function") or target.get("reason") or "target")
    name = _sanitize_identifier(f"autogen_{fn_name}_{unique_suffix}")
    filename = f"{contract_name}_AutoGen_{unique_suffix}.t.sol"

    return {
        "name": name,
        "filename": filename,
        "kind": "fallback_generated",
        "target": dict(target),
        "code": _build_constructor_aware_test_file(
            contract_name=contract_name,
            contract_source_path=contract_source_path,
            source_meta=source_meta,
            synthetic_test_name=name,
            target=target,
            unique_suffix=str(unique_suffix),
        ),
    }


def _build_constructor_aware_test_file(
    *,
    contract_name: str,
    contract_source_path: Path,
    source_meta: Dict[str, Any],
    synthetic_test_name: str,
    target: Optional[Dict[str, Any]],
    unique_suffix: str,
) -> str:
    import_path = _best_import_path(contract_source_path)
    test_contract_name = f"{contract_name}_AutoGen_{_sanitize_identifier(synthetic_test_name)}_{unique_suffix}"

    constructor = source_meta.get("constructor", {}) or {}
    constructor_params = constructor.get("params", []) or []

    setup_prelude, ctor_arg_exprs = _build_constructor_setup_and_args(constructor_params)
    ctor_args_joined = ", ".join(ctor_arg_exprs)

    target_fn_name = str((target or {}).get("function") or "").strip()
    callable_map = {
        f.get("name"): f for f in (source_meta.get("callable_functions") or []) if f.get("name")
    }
    target_fn = callable_map.get(target_fn_name)

    body_cases = _build_targeted_test_bodies(
        contract_name=contract_name,
        target_fn=target_fn,
        synthetic_test_name=synthetic_test_name,
        target=target or {},
    )

    target_comment = json.dumps(target or {}, indent=2)

    return textwrap.dedent(
        f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.13;

        import "forge-std/Test.sol";
        import "{import_path}";

        contract {test_contract_name} is Test {{
            {contract_name} internal target;

            function setUp() public {{
{_indent_block(setup_prelude, 2) if setup_prelude.strip() else ""}
                target = new {contract_name}({ctor_args_joined});
            }}

{_indent_block(body_cases, 1)}

            /*
            OBLIVION FALLBACK TARGET CONTEXT
            {target_comment}
            */
        }}
        """
    ).rstrip() + "\n"


def _build_targeted_test_bodies(
    *,
    contract_name: str,
    target_fn: Optional[Dict[str, Any]],
    synthetic_test_name: str,
    target: Dict[str, Any],
) -> str:
    pieces: List[str] = []

    base_name = _sanitize_identifier(synthetic_test_name)

    pieces.append(
        f"""
function test_{base_name}_deploys() public {{
    assertTrue(address(target) != address(0));
}}
""".strip()
    )

    if not target_fn:
        pieces.append(
            f"""
function test_{base_name}_smoke() public {{
    assertTrue(address(target) != address(0));
}}
""".strip()
        )
        return "\n\n".join(pieces)

    fn_name = str(target_fn.get("name") or "unknown")
    params = list(target_fn.get("params") or [])
    state_mutability = str(target_fn.get("state_mutability") or "").lower()
    is_payable = state_mutability == "payable"

    # deterministic bounded inputs
    bounded_prelude_lines: List[str] = []
    bounded_arg_exprs: List[str] = []
    for idx, param in enumerate(params):
        typ = str(param.get("type") or "uint256").strip()
        typ = re.sub(r"\b(memory|storage|calldata)\b", "", typ).strip()
        name = _sanitize_identifier(param.get("name") or f"arg_{idx}")
        init_lines, expr = _solidity_value_initializer(typ=typ, var_name=name, seed=idx + 1)
        bounded_prelude_lines.extend(init_lines)
        bounded_prelude_lines.extend(_bounds_for_param(typ, name))
        bounded_arg_exprs.append(expr)

    bounded_prelude = "\n".join(bounded_prelude_lines)

    # fuzz inputs
    arg_decls, fuzz_arg_exprs, fuzz_prelude = _build_function_inputs(params)

    if is_payable:
        pay_prelude = "vm.deal(address(this), 1 ether);"
        bounded_call_prelude = "\n".join([x for x in [bounded_prelude, pay_prelude] if x.strip()])
        fuzz_call_prelude = "\n".join([x for x in [fuzz_prelude, pay_prelude] if x.strip()])
        bounded_call_expr = f"target.{fn_name}{{value: 1 wei}}({', '.join(bounded_arg_exprs)})"
        fuzz_call_expr = f"target.{fn_name}{{value: 1 wei}}({', '.join(fuzz_arg_exprs)})"
    else:
        bounded_call_prelude = bounded_prelude
        fuzz_call_prelude = fuzz_prelude
        bounded_call_expr = f"target.{fn_name}({', '.join(bounded_arg_exprs)})"
        fuzz_call_expr = f"target.{fn_name}({', '.join(fuzz_arg_exprs)})"

    guard_revert_needed = any(
        intent in set(target.get("suggested_test_intent") or [])
        for intent in ("guard_revert_case", "upper_bound_case")
    )

    if state_mutability in ("view", "pure"):
        bounded_body = f"""
function test_{base_name}_{fn_name}_bounded() public {{
{_indent_block(bounded_call_prelude, 1) if bounded_call_prelude.strip() else ""}
    {bounded_call_expr};
}}
""".strip()
    else:
        bounded_body = f"""
function test_{base_name}_{fn_name}_bounded() public {{
{_indent_block(bounded_call_prelude, 1) if bounded_call_prelude.strip() else ""}
    {bounded_call_expr};
    assertTrue(address(target) != address(0));
}}
""".strip()

    pieces.append(bounded_body)

    fuzz_bounds = _build_fuzz_bounds(params)
    fuzz_sections: List[str] = []
    if fuzz_bounds.strip():
        fuzz_sections.append(fuzz_bounds)
    if fuzz_call_prelude.strip():
        fuzz_sections.append(fuzz_call_prelude)
    fuzz_sections.append(f"{fuzz_call_expr};")

    fuzz_body = f"""
function test_{base_name}_{fn_name}_fuzz(
{_indent_block(arg_decls, 1)}
) public {{
{_indent_block("\n".join(fuzz_sections), 1)}
}}
""".strip()
    pieces.append(fuzz_body)

    if guard_revert_needed and params:
        revert_prelude, revert_exprs = _build_revert_case_inputs(params)
        if revert_exprs:
            revert_call_expr = (
                f"target.{fn_name}{{value: 1 wei}}({', '.join(revert_exprs)})"
                if is_payable
                else f"target.{fn_name}({', '.join(revert_exprs)})"
            )
            revert_body = f"""
function test_{base_name}_{fn_name}_guard_probe() public {{
{_indent_block(revert_prelude, 1) if revert_prelude.strip() else ""}
    try {revert_call_expr} {{
        assertTrue(true);
    }} catch {{
        assertTrue(true);
    }}
}}
""".strip()
            pieces.append(revert_body)

    return "\n\n".join(pieces)


def _build_revert_case_inputs(params: Sequence[Dict[str, str]]) -> Tuple[str, List[str]]:
    lines: List[str] = []
    exprs: List[str] = []

    for idx, param in enumerate(params):
        typ = str(param.get("type") or "uint256").strip()
        typ = re.sub(r"\b(memory|storage|calldata)\b", "", typ).strip()
        name = _sanitize_identifier(param.get("name") or f"probe_{idx}")
        setup_lines, expr = _solidity_edge_case_initializer(typ=typ, var_name=name, seed=idx + 17)
        lines.extend(setup_lines)
        exprs.append(expr)

    return "\n".join(lines), exprs


def _solidity_edge_case_initializer(*, typ: str, var_name: str, seed: int) -> Tuple[List[str], str]:
    t = " ".join(typ.split())
    tn = t.replace(" ", "")

    if tn.endswith("[]"):
        base = t[: t.rfind("[]")].strip()
        lines = [f"{base}[] memory {var_name} = new {base}[]({0});"]
        return lines, var_name

    if tn == "address":
        return [f"address {var_name} = address(0);"], var_name

    if tn == "bool":
        return [f"bool {var_name} = false;"], var_name

    if tn.startswith("uint") or tn == "uint":
        return [f"{t} {var_name} = 999999;"], var_name

    if tn.startswith("int") or tn == "int":
        return [f"{t} {var_name} = 999999;"], var_name

    if tn == "string":
        return [f'string memory {var_name} = "";'], var_name

    if tn == "bytes":
        return [f'bytes memory {var_name} = bytes("");'], var_name

    return [f"{t} {var_name};"], var_name


def _extract_source_metadata(
    *,
    contract_name: str,
    source_text: str,
    ir_json: Optional[Dict[str, Any]],
    abi: Optional[List[Dict[str, Any]]],
) -> Dict[str, Any]:
    contract_block = _extract_contract_block(contract_name, source_text)
    constructor = _extract_constructor(contract_block)
    functions = _extract_functions(contract_block)

    if isinstance(ir_json, dict):
        _merge_ir_function_metadata(
            contract_name=contract_name,
            constructor=constructor,
            functions=functions,
            ir_json=ir_json,
        )

    if not constructor.get("exists") and isinstance(abi, list):
        abi_ctor = _constructor_from_abi(abi)
        if abi_ctor:
            constructor = abi_ctor

    callable_functions = [
        fn for fn in functions if str(fn.get("visibility") or "").lower() in {"public", "external"}
    ]

    return {
        "contract_block": contract_block,
        "constructor": constructor,
        "functions": functions,
        "callable_functions": callable_functions,
        "abi": abi if isinstance(abi, list) else [],
    }


_FUNC_RE = re.compile(
    r"""
    function\s+
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*
    \((?P<params>.*?)\)\s*
    (?P<attrs>[^;{]*)
    \{
    """,
    re.DOTALL | re.VERBOSE,
)

_CONSTRUCTOR_RE = re.compile(
    r"""
    constructor\s*
    \((?P<params>.*?)\)\s*
    (?P<attrs>[^;{]*)
    \{
    """,
    re.DOTALL | re.VERBOSE,
)

_CONTRACT_RE_TEMPLATE = r"contract\s+{name}\b.*?\{{"


def _extract_contract_block(contract_name: str, source_text: str) -> str:
    m = re.search(_CONTRACT_RE_TEMPLATE.format(name=re.escape(contract_name)), source_text)
    if not m:
        return source_text

    start = m.start()
    brace_start = source_text.find("{", m.end() - 1)
    if brace_start < 0:
        return source_text[start:]

    depth = 0
    for idx in range(brace_start, len(source_text)):
        ch = source_text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source_text[start : idx + 1]

    return source_text[start:]


def _extract_constructor(contract_block: str) -> Dict[str, Any]:
    m = _CONSTRUCTOR_RE.search(contract_block)
    if not m:
        return {"exists": False, "params": []}

    params = _parse_param_list(m.group("params") or "")
    return {
        "exists": True,
        "params": params,
        "attrs": (m.group("attrs") or "").strip(),
    }


def _extract_functions(contract_block: str) -> List[Dict[str, Any]]:
    functions: List[Dict[str, Any]] = []
    for m in _FUNC_RE.finditer(contract_block):
        name = str(m.group("name") or "").strip()
        params = _parse_param_list(m.group("params") or "")
        attrs = str(m.group("attrs") or "").strip()
        visibility = _extract_visibility(attrs)
        state_mutability = _extract_mutability(attrs)

        functions.append(
            {
                "name": name,
                "params": params,
                "attrs": attrs,
                "visibility": visibility,
                "state_mutability": state_mutability,
            }
        )
    return functions


def _constructor_from_abi(abi: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for item in abi:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "constructor":
            params = []
            for idx, inp in enumerate(item.get("inputs") or [], start=1):
                if not isinstance(inp, dict):
                    continue
                params.append(
                    {
                        "type": str(inp.get("type") or "uint256"),
                        "name": _sanitize_identifier(inp.get("name") or f"ctor_{idx}"),
                    }
                )
            return {"exists": True, "params": params, "attrs": ""}
    return None


def _merge_ir_function_metadata(
    *,
    contract_name: str,
    constructor: Dict[str, Any],
    functions: List[Dict[str, Any]],
    ir_json: Dict[str, Any],
) -> None:
    contracts = []
    contract_top = ir_json.get("contract")
    if isinstance(contract_top, dict):
        contracts.append(contract_top)

    contract_list = ir_json.get("contracts")
    if isinstance(contract_list, list):
        contracts.extend([c for c in contract_list if isinstance(c, dict)])

    chosen = None
    for c in contracts:
        if str(c.get("name") or "") == contract_name:
            chosen = c
            break
    if not chosen:
        return

    if not constructor.get("exists") and chosen.get("constructor"):
        ctor = chosen.get("constructor") or {}
        if isinstance(ctor, dict):
            params = []
            for idx, p in enumerate(ctor.get("params") or [], start=1):
                if not isinstance(p, dict):
                    continue
                params.append(
                    {
                        "type": str(p.get("type") or "uint256"),
                        "name": _sanitize_identifier(p.get("name") or f"ctor_{idx}"),
                    }
                )
            constructor.clear()
            constructor.update({"exists": True, "params": params, "attrs": ""})

    ir_functions = {}
    for fn in chosen.get("functions") or []:
        if isinstance(fn, dict) and fn.get("name"):
            ir_functions[str(fn["name"])] = fn

    for fn in functions:
        irf = ir_functions.get(str(fn.get("name") or ""))
        if not isinstance(irf, dict):
            continue
        if not fn.get("params") and irf.get("params"):
            fn["params"] = [
                {
                    "type": str(p.get("type") or "uint256"),
                    "name": _sanitize_identifier(p.get("name") or f"p_{idx}"),
                }
                for idx, p in enumerate(irf.get("params") or [], start=1)
                if isinstance(p, dict)
            ]
        if irf.get("visibility"):
            fn["visibility"] = str(irf.get("visibility"))
        if irf.get("state_mutability"):
            fn["state_mutability"] = str(irf.get("state_mutability"))


def _parse_param_list(param_blob: str) -> List[Dict[str, str]]:
    blob = (param_blob or "").strip()
    if not blob:
        return []

    raw_parts = _split_top_level_csv(blob)
    params: List[Dict[str, str]] = []

    for idx, part in enumerate(raw_parts, start=1):
        p = " ".join(part.strip().split())
        if not p:
            continue

        tokens = p.split(" ")
        if len(tokens) == 1:
            typ = tokens[0]
            name = f"p_{idx}"
        else:
            name = tokens[-1]
            typ = " ".join(tokens[:-1])
            if re.search(r"\b(memory|storage|calldata)\b", name):
                typ = p
                name = f"p_{idx}"

        params.append(
            {
                "type": typ.strip(),
                "name": _sanitize_identifier(name.strip()) if name.strip() else f"p_{idx}",
            }
        )

    return params


def _extract_visibility(attrs: str) -> str:
    text = attrs.lower()
    for key in ("external", "public", "internal", "private"):
        if re.search(rf"\b{key}\b", text):
            return key
    return "public"


def _extract_mutability(attrs: str) -> str:
    text = attrs.lower()
    for key in ("payable", "view", "pure"):
        if re.search(rf"\b{key}\b", text):
            return key
    return "nonpayable"


def _build_constructor_setup_and_args(params: Sequence[Dict[str, str]]) -> Tuple[str, List[str]]:
    lines: List[str] = []
    arg_exprs: List[str] = []

    for idx, param in enumerate(params):
        typ = str(param.get("type") or "").strip()
        typ = re.sub(r"\b(memory|storage|calldata)\b", "", typ).strip()
        name = _sanitize_identifier(param.get("name") or f"ctor_{idx}")
        setup_lines, expr = _solidity_value_initializer(typ=typ, var_name=name, seed=idx + 1)
        lines.extend(setup_lines)
        arg_exprs.append(expr)

    return "\n".join(lines), arg_exprs

def _build_function_inputs(params: Sequence[Dict[str, str]]) -> Tuple[str, List[str], str]:
    decls: List[str] = []
    exprs: List[str] = []

    for idx, param in enumerate(params):
        typ = str(param.get("type") or "uint256").strip()
        typ = re.sub(r"\b(memory|storage|calldata)\b", "", typ).strip()
        name = _sanitize_identifier(param.get("name") or f"arg_{idx}")
        decls.append(f"{typ} {name}")
        exprs.append(name)

    return ",\n".join(decls), exprs, ""

def _build_fuzz_bounds(params: Sequence[Dict[str, str]]) -> str:
    lines: List[str] = []
    for idx, param in enumerate(params):
        typ = str(param.get("type") or "uint256").strip()
        typ = re.sub(r"\b(memory|storage|calldata)\b", "", typ).strip()
        name = _sanitize_identifier(param.get("name") or f"arg_{idx}")
        lines.extend(_bounds_for_param(typ, name))
    return "\n".join(lines)


def _bounds_for_param(typ: str, name: str) -> List[str]:
    t = typ.replace(" ", "")
    lines: List[str] = []

    if t.endswith("[]"):
        lines.append(f"vm.assume({name}.length <= 4);")
        return lines

    if t.startswith("uint") or t == "uint":
        lines.append(f"{name} = bound({name}, 0, 8);")
    elif t.startswith("int") or t == "int":
        lines.append(f"{name} = int256(bound(uint256({name} >= 0 ? {name} : -{name}), 0, 8));")
    elif t == "address":
        lines.append(f"vm.assume({name} != address(0));")
    elif t == "string":
        lines.append(f"vm.assume(bytes({name}).length <= 32);")
    elif t == "bytes":
        lines.append(f"vm.assume({name}.length <= 32);")
    return lines

def _solidity_value_initializer(*, typ: str, var_name: str, seed: int) -> Tuple[List[str], str]:
    t = " ".join(typ.split())
    tn = t.replace(" ", "")

    # Dynamic array support
    if tn.endswith("[]"):
        base = t[: t.rfind("[]")].strip()
        fill_values = _array_seed_values(base, seed)

        lines = [
            f"{base}[] memory {var_name} = new {base}[]({len(fill_values)});"
        ]
        for idx, value in enumerate(fill_values):
            lines.append(f"{var_name}[{idx}] = {value};")
        return lines, var_name

    # Static array support like uint256[3]
    m = re.match(r"^(?P<base>.+)\[(?P<n>\d+)\]$", tn)
    if m:
        base = m.group("base")
        n = int(m.group("n"))
        fill_values = _array_seed_values(base, seed)[:n]
        while len(fill_values) < n:
            fill_values.append("0")
        literal = "[" + ", ".join(fill_values) + "]"
        return [f"{base}[{n}] memory {var_name} = {literal};"], var_name

    if tn == "address":
        return [f"address {var_name} = address(0x{seed + 10:x});"], var_name

    if tn == "bool":
        return [f"bool {var_name} = {'true' if (seed % 2 == 0) else 'false'};"], var_name

    if tn.startswith("uint") or tn == "uint":
        return [f"{t} {var_name} = {seed + 1};"], var_name

    if tn.startswith("int") or tn == "int":
        return [f"{t} {var_name} = {seed + 1};"], var_name

    if tn == "string":
        return [f'string memory {var_name} = "seed";'], var_name

    if tn == "bytes":
        return [f'bytes memory {var_name} = bytes("seed");'], var_name

    if tn.startswith("bytes") and tn != "bytes":
        return [f'{t} {var_name} = {t}(hex"{(seed + 1):02x}");'], var_name

    return [f"{t} {var_name};"], var_name

def _array_seed_values(base_type: str, seed: int) -> List[str]:
    bt = base_type.replace(" ", "")
    if bt.startswith("uint") or bt == "uint":
        return [str(seed), str(seed + 1), str(seed + 2)]
    if bt.startswith("int") or bt == "int":
        return [str(seed), str(seed + 1), str(seed + 2)]
    if bt == "address":
        return [f"address(0x{seed + i + 10:x})" for i in range(3)]
    if bt == "bool":
        return ["true", "false", "true"]
    if bt == "string":
        return ['"a"', '"b"', '"c"']
    if bt == "bytes":
        return ['bytes("a")', 'bytes("b")', 'bytes("c")']
    return ["0", "0", "0"]


def _best_import_path(contract_source_path: Path) -> str:
    parts = contract_source_path.parts
    if "src" in parts:
        idx = parts.index("src")
        return "/".join(parts[idx:])
    return contract_source_path.as_posix()


def _split_top_level_csv(text: str) -> List[str]:
    out: List[str] = []
    cur: List[str] = []
    depth_paren = 0
    depth_brack = 0
    depth_brace = 0

    for ch in text:
        if ch == "," and depth_paren == 0 and depth_brack == 0 and depth_brace == 0:
            piece = "".join(cur).strip()
            if piece:
                out.append(piece)
            cur = []
            continue

        cur.append(ch)
        if ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
        elif ch == "[":
            depth_brack += 1
        elif ch == "]":
            depth_brack = max(0, depth_brack - 1)
        elif ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace = max(0, depth_brace - 1)

    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_]+")


def _sanitize_identifier(value: str) -> str:
    out = _SANITIZE_RE.sub("_", str(value).strip())
    out = re.sub(r"_+", "_", out).strip("_")
    if not out:
        out = "generated"
    if out[0].isdigit():
        out = f"g_{out}"
    return out


def _indent_block(text: str, level: int) -> str:
    if not text.strip():
        return ""
    indent = "    " * level
    return "\n".join(indent + line if line.strip() else line for line in text.splitlines())