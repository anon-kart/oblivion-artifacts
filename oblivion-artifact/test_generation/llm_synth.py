from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    from decision.llm_client import call_llm
except Exception:  # pragma: no cover
    call_llm = None  # type: ignore


def build_llm_test_generator(
    model: str = "gpt-4.1-mini",
    temperature: float = 0.2,
    max_tests: int = 6,
    root: Optional[str] = None,
) -> Callable[[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Build a callable for the explicit LLM test augmentation stage.

    Expected payload keys:
      - contract_name
      - contract_source_path
      - harness_name
      - baseline_tests
      - baseline_traces
      - coverage
      - uncovered_targets
      - max_generated_tests
      - ir_json             (optional)
      - ir_json_path        (optional)
      - abi                 (optional)

    Returns list[spec], where each spec contains:
      {
        "name": str,
        "filename": str,
        "kind": "llm_generated" | "llm_fallback",
        "target": dict,
        "code": str,
      }
    """
    repo_root = Path(root).resolve() if root else Path.cwd().resolve()

    def _generate(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        contract_name = str(payload.get("contract_name") or "").strip()
        contract_source_path = Path(str(payload.get("contract_source_path") or "")).resolve()
        uncovered_targets = list(payload.get("uncovered_targets") or [])
        requested_max = int(payload.get("max_generated_tests") or max_tests or 6)
        effective_max = max(1, min(requested_max, max_tests))

        if not contract_name or not contract_source_path.exists():
            return []

        source_text = _read_text(contract_source_path)
        if not source_text.strip():
            return []

        ir_json = payload.get("ir_json")
        if not isinstance(ir_json, dict):
            ir_json_path = payload.get("ir_json_path")
            if ir_json_path:
                try:
                    ir_json = json.loads(Path(str(ir_json_path)).read_text(encoding="utf-8"))
                except Exception:
                    ir_json = None

        source_meta = _extract_source_metadata(
            contract_name=contract_name,
            source_text=source_text,
            ir_json=ir_json if isinstance(ir_json, dict) else None,
            abi=payload.get("abi"),
        )

        fallback_specs = _build_deterministic_specs(
            contract_name=contract_name,
            contract_source_path=contract_source_path,
            source_meta=source_meta,
            uncovered_targets=uncovered_targets,
            max_generated_tests=effective_max,
        )

        if call_llm is None:
            return fallback_specs

        prompt = _build_llm_prompt(
            contract_name=contract_name,
            contract_source_path=contract_source_path,
            payload=payload,
            source_meta=source_meta,
            max_generated_tests=effective_max,
            repo_root=repo_root,
        )

        debug_dir = repo_root / "artifacts" / "llm_testgen_debug"
        debug_dir.mkdir(parents=True, exist_ok=True)

        try:
            raw = call_llm(
                prompt=prompt,
                model=model,
                temperature=temperature,
                max_tokens=7000,
            )

            (debug_dir / f"{contract_name}_prompt.json").write_text(
                prompt,
                encoding="utf-8",
            )
            (debug_dir / f"{contract_name}_raw_response.txt").write_text(
                str(raw),
                encoding="utf-8",
            )

            try:
                llm_specs = _parse_llm_response_into_specs(
                    raw_response=raw,
                    contract_name=contract_name,
                    contract_source_path=contract_source_path,
                    source_meta=source_meta,
                    uncovered_targets=uncovered_targets,
                    max_generated_tests=effective_max,
                )

                (debug_dir / f"{contract_name}_parsed_specs.json").write_text(
                    json.dumps(llm_specs, indent=2),
                    encoding="utf-8",
                )

                if llm_specs:
                    (debug_dir / f"{contract_name}_parse_status.txt").write_text(
                        "ok",
                        encoding="utf-8",
                    )
                    return llm_specs

                (debug_dir / f"{contract_name}_parse_status.txt").write_text(
                    "llm_response_parsed_but_no_usable_specs",
                    encoding="utf-8",
                )

                for spec in fallback_specs:
                    spec.setdefault("llm_error", "llm_response_parsed_but_no_usable_specs")

            except Exception as exc:
                (debug_dir / f"{contract_name}_llm_exception.txt").write_text(
                    str(exc),
                    encoding="utf-8",
                )
                (debug_dir / f"{contract_name}_parse_status.txt").write_text(
                    f"llm_parse_or_generation_exception: {exc}",
                    encoding="utf-8",
                )
                for spec in fallback_specs:
                    spec.setdefault("llm_error", str(exc))

        except Exception as exc:
            (debug_dir / f"{contract_name}_llm_exception.txt").write_text(
                str(exc),
                encoding="utf-8",
            )
            (debug_dir / f"{contract_name}_parse_status.txt").write_text(
                f"llm_call_exception: {exc}",
                encoding="utf-8",
            )
            for spec in fallback_specs:
                spec.setdefault("llm_error", str(exc))

        return fallback_specs
    
    return _generate

def _build_llm_prompt(
    *,
    contract_name: str,
    contract_source_path: Path,
    payload: Dict[str, Any],
    source_meta: Dict[str, Any],
    max_generated_tests: int,
    repo_root: Path,
) -> str:
    baseline_tests = payload.get("baseline_tests") or {}
    baseline_traces = payload.get("baseline_traces") or {}
    coverage = payload.get("coverage") or {}
    uncovered_targets = payload.get("uncovered_targets") or []
    abi = payload.get("abi") or source_meta.get("abi") or []

    constructor = source_meta.get("constructor", {})
    callable_functions = source_meta.get("callable_functions", [])

    semantic_target_summary = _summarize_semantic_targets(uncovered_targets)

    prompt_obj = {
        "task": (
            "Generate additional Foundry tests for a Solidity contract. "
            "Focus on uncovered or lightly-covered functions, edge cases, loop bounds, "
            "guard/revert behavior, payable flows, array edge cases, and storage-mutation paths. "
            "Use the provided uncovered targets, semantic tags, suggested test intents, AST/IR-derived "
            "function context, and execution traces to build targeted tests. "
            "Return JSON only."
        ),
        "hard_rules": [
            "Output MUST be valid JSON only. No markdown. No code fences.",
            "Return at most max_generated_tests test files.",
            "Each test file MUST compile in a Foundry project.",
            "Use pragma solidity ^0.8.13 in generated tests.",
            'Every file MUST import "forge-std/Test.sol".',
            "Every file MUST import the target contract using the provided relative contract path.",
            "Generated tests MUST deploy the contract with constructor arguments matching the contract constructor.",
            "Do NOT invent Solidity functions that do not exist.",
            "Do NOT depend on off-chain services, custom mocks, or unsupported libraries.",
            "Prefer simple, robust tests that compile and run over complex brittle tests.",
            "For payable functions, use vm.deal and target.fn{value: ...}(...).",
            "Use basic bounds/assumptions for fuzz inputs to keep tests stable.",
            "When uncovered targets include semantic_tags, generated tests should reflect them.",
            "For loop_bound_target, prefer small bounded inputs and edge bounds.",
            "For revert_guard_target, include both success and guard-probe/revert-style cases when safe.",
            "For payable_flow_target, use vm.deal and payable invocation patterns.",
            "For array_edge_target, include empty, one-element, and short bounded-array cases when relevant.",
            "Do NOT assert exact numeric outputs unless they are directly derivable from the provided constructor inputs and function arguments.",
            "For storage-mutation targets, prefer invariant checks such as length changes, non-revert behavior, and simple monotonic properties over guessed exact values.",
            "For sequence/append/fill style functions, prefer checking resulting length or shape, not exact sums or element values unless explicitly obvious from the function contract.",
        ],
        "output_schema": {
            "type": "object",
            "required": ["tests"],
            "properties": {
                "tests": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "filename", "target", "code"],
                        "properties": {
                            "name": {"type": "string"},
                            "filename": {"type": "string"},
                            "target": {"type": "object"},
                            "code": {"type": "string"},
                        },
                    },
                }
            },
        },
        "context": {
            "contract_name": contract_name,
            "contract_source_path": _repo_relative_or_posix(contract_source_path, repo_root),
            "max_generated_tests": max_generated_tests,
            "constructor": constructor,
            "abi": abi,
            "callable_functions": callable_functions,
            "uncovered_targets": uncovered_targets,
            "semantic_target_summary": semantic_target_summary,
            "baseline_tests_summary": baseline_tests,
            "baseline_trace_summary": _summarize_traces(baseline_traces),
            "coverage_summary": _summarize_coverage_for_prompt(coverage, contract_source_path),
            "source_excerpt": _truncate(source_meta.get("contract_block", ""), 5000),
        },
        "preferred_test_patterns": [
            "Constructor smoke test with correct deployment",
            "Loop-bound target case",
            "Guard/revert target case",
            "Storage-write target case",
            "Payable-flow target case",
            "Array-edge target case",
            "View helper consistency test",
            "Repeated state update test for append/deposit/accumulate style functions",
        ],
        "example_response_shape": {
            "tests": [
                {
                    "name": "autogen_target_1",
                    "filename": f"{contract_name}_AutoGen_1.t.sol",
                    "target": {
                        "function": "exampleFunction",
                        "reason": "function_low_hit",
                        "semantic_tags": ["loop_bound_target"],
                    },
                    "code": (
                        "// SPDX-License-Identifier: MIT\\n"
                        "pragma solidity ^0.8.13;\\n"
                        'import "forge-std/Test.sol";\\n'
                        f'import "{_best_import_path(contract_source_path)}";\\n'
                        f"contract {contract_name}_AutoGen_Example is Test {{ /* ... */ }}"
                    ),
                }
            ]
        },
    }

    return json.dumps(prompt_obj, indent=2)


def _parse_llm_response_into_specs(
    *,
    raw_response: str,
    contract_name: str,
    contract_source_path: Path,
    source_meta: Dict[str, Any],
    uncovered_targets: Sequence[Dict[str, Any]],
    max_generated_tests: int,
) -> List[Dict[str, Any]]:
    cleaned = _extract_json_block(raw_response)
    parsed = json.loads(cleaned)

    tests = parsed if isinstance(parsed, list) else parsed.get("tests", [])
    if not isinstance(tests, list):
        return []

    specs: List[Dict[str, Any]] = []
    for idx, item in enumerate(tests[:max_generated_tests], start=1):
        if not isinstance(item, dict):
            continue

        code = str(item.get("code") or "").strip()
        if not code:
            continue

        target = _pick_target(item.get("target"), uncovered_targets, idx)
        code = _normalize_generated_test_code(
            code=code,
            contract_name=contract_name,
            contract_source_path=contract_source_path,
            source_meta=source_meta,
            fallback_target=target,
        )
        if not _looks_like_foundry_test(code, contract_name):
            continue

        name = _sanitize_identifier(item.get("name") or f"autogen_llm_{idx}")
        filename = str(item.get("filename") or f"{contract_name}_AutoGen_{idx}.t.sol").strip()
        if not filename.endswith(".t.sol"):
            filename = f"{Path(filename).stem}.t.sol"

        specs.append(
            {
                "name": name,
                "filename": filename,
                "kind": "llm_generated",
                "target": target,
                "code": code,
            }
        )

    return specs


def _build_deterministic_specs(
    *,
    contract_name: str,
    contract_source_path: Path,
    source_meta: Dict[str, Any],
    uncovered_targets: Sequence[Dict[str, Any]],
    max_generated_tests: int,
) -> List[Dict[str, Any]]:
    chosen_targets = list(uncovered_targets[:max_generated_tests]) if uncovered_targets else []
    if not chosen_targets:
        chosen_targets = [
            {
                "target_type": "contract",
                "contract": contract_name,
                "reason": "fallback_no_targets",
                "priority": 0.1,
                "semantic_tags": ["general_behavior_target"],
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
                "kind": "llm_fallback",
                "target": target,
                "code": code,
            }
        )
    return specs


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

    target_intents = list((target or {}).get("suggested_test_intent") or [])
    semantic_tags = list((target or {}).get("semantic_tags") or [])

    body_cases = _build_targeted_test_bodies(
        contract_name=contract_name,
        target_fn=target_fn,
        synthetic_test_name=synthetic_test_name,
        target_intents=target_intents,
        semantic_tags=semantic_tags,
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
            OBLIVION AUTOGEN TARGET CONTEXT
            {target_comment}
            */
        }}
        """
    ).rstrip() + "\n"

def _build_targeted_test_bodies(
    *,
    contract_name: str,
    target_fn: Optional[Dict[str, Any]],
    source_meta: Dict[str, Any],
    synthetic_test_name: str,
) -> str:
    pieces: List[str] = []

    safe_name = _sanitize_identifier(synthetic_test_name)

    pieces.append(
        f"""
function test_{safe_name}_deploys() public {{
    assertTrue(address(target) != address(0));
}}
""".strip()
    )

    if not target_fn:
        pieces.append(
            f"""
function test_{safe_name}_smoke() public {{
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
        name = _sanitize_identifier(param.get("name") or f"arg_{idx}")
        init_lines, expr = _solidity_value_initializer(typ=typ, var_name=name, seed=idx + 1)
        bounded_prelude_lines.extend(init_lines)
        bounded_prelude_lines.extend(_bounds_for_param(typ, name))
        bounded_arg_exprs.append(expr)

    bounded_prelude = "\n".join(bounded_prelude_lines)

    # fuzz inputs
    arg_decls, fuzz_arg_exprs, fuzz_prelude = _build_function_inputs(params, prefix="arg")
    fuzz_bounds = _build_fuzz_bounds(params)

    if is_payable:
        bounded_call_prelude = (bounded_prelude + "\nvm.deal(address(this), 10 ether);").strip()
        fuzz_call_prelude = (fuzz_prelude + "\nvm.deal(address(this), 10 ether);").strip()
        bounded_call_expr = f"target.{fn_name}{{value: 1 wei}}({', '.join(bounded_arg_exprs)})"
        fuzz_call_expr = f"target.{fn_name}{{value: 1 wei}}({', '.join(fuzz_arg_exprs)})"
    else:
        bounded_call_prelude = bounded_prelude
        fuzz_call_prelude = fuzz_prelude
        bounded_call_expr = f"target.{fn_name}({', '.join(bounded_arg_exprs)})"
        fuzz_call_expr = f"target.{fn_name}({', '.join(fuzz_arg_exprs)})"

    if state_mutability in ("view", "pure"):
        bounded_body = f"""
function test_{safe_name}_{fn_name}_bounded() public {{
{_indent_block(bounded_call_prelude, 1) if bounded_call_prelude.strip() else ""}
    {bounded_call_expr};
}}
""".strip()
    else:
        bounded_body = f"""
function test_{safe_name}_{fn_name}_bounded() public {{
{_indent_block(bounded_call_prelude, 1) if bounded_call_prelude.strip() else ""}
    {bounded_call_expr};
    assertTrue(address(target) != address(0));
}}
""".strip()

    pieces.append(bounded_body)

    fuzz_sections: List[str] = []
    if fuzz_bounds.strip():
        fuzz_sections.append(fuzz_bounds)
    if fuzz_call_prelude.strip():
        fuzz_sections.append(fuzz_call_prelude)
    fuzz_sections.append(f"{fuzz_call_expr};")

    fuzz_body = f"""
function test_{safe_name}_{fn_name}_fuzz(
{_indent_block(arg_decls, 1)}
) public {{
{_indent_block("\\n".join(fuzz_sections), 1)}
}}
""".strip()

    pieces.append(fuzz_body)

    return "\n\n".join(pieces)

def _extract_source_metadata(
    *,
    contract_name: str,
    source_text: str,
    ir_json: Optional[Dict[str, Any]],
    abi: Any,
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
            return {
                "exists": True,
                "params": params,
                "attrs": "",
            }
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
        name = _sanitize_identifier(param.get("name") or f"ctor_{idx}")
        setup_lines, expr = _solidity_value_initializer(typ=typ, var_name=name, seed=idx + 1)
        lines.extend(setup_lines)
        arg_exprs.append(expr)

    return "\n".join(lines), arg_exprs


def _build_function_inputs(params: Sequence[Dict[str, str]]) -> Tuple[str, List[str], str]:
    decls: List[str] = []
    exprs: List[str] = []
    prelude_lines: List[str] = []

    for idx, param in enumerate(params):
        typ = str(param.get("type") or "uint256").strip()
        name = _sanitize_identifier(param.get("name") or f"arg_{idx}")
        decls.append(f"{typ} {name}")
        prelude_lines.extend(_bounds_for_param(typ, name))
        exprs.append(name)

    return ",\n".join(decls), exprs, "\n".join(prelude_lines)


def _build_fuzz_bounds(params: Sequence[Dict[str, str]]) -> str:
    lines: List[str] = []
    for idx, param in enumerate(params):
        typ = str(param.get("type") or "uint256").strip()
        name = _sanitize_identifier(param.get("name") or f"arg_{idx}")
        lines.extend(_bounds_for_param(typ, name))
    return "\n".join(lines)


def _build_guard_probe_inputs(params: Sequence[Dict[str, str]]) -> Tuple[str, List[str]]:
    lines: List[str] = []
    exprs: List[str] = []

    for idx, param in enumerate(params):
        typ = str(param.get("type") or "uint256").strip()
        name = _sanitize_identifier(param.get("name") or f"probe_{idx}")
        setup_lines, expr = _solidity_edge_case_initializer(typ=typ, var_name=name, seed=idx + 17)
        lines.extend(setup_lines)
        exprs.append(expr)

    return "\n".join(lines), exprs


def _build_array_edge_inputs(params: Sequence[Dict[str, str]]) -> Tuple[str, List[str]]:
    lines: List[str] = []
    exprs: List[str] = []

    for idx, param in enumerate(params):
        typ = str(param.get("type") or "uint256").strip()
        name = _sanitize_identifier(param.get("name") or f"edge_{idx}")

        if "[]" in typ:
            arr_type = _clean_array_decl_type(typ)
            base = arr_type.replace(" ", "")[:-2]
            lines.append(f"{arr_type} memory {name} = new {base};")
            exprs.append(name)
        else:
            setup_lines, expr = _solidity_value_initializer(typ=typ, var_name=name, seed=idx + 31)
            lines.extend(setup_lines)
            exprs.append(expr)

    return "\n".join(lines), exprs


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
    """
    Returns:
      (setup_lines, expression_name_or_literal)
    """
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

def _solidity_edge_case_initializer(*, typ: str, var_name: str, seed: int) -> Tuple[List[str], str]:
    t = " ".join(typ.split())
    tn = t.replace(" ", "")

    if tn.endswith("[]"):
        base = tn[:-2]
        arr_type = _clean_array_decl_type(t)
        return [], var_name

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


def _clean_array_decl_type(t: str) -> str:
    return t.replace("calldata", "").replace("storage", "").strip() or t.strip()


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

def _generated_code_is_structurally_safe(
    *,
    code: str,
    contract_name: str,
    source_meta: Dict[str, Any],
) -> bool:
    text = code or ""
    if not _looks_like_foundry_test(text, contract_name):
        return False

    constructor = source_meta.get("constructor", {}) or {}
    ctor_params = constructor.get("params", []) or []

    # If constructor exists, require deployment of new ContractName(...)
    if constructor.get("exists"):
        if re.search(rf"\bnew\s+{re.escape(contract_name)}\s*\(", text) is None:
            return False

    # reject obvious undeclared-variable anti-pattern in bounded tests
    bad_patterns = [
        r"function\s+test_[A-Za-z0-9_]+_bounded\s*\(\)\s+public\s*\{[^}]*\bmaxIters\s*=\s*bound\(maxIters,",
        r"function\s+test_[A-Za-z0-9_]+_bounded\s*\(\)\s+public\s*\{[^}]*\bx\s*=\s*bound\(x,",
        r"function\s+test_[A-Za-z0-9_]+_bounded\s*\(\)\s+public\s*\{[^}]*\bn\s*=\s*bound\(n,",
    ]
    for pat in bad_patterns:
        if re.search(pat, text, flags=re.DOTALL):
            return False

    return True

def _normalize_generated_test_code(
    *,
    code: str,
    contract_name: str,
    contract_source_path: Path,
    source_meta: Dict[str, Any],
    fallback_target: Optional[Dict[str, Any]],
) -> str:
    text = (code or "").strip()
    text = re.sub(r"^```(?:solidity|json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    if "SPDX-License-Identifier" not in text:
        text = "// SPDX-License-Identifier: MIT\n" + text

    if "pragma solidity" not in text:
        text = text.replace(
            "// SPDX-License-Identifier: MIT\n",
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.13;\n",
            1,
        )

    correct_import_path = _best_import_path(contract_source_path)
    contract_basename = contract_source_path.name

    # Remove all non-Test imports that mention this contract basename,
    # so we can reinsert the canonical Foundry import path.
    lines = text.splitlines()
    filtered_lines: List[str] = []
    for line in lines:
        stripped = line.strip()
        if (
            stripped.startswith("import ")
            and contract_basename in stripped
            and "forge-std/Test.sol" not in stripped
        ):
            continue
        filtered_lines.append(line)
    text = "\n".join(filtered_lines)

    if 'import "forge-std/Test.sol";' not in text:
        text = text.replace(
            "pragma solidity ^0.8.13;",
            'pragma solidity ^0.8.13;\n\nimport "forge-std/Test.sol";',
            1,
        )

    if f'import "{correct_import_path}";' not in text:
        text = text.replace(
            'import "forge-std/Test.sol";',
            f'import "forge-std/Test.sol";\nimport "{correct_import_path}";',
            1,
        )

    # Guard against speculative LLM assertions for fillSequence-style tests.
    # These have been producing brittle checks like calling sumNumbersBounded()
    # after fillSequence() and asserting guessed exact values.
    if (
        "fillSequence" in text
        and "sumNumbersBounded" in text
    ):
        return _build_constructor_aware_test_file(
            contract_name=contract_name,
            contract_source_path=contract_source_path,
            source_meta=source_meta,
            synthetic_test_name=_sanitize_identifier(
                str((fallback_target or {}).get("function") or "llm_rewritten")
            ),
            target=fallback_target,
            unique_suffix="LLMFix",
        )

    if not _generated_code_is_structurally_safe(
        code=text,
        contract_name=contract_name,
        source_meta=source_meta,
    ):
        return _build_constructor_aware_test_file(
            contract_name=contract_name,
            contract_source_path=contract_source_path,
            source_meta=source_meta,
            synthetic_test_name=_sanitize_identifier(
                str((fallback_target or {}).get("function") or "llm_rewritten")
            ),
            target=fallback_target,
            unique_suffix="LLMFix",
        )

    return text.rstrip() + "\n"

def _extract_json_block(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        raise ValueError("Empty LLM response")

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    try:
        json.loads(text)
        return text
    except Exception:
        pass

    obj_match = re.search(r"(\{.*\})", text, flags=re.DOTALL)
    arr_match = re.search(r"(\[.*\])", text, flags=re.DOTALL)

    candidates = []
    if obj_match:
        candidates.append(obj_match.group(1))
    if arr_match:
        candidates.append(arr_match.group(1))

    for candidate in candidates:
        try:
            json.loads(candidate)
            return candidate
        except Exception:
            continue

    raise ValueError("LLM response did not contain valid JSON")


def _best_import_path(contract_source_path: Path) -> str:
    parts = contract_source_path.parts
    if "src" in parts:
        idx = parts.index("src")
        return "/".join(parts[idx:])
    return contract_source_path.as_posix()


def _repo_relative_or_posix(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return path.as_posix()


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _summarize_traces(traces: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(traces, dict):
        return {}
    summary: Dict[str, Any] = {}
    for idx, (test_name, entries) in enumerate(traces.items()):
        if idx >= 8:
            break
        summary[test_name] = {
            "num_entries": len(entries) if isinstance(entries, list) else 0,
        }
    return summary


def _summarize_coverage_for_prompt(coverage: Dict[str, Any], contract_source_path: Path) -> Dict[str, Any]:
    if not isinstance(coverage, dict):
        return {}
    best_key = _best_import_path(contract_source_path)
    if best_key in coverage and isinstance(coverage[best_key], dict):
        return coverage[best_key]
    basename = contract_source_path.name
    for key, value in coverage.items():
        if Path(str(key)).name == basename and isinstance(value, dict):
            return value
    return {}


def _summarize_semantic_targets(uncovered_targets: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    by_function: Dict[str, List[str]] = {}

    for target in uncovered_targets:
        if not isinstance(target, dict):
            continue
        tags = [str(x) for x in (target.get("semantic_tags") or [])]
        fn_name = str(target.get("function") or target.get("owner_function") or "").strip()

        for tag in tags:
            counts[tag] = counts.get(tag, 0) + 1

        if fn_name and tags:
            merged = by_function.get(fn_name, [])
            by_function[fn_name] = sorted(set(merged + tags))

    return {
        "tag_counts": counts,
        "by_function": by_function,
    }


def _pick_target(candidate: Any, uncovered_targets: Sequence[Dict[str, Any]], idx: int) -> Dict[str, Any]:
    if isinstance(candidate, dict) and candidate:
        return dict(candidate)
    if uncovered_targets:
        return dict(uncovered_targets[min(max(idx - 1, 0), len(uncovered_targets) - 1)])
    return {
        "reason": "llm_target_missing",
        "priority": 0.1,
        "semantic_tags": ["general_behavior_target"],
    }


def _looks_like_foundry_test(code: str, contract_name: str) -> bool:
    text = code or ""
    return (
        "forge-std/Test.sol" in text
        and re.search(r"\bcontract\s+[A-Za-z_][A-Za-z0-9_]*\s+is\s+Test\b", text) is not None
        and re.search(rf"\b{re.escape(contract_name)}\b", text) is not None
    )


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


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n/* ... truncated ... */"


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