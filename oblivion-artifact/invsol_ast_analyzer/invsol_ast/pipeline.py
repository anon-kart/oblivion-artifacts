from typing import Any, Dict, Optional, List, Set

# AST stage
from .ast import (
    parser,
    normalizer,
    extractor_functions,
    extractor_loops,
    extractor_require,
    extractor_state,
    access_control,
    extractor_effects,   # NEW
)

# IR stage
from .ir import build_ir, json_exporter

# Validators
from .validators import schema_validator, consistency_checks

# Utils
from .utils import logging as log
from .utils import solc_wrapper
from .utils.errors import ValidationError

from .config import IR_VERSION


def _walk(node: Any):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for x in node:
            yield from _walk(x)


def _type_name_to_str(type_node: dict | None) -> str:
    if not isinstance(type_node, dict):
        return ""

    node_type = type_node.get("nodeType", "")

    if node_type == "ElementaryTypeName":
        return str(type_node.get("name", "") or "")

    if node_type == "UserDefinedTypeName":
        return str(
            type_node.get("namePath", "")
            or type_node.get("typeDescriptions", {}).get("typeString", "")
            or ""
        )

    if node_type == "ArrayTypeName":
        base = _type_name_to_str(type_node.get("baseType"))
        length = ""
        if type_node.get("length") is not None:
            try:
                length = str(type_node["length"].get("value", ""))
            except Exception:
                length = ""
        return f"{base}[{length}]"

    if node_type == "Mapping":
        return "mapping"

    return str(type_node.get("typeDescriptions", {}).get("typeString", "") or "")


def _is_reference_type_name(type_node: dict | None) -> bool:
    if not isinstance(type_node, dict):
        return False

    node_type = type_node.get("nodeType", "")
    if node_type in ("ArrayTypeName", "Mapping"):
        return True

    if node_type == "ElementaryTypeName":
        return str(type_node.get("name", "")) in ("string", "bytes")

    return False


def _extract_local_decls_from_body(body_node: dict | None, return_var_names: Set[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(body_node, dict):
        return out

    for n in _walk(body_node):
        if not isinstance(n, dict):
            continue
        if n.get("nodeType") != "VariableDeclarationStatement":
            continue

        decls = n.get("declarations") or []
        for d in decls:
            if not isinstance(d, dict):
                continue

            type_node = d.get("typeName")
            name = str(d.get("name", "") or "")
            storage_location = str(d.get("storageLocation", "") or "")

            out.append(
                {
                    "name": name,
                    "type": _type_name_to_str(type_node),
                    "storage_location": storage_location,
                    "is_return_var": bool(name and name in return_var_names),
                    "is_reference_type": _is_reference_type_name(type_node),
                }
            )

    return out


def _extract_modifier_invocations(fn_node: dict) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for inv in fn_node.get("modifiers") or []:
        if not isinstance(inv, dict):
            continue

        mod_name = ""
        mod_name_node = inv.get("modifierName")
        if isinstance(mod_name_node, dict):
            mod_name = str(mod_name_node.get("name", "") or "")

        out.append(
            {
                "name": mod_name,
                "arguments_count": len(inv.get("arguments") or []),
                "src": inv.get("src"),
            }
        )

    return out


def _extract_state_vars_from_contract(contract_node: dict) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for child in contract_node.get("nodes") or []:
        if not isinstance(child, dict):
            continue
        if child.get("nodeType") != "VariableDeclaration":
            continue
        if child.get("stateVariable") is not True:
            continue

        type_node = child.get("typeName")
        vis = str(child.get("visibility", "") or "")

        out.append(
            {
                "name": str(child.get("name", "") or ""),
                "visibility": vis,
                "type": _type_name_to_str(type_node),
                "is_public_getter": vis == "public",
                "is_immutable": bool((child.get("mutability") or "") == "immutable"),
                "initializer_present": child.get("value") is not None,
            }
        )

    return out


def _node_contains(node: Any, target_types: set[str]) -> bool:
    for n in _walk(node):
        if isinstance(n, dict) and n.get("nodeType") in target_types:
            return True
    return False


def _count_placeholder_statements(body_node: dict | None) -> int:
    count = 0
    for n in _walk(body_node):
        if isinstance(n, dict) and n.get("nodeType") == "PlaceholderStatement":
            count += 1
    return count


def _has_post_placeholder_code(body_node: dict | None) -> bool:
    if not isinstance(body_node, dict):
        return False

    stmts = body_node.get("statements") or []
    seen_placeholder = False

    for s in stmts:
        if not isinstance(s, dict):
            continue
        if s.get("nodeType") == "PlaceholderStatement":
            seen_placeholder = True
            continue
        if seen_placeholder:
            return True

    return False


def _extract_modifier_defs_from_contract(contract_node: dict) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for child in contract_node.get("nodes") or []:
        if not isinstance(child, dict):
            continue
        if child.get("nodeType") != "ModifierDefinition":
            continue

        params: List[Dict[str, Any]] = []
        param_nodes = (child.get("parameters") or {}).get("parameters") or []
        for p in param_nodes:
            if not isinstance(p, dict):
                continue
            params.append(
                {
                    "name": str(p.get("name", "") or ""),
                    "type": _type_name_to_str(p.get("typeName")),
                    "storage_location": str(p.get("storageLocation", "") or ""),
                }
            )

        body = child.get("body")
        out.append(
            {
                "name": str(child.get("name", "") or ""),
                "params": params,
                "placeholder_count": _count_placeholder_statements(body),
                "has_post_placeholder_code": _has_post_placeholder_code(body),
                "has_external_calls": _node_contains(body, {"FunctionCall", "MemberAccess"}),
                "has_loops": _node_contains(body, {"ForStatement", "WhileStatement", "DoWhileStatement"}),
                "src": child.get("src"),
            }
        )

    return out


def _build_contract_enrichment_maps(norm: Dict[str, Any]) -> tuple[Dict[str, List[Dict[str, Any]]], Dict[str, List[Dict[str, Any]]]]:
    """
    Returns:
      - contract_state_vars: {contract_name: [...]}
      - contract_modifier_defs: {contract_name: [...]}
    """
    contract_state_vars: Dict[str, List[Dict[str, Any]]] = {}
    contract_modifier_defs: Dict[str, List[Dict[str, Any]]] = {}

    for n in _walk(norm):
        if not isinstance(n, dict):
            continue
        if n.get("nodeType") != "ContractDefinition":
            continue

        contract_name = str(n.get("name", "") or "")
        if not contract_name:
            continue

        contract_state_vars[contract_name] = _extract_state_vars_from_contract(n)
        contract_modifier_defs[contract_name] = _extract_modifier_defs_from_contract(n)

    return contract_state_vars, contract_modifier_defs


def _build_function_enrichment_map(norm: Dict[str, Any]) -> Dict[tuple[str, str], Dict[str, Any]]:
    """
    Returns:
      {(contract_name, function_name): {"modifiers_full": [...], "local_decls": [...]}}

    This walks the normalized AST directly so we can enrich the extracted function entries
    without forcing fragile regex-based downstream transforms.
    """
    out: Dict[tuple[str, str], Dict[str, Any]] = {}

    for contract_node in _walk(norm):
        if not isinstance(contract_node, dict):
            continue
        if contract_node.get("nodeType") != "ContractDefinition":
            continue

        contract_name = str(contract_node.get("name", "") or "")
        if not contract_name:
            continue

        for child in contract_node.get("nodes") or []:
            if not isinstance(child, dict):
                continue
            if child.get("nodeType") != "FunctionDefinition":
                continue

            fn_kind = str(child.get("kind", "") or "")
            fn_name = str(child.get("name", "") or "")
            if fn_kind == "constructor" and not fn_name:
                fn_name = "constructor"

            if not fn_name:
                continue

            return_var_names: Set[str] = set()
            ret_params = (child.get("returnParameters") or {}).get("parameters") or []
            for rp in ret_params:
                if isinstance(rp, dict):
                    nm = str(rp.get("name", "") or "")
                    if nm:
                        return_var_names.add(nm)

            out[(contract_name, fn_name)] = {
                "modifiers_full": _extract_modifier_invocations(child),
                "local_decls": _extract_local_decls_from_body(child.get("body"), return_var_names),
            }

    return out


def _enrich_functions_with_ast_features(
    funcs: List[Dict[str, Any]],
    fn_enrichment: Dict[tuple[str, str], Dict[str, Any]],
) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []

    for f in funcs:
        f2 = dict(f)
        key = (str(f2.get("contract", "") or ""), str(f2.get("name", "") or ""))
        extra = fn_enrichment.get(key, {})
        f2["modifiers_full"] = extra.get("modifiers_full", [])
        f2["local_decls"] = extra.get("local_decls", [])
        enriched.append(f2)

    return enriched


def _attach_contract_features_to_ir(
    ir: Dict[str, Any],
    contract_state_vars: Dict[str, List[Dict[str, Any]]],
    contract_modifier_defs: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """
    Attach contract-level enrichments to the final IR object in a non-destructive way.
    Supports either:
      - top-level ir["contracts"] list
      - top-level ir["contract"] singleton-ish metadata
    """
    if not isinstance(ir, dict):
        return ir

    contracts = ir.get("contracts")
    if isinstance(contracts, list):
        new_contracts = []
        for c in contracts:
            if not isinstance(c, dict):
                new_contracts.append(c)
                continue

            c2 = dict(c)
            cname = str(c2.get("name", "") or "")
            c2["state_vars"] = contract_state_vars.get(cname, [])
            c2["modifier_defs"] = contract_modifier_defs.get(cname, [])
            new_contracts.append(c2)

        ir = dict(ir)
        ir["contracts"] = new_contracts
        return ir

    if isinstance(ir.get("contract"), dict):
        c2 = dict(ir["contract"])
        cname = str(c2.get("name", "") or "")
        c2["state_vars"] = contract_state_vars.get(cname, [])
        c2["modifier_defs"] = contract_modifier_defs.get(cname, [])
        ir = dict(ir)
        ir["contract"] = c2
        return ir

    return ir


def _get_ast(path: str, solc_path: Optional[str]) -> Dict[str, Any]:
    """
    Prefer the shared solc wrapper when an explicit solc_path is given;
    otherwise fall back to parser.parse_solidity_to_ast (dev-friendly).
    """
    if solc_path:
        ast = solc_wrapper.get_ast_best_effort(path, solc_path=solc_path)
        return {"source": path, "ast": ast}
    return parser.parse_solidity_to_ast(path)


def run_pipeline(
    path: str,
    out: str,
    *,
    solc_path: Optional[str] = None,
    validate: bool = True,
    strict: bool = False,
    dump_ast: Optional[str] = None,  # save normalized AST JSON if provided
) -> Dict[str, Any]:
    """parse -> normalize -> extract -> build -> (validate) -> export"""

    # 1) Parse
    with log.timed("parse"):
        ast_bundle = _get_ast(path, solc_path)

    # 2) Normalize
    with log.timed("normalize"):
        norm = normalizer.normalize_ast(ast_bundle)

    # Optional: dump normalized analyzer JSON
    if dump_ast:
        json_exporter.write_json(norm, dump_ast)
        log.info(f"Wrote normalized AST (analyzer JSON) to {dump_ast}")

    # Build a state index for downstream passes
    state_index = extractor_effects.build_state_index_from_norm(norm)

    # Precompute AST enrichments so they can be merged into extracted IR facts.
    contract_state_vars, contract_modifier_defs = _build_contract_enrichment_maps(norm)
    fn_enrichment = _build_function_enrichment_map(norm)

    # 3) Extract
    with log.timed("extract: functions"):
        funcs = extractor_functions.extract_functions(norm)
        funcs = _enrich_functions_with_ast_features(funcs, fn_enrichment)

    with log.timed("extract: loops"):
        loops = extractor_loops.extract_loops(norm, state_index=state_index)  # pass index

    with log.timed("extract: requires"):
        reqs = extractor_require.extract_requires(norm)

    with log.timed("extract: modifier requires"):
        # NOTE: this dict must support both plain and contract-qualified keys:
        #   { "onlyOwner": [...], "AssetTransfer.onlyOwner": [...] }
        modifier_requires = extractor_require.extract_modifier_requires(norm)

    # Attach modifier-level requires to functions (so they show up in function.requires)
    # We look up both qualified and plain keys.
    reqs_aug = list(reqs)
    for f in funcs:
        c = f.get("contract") or ""
        fname = f.get("name") or ""
        for mod in f.get("modifiers") or []:
            qkey = f"{c}.{mod}" if c else mod
            conds = modifier_requires.get(qkey) or modifier_requires.get(mod) or []
            for cond in conds:
                reqs_aug.append(
                    {"contract": c, "function": fname, "condition": cond, "node_id": None}
                )

    # De-dup requires per function
    dedup: Dict[tuple, set] = {}
    for r in reqs_aug:
        key = (r["contract"], r["function"])
        dedup.setdefault(key, set()).add(r["condition"])
    reqs_aug = [
        {"contract": c, "function": f, "condition": cond, "node_id": None}
        for (c, f), conds in dedup.items()
        for cond in sorted(conds)
    ]

    with log.timed("extract: state"):
        state = extractor_state.extract_state(norm)

    with log.timed("extract: access control"):
        acl = access_control.resolve_access_control(norm)

    with log.timed("extract: function effects"):
        fn_effects = extractor_effects.extract_function_effects(norm, state_index=state_index)

    # 4) Build IR
    with log.timed("build IR"):
        try:
            # Works whether solc_path is None or a path; wrapper uses "solc" on PATH if None
            solidity_version = solc_wrapper.get_solc_version(solc_path)
        except Exception:
            solidity_version = None

        ir = build_ir.build(
            functions=funcs,
            loops=loops,
            requires=reqs_aug,
            state=state,
            acl=acl,
            solidity_version=solidity_version,
            version=IR_VERSION,
            function_effects=fn_effects,        # effects map keyed by (contract, function)
            modifier_requires=modifier_requires # pass through for access_dependencies merge
        )

        # Attach richer contract-level features needed by newer transforms/planner gates.
        ir = _attach_contract_features_to_ir(
            ir,
            contract_state_vars=contract_state_vars,
            contract_modifier_defs=contract_modifier_defs,
        )

    # 5) Validate
    if validate:
        with log.timed("validate: schema"):
            schema_errors = schema_validator.validate(ir)
        if schema_errors:
            msg = "IR schema validation issues:\n- " + "\n- ".join(schema_errors)
            if strict:
                raise ValidationError(msg)
            else:
                log.warning(msg)

        with log.timed("validate: consistency"):
            problems = consistency_checks.check(ir, strict=False)
        if problems:
            msg = "IR consistency issues:\n- " + "\n- ".join(problems)
            if strict:
                raise ValidationError(msg)
            else:
                log.warning(msg)

    # 6) Export
    with log.timed("export JSON"):
        json_exporter.write_json(ir, out)
        log.info(f"Wrote IR to {out}")

    return ir