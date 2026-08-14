from typing import Any, Dict, List, Tuple, Optional
import re

from .model import (
    IRDoc,
    IRContract,
    IRFunction,
    IRParam,
    IRReturn,           # NEW
    IRLoopSignature,
    IRState,
    IRStateVar,
    IRMapping,
    IRAccessEdge,
    IRStorageTouch,
    IRAccessDependency,
    to_dict,
    IR_VERSION_DEFAULT,
)

_MAP_RE = re.compile(r"mapping\s*\(([^=]+)=>\s*([^)]+)\)")


def _sanitize_storage_touch_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize storage touch entries before constructing IRStorageTouch.

    Canonical form:
      - indexed access: {"var": "...", "key": "..."}
      - scalar access:  {"var": "..."}   (omit key entirely)

    We intentionally drop null/empty keys so the exported IR is stable and
    schema-friendly.
    """
    var = d.get("var")
    key = d.get("key", None)

    out = {"var": var}
    if isinstance(key, str) and key.strip():
        out["key"] = key
    return out


def _group_loops_and_requires(
    loops: List[Dict[str, Any]],
    requires: List[Dict[str, Any]],
) -> Dict[str, Dict[str, List]]:
    """
    Group loop signatures and require-conditions by function name.
    Returns: { "<fn>": { "loops": [IRLoopSignature,...], "requires": [cond,...] } }
    """
    grouped: Dict[str, Dict[str, List]] = {}

    def ensure(fn_name: str):
        if fn_name not in grouped:
            grouped[fn_name] = {"loops": [], "requires": []}
        return grouped[fn_name]

    for lp in loops:
        fn = lp.get("function") or "unknown"
        sig = lp.get("signature") or {}
        ensure(fn)["loops"].append(
            IRLoopSignature(
                type=sig.get("type", "loop"),
                init=sig.get("init", ""),
                guard=sig.get("guard", ""),
                update=sig.get("update", ""),
                body_summary=sig.get("body_summary"),
                bounds=sig.get("bounds"),
            )
        )

    for rq in requires:
        fn = rq.get("function") or "unknown"
        cond = rq.get("condition") or ""
        if cond:
            ensure(fn)["requires"].append(cond)

    return grouped


def _guess_contract_name(
    functions: List[Dict[str, Any]],
    state: Dict[str, Any],
    acl: List[Dict[str, Any]],
) -> str:
    counts: Dict[str, int] = {}
    for f in functions:
        c = f.get("contract") or ""
        if c:
            counts[c] = counts.get(c, 0) + 1
    for v in (state or {}).get("variables", []):
        c = v.get("contract") or ""
        if c:
            counts[c] = counts.get(c, 0) + 1
    for m in (state or {}).get("mappings", []):
        c = m.get("contract") or ""
        if c:
            counts[c] = counts.get(c, 0) + 1
    for e in acl:
        c = e.get("contract") or ""
        if c:
            counts[c] = counts.get(c, 0) + 1
    if not counts:
        return "Placeholder"
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[0][0]


def _build_access_dependencies(
    ir_functions: List[IRFunction],
    acl_edges: List[Dict[str, Any]],
    modifier_requires: Optional[Dict[str, List[str]]] = None,
) -> List[IRAccessDependency]:
    """
    Build access dependencies by merging:
      - ACL edges (modifier uses) with known modifier-level require(...) conditions
        (try <Contract>.<modifier> key first, then plain <modifier>), and
      - function-level requires that reference msg.sender / tx.origin.
    """
    deps: List[IRAccessDependency] = []
    seen: set[Tuple[str, str, str, Optional[str]]] = set()
    modifier_requires = modifier_requires or {}

    # Index ACL edges by function name
    acl_by_fn: Dict[str, List[Dict[str, Any]]] = {}
    for e in acl_edges:
        fn = e.get("function") or ""
        acl_by_fn.setdefault(fn, []).append(e)

    for f in ir_functions:
        fname = f.name
        fcontract = getattr(f, "contract", "") or ""

        # 1) ACL-derived deps with modifier conditions (if known)
        for e in acl_by_fn.get(fname, []):
            mod = e.get("modifier") or ""
            role = e.get("role") or None

            # Prefer contract-qualified key, then fallback to plain modifier name
            cond_list: List[str] = []
            qualified_key = f"{fcontract}.{mod}" if fcontract else None
            if qualified_key and qualified_key in modifier_requires:
                cond_list = modifier_requires[qualified_key]
            elif mod in modifier_requires:
                cond_list = modifier_requires[mod]

            cond = " && ".join(c for c in cond_list if isinstance(c, str) and c.strip())  # may be ""
            key = (fname, f"modifier:{mod}", cond, role)
            if key not in seen:
                deps.append(
                    IRAccessDependency(
                        function=fname,
                        source=f"modifier:{mod}",
                        condition=cond,
                        role=role,
                    )
                )
                seen.add(key)

        # 2) Function-level sender/tx-origin guards
        for cond in f.requires:
            if isinstance(cond, str) and ("msg.sender" in cond or "tx.origin" in cond):
                key = (fname, "require", cond, None)
                if key not in seen:
                    deps.append(
                        IRAccessDependency(
                            function=fname,
                            source="require",
                            condition=cond,
                            role=None,
                        )
                    )
                    seen.add(key)

    return deps


def _pick_mapping_param_name(key_type: str) -> str:
    """Nice param names for common key types."""
    kt = (key_type or "").strip()
    if kt == "address":
        return "account"
    if kt in {"bytes32", "bytes", "string"}:
        return "key"
    # default
    return "key"


def _synthesize_public_getters_from_state(
    state_raw: Dict[str, Any],
    contract_name: str,
    existing_fn_names: set,
) -> List[IRFunction]:
    """
    Synthesize getters for PUBLIC state variables:
      - scalar:   function <var>() public view returns (<type>)
      - mapping:  function <var>(<keyType> key) public view returns (<valType>)
    Requires that extract_state provides 'visibility' for each variable.
    """
    synth: List[IRFunction] = []

    for v in (state_raw or {}).get("variables", []):
        vis = (v.get("visibility") or "").lower()
        if vis != "public":
            continue

        var_name = v.get("name") or ""
        if not var_name or var_name in existing_fn_names:
            continue

        tdesc = v.get("type") or ""
        # mapping getter
        if tdesc.startswith("mapping"):
            m = _MAP_RE.search(tdesc.replace(" ", ""))
            if not m:
                continue
            key_t, val_t = m.group(1), m.group(2)
            param_name = _pick_mapping_param_name(key_t)
            synth.append(
                IRFunction(
                    contract=contract_name,
                    name=var_name,
                    visibility="public",
                    mutability="view",
                    modifiers=[],
                    params=[IRParam(name=param_name, type=key_t)],
                    returns=[IRReturn(type=val_t)],
                    loops=[],
                    requires=[],
                    reads=[var_name],
                    writes=[],
                    member_accesses=[],
                    internal_calls=[],
                    external_calls=[],
                    events_emitted=[],
                    storage_reads=[IRStorageTouch(var=var_name, key=param_name)],
                    storage_writes=[],
                    synthetic=True,
                )
            )
        else:
            # scalar getter
            synth.append(
                IRFunction(
                    contract=contract_name,
                    name=var_name,
                    visibility="public",
                    mutability="view",
                    modifiers=[],
                    params=[],
                    returns=[IRReturn(type=tdesc)],
                    loops=[],
                    requires=[],
                    reads=[var_name],
                    writes=[],
                    member_accesses=[],
                    internal_calls=[],
                    external_calls=[],
                    events_emitted=[],
                    storage_reads=[IRStorageTouch(var=var_name)],
                    storage_writes=[],
                    synthetic=True,
                )
            )

    return synth


def build(
    functions: List[Dict[str, Any]],
    loops: List[Dict[str, Any]],
    requires: List[Dict[str, Any]],
    state: Dict[str, Any],
    acl: List[Dict[str, Any]],
    solidity_version: Optional[str] = None,
    version: str = IR_VERSION_DEFAULT,
    function_effects: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None,
    modifier_requires: Optional[Dict[str, List[str]]] = None,  # NEW: feed modifier-level requires
) -> Dict[str, Any]:

    grouped = _group_loops_and_requires(loops, requires)
    effects = function_effects or {}

    ir_funcs: List[IRFunction] = []
    for f in functions:
        fn_name = f.get("name") or f.get("kind") or "function"
        g = grouped.get(fn_name, {})
        params = [IRParam(**p) for p in (f.get("params") or [])]
        returns = [IRReturn(**r) for r in (f.get("returns") or [])]  # NEW
        eff = effects.get((f.get("contract") or "", fn_name), {})

        ir_funcs.append(
            IRFunction(
                contract=f.get("contract") or "",
                name=fn_name,
                visibility=f.get("visibility") or "",
                mutability=f.get("mutability") or "",
                modifiers=f.get("modifiers") or [],
                params=params,
                returns=returns,  # NEW
                loops=g.get("loops", []),
                requires=sorted(set(g.get("requires", []))),
                reads=eff.get("reads", []),
                writes=eff.get("writes", []),
                member_accesses=eff.get("member_accesses", []),
                internal_calls=eff.get("internal_calls", []),
                external_calls=eff.get("external_calls", []),
                events_emitted=eff.get("events_emitted", []),
                storage_reads=[
                    IRStorageTouch(**_sanitize_storage_touch_dict(d))
                    for d in eff.get("storage_reads", [])
                ],
                storage_writes=[
                    IRStorageTouch(**_sanitize_storage_touch_dict(d))
                    for d in eff.get("storage_writes", [])
                ],
                synthetic=False,  # user-defined
            )
        )

    # State
    s_vars = [IRStateVar(**{k: v for k, v in sv.items() if k in {"contract", "name", "type"}})
              for sv in (state or {}).get("variables", [])]
    s_maps = [IRMapping(**m) for m in (state or {}).get("mappings", [])]
    ir_state = IRState(variables=s_vars, mappings=s_maps)

    # Access control edges
    ir_acl = [IRAccessEdge(**e) for e in (acl or [])]

    # Access dependencies (derived; use raw acl dicts to match names, plus modifier_requires)
    access_deps = _build_access_dependencies(ir_funcs, acl, modifier_requires)

    # Synthesize getters for public state vars (requires extractor_state to include 'visibility')
    contract_name = _guess_contract_name(functions, state, acl)
    existing_names = {f.name for f in ir_funcs if f.contract == contract_name}
    synthesized = _synthesize_public_getters_from_state(
        state_raw=state,
        contract_name=contract_name,
        existing_fn_names=existing_names,
    )
    if synthesized:
        ir_funcs.extend(synthesized)

    contract = IRContract(
        name=contract_name,
        solidity_version=solidity_version,
        functions=ir_funcs,
        state=ir_state,
        access_control=ir_acl,
        access_dependencies=access_deps,
    )

    doc = IRDoc(ir_version=version, contract=contract)
    return to_dict(doc)