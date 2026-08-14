import json
from typing import Dict, List, Any
from collections import Counter


def _norm_fn(fn: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": fn.get("name"),
        "visibility": fn.get("visibility", "public"),
        "mutability": fn.get("mutability"),
        "modifiers": fn.get("modifiers", []) or [],
        "params": fn.get("params", []) or [],
        "requires": fn.get("requires", []) or [],
        "reads": fn.get("reads", []) or [],
        "writes": fn.get("writes", []) or [],
    }


def _norm_state_vars(state_vars: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for sv in state_vars or []:
        out.append({
            "name": sv.get("name"),
            # prefer "type"; fall back to "datatype" if your analyzer used that
            "type": (sv.get("type") or sv.get("datatype") or ""),
            "visibility": sv.get("visibility"),
            "constant": sv.get("constant") or sv.get("is_constant") or False,
        })
    return out


def load_contract_model(ast_json_path: str) -> dict:
    with open(ast_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Some analyzers put everything under "contract", others at root.
    contract = data.get("contract", data)

    # --- Robust contract name inference ---
    # Start from the name in the IR/analyzer output
    name = contract.get("name") or "Contract"

    # If name is missing or clearly a placeholder, infer from functions
    fn_contracts = [
        (fn.get("contract") or "").strip()
        for fn in contract.get("functions", []) or []
        if (fn.get("contract") or "").strip()
    ]
    if (not name or name == "Placeholder") and fn_contracts:
        name = Counter(fn_contracts).most_common(1)[0][0]

    solidity_version = contract.get("solidity_version", "0.8.20")

    # Functions
    funs = [_norm_fn(fn) for fn in contract.get("functions", []) or []]

    # Constructor (surface at top-level AND optionally as a 'constructor' entry in functions)
    ctor = contract.get("constructor") or {}
    ctor_params = ctor.get("params", []) or []
    constructor_obj = {"params": ctor_params}
    if ctor_params or ctor:
        funs.append(_norm_fn({
            "name": "constructor",
            "visibility": "public",
            "params": ctor_params,
            "modifiers": ctor.get("modifiers", []) or [],
            "requires": ctor.get("requires", []) or [],
            "reads": ctor.get("reads", []) or [],
            "writes": ctor.get("writes", []) or [],
        }))

    # State variables (normalized)
    state_vars_raw = (contract.get("state") or {}).get("variables", []) or []
    state_vars = _norm_state_vars(state_vars_raw)

    # Access dependencies passthrough
    access_deps = contract.get("access_dependencies", []) or []

    return {
        "name": name,
        "solidity_version": solidity_version,
        "functions": funs,
        "state_variables": state_vars,
        "access_dependencies": access_deps,
        # Top-level constructor info so the generator can read it directly
        "constructor": constructor_obj if ctor_params else {},
    }
