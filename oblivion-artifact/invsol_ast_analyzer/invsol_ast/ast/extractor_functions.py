from typing import Any, Dict, List
from .extractor_core import find_by_type


def _type_string(n: Dict[str, Any]) -> str:
    if not isinstance(n, dict):
        return ""
    td = (n.get("typeDescriptions") or {})
    ts = td.get("typeString")
    if ts:
        return ts
    tn = n.get("typeName") or {}
    # fallbacks for older compiler JSONs
    return tn.get("name") or ""


def _param_list(params_node) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not isinstance(params_node, dict):
        return out
    for p in (params_node.get("parameters") or []):
        if not isinstance(p, dict):
            continue
        name = p.get("name") or ""
        tdesc = (p.get("typeDescriptions") or {}).get("typeString") or (p.get("typeName") or {}).get("name") or ""
        out.append({"name": name, "type": tdesc})
    return out


def _returns_list(returns_node) -> List[Dict[str, str]]:
    """
    Extract return parameter types. Names are often empty for returns, so we only include type.
    """
    out: List[Dict[str, str]] = []
    if not isinstance(returns_node, dict):
        return out
    for r in (returns_node.get("parameters") or []):
        if not isinstance(r, dict):
            continue
        rtype = (r.get("typeDescriptions") or {}).get("typeString") or (r.get("typeName") or {}).get("name") or ""
        if rtype:
            out.append({"type": rtype})
    return out


def _modifiers(mods_node) -> List[str]:
    names = []
    for m in (mods_node or []):
        if not isinstance(m, dict):
            continue
        ref = m.get("modifierName") or {}
        n = ref.get("name") or ""
        if n:
            names.append(n)
    return names


def _guess_key_param_name(key_type: str) -> str:
    kt = (key_type or "").lower()
    if "address" in kt:
        return "account"
    if "uint" in kt:
        return "index"
    return "key"


def _parse_mapping_key_value(type_string: str) -> (str, str):
    """
    Very lightweight parser for single-level mapping like:
      'mapping(address => uint256)'
    Returns (key_type, value_type) or ("","") if not a simple mapping.
    """
    s = (type_string or "").strip()
    if not s.startswith("mapping(") or not s.endswith(")"):
        return "", ""
    inner = s[len("mapping("):-1]
    if "=>" not in inner:
        return "", ""
    key, val = inner.split("=>", 1)
    return key.strip(), val.strip()


def _array_base_type(type_string: str) -> str:
    """
    Return the base element type for a 1-D dynamic array 'T[]'.
    """
    s = (type_string or "").strip()
    if s.endswith("[]"):
        return s[:-2]
    return ""


def extract_functions(norm_ast: Dict[str, Any]) -> List[Dict[str, Any]]:
    funcs: List[Dict[str, Any]] = []

    for contract in norm_ast.get("contracts", []):
        cname = contract.get("name") or ""

        # 1) Real, declared functions
        for fn in find_by_type(contract, "FunctionDefinition"):
            name = fn.get("name") or (fn.get("kind") or "function")
            visibility = fn.get("visibility") or ""
            mutability = fn.get("stateMutability") or ""
            params = _param_list(fn.get("parameters") or {})
            returns = _returns_list(fn.get("returnParameters") or {})
            modifiers = _modifiers(fn.get("modifiers") or [])
            funcs.append({
                "contract": cname,
                "name": name,
                "visibility": visibility,
                "mutability": mutability,
                "modifiers": modifiers,
                "params": params,
                "returns": returns,          # ← include returns
                "node_id": fn.get("id"),
                "synthetic": False,          # ← explicitly mark declared fns as non-synthetic
            })

        # 2) Synthetic getters for public state variables
        #    (public scalar → no params; mapping(K=>V) → one key param; array T[] → index param)
        for vd in find_by_type(contract, "VariableDeclaration"):
            try:
                if not vd.get("stateVariable"):
                    continue
                if (vd.get("visibility") or "") != "public":
                    continue
                vname = vd.get("name") or ""
                if not vname:
                    continue

                tstr = _type_string(vd)
                params: List[Dict[str, str]] = []
                returns: List[Dict[str, str]] = []
                mutability = "view"

                # mapping getter
                ktype, vtype = _parse_mapping_key_value(tstr)
                if ktype and vtype:
                    params.append({"name": _guess_key_param_name(ktype), "type": ktype})
                    returns.append({"type": vtype})
                else:
                    # array getter
                    base = _array_base_type(tstr)
                    if base:
                        params.append({"name": "index", "type": "uint256"})
                        returns.append({"type": base})
                    else:
                        # scalar getter
                        returns.append({"type": tstr})

                funcs.append({
                    "contract": cname,
                    "name": vname,
                    "visibility": "public",
                    "mutability": mutability,
                    "modifiers": [],
                    "params": params,
                    "returns": returns,   # ← include returns
                    "node_id": vd.get("id"),
                    "synthetic": True,    # ← mark getters synthetic
                })
            except Exception:
                # Be defensive; if anything odd, just skip synthesizing
                continue

    return funcs
