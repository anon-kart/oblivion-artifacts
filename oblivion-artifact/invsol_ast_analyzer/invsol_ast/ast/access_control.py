from typing import Any, Dict, List
from .extractor_core import find_by_type

def _guess_role_from_modifier(mod: str) -> str:
    m = mod.lower()
    if "owner" in m:
        return "owner"
    if "admin" in m:
        return "admin"
    if "role" in m:
        return "role"
    return "unknown"

def resolve_access_control(norm_ast: Dict[str, Any]) -> List[Dict[str, str]]:
    edges: List[Dict[str, str]] = []
    for contract in norm_ast.get("contracts", []):
        for fn in find_by_type(contract, "FunctionDefinition"):
            mods = (fn.get("modifiers") or [])
            for m in mods:
                name = (m.get("modifierName") or {}).get("name") or ""
                if not name:
                    continue
                edges.append({
                    "contract": contract.get("name") or "",
                    "function": fn.get("name") or fn.get("kind") or "",
                    "modifier": name,
                    "role": _guess_role_from_modifier(name),
                })
    return edges
