import re
from typing import Any, Dict, List
from .extractor_core import find_by_type

# Tolerant single-level mapping regex:
#   mapping ( <key> => <value> )
# We intentionally keep it single-level for the "mappings" summary.
_MAP_RE = re.compile(r"mapping\s*\(\s*([^=]+?)\s*=>\s*([^)]+?)\s*\)\s*$", re.IGNORECASE)

def _type_string(vd: Dict[str, Any]) -> str:
    td = (vd.get("typeDescriptions") or {})
    ts = (td.get("typeString") or "").strip()
    return ts

def extract_state(norm_ast: Dict[str, Any]) -> Dict[str, Any]:
    variables: List[Dict[str, str]] = []
    mappings: List[Dict[str, str]] = []

    for contract in norm_ast.get("contracts", []):
        cname = contract.get("name") or ""
        for vd in find_by_type(contract, "VariableDeclaration"):
            if not vd.get("stateVariable"):
                continue

            name = vd.get("name") or ""
            tdesc = _type_string(vd)

            # Record every state var with its type as-is
            variables.append({
                "contract": cname,
                "name": name,
                "type": tdesc,
            })

            # If it's a single-level mapping, extract key/value types for the "mappings" list
            if tdesc.lower().startswith("mapping"):
                # Normalize any internal whitespace/newlines before matching
                candidate = " ".join(tdesc.split())
                m = _MAP_RE.match(candidate)
                if m:
                    key_t = m.group(1).strip()
                    val_t = m.group(2).strip()
                    mappings.append({
                        "contract": cname,
                        "name": name,
                        "key": key_t,
                        "value": val_t,
                    })

    return {"variables": variables, "mappings": mappings}
