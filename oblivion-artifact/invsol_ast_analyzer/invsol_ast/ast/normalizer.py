from typing import Any, Dict, List

def normalize_ast(ast_bundle: Dict[str, Any]) -> Dict[str, Any]:
    src = ast_bundle.get("source")
    raw = ast_bundle.get("ast") or {}
    nodes = raw.get("nodes") or raw.get("ast", {}).get("nodes") or []

    contracts: List[Dict[str, Any]] = []
    def collect_contracts(n: Dict[str, Any]):
        if isinstance(n, dict):
            if n.get("nodeType") == "ContractDefinition":
                contracts.append(n)
            for v in n.values():
                if isinstance(v, dict):
                    collect_contracts(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            collect_contracts(item)

    if isinstance(nodes, list):
        for n in nodes:
            collect_contracts(n)
    elif isinstance(nodes, dict):
        collect_contracts(nodes)

    # NEW: annotate each node under a function with contextual attributes
    for c in contracts:
        _annotate_function_context(c)

    return {
        "source": src,
        "contracts": contracts,
        "augmented": True,  # helpful flag when you dump with --dump-ast
    }

def _annotate_function_context(contract: Dict[str, Any]) -> None:
    cname = contract.get("name") or ""

    def walk(n: Any, fn_ctx: Dict[str, Any] | None):
        if isinstance(n, dict):
            nt = n.get("nodeType")

            # entering a function ⇒ establish context for its subtree
            if nt == "FunctionDefinition":
                fn_ctx = {
                    "contract": cname,
                    "function": n.get("name") or n.get("kind") or "",
                    "visibility": n.get("visibility") or "",
                    "mutability": n.get("stateMutability") or "",
                    "modifiers": [
                        (m.get("modifierName") or {}).get("name")
                        for m in (n.get("modifiers") or [])
                        if isinstance(m, dict)
                    ],
                }

            # attach context only to AST-like nodes, and avoid mutating + recursing into it
            if fn_ctx and ("nodeType" in n or "src" in n or "name" in n):
                # shallow copy so later mutations to fn_ctx don't ripple
                n["__ctx"] = dict(fn_ctx)

            # IMPORTANT: do not recurse into the injected __ctx
            for k, v in list(n.items()):
                if k == "__ctx":
                    continue
                if isinstance(v, (dict, list)):
                    walk(v, fn_ctx)

        elif isinstance(n, list):
            for it in n:
                if isinstance(it, (dict, list)):
                    walk(it, fn_ctx)

    walk(contract, None)
