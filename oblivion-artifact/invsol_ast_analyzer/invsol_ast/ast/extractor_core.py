from typing import Any, Dict, Generator, Iterable, Optional

def walk(node: Any) -> Generator[Any, None, None]:
    """Generic DFS over dict/list AST."""
    if isinstance(node, dict):
        yield node
        for v in node.values():
            if isinstance(v, (dict, list)):
                yield from walk(v)
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                yield from walk(item)

def find_by_type(root: Any, node_type: str) -> Iterable[Dict]:
    for n in walk(root):
        if isinstance(n, dict) and n.get("nodeType") == node_type:
            yield n

def find_parent_function(root: Dict, target: Dict) -> Optional[Dict]:
    """
    Best-effort parent function lookup by walking and tracking a stack.
    """
    stack = []
    def dfs(n):
        stack.append(n)
        if n is target:
            # walk stack upwards to find nearest FunctionDefinition
            for m in reversed(stack):
                if isinstance(m, dict) and m.get("nodeType") == "FunctionDefinition":
                    return m
            return None
        if isinstance(n, dict):
            for v in n.values():
                if isinstance(v, (dict, list)):
                    res = dfs(v)
                    if res is not None:
                        return res
        elif isinstance(n, list):
            for item in n:
                if isinstance(item, (dict, list)):
                    res = dfs(item)
                    if res is not None:
                        return res
        stack.pop()
        return None
    return dfs(root)
