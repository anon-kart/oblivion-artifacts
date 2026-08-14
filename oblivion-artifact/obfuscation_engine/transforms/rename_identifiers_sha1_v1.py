# obfuscation_engine/transforms/rename_identifiers_sha1_v1.py
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import random
import re
from typing import Any, Dict, Tuple


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


_SOL_BUILTINS = {
    "msg", "block", "tx", "this", "super",
    "keccak256", "sha256", "ripemd160", "ecrecover",
    "abi", "type",
    "address", "uint", "uint256", "int", "int256", "bool", "bytes", "string",
    "mapping", "memory", "storage", "calldata",
    "true", "false",
    "require", "assert", "revert", "emit",
}


def _is_generated_obf_name(name: str) -> bool:
    return name.startswith("__obf_")


def _find_function_span(source: str, fn_name: str) -> Tuple[int, int]:
    needle = f"function {fn_name}"
    i = source.find(needle)
    if i < 0:
        needle2 = f"function\n{fn_name}"
        i = source.find(needle2)
    if i < 0:
        raise ValueError(f"sha1_rename_v1: function {fn_name} not found")

    brace_open = source.find("{", i)
    if brace_open < 0:
        raise ValueError("sha1_rename_v1: cannot find body open brace")

    depth = 0
    j = brace_open
    while j < len(source):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return brace_open, j + 1
        j += 1
    raise ValueError("sha1_rename_v1: cannot match braces")


_DECL_RE = re.compile(
    r"\b(uint256|uint|int256|int|bool|address|bytes32|bytes|string)\b\s+([A-Za-z_]\w*)\b"
)


def _hash_name(name: str, salt: str) -> str:
    h = hashlib.sha1((salt + ":" + name).encode("utf-8")).hexdigest()
    return "v_0x" + h[:10]


def _safe_replace_identifiers(text: str, rename_map: Dict[str, str]) -> str:
    """
    Replace identifier tokens conservatively:
    - never rewrite member-access fields like obj.field
    - never rewrite generated obf identifiers
    - preserve non-matching text exactly
    """
    if not rename_map:
        return text

    token_re = re.compile(r"\b[A-Za-z_]\w*\b")
    out = []
    last = 0

    for match in token_re.finditer(text):
        start, end = match.start(), match.end()
        ident = match.group(0)

        out.append(text[last:start])

        # Never rewrite member-access field names like __obf_state.__obf_g_x
        if start > 0 and text[start - 1] == ".":
            out.append(ident)
            last = end
            continue

        # Never rewrite generated obf names
        if _is_generated_obf_name(ident):
            out.append(ident)
            last = end
            continue

        repl = rename_map.get(ident, ident)
        out.append(repl)
        last = end

    out.append(text[last:])
    return "".join(out)


def apply_rename_identifiers_sha1_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **_: Any,
) -> TransformResult:
    rnd = random.Random(int(seed))
    salt = f"{contract_name}:{fn_name}:{seed}:{rnd.randint(0, 1_000_000)}"

    body_open, body_close = _find_function_span(source, fn_name)
    body = source[body_open:body_close]

    # Find local decls
    rename_map: Dict[str, str] = {}
    for m in _DECL_RE.finditer(body):
        name = m.group(2)
        if name in _SOL_BUILTINS:
            continue
        if _is_generated_obf_name(name):
            continue
        new_name = _hash_name(name, salt)
        if new_name == name:
            continue
        rename_map[name] = new_name

    if not rename_map:
        return TransformResult(
            new_source=source,
            details={"renamed": 0, "note": "no local decls matched"},
        )

    # Apply replacements conservatively
    new_body = _safe_replace_identifiers(body, rename_map)

    new_source = source[:body_open] + new_body + source[body_close:]
    return TransformResult(
        new_source=new_source,
        details={
            "renamed": len(rename_map),
            "seed": seed,
            "rename_map": rename_map,
            "note": "rename_identifiers_sha1_v1 applied (locals -> sha1-like names)",
        },
    )