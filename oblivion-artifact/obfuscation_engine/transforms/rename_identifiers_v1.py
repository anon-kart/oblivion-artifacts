# obfuscation_engine/transforms/rename_identifiers_v1.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

# NEW: hygienic name allocator + identifier collector
from ..name_alloc import NameAllocator, collect_identifiers


SOLIDITY_PRIMITIVE_TYPES = [
    "uint", "uint256", "uint128", "uint64", "uint32", "uint16", "uint8",
    "int", "int256", "int128", "int64", "int32", "int16", "int8",
    "address", "bool", "bytes", "bytes32", "bytes16", "bytes8", "bytes4",
    "string",
]

RESERVED_WORDS = set([
    "function", "constructor", "returns", "return", "if", "else", "for", "while", "do",
    "break", "continue", "emit", "event", "modifier", "mapping", "storage", "memory",
    "calldata", "public", "private", "internal", "external", "view", "pure", "payable",
    "require", "revert", "assert", "new", "delete", "unchecked", "try", "catch",
    "contract", "interface", "library", "pragma", "import",
    "this", "super", "msg", "tx", "block",
    "true", "false",
])

# NEW: do not rename already obfuscated identifiers (prevents repeated passes breaking things)
_OBF_ALREADY = re.compile(r"^(v_\d+_\d+|__obf_.+)$")


@dataclass
class RenameResult:
    new_source: str
    rename_map: Dict[str, str]


def _find_function_span(source: str, fn_name: str) -> Tuple[int, int]:
    """
    Returns (start_idx, end_idx) for the function *body* including braces: {...}
    """
    # match: function <name> ( ... ) [stuff] {
    pat = re.compile(rf"\bfunction\s+{re.escape(fn_name)}\s*\(", re.MULTILINE)
    m = pat.search(source)
    if not m:
        raise ValueError(f"Could not find function '{fn_name}' in source.")

    # find the first '{' after the signature
    brace_open = source.find("{", m.end())
    if brace_open == -1:
        raise ValueError(f"Could not find body '{{' for function '{fn_name}'.")

    # brace matching
    depth = 0
    i = brace_open
    while i < len(source):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return brace_open, i + 1
        i += 1

    raise ValueError(f"Unbalanced braces in function '{fn_name}'.")


def _extract_params(signature_text: str) -> List[str]:
    """
    signature_text: content between '(' and ')'
    For each param chunk, returns the last token if it's an identifier.
    This is intentionally simple (MVP).
    """
    params = []
    for part in signature_text.split(","):
        part = part.strip()
        if not part:
            continue
        tokens = re.split(r"\s+", part)
        if not tokens:
            continue
        # last token can be name
        candidate = tokens[-1]
        # ignore when last token is a storage location keyword
        if candidate in ("memory", "calldata", "storage"):
            continue
        # ignore if last token looks like a type (no name provided)
        if candidate in SOLIDITY_PRIMITIVE_TYPES:
            continue
        if re.fullmatch(r"[A-Za-z_]\w*", candidate) and candidate not in RESERVED_WORDS:
            params.append(candidate)
    return params


def _extract_locals(body_text: str) -> List[str]:
    """
    Very conservative local variable extraction:
    matches things like:
      uint256 x = ...
      address foo;
      bool ok = ...
      uint[] memory arr = ...
    """
    # build type regex
    type_re = r"|".join(re.escape(t) for t in SOLIDITY_PRIMITIVE_TYPES)
    # allow arrays and simple generic-like (bytes memory b) etc
    decl = re.compile(
        rf"\b(?:{type_re})(?:\s*(?:\[\])*)\s+(?:memory|calldata|storage\s+)?([A-Za-z_]\w*)\b",
        re.MULTILINE,
    )
    found = []
    for m in decl.finditer(body_text):
        name = m.group(1)
        if name and name not in RESERVED_WORDS:
            found.append(name)
    return sorted(set(found))


def _safe_replace_ident(source: str, old: str, new: str) -> str:
    """
    Replace identifier occurrences using word boundaries,
    but avoid member access: ".old"
    """
    # negative lookbehind for '.' or identifier char
    # negative lookahead for identifier char
    pat = re.compile(rf"(?<![\w\.]){re.escape(old)}(?!\w)")
    return pat.sub(new, source)


def apply_rename_identifiers_v1(source: str, contract_name: str, fn_name: str, seed: int = 1337) -> RenameResult:
    """
    Rename parameters + local vars in a single function.
    Does NOT change state vars or public ABI (param names don't affect ABI).

    Hygiene fixes:
    - Do NOT rename already-obfuscated identifiers (v_<seed>_<n>, __obf_*)
    - Generate fresh names that are guaranteed not to collide inside the function
    """
    # 1) locate function signature bounds to get params text
    sig_pat = re.compile(rf"\bfunction\s+{re.escape(fn_name)}\s*\((.*?)\)", re.DOTALL)
    sig_m = sig_pat.search(source)
    if not sig_m:
        # no signature → probably constructor / fallback → no-op
        return RenameResult(new_source=source, rename_map={})

    params_text = sig_m.group(1)
    param_names = _extract_params(params_text)

    # 2) locate body span
    body_l, body_r = _find_function_span(source, fn_name)
    body_text = source[body_l:body_r]

    # 3) extract locals
    local_names = _extract_locals(body_text)

    # 4) build rename map (avoid collisions + avoid re-obfuscation)
    all_names: List[str] = []
    for n in param_names + local_names:
        if n and n not in RESERVED_WORDS and n not in all_names:
            all_names.append(n)

    # 5) only apply replacements inside this function region (signature+body)
    fn_start = sig_m.start()
    fn_end = body_r  # end after body closes
    fn_text = source[fn_start:fn_end]

    # NEW: collect used identifiers and allocate hygienic fresh names
    used_names = collect_identifiers(fn_text)
    alloc = NameAllocator(seed=seed, used=used_names)

    rename_map: Dict[str, str] = {}
    for name in all_names:
        # Skip already-obfuscated names to prevent repeated passes destroying hygiene
        if _OBF_ALREADY.match(name):
            continue
        # Skip reserved
        if name in RESERVED_WORDS:
            continue

        # Fresh name guaranteed not to collide within this function
        new_name = alloc.fresh("v")
        if new_name != name:
            rename_map[name] = new_name

    # Apply replacements
    for old, new in rename_map.items():
        fn_text = _safe_replace_ident(fn_text, old, new)

    new_source = source[:fn_start] + fn_text + source[fn_end:]
    return RenameResult(new_source=new_source, rename_map=rename_map)