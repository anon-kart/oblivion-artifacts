from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

# Keep primitive types list consistent with v1
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


@dataclass
class RenameResult:
    new_source: str
    rename_map: Dict[str, str]
    details: Dict[str, object]


def _is_generated_obf_name(name: str) -> bool:
    return name.startswith("__obf_")


def _find_function_sig_match(source: str, fn_name: str) -> Optional[re.Match]:
    # captures params between (...)
    sig_pat = re.compile(rf"\bfunction\s+{re.escape(fn_name)}\s*\((.*?)\)", re.DOTALL)
    return sig_pat.search(source)


def _find_function_span(source: str, fn_name: str) -> Tuple[int, int]:
    """
    Returns (start_idx, end_idx) for the function body including braces: {...}
    """
    pat = re.compile(rf"\bfunction\s+{re.escape(fn_name)}\s*\(", re.MULTILINE)
    m = pat.search(source)
    if not m:
        raise ValueError(f"Could not find function '{fn_name}' in source.")

    brace_open = source.find("{", m.end())
    if brace_open == -1:
        raise ValueError(f"Could not find body '{{' for function '{fn_name}'.")

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
    params: List[str] = []
    for part in signature_text.split(","):
        part = part.strip()
        if not part:
            continue
        tokens = re.split(r"\s+", part)
        if not tokens:
            continue
        candidate = tokens[-1]
        if candidate in ("memory", "calldata", "storage"):
            continue
        if candidate in SOLIDITY_PRIMITIVE_TYPES:
            continue
        if (
            re.fullmatch(r"[A-Za-z_]\w*", candidate)
            and candidate not in RESERVED_WORDS
            and not _is_generated_obf_name(candidate)
        ):
            params.append(candidate)
    return params


def _extract_locals(body_text: str) -> List[str]:
    """
    Conservative local variable extraction.
    Includes primitive declarations + simple arrays + (type) storage/memory/calldata name.
    """
    type_re = r"|".join(re.escape(t) for t in SOLIDITY_PRIMITIVE_TYPES)
    decl = re.compile(
        rf"\b(?:{type_re})(?:\s*(?:\[\])*)\s+(?:memory|calldata|storage\s+)?([A-Za-z_]\w*)\b",
        re.MULTILINE,
    )
    found: List[str] = []
    for m in decl.finditer(body_text):
        name = m.group(1)
        if (
            name
            and name not in RESERVED_WORDS
            and not _is_generated_obf_name(name)
        ):
            found.append(name)
    return sorted(set(found))


def _all_identifiers_in_text(text: str) -> Set[str]:
    """
    Best-effort: gather identifier tokens. Helps avoid collisions.
    """
    toks = set(re.findall(r"\b[A-Za-z_]\w*\b", text))
    toks -= RESERVED_WORDS
    return toks


def _safe_replace_ident(text: str, old: str, new: str) -> str:
    """
    Replace identifier occurrences using word boundaries,
    but avoid member access: ".old"
    """
    pat = re.compile(rf"(?<![\w\.]){re.escape(old)}(?!\w)")
    return pat.sub(new, text)


def _classify_specials(fn_text: str, names: List[str]) -> Dict[str, str]:
    """
    Returns name -> kind: "loop_index" | "len_temp" | "normal"
    """
    kinds: Dict[str, str] = {n: "normal" for n in names}

    # loop index heuristic: appears in a for(...) header as a declared uint and used in cond/inc
    for n in names:
        if re.search(rf"\bfor\s*\([^;]*\buint(?:256)?\s+{re.escape(n)}\b", fn_text):
            kinds[n] = "loop_index"

    # length temp heuristic: assigned from ".length" or " = <something>.length"
    for n in names:
        if re.search(rf"\b{re.escape(n)}\s*=\s*[^;]*\.length\b", fn_text):
            kinds[n] = "len_temp"
        if re.search(rf"\buint(?:256)?\s+{re.escape(n)}\s*=\s*[^;]*\.length\b", fn_text):
            kinds[n] = "len_temp"

    return kinds


def apply_rename_identifiers_v2_scoped(
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
) -> RenameResult:
    """
    Scoped/unique renamer that avoids shadowing/collisions.

    Rules:
    - maintain per-function counter
    - never reuse a generated name inside same function
    - never rename to a name already present in that function
    - special-case loop indices and "len" temporaries with distinct prefixes
    - only rewrite inside the function text region (signature + body)
    - never rename generated __obf_* identifiers
    - never rename member-access field names (.foo)
    """
    _ = contract_name

    sig_m = _find_function_sig_match(source, fn_name)
    if not sig_m:
        return RenameResult(new_source=source, rename_map={}, details={"note": "no signature match (noop)"})

    params_text = sig_m.group(1)
    param_names = _extract_params(params_text)

    body_l, body_r = _find_function_span(source, fn_name)
    fn_start = sig_m.start()
    fn_end = body_r
    fn_text = source[fn_start:fn_end]

    body_text = source[body_l:body_r]
    local_names = _extract_locals(body_text)

    # Unique in-order list
    all_names: List[str] = []
    for n in param_names + local_names:
        if (
            n
            and n not in RESERVED_WORDS
            and not _is_generated_obf_name(n)
            and n not in all_names
        ):
            all_names.append(n)

    # Collect identifiers already present (avoid collisions with existing names, incl. injected temps)
    present = _all_identifiers_in_text(fn_text)
    used_new: Set[str] = set()

    # classify specials
    kinds = _classify_specials(fn_text, all_names)

    rename_map: Dict[str, str] = {}
    counter = 0

    def gen(prefix: str) -> str:
        nonlocal counter
        # deterministic; always unique due to counter + collision checks
        while True:
            cand = f"{prefix}_{seed}_{counter}"
            counter += 1
            if cand in RESERVED_WORDS:
                continue
            if cand in present:
                continue
            if cand in used_new:
                continue
            used_new.add(cand)
            present.add(cand)
            return cand

    for old in all_names:
        if old in RESERVED_WORDS:
            continue
        # If it already looks obfuscated, skip to reduce churn
        if _is_generated_obf_name(old) or re.fullmatch(r"v_\d+_\d+", old):
            continue

        kind = kinds.get(old, "normal")
        if kind == "loop_index":
            new = gen("idx")
        elif kind == "len_temp":
            new = gen("len")
        else:
            new = gen("v")

        if new != old:
            rename_map[old] = new

    # Apply replacements only inside function text
    out_fn_text = fn_text
    for old, new in rename_map.items():
        # Extra safety: generated names should never be renamed
        if _is_generated_obf_name(old) or _is_generated_obf_name(new):
            continue
        out_fn_text = _safe_replace_ident(out_fn_text, old, new)

    new_source = source[:fn_start] + out_fn_text + source[fn_end:]

    if not rename_map:
        return RenameResult(
            new_source=source,
            rename_map={},
            details={
                "seed": seed,
                "renamed_count": 0,
                "note": "rename_identifiers_v2_scoped: no eligible identifiers",
            },
        )

    return RenameResult(
        new_source=new_source,
        rename_map=rename_map,
        details={
            "seed": seed,
            "renamed_count": len(rename_map),
            "note": "rename_identifiers_v2_scoped applied (collision-safe)",
        },
    )