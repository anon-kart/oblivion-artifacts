from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Optional
import re


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


# Top-level scalar state vars only.
# Intentionally excludes:
# - public (ABI getter risk)
# - constant / immutable
# - mappings / arrays
# - initialized declarations in v1
# - multiple declarations on one line
#
# Examples matched:
#   uint256 private total;
#   bool internal paused;
#   address private owner;
#   string private name;
#   bytes32 internal salt;
_STATE_VAR_LINE_RE = re.compile(
    r"^(?P<indent>[ \t]*)"
    r"(?P<typ>"
    r"uint(?:8|16|32|64|128|256)?|"
    r"int(?:8|16|32|64|128|256)?|"
    r"bool|"
    r"address(?:\s+payable)?|"
    r"string|"
    r"bytes(?:[1-9]|1[0-9]|2[0-9]|3[0-2])?|"
    r"bytes"
    r")"
    r"\s+"
    r"(?P<vis>private|internal)"
    r"(?:\s+(?P<extra>(?!;)[^=;]*?))?"
    r"\s+"
    r"(?P<name>[A-Za-z_]\w*)"
    r"\s*;",
    re.MULTILINE,
)

_FUNCTION_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\b")
_CONSTRUCTOR_RE = re.compile(r"\bconstructor\s*\(")


def _find_contract_span(source: str, contract_name: str) -> Tuple[int, int, int]:
    """
    Returns (contract_start, contract_open_brace, contract_close_exclusive)
    """
    m = re.search(rf"\bcontract\s+{re.escape(contract_name)}\b", source)
    if not m:
        raise ValueError(f"scalar_to_struct_indirection_v1: contract {contract_name} not found")

    brace_open = source.find("{", m.end())
    if brace_open < 0:
        raise ValueError("scalar_to_struct_indirection_v1: cannot find contract body open brace")

    depth = 0
    j = brace_open
    while j < len(source):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return m.start(), brace_open, j + 1
        j += 1

    raise ValueError("scalar_to_struct_indirection_v1: cannot match contract braces")


def _find_all_function_spans(source: str) -> List[Tuple[str, int, int]]:
    """
    Returns list of (name, body_open, body_close_exclusive) for all functions/constructors.
    """
    out: List[Tuple[str, int, int]] = []

    for m in _FUNCTION_RE.finditer(source):
        fn_name = m.group("name")
        body_open = source.find("{", m.end())
        if body_open < 0:
            continue
        depth = 0
        j = body_open
        while j < len(source):
            c = source[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    out.append((fn_name, body_open, j + 1))
                    break
            j += 1

    for m in _CONSTRUCTOR_RE.finditer(source):
        body_open = source.find("{", m.end())
        if body_open < 0:
            continue
        depth = 0
        j = body_open
        while j < len(source):
            c = source[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    out.append(("constructor", body_open, j + 1))
                    break
            j += 1

    out.sort(key=lambda t: t[1])
    return out


def _strip_strings_and_comments_keep_len(s: str) -> str:
    """
    Replace contents of strings/comments with spaces so indices stay aligned.
    """
    out = list(s)
    i = 0
    n = len(s)
    in_line = False
    in_block = False
    in_str = False
    quote = ""

    while i < n:
        ch = s[i]
        nxt = s[i + 1] if i + 1 < n else ""

        if in_line:
            if ch != "\n":
                out[i] = " "
            else:
                in_line = False
            i += 1
            continue

        if in_block:
            out[i] = " "
            if ch == "*" and nxt == "/":
                out[i + 1] = " "
                i += 2
                in_block = False
            else:
                i += 1
            continue

        if in_str:
            out[i] = " "
            if ch == "\\" and i + 1 < n:
                out[i + 1] = " "
                i += 2
                continue
            if ch == quote:
                in_str = False
                quote = ""
            i += 1
            continue

        if ch == "/" and nxt == "/":
            out[i] = out[i + 1] = " "
            i += 2
            in_line = True
            continue

        if ch == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            i += 2
            in_block = True
            continue

        if ch in ("'", '"'):
            out[i] = " "
            in_str = True
            quote = ch
            i += 1
            continue

        i += 1

    return "".join(out)


def _replace_identifier_outside_strings_comments(src: str, old: str, new: str) -> Tuple[str, int]:
    if old == new:
        return src, 0

    masked = _strip_strings_and_comments_keep_len(src)
    token_re = re.compile(rf"\b{re.escape(old)}\b")
    matches = list(token_re.finditer(masked))
    if not matches:
        return src, 0

    out: List[str] = []
    last = 0
    replaced = 0
    for m in matches:
        a, b = m.span()
        out.append(src[last:a])
        out.append(new)
        last = b
        replaced += 1
    out.append(src[last:])
    return "".join(out), replaced


def _make_struct_name(source: str) -> str:
    base = "__ObfState"
    name = base
    k = 0
    while re.search(rf"\b{re.escape(name)}\b", source):
        k += 1
        name = f"{base}_{k}"
    return name


def _make_struct_var_name(source: str) -> str:
    base = "__obf_state"
    name = base
    k = 0
    while re.search(rf"\b{re.escape(name)}\b", source):
        k += 1
        name = f"{base}_{k}"
    return name


def _build_state_var_meta_map(state_var_meta: Optional[List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(state_var_meta, list):
        return out
    for item in state_var_meta:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "")
        if name:
            out[name] = item
    return out


def _find_state_var_candidates(
    contract_body: str,
    max_fields: int,
    state_var_meta_map: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """
    Scan top-level contract body only. Avoid nested function bodies by tracking brace depth.
    """
    candidates: List[Dict[str, Any]] = []
    depth = 0
    line_start = 0
    i = 0
    n = len(contract_body)
    meta_map = state_var_meta_map or {}

    while i <= n:
        if i == n or contract_body[i] == "\n":
            line = contract_body[line_start:i]
            if depth == 0:
                m = _STATE_VAR_LINE_RE.match(line)
                if m:
                    full_extra = (m.group("extra") or "").strip()
                    lower_extra = f" {full_extra.lower()} "
                    name = m.group("name").strip()

                    meta = meta_map.get(name, {})
                    vis = str(meta.get("visibility", "") or m.group("vis").strip())
                    is_public_getter = bool(meta.get("is_public_getter")) or vis == "public"
                    is_immutable = bool(meta.get("is_immutable")) or (" immutable " in lower_extra)
                    initializer_present = bool(meta.get("initializer_present"))

                    if is_public_getter:
                        pass
                    elif is_immutable:
                        pass
                    elif initializer_present:
                        pass
                    elif " constant " in lower_extra:
                        pass
                    else:
                        candidates.append(
                            {
                                "line_start": line_start,
                                "line_end": i,
                                "indent": m.group("indent"),
                                "type": m.group("typ").strip(),
                                "visibility": vis if vis else m.group("vis").strip(),
                                "extra": full_extra,
                                "name": name,
                                "decl_line": line,
                            }
                        )
                        if len(candidates) >= int(max_fields):
                            return candidates
            line_start = i + 1

        if i < n:
            ch = contract_body[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        i += 1

    return candidates


def _contains_any_identifier(text: str, names: List[str]) -> bool:
    for name in names:
        if re.search(rf"\b{re.escape(name)}\b", text):
            return True
    return False


def _should_skip_entire_transform(
    contract_body: str,
    candidate_names: List[str],
    modifier_defs: Optional[List[Dict[str, Any]]] = None,
) -> Optional[str]:
    lower_body = contract_body.lower()

    # Only skip for truly risky modifier cases, not just any modifier existing in the contract.
    if isinstance(modifier_defs, list) and modifier_defs:
        for md in modifier_defs:
            if not isinstance(md, dict):
                continue
            if bool(md.get("has_post_placeholder_code")):
                return "complex modifier definition present"
            if bool(md.get("has_external_calls")):
                return "modifier with external-call-like behavior present"
            if bool(md.get("has_loops")):
                return "modifier with loops present"

    if re.search(r"\binherit|override\b", lower_body):
        return "override/inheritance-like pattern present"

    # Conservative skip if any obvious event declaration names overlap candidate names.
    for name in candidate_names:
        if re.search(rf"\bevent\b[^\n;]*\b{re.escape(name)}\b", contract_body):
            return f"candidate {name} appears in event declaration context"

    return None


def _inject_struct_block(
    source: str,
    contract_name: str,
    struct_name: str,
    struct_var_name: str,
    fields: List[Dict[str, Any]],
) -> Tuple[str, bool]:
    if not fields:
        return source, False

    _, brace_open, _ = _find_contract_span(source, contract_name)
    insert_at = brace_open + 1

    blob_lines = [
        "",
        "    // --- OBLIVION scalar->struct indirection (generated) ---",
        f"    struct {struct_name} {{",
    ]
    for f in fields:
        blob_lines.append(f"        {f['type']} {f['name']};")
    blob_lines.append("    }")
    blob_lines.append(f"    {struct_name} private {struct_var_name};")
    blob_lines.append("")

    blob = "\n".join(blob_lines)
    new_source = source[:insert_at] + blob + source[insert_at:]
    return new_source, True


def _remove_original_decl_lines(contract_body: str, fields: List[Dict[str, Any]]) -> str:
    if not fields:
        return contract_body

    ranges = sorted((f["line_start"], f["line_end"]) for f in fields)
    out: List[str] = []
    last = 0
    for a, b in ranges:
        out.append(contract_body[last:a])
        if b < len(contract_body) and contract_body[b:b + 1] == "\n":
            b += 1
        last = b
    out.append(contract_body[last:])
    return "".join(out)


def apply_scalar_to_struct_indirection_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    max_fields: int = 4,
    rewrite_all_functions: bool = True,
    state_var_meta: Optional[List[Dict[str, Any]]] = None,
    modifier_defs: Optional[List[Dict[str, Any]]] = None,
    **_: Any,
) -> TransformResult:
    """
    Conservative BiAn-style scalar state -> struct-member indirection.

    What it does:
      - finds top-level private/internal scalar state vars in the target contract
      - injects:
            struct __ObfState { ... }
            __ObfState private __obf_state;
      - removes original matching declarations
      - rewrites references:
            total -> __obf_state.total
        in either:
          * all functions/constructors (default), or
          * only the target function fn_name

    Safety / scope:
      - only uninitialized private/internal scalar vars
      - no public vars (ABI getter risk)
      - no constant/immutable
      - no mappings/arrays
      - skips only for complex modifier cases, not merely because modifiers exist
      - best-effort lexical rewrite only
    """
    _ = seed  # reserved for future diversification

    if int(max_fields) <= 0:
        return TransformResult(
            new_source=source,
            details={"note": "scalar_to_struct_indirection_v1 skipped: max_fields <= 0", "fields": []},
        )

    _contract_start, contract_open, contract_close = _find_contract_span(source, contract_name)
    contract_body = source[contract_open + 1:contract_close - 1]
    state_var_meta_map = _build_state_var_meta_map(state_var_meta)

    fields = _find_state_var_candidates(
        contract_body,
        int(max_fields),
        state_var_meta_map=state_var_meta_map,
    )
    if not fields:
        return TransformResult(
            new_source=source,
            details={"note": "scalar_to_struct_indirection_v1: no eligible state vars found", "fields": []},
        )

    candidate_names = [f["name"] for f in fields]
    skip_reason = _should_skip_entire_transform(
        contract_body,
        candidate_names,
        modifier_defs=modifier_defs,
    )
    if skip_reason:
        return TransformResult(
            new_source=source,
            details={"note": f"scalar_to_struct_indirection_v1 skipped: {skip_reason}", "fields": []},
        )

    struct_name = _make_struct_name(source)
    struct_var_name = _make_struct_var_name(source)

    # Step 1: inject struct block near top of contract.
    src1, injected = _inject_struct_block(source, contract_name, struct_name, struct_var_name, fields)

    # Step 2: recompute contract span on updated source.
    _, new_contract_open, new_contract_close = _find_contract_span(src1, contract_name)
    new_contract_body = src1[new_contract_open + 1:new_contract_close - 1]

    # Step 3: locate eligible fields again against updated contract body, then remove original decl lines.
    fields2 = _find_state_var_candidates(
        new_contract_body,
        int(max_fields),
        state_var_meta_map=state_var_meta_map,
    )
    if not fields2:
        return TransformResult(
            new_source=src1,
            details={
                "note": "scalar_to_struct_indirection_v1 partial: struct injected but original decls not re-located",
                "fields": [],
                "injected_struct": injected,
                "struct_name": struct_name,
                "struct_var_name": struct_var_name,
            },
        )

    cleaned_contract_body = _remove_original_decl_lines(new_contract_body, fields2)
    src2 = src1[:new_contract_open + 1] + cleaned_contract_body + src1[new_contract_close - 1:]

    # Step 4: rewrite function / constructor bodies.
    spans = _find_all_function_spans(src2)
    rewrites: List[Dict[str, Any]] = []
    new_source = src2

    # Reverse order so index positions remain stable.
    for name, body_open, body_close in reversed(spans):
        if not rewrite_all_functions and name != fn_name:
            continue

        body_text = new_source[body_open:body_close]
        body_inner = body_text[1:-1]

        if not _contains_any_identifier(body_inner, candidate_names):
            continue

        rewritten_body_inner = body_inner
        per_fn_counts: Dict[str, int] = {}

        for f in fields:
            old = f["name"]
            new = f"{struct_var_name}.{old}"
            rewritten_body_inner, count = _replace_identifier_outside_strings_comments(rewritten_body_inner, old, new)
            if count > 0:
                per_fn_counts[old] = per_fn_counts.get(old, 0) + count

        if rewritten_body_inner != body_inner:
            new_body_text = "{" + rewritten_body_inner + "}"
            new_source = new_source[:body_open] + new_body_text + new_source[body_close:]
            rewrites.append({"function": name, "counts": per_fn_counts})

    # Step 5: final sanity check when target-only mode is requested.
    if not rewrite_all_functions:
        if fn_name != "constructor":
            if not re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", new_source):
                return TransformResult(
                    new_source=source,
                    details={"note": "scalar_to_struct_indirection_v1 aborted: target function disappeared", "fields": []},
                )
        else:
            if not re.search(r"\bconstructor\s*\(", new_source):
                return TransformResult(
                    new_source=source,
                    details={"note": "scalar_to_struct_indirection_v1 aborted: constructor disappeared", "fields": []},
                )

    return TransformResult(
        new_source=new_source,
        details={
            "note": "scalar_to_struct_indirection_v1 applied",
            "injected_struct": injected,
            "struct_name": struct_name,
            "struct_var_name": struct_var_name,
            "field_count": len(fields),
            "fields": [
                {
                    "name": f["name"],
                    "type": f["type"],
                    "visibility": f["visibility"],
                }
                for f in fields
            ],
            "rewrite_scope": "all_functions" if rewrite_all_functions else f"target_only:{fn_name}",
            "rewrites": rewrites,
        },
    )