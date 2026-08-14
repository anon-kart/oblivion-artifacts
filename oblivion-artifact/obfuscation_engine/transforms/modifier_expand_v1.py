from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import re


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


_FUNCTION_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\(",
    re.MULTILINE,
)

_MODIFIER_DEF_RE = re.compile(
    r"\bmodifier\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)",
    re.MULTILINE,
)

_CONSTRUCTOR_RE = re.compile(r"\bconstructor\s*\(", re.MULTILINE)


def _find_contract_span(source: str, contract_name: str) -> Tuple[int, int, int]:
    """
    Returns (contract_start, contract_open_brace, contract_close_exclusive)
    """
    m = re.search(rf"\bcontract\s+{re.escape(contract_name)}\b", source)
    if not m:
        raise ValueError(f"modifier_expand_v1: contract {contract_name} not found")

    brace_open = source.find("{", m.end())
    if brace_open < 0:
        raise ValueError("modifier_expand_v1: cannot find contract body open brace")

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

    raise ValueError("modifier_expand_v1: cannot match contract braces")


def _find_function_span(source: str, fn_name: str) -> Tuple[int, int, int, int]:
    """
    Returns (sig_start, body_open, body_close_exclusive, sig_end)
    where sig_end == body_open.
    """
    if fn_name == "constructor":
        m = _CONSTRUCTOR_RE.search(source)
    else:
        m = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", source)

    if not m:
        raise ValueError(f"modifier_expand_v1: function {fn_name} not found")

    body_open = source.find("{", m.end())
    if body_open < 0:
        raise ValueError(f"modifier_expand_v1: cannot find body open brace for {fn_name}")

    depth = 0
    j = body_open
    while j < len(source):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return m.start(), body_open, j + 1, body_open
        j += 1

    raise ValueError(f"modifier_expand_v1: cannot match braces for {fn_name}")


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


def _split_top_level_csv(s: str) -> List[str]:
    parts: List[str] = []
    cur: List[str] = []
    depth_paren = 0
    depth_brack = 0
    depth_brace = 0
    in_str = False
    quote = ""
    i = 0

    while i < len(s):
        ch = s[i]
        if in_str:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if ch == quote:
                in_str = False
                quote = ""
            i += 1
            continue

        if ch in ("'", '"'):
            in_str = True
            quote = ch
            cur.append(ch)
            i += 1
            continue

        if ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren -= 1
        elif ch == "[":
            depth_brack += 1
        elif ch == "]":
            depth_brack -= 1
        elif ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace -= 1
        elif ch == "," and depth_paren == 0 and depth_brack == 0 and depth_brace == 0:
            parts.append("".join(cur).strip())
            cur = []
            i += 1
            continue

        cur.append(ch)
        i += 1

    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _find_matching_paren(s: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    in_str = False
    quote = ""

    while i < len(s):
        ch = s[i]
        if in_str:
            if ch == "\\" and i + 1 < len(s):
                i += 2
                continue
            if ch == quote:
                in_str = False
                quote = ""
            i += 1
            continue

        if ch in ("'", '"'):
            in_str = True
            quote = ch
            i += 1
            continue

        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1

    return -1


def _extract_modifier_defs(contract_text: str) -> Dict[str, Dict[str, Any]]:
    defs: Dict[str, Dict[str, Any]] = {}

    for m in _MODIFIER_DEF_RE.finditer(contract_text):
        name = m.group("name").strip()
        params_raw = (m.group("params") or "").strip()
        body_open = contract_text.find("{", m.end())
        if body_open < 0:
            continue

        depth = 0
        j = body_open
        while j < len(contract_text):
            c = contract_text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    body_close = j + 1
                    defs[name] = {
                        "name": name,
                        "params_raw": params_raw,
                        "params": _parse_modifier_params(params_raw),
                        "sig_start": m.start(),
                        "body_open": body_open,
                        "body_close": body_close,
                        "body_text": contract_text[body_open:body_close],
                        "body_inner": contract_text[body_open + 1:body_close - 1],
                    }
                    break
            j += 1

    return defs


def _parse_modifier_params(params_raw: str) -> List[str]:
    if not params_raw.strip():
        return []

    out: List[str] = []
    for piece in _split_top_level_csv(params_raw):
        piece = piece.strip()
        if not piece:
            continue
        toks = piece.split()
        if not toks:
            continue
        name = toks[-1].strip()
        name = name.replace(",", "").strip()
        if re.match(r"^[A-Za-z_]\w*$", name):
            out.append(name)
    return out


def _remove_comments_from_header_for_scan(s: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", lambda m: " " * (m.end() - m.start()), s, flags=re.DOTALL)


def _extract_function_header_parts(signature_text: str, fn_name: str) -> Dict[str, Any]:
    """
    Parse the function header region (everything before '{') and identify:
    - param close
    - returns clause range if present
    - modifiers segment between attributes and returns
    """
    scan = _remove_comments_from_header_for_scan(signature_text)

    if fn_name == "constructor":
        anchor = re.search(r"\bconstructor\s*\(", scan)
    else:
        anchor = re.search(rf"\bfunction\s+{re.escape(fn_name)}\s*\(", scan)

    if not anchor:
        raise ValueError(f"modifier_expand_v1: cannot parse function header for {fn_name}")

    paren_open = scan.find("(", anchor.end() - 1)
    if paren_open < 0:
        raise ValueError(f"modifier_expand_v1: cannot find parameter '(' for {fn_name}")

    paren_close = _find_matching_paren(scan, paren_open)
    if paren_close < 0:
        raise ValueError(f"modifier_expand_v1: cannot match parameter ')' for {fn_name}")

    after_params = scan[paren_close + 1:]
    returns_m = re.search(r"\breturns\s*\(", after_params)
    returns_abs_start = -1
    returns_abs_end = -1

    if returns_m:
        returns_abs_start = paren_close + 1 + returns_m.start()
        ret_open = scan.find("(", returns_abs_start)
        ret_close = _find_matching_paren(scan, ret_open)
        if ret_close < 0:
            raise ValueError(f"modifier_expand_v1: cannot match returns ')' for {fn_name}")
        returns_abs_end = ret_close + 1

    attrs_start = paren_close + 1
    attrs_end = returns_abs_start if returns_abs_start >= 0 else len(signature_text)

    return {
        "params_open": paren_open,
        "params_close": paren_close,
        "attrs_start": attrs_start,
        "attrs_end": attrs_end,
        "returns_start": returns_abs_start,
        "returns_end": returns_abs_end,
        "attrs_text": signature_text[attrs_start:attrs_end],
    }


def _find_modifier_invocations_in_header(
    attrs_text: str,
    modifier_defs: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Find modifier invocations in the attributes part of a function header.

    Supports:
      onlyOwner
      gate(x, y)

    Excludes well-known non-modifier keywords.
    """
    out: List[Dict[str, Any]] = []
    if not attrs_text.strip():
        return out

    reserved = {
        "public", "private", "internal", "external",
        "view", "pure", "payable", "virtual", "override",
        "returns", "memory", "calldata", "storage",
    }

    scan = _remove_comments_from_header_for_scan(attrs_text)
    i = 0
    n = len(scan)

    while i < n:
        m = re.search(r"\b([A-Za-z_]\w*)\b", scan[i:])
        if not m:
            break

        start = i + m.start()
        end = i + m.end()
        tok = m.group(1)

        if tok in reserved or tok not in modifier_defs:
            i = end
            continue

        j = end
        while j < n and scan[j].isspace():
            j += 1

        args_text = ""
        end_pos = j
        if j < n and scan[j] == "(":
            close = _find_matching_paren(scan, j)
            if close < 0:
                i = end
                continue
            args_text = attrs_text[j + 1:close]
            end_pos = close + 1

        out.append(
            {
                "name": tok,
                "start": start,
                "end": end_pos,
                "args_raw": args_text,
                "args": _split_top_level_csv(args_text) if args_text.strip() else [],
            }
        )
        i = end_pos

    return out


def _modifier_body_supported(body_inner: str) -> Tuple[bool, str]:
    masked = _strip_strings_and_comments_keep_len(body_inner)

    placeholder_count = len(re.findall(r"(?<![A-Za-z0-9_])_(?![A-Za-z0-9_])", masked))
    if placeholder_count != 1:
        return False, f"modifier placeholder count is {placeholder_count}, expected 1"

    if re.search(r"\bfor\b|\bwhile\b|\bdo\b", masked):
        return False, "loop present in modifier body"

    if re.search(r"\bif\b|\belse\b", masked):
        return False, "branch present in modifier body"

    if re.search(r"\bassembly\b", masked):
        return False, "assembly present in modifier body"

    if re.search(r"\btry\b|\bcatch\b", masked):
        return False, "try/catch present in modifier body"

    if re.search(r"\bemit\b", masked):
        return False, "emit present in modifier body"

    if re.search(r"\breturn\b", masked):
        return False, "return present in modifier body"

    if re.search(r"\bmodifier\b", masked):
        return False, "nested modifier definition pattern present"

    # Conservative external/member-call-like blocker.
    if re.search(r"\b[A-Za-z_]\w*\s*\.\s*[A-Za-z_]\w*\s*\(", masked):
        return False, "member call pattern present"

    ph = re.search(r"(?<![A-Za-z0-9_])_(?![A-Za-z0-9_])", masked)
    if not ph:
        return False, "modifier placeholder missing after re-scan"

    prefix = masked[:ph.start()]
    suffix = masked[ph.end():]
    if suffix.strip().strip(";"):
        return False, "statements after placeholder are present"

    if not prefix.strip():
        return False, "empty prelude before placeholder"

    return True, "ok"


def _substitute_modifier_params(prelude: str, param_names: List[str], arg_exprs: List[str]) -> Tuple[str, Dict[str, str]]:
    if len(param_names) != len(arg_exprs):
        raise ValueError(
            f"modifier_expand_v1: parameter/argument count mismatch "
            f"({len(param_names)} params vs {len(arg_exprs)} args)"
        )

    out = prelude
    mapping: Dict[str, str] = {}
    for name, expr in zip(param_names, arg_exprs):
        expr_clean = expr.strip()
        mapping[name] = expr_clean
        out = re.sub(rf"\b{re.escape(name)}\b", f"({expr_clean})", out)

    return out, mapping


def _extract_modifier_prelude(body_inner: str) -> str:
    masked = _strip_strings_and_comments_keep_len(body_inner)
    ph = re.search(r"(?<![A-Za-z0-9_])_(?![A-Za-z0-9_])", masked)
    if not ph:
        raise ValueError("modifier_expand_v1: placeholder '_' not found in modifier body")
    prelude = body_inner[:ph.start()]
    # Drop trailing semicolons and surrounding blank space, then normalize ending.
    prelude = prelude.rstrip()
    if prelude.endswith(";"):
        prelude = prelude.rstrip(";").rstrip()
    return prelude


def _indent_of_line_at(src: str, pos: int) -> str:
    line_start = src.rfind("\n", 0, pos)
    line_start = 0 if line_start < 0 else line_start + 1
    i = line_start
    while i < len(src) and src[i] in (" ", "\t"):
        i += 1
    return src[line_start:i]


def _indent_block(block: str, indent: str) -> str:
    lines = block.splitlines()
    if not lines:
        return indent

    out: List[str] = []
    for line in lines:
        stripped = line.rstrip()
        if stripped:
            out.append(indent + stripped)
        else:
            out.append("")
    return "\n".join(out)


def _remove_modifier_invocations_from_attrs(attrs_text: str, invocations: List[Dict[str, Any]]) -> str:
    if not invocations:
        return attrs_text

    out: List[str] = []
    last = 0
    for inv in sorted(invocations, key=lambda x: x["start"]):
        out.append(attrs_text[last:inv["start"]])
        last = inv["end"]
    out.append(attrs_text[last:])

    # Normalize whitespace but keep overall header readable.
    cleaned = "".join(out)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\s+\n", "\n", cleaned)
    return cleaned


def _splice_function_header_remove_modifiers(
    signature_text: str,
    fn_name: str,
    modifier_defs: Dict[str, Dict[str, Any]],
) -> Tuple[str, List[Dict[str, Any]], Optional[str]]:
    parts = _extract_function_header_parts(signature_text, fn_name)
    attrs_text = parts["attrs_text"]
    invocations = _find_modifier_invocations_in_header(attrs_text, modifier_defs)

    if not invocations:
        return signature_text, [], "no supported modifier invocation found in header"

    cleaned_attrs = _remove_modifier_invocations_from_attrs(attrs_text, invocations)

    new_sig = (
        signature_text[:parts["attrs_start"]]
        + cleaned_attrs
        + signature_text[parts["attrs_end"]:]
    )

    new_sig = re.sub(r"[ \t]+\{?$", lambda m: " " if "{" not in m.group(0) else m.group(0), new_sig)
    new_sig = re.sub(r"\s+\s", " ", new_sig)
    new_sig = re.sub(r"\)\s+returns", ") returns", new_sig)
    new_sig = re.sub(r"\)\s+\{", ") {", new_sig)
    new_sig = re.sub(r"\s+\{", " {", new_sig)

    return new_sig, invocations, None


def apply_modifier_expand_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    allow_multiple_modifiers: bool = False,
    **_: Any,
) -> TransformResult:
    """
    Conservative Solidity modifier expansion.

    What it does:
      - finds the target function header
      - detects simple modifier invocations in that header
      - resolves the corresponding modifier definition(s)
      - inlines the modifier prelude before the function body
      - removes the expanded modifier invocation(s) from the function header

    Supported modifier shape in v1:
      - exactly one `_`
      - straight-line statements before `_`
      - no statements after `_`
      - no loops / if / else / try / catch / assembly / emit / return
      - no member-call-like patterns
      - parameter substitution is token-based

    Safety / scope:
      - default: expands exactly one modifier only
      - skips stacked modifiers unless allow_multiple_modifiers=True
      - only works inside one target contract
      - best-effort lexical transform only
    """
    _ = seed  # reserved for future diversification

    contract_start, contract_open, contract_close = _find_contract_span(source, contract_name)
    contract_text = source[contract_start:contract_close]

    modifier_defs = _extract_modifier_defs(contract_text)
    if not modifier_defs:
        return TransformResult(
            new_source=source,
            details={"note": "modifier_expand_v1 skipped: no modifier definitions found", "expanded": []},
        )

    sig_start, body_open, body_close, sig_end = _find_function_span(source, fn_name)
    signature_text = source[sig_start:sig_end]
    body_text = source[body_open:body_close]
    body_inner = body_text[1:-1]

    new_signature_text, invocations, reason = _splice_function_header_remove_modifiers(
        signature_text=signature_text,
        fn_name=fn_name,
        modifier_defs=modifier_defs,
    )
    if not invocations:
        return TransformResult(
            new_source=source,
            details={"note": f"modifier_expand_v1 skipped: {reason or 'no matching modifier'}", "expanded": []},
        )

    if len(invocations) > 1 and not allow_multiple_modifiers:
        return TransformResult(
            new_source=source,
            details={
                "note": "modifier_expand_v1 skipped: multiple modifiers present; allow_multiple_modifiers=False",
                "expanded": [],
            },
        )

    selected_invocations = invocations if allow_multiple_modifiers else [invocations[0]]

    prelude_blocks: List[str] = []
    expanded_details: List[Dict[str, Any]] = []

    for inv in selected_invocations:
        mod_def = modifier_defs.get(inv["name"])
        if not mod_def:
            return TransformResult(
                new_source=source,
                details={
                    "note": f"modifier_expand_v1 skipped: definition for modifier {inv['name']} not found",
                    "expanded": [],
                },
            )

        ok, why = _modifier_body_supported(mod_def["body_inner"])
        if not ok:
            return TransformResult(
                new_source=source,
                details={
                    "note": f"modifier_expand_v1 skipped: modifier {inv['name']} unsupported: {why}",
                    "expanded": [],
                },
            )

        prelude = _extract_modifier_prelude(mod_def["body_inner"])
        try:
            substituted, param_map = _substitute_modifier_params(
                prelude=prelude,
                param_names=mod_def["params"],
                arg_exprs=inv["args"],
            )
        except Exception as e:
            return TransformResult(
                new_source=source,
                details={
                    "note": f"modifier_expand_v1 skipped: modifier {inv['name']} parameter substitution failed: {e}",
                    "expanded": [],
                },
            )

        prelude_blocks.append(substituted)
        expanded_details.append(
            {
                "modifier": inv["name"],
                "args": inv["args"],
                "param_names": mod_def["params"],
                "param_bindings": param_map,
            }
        )

    body_indent = _indent_of_line_at(source, body_open)
    stmt_indent = body_indent + "    "

    rendered_blocks: List[str] = []
    for block in prelude_blocks:
        rendered_blocks.append(_indent_block(block, stmt_indent).rstrip())

    injected_prefix = "\n".join(b for b in rendered_blocks if b.strip())
    existing_body = body_inner.strip("\n")

    if injected_prefix.strip():
        if existing_body.strip():
            new_body_inner = "\n" + injected_prefix + "\n" + existing_body + "\n" + body_indent
        else:
            new_body_inner = "\n" + injected_prefix + "\n" + body_indent
    else:
        new_body_inner = body_inner

    new_body_text = "{" + new_body_inner + "}"

    new_source = (
        source[:sig_start]
        + new_signature_text
        + source[sig_end:body_open]
        + new_body_text
        + source[body_close:]
    )

    return TransformResult(
        new_source=new_source,
        details={
            "note": "modifier_expand_v1 applied",
            "expanded_count": len(expanded_details),
            "expanded": expanded_details,
            "allow_multiple_modifiers": bool(allow_multiple_modifiers),
        },
    )