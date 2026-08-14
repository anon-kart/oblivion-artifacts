from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Set
import re


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


# Simple scalar/reference-lite local declarations only.
# Examples matched:
#   uint256 x = 7;
#   bool ok = a > b;
#   address who = msg.sender;
#   string memory s = name;
#   bytes memory b = data;
#
# Intentionally NOT matched:
#   uint256 a = 1, b = 2;
#   mapping(...)
#   uint256[] memory xs = ...
#   Foo storage f = ...
#   (uint a, uint b) = ...
_SIMPLE_LOCAL_RE = re.compile(
    r"(?P<indent>^[ \t]*)"
    r"(?P<typ>"
    r"uint(?:8|16|32|64|128|256)?|"
    r"int(?:8|16|32|64|128|256)?|"
    r"bool|"
    r"address(?:\s+payable)?|"
    r"string|"
    r"bytes(?:[1-9]|1[0-9]|2[0-9]|3[0-2])?|"
    r"bytes"
    r")"
    r"(?:\s+(?P<loc>memory|calldata|storage))?"
    r"\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]+);",
    re.MULTILINE,
)

_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_]\w*\b")
_EXTERNAL_CALL_RE = re.compile(
    r"\.\s*call\b|\.\s*delegatecall\b|\.\s*staticcall\b|interface\s+[A-Za-z_]\w*",
    re.I,
)


def _find_contract_span(source: str, contract_name: str) -> Tuple[int, int, int]:
    """
    Returns (contract_start, contract_open_brace, contract_close_exclusive)
    """
    m = re.search(rf"\bcontract\s+{re.escape(contract_name)}\b", source)
    if not m:
        raise ValueError(f"local_to_state_lift_v1: contract {contract_name} not found")

    brace_open = source.find("{", m.end())
    if brace_open < 0:
        raise ValueError("local_to_state_lift_v1: cannot find contract body open brace")

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

    raise ValueError("local_to_state_lift_v1: cannot match contract braces")


def _find_function_span(source: str, fn_name: str) -> Tuple[int, int, int, int]:
    """
    Returns (sig_start, body_open, body_close_exclusive, sig_end)
    where sig_end == body_open.
    """
    if fn_name == "constructor":
        m = re.search(r"\bconstructor\s*\(", source)
    else:
        m = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", source)

    if not m:
        raise ValueError(f"local_to_state_lift_v1: function {fn_name} not found")

    body_open = source.find("{", m.end())
    if body_open < 0:
        raise ValueError(f"local_to_state_lift_v1: cannot find body open brace for {fn_name}")

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

    raise ValueError(f"local_to_state_lift_v1: cannot match braces for {fn_name}")


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
    """
    Replace identifier token `old` with `new` only outside strings/comments.
    Best-effort lexical replacement with aligned masking.
    """
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


def _contains_disqualifying_patterns(fn_body_inner: str) -> Optional[str]:
    s = fn_body_inner
    sl = s.lower()

    if re.search(r"\bassembly\b", sl):
        return "assembly present"
    if re.search(r"\btry\b|\bcatch\b", sl):
        return "try/catch present"
    if _EXTERNAL_CALL_RE.search(s):
        return "external-call-like pattern present"
    # Conservative: block obvious member-call patterns. Plain property access like
    # numbers.length is fine; only `.foo(`-style invocation is blocked here.
    if re.search(r"\b[A-Za-z_]\w*\s*\.\s*[A-Za-z_]\w*\s*\(", s):
        return "member call pattern present"

    return None


def _extract_named_return_vars(signature_text: str) -> Set[str]:
    """
    Best-effort parser for:
      returns (uint256 x, bool ok, bytes32)
    We only care about named returns, not anonymous ones.
    """
    out: Set[str] = set()
    sig = signature_text

    m = re.search(r"\breturns\s*\((.*?)\)", sig, flags=re.DOTALL)
    if not m:
        return out

    payload = m.group(1).strip()
    if not payload:
        return out

    parts: List[str] = []
    cur: List[str] = []
    depth = 0
    for ch in payload:
        if ch == "," and depth == 0:
            piece = "".join(cur).strip()
            if piece:
                parts.append(piece)
            cur = []
            continue
        if ch in "([{" :
            depth += 1
        elif ch in ")]}":
            depth -= 1
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)

    for part in parts:
        toks = [t for t in part.strip().split() if t]
        if len(toks) >= 2:
            cand = toks[-1].strip()
            if re.match(r"^[A-Za-z_]\w*$", cand):
                out.add(cand)

    return out


def _build_local_meta_map(local_decl_meta: Optional[List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(local_decl_meta, list):
        return out
    for item in local_decl_meta:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "")
        if not name:
            continue
        out[name] = item
    return out


def _make_unique_state_name(source: str, fn_name: str, local_name: str, ordinal: int) -> str:
    base = f"__obf_g_{fn_name}_{local_name}_{ordinal}"
    candidate = base
    k = 0
    while re.search(rf"\b{re.escape(candidate)}\b", source):
        k += 1
        candidate = f"{base}_{k}"
    return candidate

def _inject_state_decls(source: str, contract_name: str, decl_lines: List[str]) -> Tuple[str, bool]:
    if not decl_lines:
        return source, False

    banner = "// --- OBLIVION local->state lifted vars (generated) ---"

    # Guard against duplicate helper/banner insertion across repeated runs.
    if banner in source:
        return source, False

    _, brace_open, _ = _find_contract_span(source, contract_name)
    insert_at = brace_open + 1

    blob = "\n    " + banner + "\n"
    blob += "\n".join(decl_lines) + "\n"

    new_source = source[:insert_at] + blob + source[insert_at:]
    return new_source, True

def apply_local_to_state_lift_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    max_locals: int = 2,
    skip_view: bool = True,
    skip_pure: bool = True,
    local_decl_meta: Optional[List[Dict[str, Any]]] = None,
    **_: Any,
) -> TransformResult:
    """
    Conservative BiAn-style local -> state lifting.

    What it does:
      - inside one target function, find simple local declarations:
            T x = expr;
      - inject contract-level private state vars:
            T __obf_g_<fn>_<x>_<n>;
      - replace declaration with:
            __obf_g_<...> = expr;
      - replace later uses of x with __obf_g_<...>

    Safety / scope:
      - simple scalar-ish types only
      - skips pure/view by default
      - skips functions containing assembly / try-catch / external/member-call patterns
      - skips only unsafe locals, not the whole function
      - skips named return variables
      - skips calldata/storage/reference locals via IR metadata when provided
      - best-effort lexical rewrite only
    """
    _ = seed  # reserved for future naming diversification

    if int(max_locals) <= 0:
        return TransformResult(
            new_source=source,
            details={"note": "local_to_state_lift_v1 skipped: max_locals <= 0", "lifted": []},
        )

    sig_start, body_open, body_close, sig_end = _find_function_span(source, fn_name)
    signature_text = source[sig_start:sig_end]
    body_text = source[body_open:body_close]
    body_inner = body_text[1:-1]

    sig_l = " " + signature_text.lower() + " "

    if skip_pure and " pure " in sig_l:
        return TransformResult(
            new_source=source,
            details={"note": "local_to_state_lift_v1 skipped: pure function", "lifted": []},
        )

    if skip_view and " view " in sig_l:
        return TransformResult(
            new_source=source,
            details={"note": "local_to_state_lift_v1 skipped: view function", "lifted": []},
        )

    disq = _contains_disqualifying_patterns(body_inner)
    if disq:
        return TransformResult(
            new_source=source,
            details={"note": f"local_to_state_lift_v1 skipped: {disq}", "lifted": []},
        )

    named_return_vars = _extract_named_return_vars(signature_text)
    local_meta_map = _build_local_meta_map(local_decl_meta)

    current_body_inner = body_inner
    lifted: List[Dict[str, Any]] = []
    decl_lines: List[str] = []

    # Re-scan after each accepted lift so indices remain valid.
    while len(lifted) < int(max_locals):
        masked = _strip_strings_and_comments_keep_len(current_body_inner)
        m = _SIMPLE_LOCAL_RE.search(masked)
        if not m:
            break

        indent = m.group("indent")
        typ = m.group("typ").strip()
        loc = (m.group("loc") or "").strip()
        local_name = m.group("name").strip()
        expr = current_body_inner[m.start("expr"):m.end("expr")].strip()

        # Skip named return variables rather than skipping the whole function.
        if local_name in named_return_vars:
            current_body_inner = (
                current_body_inner[:m.start()] +
                (" " * (m.end() - m.start())) +
                current_body_inner[m.end():]
            )
            continue

        meta = local_meta_map.get(local_name) or {}

        # Skip IR-known unsafe declarations.
        if bool(meta.get("is_return_var")):
            current_body_inner = (
                current_body_inner[:m.start()] +
                (" " * (m.end() - m.start())) +
                current_body_inner[m.end():]
            )
            continue

        storage_loc_meta = str(meta.get("storage_location", "") or "")
        if storage_loc_meta in ("calldata", "storage"):
            current_body_inner = (
                current_body_inner[:m.start()] +
                (" " * (m.end() - m.start())) +
                current_body_inner[m.end():]
            )
            continue

        if bool(meta.get("is_reference_type")):
            current_body_inner = (
                current_body_inner[:m.start()] +
                (" " * (m.end() - m.start())) +
                current_body_inner[m.end():]
            )
            continue

        # Skip obviously unsafe/self-referential declarations.
        if re.search(rf"\b{re.escape(local_name)}\b", expr):
            current_body_inner = (
                current_body_inner[:m.start()] +
                (" " * (m.end() - m.start())) +
                current_body_inner[m.end():]
            )
            continue

        # Skip calldata/storage locals if not already blocked via metadata.
        if loc in ("calldata", "storage"):
            current_body_inner = (
                current_body_inner[:m.start()] +
                (" " * (m.end() - m.start())) +
                current_body_inner[m.end():]
            )
            continue

        state_type = typ
        if loc == "memory" and typ in ("string", "bytes"):
            # Still keep state declaration as plain string/bytes if we decide to lift.
            # In practice, IR metadata usually marks these as reference-typed and blocks them.
            state_type = typ

        state_name = _make_unique_state_name(source, fn_name, local_name, len(lifted))
        decl_lines.append(f"    {state_type} private {state_name};")

        # Replace declaration with assignment to state var.
        replacement_decl = f"{indent}{state_name} = {expr};"
        before_decl = current_body_inner[:m.start()]
        after_decl = current_body_inner[m.end():]

        # Replace later uses only in the suffix after declaration.
        rewritten_suffix, replaced_uses = _replace_identifier_outside_strings_comments(
            after_decl,
            local_name,
            state_name,
        )

        current_body_inner = before_decl + replacement_decl + rewritten_suffix

        lifted.append(
            {
                "local": local_name,
                "state_var": state_name,
                "type": state_type,
                "initializer": expr,
                "uses_rewritten": replaced_uses,
            }
        )

    if not lifted:
        return TransformResult(
            new_source=source,
            details={
                "note": "local_to_state_lift_v1: no eligible locals found",
                "named_return_vars": sorted(named_return_vars),
                "lifted": [],
            },
        )

    # Inject state declarations first, then rewrite the target function body on the updated source.
    new_source, injected = _inject_state_decls(source, contract_name, decl_lines)

    # Because contract source changed, re-find function span before replacing body.
    _, new_body_open, new_body_close, _ = _find_function_span(new_source, fn_name)
    new_body_text = "{" + current_body_inner + "}"
    new_source = new_source[:new_body_open] + new_body_text + new_source[new_body_close:]

    return TransformResult(
        new_source=new_source,
        details={
            "note": "local_to_state_lift_v1 applied",
            "injected_state_decls": injected,
            "lifted_count": len(lifted),
            "named_return_vars": sorted(named_return_vars),
            "lifted": lifted,
        },
    )