from __future__ import annotations

from dataclasses import dataclass
import random
import re
from typing import Any, Dict, List, Tuple


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


_INT_LIT_RE = re.compile(r"\b\d+\b")
_BOOL_LIT_RE = re.compile(r"\b(?:true|false)\b")
_STRING_LIT_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_HEX_STR_LIT_RE = re.compile(r'hex"(?:[0-9a-fA-F]{2})*"')
_HEX_BYTES_LIT_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")

# IMPORTANT:
# Do not globally skip 0 and 1 anymore.
# Bian-style obfuscation benefits a lot from replacing 0/1/10/18.
# 0 and 1 are now blocked only in sensitive require/assert/revert/auth-like contexts.
_SKIP_INT_VALUES = {32, 255}


def _find_contract_span(source: str, contract_name: str) -> Tuple[int, int, int]:
    """
    Returns (contract_start, contract_open_brace, contract_close_exclusive)
    """
    needle = f"contract {contract_name}"
    i = source.find(needle)
    if i < 0:
        raise ValueError(f"dynamic_constants_v1: contract {contract_name} not found")

    brace_open = source.find("{", i)
    if brace_open < 0:
        raise ValueError("dynamic_constants_v1: cannot find contract body open brace")

    depth = 0
    j = brace_open
    while j < len(source):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i, brace_open, j + 1
        j += 1
    raise ValueError("dynamic_constants_v1: cannot match contract braces")


def _find_function_span(source: str, fn_name: str) -> Tuple[int, int]:
    needle = f"function {fn_name}"
    i = source.find(needle)
    if i < 0:
        needle2 = f"function\n{fn_name}"
        i = source.find(needle2)
    if i < 0:
        raise ValueError(f"dynamic_constants_v1: function {fn_name} not found")

    brace_open = source.find("{", i)
    if brace_open < 0:
        raise ValueError(f"dynamic_constants_v1: cannot find body open brace for {fn_name}")

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

    raise ValueError(f"dynamic_constants_v1: cannot match braces for {fn_name}")


def _strip_comments_keep_strings_len(s: str) -> str:
    """
    Replace comments with spaces, but keep strings intact.
    Needed because we want to detect string/hex literals too.
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
            if ch == "\\" and i + 1 < n:
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
            in_str = True
            quote = ch
            i += 1
            continue

        i += 1

    return "".join(out)


def _collect_literal_spans(masked: str) -> List[Tuple[int, int]]:
    spans: List[Tuple[int, int]] = []
    for rx in (_STRING_LIT_RE, _HEX_STR_LIT_RE, _HEX_BYTES_LIT_RE):
        for m in rx.finditer(masked):
            spans.append((m.start(), m.end()))
    spans.sort()
    return spans


def _inject_helpers_if_missing(source: str, contract_name: str, helper_blob: str) -> Tuple[str, bool]:
    """
    Insert helper_blob near top of contract body if not already present.
    """
    _, brace_open, _ = _find_contract_span(source, contract_name)

    already_present = (
        "function __obf_u(" in source
        or "function __obf_b(" in source
        or "function __obf_s(" in source
        or "function __obf_x(" in source
    )
    if already_present:
        return source, False

    insert_at = brace_open + 1
    new_source = source[:insert_at] + "\n" + helper_blob + "\n" + source[insert_at:]
    return new_source, True


def _sol_string_literal(py_decoded: str) -> str:
    escaped = py_decoded.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{escaped}"'


def _normalize_hex_payload(raw: str) -> str:
    if raw.startswith('hex"') and raw.endswith('"'):
        return raw[4:-1]
    if raw.startswith("0x") or raw.startswith("0X"):
        return raw[2:]
    return raw


def _build_obf_u_helper(pool: List[int]) -> str:
    lines: List[str] = []
    lines.append("    // --- OBLIVION dynamic constant pools (generated) ---")
    lines.append("    function __obf_u(uint256 i) internal pure returns (uint256) {")
    if not pool:
        lines.append("        return 0;")
        lines.append("    }")
        return "\n".join(lines) + "\n"

    lines.append(f"        if (i == 0) return uint256({pool[0]});")
    for idx, val in enumerate(pool[1:], start=1):
        lines.append(f"        else if (i == {idx}) return uint256({val});")
    lines.append("        return 0;")
    lines.append("    }")
    return "\n".join(lines) + "\n"


def _build_obf_b_helper(pool: List[bool]) -> str:
    lines: List[str] = []
    lines.append("    function __obf_b(uint256 i) internal pure returns (bool) {")
    if not pool:
        lines.append("        return false;")
        lines.append("    }")
        return "\n".join(lines) + "\n"

    first = "true" if pool[0] else "false"
    lines.append(f"        if (i == 0) return {first};")
    for idx, val in enumerate(pool[1:], start=1):
        lit = "true" if val else "false"
        lines.append(f"        else if (i == {idx}) return {lit};")
    lines.append("        return false;")
    lines.append("    }")
    return "\n".join(lines) + "\n"


def _build_obf_s_helper(pool: List[str]) -> str:
    lines: List[str] = []
    lines.append("    function __obf_s(uint256 i) internal pure returns (string memory) {")
    if not pool:
        lines.append('        return "";')
        lines.append("    }")
        return "\n".join(lines) + "\n"

    lines.append(f"        if (i == 0) return {_sol_string_literal(pool[0])};")
    for idx, val in enumerate(pool[1:], start=1):
        lines.append(f"        else if (i == {idx}) return {_sol_string_literal(val)};")
    lines.append('        return "";')
    lines.append("    }")
    return "\n".join(lines) + "\n"


def _build_obf_x_helper(pool: List[str]) -> str:
    lines: List[str] = []
    lines.append("    function __obf_x(uint256 i) internal pure returns (bytes memory) {")
    if not pool:
        lines.append('        return hex"";')
        lines.append("    }")
        return "\n".join(lines) + "\n"

    lines.append(f'        if (i == 0) return hex"{pool[0]}";')
    for idx, val in enumerate(pool[1:], start=1):
        lines.append(f'        else if (i == {idx}) return hex"{val}";')
    lines.append('        return hex"";')
    lines.append("    }")
    return "\n".join(lines) + "\n"


def _build_helper_blob(
    *,
    int_pool: List[int],
    bool_pool: List[bool],
    string_pool: List[str],
    hex_pool: List[str],
) -> str:
    blobs: List[str] = []
    blobs.append(_build_obf_u_helper(int_pool))
    blobs.append(_build_obf_b_helper(bool_pool))
    blobs.append(_build_obf_s_helper(string_pool))
    blobs.append(_build_obf_x_helper(hex_pool))
    return "\n".join(blobs).rstrip() + "\n"


def _find_blocked_spans(masked: str, avoid_in_require: bool) -> List[Tuple[int, int]]:
    blocked_spans: List[Tuple[int, int]] = []
    if not avoid_in_require:
        return blocked_spans

    for kw in ("require", "assert", "revert"):
        start = 0
        while True:
            k = masked.find(kw + "(", start)
            if k < 0:
                break
            p = k + len(kw)
            if p >= len(masked) or masked[p] != "(":
                start = k + 1
                continue
            depth = 0
            j = p
            while j < len(masked):
                if masked[j] == "(":
                    depth += 1
                elif masked[j] == ")":
                    depth -= 1
                    if depth == 0:
                        blocked_spans.append((k, j + 1))
                        break
                j += 1
            start = k + 1
    return blocked_spans


def _is_blocked(idx: int, blocked_spans: List[Tuple[int, int]]) -> bool:
    for a, b in blocked_spans:
        if a <= idx < b:
            return True
    return False


def _line_bounds(text: str, idx: int) -> Tuple[int, int]:
    a = text.rfind("\n", 0, idx)
    b = text.find("\n", idx)
    if a < 0:
        a = 0
    else:
        a += 1
    if b < 0:
        b = len(text)
    return a, b


def _context_window(text: str, start: int, end: int, radius: int = 48) -> str:
    a = max(0, start - radius)
    b = min(len(text), end + radius)
    return text[a:b]


def _in_generated_helper_call_context(masked: str, start: int, end: int, radius: int = 24) -> bool:
    ctx = _context_window(masked, start, end, radius=radius)
    return (
        "__obf_u(" in ctx
        or "__obf_b(" in ctx
        or "__obf_s(" in ctx
        or "__obf_x(" in ctx
    )


def _should_skip_int_literal(masked: str, start: int, end: int, raw: str) -> bool:
    try:
        v = int(raw)
    except Exception:
        return True

    if v in _SKIP_INT_VALUES:
        return True

    if _in_generated_helper_call_context(masked, start, end):
        return True

    line_a, line_b = _line_bounds(masked, start)
    line = masked[line_a:line_b]
    ctx = _context_window(masked, start, end)

    if "pragma solidity" in line:
        return True

    if re.search(r"\bfor\s*\(", line):
        if ";" in line:
            return True

    if re.search(r"\bwhile\s*\(", line):
        return True

    if re.search(r"\.\s*length\b", ctx) and re.search(r"\[[^\]]*\b" + re.escape(raw) + r"\b[^\]]*\]", ctx):
        return True

    if "[" in ctx and "]" in ctx:
        if re.search(r"\[[^\]]*\b" + re.escape(raw) + r"\b[^\]]*\]", ctx):
            return True

    if re.search(r"\bemit\b", line):
        return True

    # Do not rewrite 0/1 in direct comparison contexts.
    # This protects auth-like and guard-like expressions such as:
    #   wards[msg.sender] == 1
    #   live == 1
    #   permitted == 0
    if v in {0, 1}:
        if re.search(r"(==|!=|<=|>=|<|>)\s*" + re.escape(raw), ctx):
            return True
        if re.search(re.escape(raw) + r"\s*(==|!=|<=|>=|<|>)", ctx):
            return True

    # Do not rewrite literals that are operands of exponentiation `**`.
    #
    # The __obf_u(i) helper returns 0 on any index it does not know about
    # (its fallthrough is `return 0;`). Exponent arithmetic has no headroom
    # for that: an expression like `10 ** (18 - dec)` rewritten to
    # `__obf_u(0) ** (__obf_u(1) - dec)` underflows to a 0x11 panic the moment
    # any referenced index is missing from the live helper (e.g. when a
    # per-function helper from an earlier function shadows this one). Encoding
    # `**` operands is therefore never worth the risk; skip both the base and
    # the exponent literal. The exact byte span of the `raw` match is checked
    # against `**` on either immediate side (whitespace/parens tolerated).
    left = masked[max(0, start - 6):start]
    right = masked[end:end + 6]
    if re.search(r"\*\*\s*\(?\s*$", left) or re.search(r"^\s*\)?\s*\*\*", right):
        return True
    # Also catch the exponent inside a parenthesized group: `** ( 18 - dec )`.
    # Look a little further left for an unmatched `(` that is itself preceded
    # by `**`, which is the common `base ** (a - b)` scaling idiom.
    near_left = masked[max(0, start - 24):start]
    if re.search(r"\*\*\s*\([^)]*$", near_left):
        return True

    return False


def _should_skip_bool_literal(masked: str, start: int, end: int) -> bool:
    line_a, line_b = _line_bounds(masked, start)
    line = masked[line_a:line_b]
    ctx = _context_window(masked, start, end)

    if re.search(r"\b(?:require|assert|revert)\s*\(", ctx):
        return True

    if re.search(r"\breturn\s+(true|false)\s*;", line):
        return True

    return False


def _should_skip_string_literal(masked: str, start: int, end: int) -> bool:
    line_a, line_b = _line_bounds(masked, start)
    line = masked[line_a:line_b]
    ctx = _context_window(masked, start, end, radius=96)

    if re.search(r"\b(?:require|assert|revert)\s*\(", ctx):
        return True

    if "event" in line or "emit" in line:
        return True

    # Skip literals used in bytes32("...") / bytesN("...") style casts.
    left_ctx = masked[max(0, start - 64):start]
    if re.search(r"\bbytes(?:[1-9]|[12]\d|3[0-2])?\s*\(\s*$", left_ctx):
        return True

    return False


def _should_skip_hex_literal(masked: str, start: int, end: int) -> bool:
    line_a, line_b = _line_bounds(masked, start)
    line = masked[line_a:line_b]
    ctx = _context_window(masked, start, end, radius=96)

    if re.search(r"\b(?:require|assert|revert)\s*\(", ctx):
        return True

    if "[" in ctx and "]" in ctx:
        return True

    if "emit" in line:
        return True

    # Skip if used with bitwise/arithmetic operators, because __obf_x returns bytes memory.
    if re.search(r"[&|^~]|<<|>>", ctx):
        return True

    if re.search(r"[+\-*/%]", ctx):
        return True

    # Skip if inside explicit numeric/address/bytesN casts.
    left_ctx = masked[max(0, start - 64):start]
    if re.search(
        r"\b(?:uint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?|"
        r"int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?|"
        r"address|bytes(?:[1-9]|[12]\d|3[0-2]))\s*\(\s*$",
        left_ctx,
    ):
        return True

    return False


def apply_dynamic_constants_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    max_consts: int = 32,
    min_value: int = 0,
    avoid_in_require: bool = True,
    enable_bools: bool = True,
    enable_strings: bool = True,
    enable_hex_bytes: bool = True,
    max_string_consts: int = 16,
    max_hex_consts: int = 16,
    **_: Any,
) -> TransformResult:
    """
    Extended BiAn-style "static -> dynamic" constants, done conservatively:

      - collects literals in the target function body:
          * integer literals
          * bool literals
          * string literals
          * hex string / bytes literals
      - injects pure helpers into contract:
          * __obf_u(i) -> uint256
          * __obf_b(i) -> bool
          * __obf_s(i) -> string memory
          * __obf_x(i) -> bytes memory
      - replaces literals with helper calls

    Safety:
      - avoids literals inside require/assert/revert(...) spans by default
      - allows 0 and 1 outside blocked/guard-like contexts
      - does not touch comments
      - string/hex scanning is done with comments stripped but strings preserved

    Notes:
      - hex"abcd" is rewritten to __obf_x(i)
      - plain 0x... literals are intentionally skipped because __obf_x returns bytes memory
    """
    rnd = random.Random(int(seed))

    body_open, body_close = _find_function_span(source, fn_name)
    body = source[body_open:body_close]

    has_ints = bool(_INT_LIT_RE.search(body))
    has_bools = bool(_BOOL_LIT_RE.search(body))
    has_strings = bool(_STRING_LIT_RE.search(body))
    has_hex = bool(_HEX_STR_LIT_RE.search(body) or _HEX_BYTES_LIT_RE.search(body))

    if not (has_ints or has_bools or has_strings or has_hex):
        return TransformResult(
            new_source=source,
            details={
                "int_pool_size": 0,
                "bool_pool_size": 0,
                "string_pool_size": 0,
                "hex_pool_size": 0,
                "replacements": 0,
                "note": "dynamic_constants_v1: no eligible literals in target function",
            },
        )

    masked_comments_only = _strip_comments_keep_strings_len(body)
    blocked_spans = _find_blocked_spans(masked_comments_only, avoid_in_require)
    literal_spans = _collect_literal_spans(masked_comments_only)

    # Block numeric/bool rewrites inside string/hex literal spans.
    non_numeric_safe_blocked_spans = blocked_spans + literal_spans

    int_lits: List[int] = []
    bool_lits: List[bool] = []
    string_lits: List[str] = []
    hex_lits: List[str] = []

    # Collect integer literals
    for m in _INT_LIT_RE.finditer(masked_comments_only):
        if _is_blocked(m.start(), non_numeric_safe_blocked_spans):
            continue

        if _in_generated_helper_call_context(masked_comments_only, m.start(), m.end()):
            continue

        raw = m.group(0)

        if _should_skip_int_literal(masked_comments_only, m.start(), m.end(), raw):
            continue

        v = int(raw)

        if v < int(min_value):
            continue

        # Do not replace 0/1 inside require/assert/revert spans unless explicitly allowed.
        # This is the key safety rule for GemJoin-style auth/live/implementation guards.
        if v in (0, 1) and avoid_in_require and _is_blocked(m.start(), blocked_spans):
            continue

        int_lits.append(v)

    # Collect bool literals
    if enable_bools:
        for m in _BOOL_LIT_RE.finditer(masked_comments_only):
            if _is_blocked(m.start(), non_numeric_safe_blocked_spans):
                continue

            if _should_skip_bool_literal(masked_comments_only, m.start(), m.end()):
                continue

            v = m.group(0) == "true"
            bool_lits.append(v)

    # Collect string literals
    if enable_strings:
        for m in _STRING_LIT_RE.finditer(masked_comments_only):
            if _is_blocked(m.start(), blocked_spans):
                continue

            if _should_skip_string_literal(masked_comments_only, m.start(), m.end()):
                continue

            raw = m.group(0)
            try:
                decoded = bytes(raw[1:-1], "utf-8").decode("unicode_escape")
            except Exception:
                decoded = raw[1:-1]
            string_lits.append(decoded)

    # Collect hex literals
    if enable_hex_bytes:
        for m in _HEX_STR_LIT_RE.finditer(masked_comments_only):
            if _is_blocked(m.start(), blocked_spans):
                continue

            if _should_skip_hex_literal(masked_comments_only, m.start(), m.end()):
                continue

            hex_lits.append(_normalize_hex_payload(m.group(0)))

        # NOTE:
        # Plain 0x... literals are often used as integer/bitmask values in Solidity.
        # __obf_x(...) returns bytes memory, so rewriting these is not type-safe.
        # For now, skip 0x... literals entirely and only support hex"...".
        pass

    def _dedupe_cap(seq: List[Any], cap: int) -> List[Any]:
        items = seq[:]
        rnd.shuffle(items)
        out: List[Any] = []
        seen = set()
        for x in items:
            key = x
            if key in seen:
                continue
            seen.add(key)
            out.append(x)
            if len(out) >= int(cap):
                break
        return out

    int_pool = _dedupe_cap(int_lits, int(max_consts))
    bool_pool = _dedupe_cap(bool_lits, 2)
    string_pool = _dedupe_cap(string_lits, int(max_string_consts))
    hex_pool = _dedupe_cap(hex_lits, int(max_hex_consts))

    if not int_pool and not bool_pool and not string_pool and not hex_pool:
        return TransformResult(
            new_source=source,
            details={
                "int_pool_size": 0,
                "bool_pool_size": 0,
                "string_pool_size": 0,
                "hex_pool_size": 0,
                "replacements": 0,
                "note": "dynamic_constants_v1: no conservatively eligible literals found",
            },
        )

    int_idx = {v: i for i, v in enumerate(int_pool)}
    bool_idx = {v: i for i, v in enumerate(bool_pool)}
    string_idx = {v: i for i, v in enumerate(string_pool)}
    hex_idx = {v: i for i, v in enumerate(hex_pool)}

    replacements: List[Tuple[int, int, str]] = []

    # Emit integer replacements
    for m in _INT_LIT_RE.finditer(masked_comments_only):
        if _is_blocked(m.start(), non_numeric_safe_blocked_spans):
            continue

        if _in_generated_helper_call_context(masked_comments_only, m.start(), m.end()):
            continue

        raw = m.group(0)

        if _should_skip_int_literal(masked_comments_only, m.start(), m.end(), raw):
            continue

        v = int(raw)

        if v < int(min_value):
            continue

        # Do not replace 0/1 inside require/assert/revert spans unless explicitly allowed.
        if v in (0, 1) and avoid_in_require and _is_blocked(m.start(), blocked_spans):
            continue

        if v in int_idx:
            replacements.append((m.start(), m.end(), f"__obf_u({int_idx[v]})"))

    # Emit bool replacements
    if enable_bools:
        for m in _BOOL_LIT_RE.finditer(masked_comments_only):
            if _is_blocked(m.start(), non_numeric_safe_blocked_spans):
                continue

            if _should_skip_bool_literal(masked_comments_only, m.start(), m.end()):
                continue

            v = m.group(0) == "true"
            if v in bool_idx:
                replacements.append((m.start(), m.end(), f"__obf_b({bool_idx[v]})"))

    # Emit string replacements
    if enable_strings:
        for m in _STRING_LIT_RE.finditer(masked_comments_only):
            if _is_blocked(m.start(), blocked_spans):
                continue

            if _should_skip_string_literal(masked_comments_only, m.start(), m.end()):
                continue

            raw = m.group(0)
            try:
                decoded = bytes(raw[1:-1], "utf-8").decode("unicode_escape")
            except Exception:
                decoded = raw[1:-1]

            if decoded in string_idx:
                replacements.append((m.start(), m.end(), f"__obf_s({string_idx[decoded]})"))

    # Emit hex replacements
    if enable_hex_bytes:
        for m in _HEX_STR_LIT_RE.finditer(masked_comments_only):
            if _is_blocked(m.start(), blocked_spans):
                continue

            if _should_skip_hex_literal(masked_comments_only, m.start(), m.end()):
                continue

            payload = _normalize_hex_payload(m.group(0))

            if payload in hex_idx:
                replacements.append((m.start(), m.end(), f"__obf_x({hex_idx[payload]})"))

        # Skip emitting replacements for plain 0x... literals for now.
        pass

    if not replacements:
        return TransformResult(
            new_source=source,
            details={
                "int_pool_size": len(int_pool),
                "bool_pool_size": len(bool_pool),
                "string_pool_size": len(string_pool),
                "hex_pool_size": len(hex_pool),
                "replacements": 0,
                "note": "dynamic_constants_v1: eligible pools built but no concrete replacements were emitted",
            },
        )

    new_body = body
    seen_ranges = set()

    for a, b, rep in sorted(replacements, key=lambda x: (x[0], x[1], x[2]), reverse=True):
        key = (a, b)
        if key in seen_ranges:
            continue
        seen_ranges.add(key)
        new_body = new_body[:a] + rep + new_body[b:]

    helper_blob = _build_helper_blob(
        int_pool=int_pool,
        bool_pool=bool_pool,
        string_pool=string_pool,
        hex_pool=hex_pool,
    )

    with_helpers, injected = _inject_helpers_if_missing(source, contract_name, helper_blob)

    if not injected:
        # A __obf_u/__obf_b/__obf_s/__obf_x helper already exists in the
        # contract, built from a DIFFERENT (earlier) function's pool. The
        # helper is a single contract-level function, but pools are built
        # per-function invocation, so our freshly-computed indices
        # (int_idx, bool_idx, ...) do NOT correspond to the live helper's
        # entries. Emitting our replacements here would reference indices the
        # live helper does not know about -> its fallthrough `return 0;` makes
        # every such call evaluate to 0, which is silently wrong in value
        # contexts and a hard 0x11 underflow panic inside `**` exponents
        # (e.g. `10 ** (18 - dec)` -> `__obf_u(0) ** (__obf_u(1) - dec)` where
        # __obf_u(1) is missing). The only composition-safe action is to leave
        # this function untouched so the first function to own the helper keeps
        # full encoding and later functions are never desynced from it.
        return TransformResult(
            new_source=source,
            details={
                "int_pool_size": len(int_pool),
                "bool_pool_size": len(bool_pool),
                "string_pool_size": len(string_pool),
                "hex_pool_size": len(hex_pool),
                "replacements": 0,
                "injected_helpers": False,
                "note": (
                    "dynamic_constants_v1: skipped — a shared __obf_* helper from an "
                    "earlier function is already present; applying here would desync "
                    "indices from the live helper"
                ),
            },
        )

    body_open2, body_close2 = _find_function_span(with_helpers, fn_name)
    new_source = with_helpers[:body_open2] + new_body + with_helpers[body_close2:]

    return TransformResult(
        new_source=new_source,
        details={
            "int_pool_size": len(int_pool),
            "bool_pool_size": len(bool_pool),
            "string_pool_size": len(string_pool),
            "hex_pool_size": len(hex_pool),
            "replacements": len(seen_ranges),
            "seed": seed,
            "injected_helpers": injected,
            "note": (
                "dynamic_constants_v1 applied "
                "(int/bool/string/hex literals -> __obf_u/__obf_b/__obf_s/__obf_x)"
            ),
        },
    )