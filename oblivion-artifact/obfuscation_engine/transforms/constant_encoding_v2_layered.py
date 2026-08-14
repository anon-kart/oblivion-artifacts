from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


SAFE_SKIP_LITS = {0, 1, 32, 255}


def _find_contract_block(source: str, contract_name: str) -> Tuple[int, int]:
    m = re.search(rf"\bcontract\s+{re.escape(contract_name)}\b", source)
    if not m:
        raise ValueError(f"contract '{contract_name}' not found")

    brace_open = source.find("{", m.end())
    if brace_open < 0:
        raise ValueError(f"contract '{contract_name}' has no opening brace")

    depth = 0
    i = brace_open
    while i < len(source):
        c = source[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return brace_open, i + 1
        i += 1

    raise ValueError(f"contract '{contract_name}' block not closed")


def _find_function_block(contract_src: str, fn_name: str) -> Tuple[int, int]:
    m = re.search(rf"\bfunction\s+{re.escape(fn_name)}\b", contract_src)
    if not m:
        raise ValueError(f"function '{fn_name}' not found in contract block")

    brace_open = contract_src.find("{", m.end())
    if brace_open < 0:
        raise ValueError(f"function '{fn_name}' has no body")

    depth = 0
    i = brace_open
    while i < len(contract_src):
        c = contract_src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return m.start(), i + 1
        i += 1

    raise ValueError(f"function '{fn_name}' block not closed")


def _safe_int_encode_v2(n: int, salt: int) -> str:
    a = (salt % 17) + 3
    b = (salt % 11) + 5
    c = (salt % 7) + 2
    mode = salt % 4

    if mode == 0:
        return f"(((({n} + {a}) - {a}) ^ {b}) ^ {b})"
    if mode == 1:
        return f"((((uint256({n}) + {a}) - {a}) + {b}) - {b})"
    if mode == 2:
        return f"((((uint256({n}) ^ {a}) ^ {a}) + ({b} * 0)) + 0)"
    return f"((((uint256({n}) + {a}) ^ {c}) ^ {c}) - {a})"


def _eligible_int_literal(txt: str) -> bool:
    try:
        v = int(txt)
    except Exception:
        return False
    return v not in SAFE_SKIP_LITS


def _mask_comments_and_strings(src: str) -> Tuple[str, List[str]]:
    placeholders: List[str] = []

    def _mask(m: re.Match) -> str:
        placeholders.append(m.group(0))
        return f"__OBF_MASK_{len(placeholders)-1}__"

    mask_re = re.compile(
        r"(/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')",
        re.DOTALL,
    )
    masked = re.sub(mask_re, _mask, src)
    return masked, placeholders


def _unmask_comments_and_strings(src: str, placeholders: List[str]) -> str:
    def _unmask(m: re.Match) -> str:
        idx = int(m.group(1))
        return placeholders[idx]

    return re.sub(r"__OBF_MASK_([0-9]+)__", _unmask, src)


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


def _should_skip_literal(masked: str, start: int, end: int, raw: str) -> bool:
    line_a, line_b = _line_bounds(masked, start)
    line = masked[line_a:line_b]
    ctx = _context_window(masked, start, end)

    if "__obf_u(" in ctx or "__obf_b(" in ctx or "__obf_s(" in ctx or "__obf_x(" in ctx:
        return True
    if not _eligible_int_literal(raw):
        return True

    try:
        n = int(raw)
    except Exception:
        return True

    if n > 10**15:
        return True
    if "pragma solidity" in line:
        return True
    if re.search(r"\bfor\s*\(", line) and ";" in line:
        return True
    if re.search(r"\bwhile\s*\(", line):
        return True
    if re.search(r"\.\s*length\b", ctx) and re.search(r"\[[^\]]*\b" + re.escape(raw) + r"\b[^\]]*\]", ctx):
        return True
    if "[" in ctx and "]" in ctx and re.search(r"\[[^\]]*\b" + re.escape(raw) + r"\b[^\]]*\]", ctx):
        return True
    if re.search(r"\bemit\b", line):
        return True
    if re.search(r"\b(?:require|assert|revert)\s*\(", ctx):
        return True
    if re.search(r"(==|!=|<=|>=|<|>)\s*" + re.escape(raw), ctx):
        if n in {0, 1}:
            return True
    return False


def _replace_uint_literals(src: str, seed: int, max_replacements: int) -> Tuple[str, int]:
    masked, placeholders = _mask_comments_and_strings(src)
    lit_re = re.compile(r"(?<!0x)\b([0-9]{1,18})\b")

    replacements: List[Tuple[int, int, str]] = []
    replaced = 0

    for m in lit_re.finditer(masked):
        if replaced >= max_replacements:
            break
        s = m.group(1)
        if _should_skip_literal(masked, m.start(), m.end(), s):
            continue
        try:
            n = int(s)
        except Exception:
            continue
        replaced += 1
        replacements.append((m.start(), m.end(), _safe_int_encode_v2(n, seed + replaced)))

    if not replacements:
        return src, 0

    masked2 = masked
    seen = set()
    for a, b, rep in sorted(replacements, key=lambda x: (x[0], x[1]), reverse=True):
        key = (a, b)
        if key in seen:
            continue
        seen.add(key)
        masked2 = masked2[:a] + rep + masked2[b:]

    restored = _unmask_comments_and_strings(masked2, placeholders)
    return restored, len(seen)


def apply_constant_encoding_v2_layered(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    max_replacements: int = 8,
    **_kwargs: Any,
) -> TransformResult:
    c0, c1 = _find_contract_block(source, contract_name)
    contract_src = source[c0:c1]
    f0, f1 = _find_function_block(contract_src, fn_name)
    fn_src = contract_src[f0:f1]

    h = hashlib.sha256(f"{contract_name}:{fn_name}:{seed}".encode("utf-8")).hexdigest()
    fn_salt = int(h[:8], 16)

    new_fn_src, replaced = _replace_uint_literals(fn_src, seed=fn_salt, max_replacements=int(max_replacements))

    if replaced == 0:
        return TransformResult(
            new_source=source,
            details={
                "note": "constant_encoding_v2_layered: no eligible integer literals found",
                "replaced": 0,
            },
        )

    new_contract_src = contract_src[:f0] + new_fn_src + contract_src[f1:]
    new_source = source[:c0] + new_contract_src + source[c1:]
    return TransformResult(
        new_source=new_source,
        details={
            "note": "constant_encoding_v2_layered applied",
            "replaced": replaced,
            "seed": seed,
            "fn_salt": fn_salt,
            "max_replacements": int(max_replacements),
        },
    )