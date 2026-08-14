from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


def _find_function_def(source: str, fn_name: str) -> Tuple[int, int, int, str, str]:
    needle = f"function {fn_name}"
    sig_start = source.find(needle)
    if sig_start < 0:
        return (-1, -1, -1, "", "")

    brace_open = source.find("{", sig_start)
    if brace_open < 0:
        return (-1, -1, -1, "", "")

    signature_text = source[sig_start:brace_open].strip()
    depth = 0
    j = brace_open
    while j < len(source):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                body_close = j + 1
                body_text = source[brace_open:body_close]
                return (sig_start, brace_open, body_close, signature_text, body_text)
        j += 1

    return (-1, -1, -1, "", "")


def _extract_params(sig: str) -> List[Tuple[str, str]]:
    m = re.search(r"function\s+\w+\s*\((.*?)\)", sig, flags=re.S)
    if not m:
        return []
    inside = m.group(1).strip()
    if not inside:
        return []
    parts = [p.strip() for p in inside.split(",")]
    out: List[Tuple[str, str]] = []
    for p in parts:
        p2 = re.sub(r"\b(memory|calldata|storage)\b", "", p).strip()
        toks = p2.split()
        if len(toks) < 2:
            out.append((p.strip(), ""))
        else:
            out.append((" ".join(toks[:-1]), toks[-1]))
    return out


def _body_without_braces(body: str) -> str:
    body = body.strip()
    if body.startswith("{"):
        body = body[1:]
    if body.endswith("}"):
        body = body[:-1]
    return body.strip()


def _split_args(args: str) -> List[str]:
    if not args.strip():
        return []
    out: List[str] = []
    cur: List[str] = []
    dp = db = dc = 0
    in_sq = False
    in_dq = False
    i = 0
    while i < len(args):
        ch = args[i]
        if in_sq:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(args):
                cur.append(args[i + 1])
                i += 2
                continue
            if ch == "'":
                in_sq = False
            i += 1
            continue
        if in_dq:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(args):
                cur.append(args[i + 1])
                i += 2
                continue
            if ch == '"':
                in_dq = False
            i += 1
            continue
        if ch == "'":
            in_sq = True
            cur.append(ch)
            i += 1
            continue
        if ch == '"':
            in_dq = True
            cur.append(ch)
            i += 1
            continue
        if ch == "(":
            dp += 1
        elif ch == ")":
            dp -= 1
        elif ch == "[":
            db += 1
        elif ch == "]":
            db -= 1
        elif ch == "{":
            dc += 1
        elif ch == "}":
            dc -= 1
        elif ch == "," and dp == 0 and db == 0 and dc == 0:
            out.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    if cur:
        out.append("".join(cur).strip())
    return out


def _safe_ident_replace(text: str, old: str, new: str) -> str:
    return re.sub(rf"\b{re.escape(old)}\b", new, text)


def _wrap_simple_rhs(expr: str, mode: int) -> str:
    if mode == 0:
        return f"(({expr}) + 0)"
    if mode == 1:
        return f"(({expr}) ^ 0)"
    return f"((({expr}) * 1))"


def _wrap_assignments(block: str, seed: int) -> str:
    pat = re.compile(r"=\s*([A-Za-z_][A-Za-z0-9_() \t+\-*/^|&<>!]*)\s*;")

    def _repl(m: re.Match) -> str:
        rhs = m.group(1).strip()
        wrapped = _wrap_simple_rhs(rhs, seed % 3)
        return f"= {wrapped};"

    return re.sub(pat, _repl, block)


def _split_statements_by_lines(block: str) -> Tuple[str, str]:
    lines = [ln for ln in block.splitlines() if ln.strip()]
    if len(lines) < 4:
        return block, ""
    mid = len(lines) // 2
    first = "\n".join(lines[:mid]).strip()
    second = "\n".join(lines[mid:]).strip()
    return first, second


_CALL_STMT_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\((.*?)\)\s*;", flags=re.S)


def apply_inline_internal_v2_diversified(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    max_inline: int = 2,
    seed: int = 1337,
    **_: Any,
) -> TransformResult:
    _ = contract_name

    t_sig_start, t_brace_open, t_body_close, _t_sig, t_body = _find_function_def(source, fn_name)
    if t_sig_start < 0:
        raise ValueError(f"inline_internal_v2_diversified: target function {fn_name} not found")

    t_body_inner = _body_without_braces(t_body)
    inlined = 0
    changes: List[Dict[str, Any]] = []

    matches = list(_CALL_STMT_RE.finditer(t_body_inner))
    for m in reversed(matches):
        if inlined >= int(max_inline):
            break

        callee = m.group(1)
        args = m.group(2).strip()
        if callee == fn_name:
            continue

        c_sig_start, _c_brace_open, _c_body_close, c_sig, c_body = _find_function_def(source, callee)
        if c_sig_start < 0:
            continue

        sig_l = c_sig.lower()
        if (" internal" not in sig_l) and (" private" not in sig_l):
            continue
        if "returns" in sig_l:
            continue

        inner = _body_without_braces(c_body)
        if "return" in inner or "assembly" in inner or "try" in inner or "catch" in inner:
            continue

        params = _extract_params(c_sig)
        if any((name == "" for _, name in params)):
            continue

        arg_list = _split_args(args)
        if len(arg_list) != len(params):
            continue

        alias_prefix = f"__inl_alias_{seed}_{inlined}"
        alias_lines: List[str] = []
        substituted = inner

        for idx, ((ptype, pname), aval) in enumerate(zip(params, arg_list)):
            alias_name = f"{alias_prefix}_{idx}_{pname}"
            alias_lines.append(f"{ptype} {alias_name} = ({aval});")
            substituted = _safe_ident_replace(substituted, pname, alias_name)

        substituted = _wrap_assignments(substituted, seed + inlined)

        gate = (
            f"uint256 __inl_gate_{seed}_{inlined} = uint256({seed}) ^ uint256({seed});\n"
            f"if (__inl_gate_{seed}_{inlined} == 1) {{\n"
            f"    __inl_gate_{seed}_{inlined} = __inl_gate_{seed}_{inlined} + 9;\n"
            f"}}"
        )

        first_half, second_half = _split_statements_by_lines(substituted)
        blocks: List[str] = []
        if first_half.strip():
            blocks.append("{\n" + first_half + "\n}")
        if second_half.strip():
            blocks.append("{\n" + second_half + "\n}")
        diversified_body = "\n".join(blocks) if blocks else "{\n" + substituted + "\n}"

        replacement = (
            "{\n"
            + "\n".join(alias_lines)
            + ("\n" if alias_lines else "")
            + gate
            + "\n"
            + diversified_body
            + "\n}"
        )

        a, b = m.start(), m.end()
        t_body_inner = t_body_inner[:a] + replacement + t_body_inner[b:]
        inlined += 1
        changes.append({"callee": callee, "args": arg_list, "aliases": len(alias_lines)})

    if inlined == 0:
        return TransformResult(new_source=source, details={"inlined": 0, "note": "no eligible internal calls found"})

    new_t_body = "{\n" + t_body_inner + "\n}"
    new_source = source[:t_brace_open] + new_t_body + source[t_body_close:]
    return TransformResult(
        new_source=new_source,
        details={
            "inlined": inlined,
            "changes": list(reversed(changes)),
            "note": "inline_internal_v2_diversified applied (diversified semantic cloning)",
        },
    )