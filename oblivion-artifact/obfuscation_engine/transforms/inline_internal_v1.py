# obfuscation_engine/transforms/inline_internal_v1.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


def _find_function_def(source: str, fn_name: str) -> Tuple[int, int, int, str, str]:
    """
    Find function definition and return:
      (sig_start, brace_open, body_close, signature_text, body_text_including_braces)

    Conservative matcher (no AST). Assumes function keyword exists verbatim.
    """
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
    """
    Very simple param parser:
      function foo(uint a, address b) internal { ... }
    returns list of (type, name).
    If name missing -> ("type", "") and we refuse to inline.
    """
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
            out.append((p.strip(), ""))  # name missing
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


_CALL_STMT_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\((.*?)\)\s*;", flags=re.S)


def apply_inline_internal_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    max_inline: int = 3,
    seed: int = 1337,
    **_: Any,
) -> TransformResult:
    """
    Conservative v1:
      - inline only call-statements inside target function of the form: callee(a,b);
      - callee must be defined in same file
      - callee signature must include 'internal' (or 'private') and must NOT have 'returns'
      - callee body must NOT contain 'return'
      - parameter names must exist (no unnamed params)
      - skips if callee body contains assembly/try/catch
    """
    _ = contract_name

    t_sig_start, t_brace_open, t_body_close, _t_sig, t_body = _find_function_def(source, fn_name)
    if t_sig_start < 0:
        raise ValueError(f"inline_internal_v1: target function {fn_name} not found")

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
            continue  # don't inline recursion

        c_sig_start, _c_brace_open, _c_body_close, c_sig, c_body = _find_function_def(source, callee)
        if c_sig_start < 0:
            continue

        sig_l = c_sig.lower()
        if (" internal" not in sig_l) and (" private" not in sig_l):
            continue
        if "returns" in sig_l:
            continue

        inner = _body_without_braces(c_body)
        if "return" in inner:
            continue
        if "assembly" in inner:
            continue
        if "try" in inner or "catch" in inner:
            continue

        params = _extract_params(c_sig)
        if any((name == "" for _, name in params)):
            continue

        # split args (best-effort)
        arg_list = [a.strip() for a in args.split(",")] if args else []
        if len(arg_list) != len(params):
            continue

        substituted = inner
        for (_, pname), aval in zip(params, arg_list):
            substituted = re.sub(rf"\b{re.escape(pname)}\b", f"({aval})", substituted)

        # Add some harmless noise to resemble “inline” blocks from stronger obfuscators
        noise = (
            f"\n        uint256 __inl_{seed}_{inlined} = uint256({seed}) ^ uint256({seed});\n"
            f"        if (__inl_{seed}_{inlined} != 0) {{ __inl_{seed}_{inlined} = __inl_{seed}_{inlined} ^ __inl_{seed}_{inlined}; }}\n"
        )

        replacement = "{\n" + noise + substituted + "\n}"

        a, b = m.start(), m.end()
        t_body_inner = t_body_inner[:a] + replacement + t_body_inner[b:]

        inlined += 1
        changes.append({"callee": callee, "args": arg_list})

    if inlined == 0:
        return TransformResult(new_source=source, details={"inlined": 0, "note": "no eligible internal calls found"})

    # Rebuild by replacing ONLY the target body slice (safe)
    new_t_body = "{\n" + t_body_inner + "\n}"
    new_source = source[:t_brace_open] + new_t_body + source[t_body_close:]

    return TransformResult(
        new_source=new_source,
        details={
            "inlined": inlined,
            "changes": list(reversed(changes)),
            "note": "inline_internal_v1 inlined simple internal calls into target function",
        },
    )
