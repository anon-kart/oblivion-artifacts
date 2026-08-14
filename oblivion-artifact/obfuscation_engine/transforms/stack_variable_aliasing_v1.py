from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import re


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


def _find_function_span(source: str, fn_name: str) -> Optional[Tuple[int, int, int, int]]:
    """
    Returns (sig_start, sig_end, body_lbrace, body_rbrace)
    Best-effort, brace-balanced.
    """
    if fn_name == "constructor":
        pat = r"\bconstructor\s*\("
    else:
        pat = rf"\bfunction\s+{re.escape(fn_name)}\b\s*\("

    m = re.search(pat, source)
    if not m:
        return None
    sig_start = m.start()

    after = source[m.end():]
    m2 = re.search(r"\{", after)
    if not m2:
        return None
    body_l = m.end() + m2.start()

    depth = 0
    body_r = None
    for i in range(body_l, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                body_r = i
                break
    if body_r is None:
        return None

    sig_end = body_l
    return (sig_start, sig_end, body_l, body_r)


def _parse_params_from_signature(sig: str) -> List[Tuple[str, str]]:
    """
    Parse params from signature chunk like:
      function foo(uint256 x, address a, bool b) external ...
    Returns list of (type, name).

    Best-effort; supports simple types only.
    """
    m = re.search(r"\((.*?)\)", sig, flags=re.DOTALL)
    if not m:
        return []
    inside = m.group(1).strip()
    if not inside:
        return []

    parts = [p.strip() for p in inside.split(",") if p.strip()]
    out: List[Tuple[str, str]] = []

    for p in parts:
        p2 = re.sub(r"\b(calldata|memory|storage)\b", "", p).strip()
        p2 = re.sub(r"\s+", " ", p2)
        toks = p2.split(" ")
        if len(toks) < 2:
            continue
        ptype = " ".join(toks[:-1]).strip()
        pname = toks[-1].strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", pname):
            continue
        out.append((ptype, pname))

    return out


def _is_generated_obf_name(name: str) -> bool:
    return (
        name.startswith("__obf_")
        or name.startswith("__obf_g_")
        or name == "__obf_state"
    )


def _rewrite_ident_uses_safely(text: str, old: str, new: str) -> str:
    """
    Replace identifier uses in text, but skip:
      - member accesses: .old
      - generated obf names
      - longer identifiers
    """
    if not old or old == new:
        return text

    pat = re.compile(rf"\b{re.escape(old)}\b")
    out: List[str] = []
    last = 0

    for m in pat.finditer(text):
        s, e = m.start(), m.end()

        # Skip member access: ".old"
        if s > 0 and text[s - 1] == ".":
            continue

        # Skip if somehow part of generated obf token surface
        token = text[s:e]
        if _is_generated_obf_name(token):
            continue

        out.append(text[last:s])
        out.append(new)
        last = e

    out.append(text[last:])
    return "".join(out)


def apply_stack_variable_aliasing_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **params: Any,
) -> TransformResult:
    """
    Stack-variable / parameter aliasing:
    - For each parameter of type in {uint256,int256,address,bool,bytes32} create local alias:
        T __obf_alias_<name> = <name>;
    - Replace uses of <name> in the ORIGINAL body with alias.
    - Important: replacements are applied only to the original body text,
      not to the injected alias declarations, to avoid self-referential aliases.

    Safety additions:
    - do not alias already-generated obf names
    - do not rewrite member-access field names (.foo)
    """
    _ = (contract_name, params)

    span = _find_function_span(source, fn_name)
    if not span:
        return TransformResult(
            new_source=source,
            details={"note": "stack_variable_aliasing_v1: function not found"},
        )

    sig_start, sig_end, body_l, body_r = span
    sig_text = source[sig_start:sig_end]
    body_inner = source[body_l + 1 : body_r]

    # Avoid double application
    if "__obf_alias_" in body_inner:
        return TransformResult(
            new_source=source,
            details={"note": "stack_variable_aliasing_v1: already applied"},
        )

    params_list = _parse_params_from_signature(sig_text)
    if not params_list:
        return TransformResult(
            new_source=source,
            details={"note": "stack_variable_aliasing_v1: no params to alias"},
        )

    allowed_types = {"uint256", "int256", "address", "bool", "bytes32"}
    alias_pairs: List[Tuple[str, str, str]] = []  # (orig, alias, type)

    for (ptype, pname) in params_list:
        ptype_norm = ptype.strip()
        if ptype_norm not in allowed_types:
            continue

        # Never alias generated obf names
        if _is_generated_obf_name(pname):
            continue

        alias = f"__obf_alias_{pname}"

        # Skip if alias name already somehow appears
        if re.search(rf"\b{re.escape(alias)}\b", body_inner):
            continue

        alias_pairs.append((pname, alias, ptype_norm))

    if not alias_pairs:
        return TransformResult(
            new_source=source,
            details={"note": "stack_variable_aliasing_v1: no simple typed params"},
        )

    # ------------------------------------------------------------
    # Rewrite ONLY the original body, then prepend alias declarations.
    # Do NOT run replacement over the injected declarations.
    # ------------------------------------------------------------
    rewritten_body_inner = body_inner
    for (orig, alias, _ptype) in alias_pairs:
        rewritten_body_inner = _rewrite_ident_uses_safely(
            rewritten_body_inner,
            orig,
            alias,
        )

    inject_lines = []
    for (orig, alias, ptype) in alias_pairs:
        inject_lines.append(f"        {ptype} {alias} = {orig};")

    inject_src = "\n" + "\n".join(inject_lines) + "\n"
    new_body_inner = inject_src + rewritten_body_inner

    new_source = source[: body_l + 1] + new_body_inner + source[body_r:]

    return TransformResult(
        new_source=new_source,
        details={
            "seed": seed,
            "note": "stack_variable_aliasing_v1 aliased simple params into new locals and rewrote uses",
            "aliased": [{"param": o, "alias": a, "type": t} for (o, a, t) in alias_pairs],
        },
    )