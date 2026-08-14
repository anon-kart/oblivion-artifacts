# security_advisor/advisor.py

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import re
from bisect import bisect_right


# ----------------------------
# Slither runner (Foundry-safe)
# ----------------------------

def run_slither_json(*, target: Path, out_json: Path, cwd: Path) -> dict:
    """
    Run Slither and write JSON output.

    Key realities:
      - Slither may exit non-zero even when it succeeds (findings).
      - Slither refuses to overwrite an existing --json file.
      - So: if new JSON isn't produced but an old JSON already exists, reuse it.

    Notes:
      - We pass the target file to Slither, but still keep Foundry compilation mode.
      - If Slither still analyzes wider project context, later grouping/filtering keeps
        only findings relevant to the requested source_relpath.
    """
    from uuid import uuid4

    cwd = Path(cwd).resolve()
    out_json = Path(out_json).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)

    target_path = Path(target).resolve()

    # In Foundry mode, Slither/CryticCompile should be launched from the Foundry project root.
    # Passing the Solidity file itself as the primary target can cause CryticCompile to treat
    # that file path like a working directory/project root, which breaks forge clean/config.
    #
    # So:
    #   - run Slither against the Foundry project root (".")
    #   - keep the real source file path only for later filtering/grouping
    target_arg = "."

    log_path = out_json.with_suffix(out_json.suffix + ".slither.log.txt")
    tmp_json = out_json.parent / f"{out_json.stem}.{uuid4().hex}.json"

    cmd = [
        "slither",
        target_arg,
        "--json",
        str(tmp_json),
        "--compile-force-framework",
        "foundry",
    ]

    res = subprocess.run(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    log_path.write_text(res.stdout or "", encoding="utf-8")

    if not tmp_json.exists():
        if out_json.exists():
            try:
                return json.loads(out_json.read_text(encoding="utf-8"))
            except Exception:
                pass
        raise RuntimeError(
            f"Slither did not produce JSON (code={res.returncode}). See log: {log_path}"
        )

    data = json.loads(tmp_json.read_text(encoding="utf-8"))
    out_json.write_text(json.dumps(data, indent=2), encoding="utf-8")

    try:
        tmp_json.unlink()
    except Exception:
        pass

    return data


# ----------------------------
# Severity / score helpers
# ----------------------------

_IMPACT_WEIGHTS = {
    "CRITICAL": 1.00,
    "HIGH": 0.90,
    "MEDIUM": 0.60,
    "LOW": 0.25,
    "INFO": 0.10,
    "INFORMATIONAL": 0.05,
    "OPTIMIZATION": 0.00,
    "UNKNOWN": 0.20,
}

_CONFIDENCE_WEIGHTS = {
    "HIGH": 1.00,
    "MEDIUM": 0.75,
    "LOW": 0.50,
    "UNKNOWN": 0.60,
}


def _impact_rank(impact: str) -> int:
    impact = (impact or "").upper()
    if impact == "CRITICAL":
        return 4
    if impact == "HIGH":
        return 3
    if impact == "MEDIUM":
        return 2
    if impact == "LOW":
        return 1
    return 0


def _impact_weight(impact: str) -> float:
    return _IMPACT_WEIGHTS.get((impact or "").upper(), 0.20)


def _confidence_weight(confidence: str) -> float:
    return _CONFIDENCE_WEIGHTS.get((confidence or "").upper(), 0.60)


def _score_to_severity(score: float) -> str:
    if score >= 0.85:
        return "HIGH"
    if score >= 0.50:
        return "MEDIUM"
    if score >= 0.15:
        return "LOW"
    return "INFO"


# ----------------------------
# Slither issue extraction
# ----------------------------

def _extract_issues(slither_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = (slither_json or {}).get("results") or {}
    detectors = results.get("detectors") or []
    issues: List[Dict[str, Any]] = []

    for d in detectors:
        if not isinstance(d, dict):
            continue

        check = d.get("check") or d.get("id") or "unknown_check"
        impact = (d.get("impact") or d.get("severity") or "").upper() or "UNKNOWN"
        confidence = (d.get("confidence") or "").upper() or "UNKNOWN"

        elements = d.get("elements") or []
        locations: List[Dict[str, Any]] = []
        for el in elements:
            if not isinstance(el, dict):
                continue
            sm = el.get("source_mapping") or {}
            locations.append(
                {
                    "type": el.get("type"),
                    "name": el.get("name"),
                    "contract": el.get("contract"),
                    "source_mapping": sm,
                }
            )

        issues.append(
            {
                "check": check,
                "impact": impact,
                "confidence": confidence,
                "description": d.get("description") or "",
                "locations": locations,
            }
        )

    return issues


# ----------------------------
# Group issues by function
# ----------------------------

def _group_by_function(
    *,
    issues: List[Dict[str, Any]],
    source_relpath: str,
) -> Dict[str, List[Dict[str, Any]]]:
    by_fn: Dict[str, List[Dict[str, Any]]] = {}
    want = (source_relpath or "").strip()

    for issue in issues:
        assigned = False
        location_files = set()

        for loc in issue.get("locations", []):
            if not isinstance(loc, dict):
                continue

            sm = loc.get("source_mapping") or {}
            if not isinstance(sm, dict):
                continue

            fnrel = (sm.get("filename_relative") or "").strip()
            if fnrel:
                location_files.add(fnrel)

            if want and fnrel != want:
                continue

            nm = (loc.get("name") or "").strip()
            tp = (loc.get("type") or "").lower()

            if "function" in tp and nm:
                by_fn.setdefault(nm, []).append(issue)
                assigned = True
                break

        if not assigned:
            # Keep unmatched issues at contract level ONLY if all referenced
            # files belong to the requested source file.
            if location_files and location_files == {want}:
                by_fn.setdefault("__contract__", []).append(issue)

    return by_fn


# ----------------------------
# Dynamic evidence helpers
# ----------------------------

def _load_json_if_exists(path: Optional[Path]) -> Dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _build_runtime_maps(
    contract_name: str,
    traces: Dict[str, Any],
) -> Tuple[Dict[str, int], Dict[str, List[str]]]:
    dyn_calls: Dict[str, int] = {}
    tests_per_fn: Dict[str, List[str]] = {}

    def _record(test_name: str, fn_name: str):
        fn_name = str(fn_name or "").strip()
        if not fn_name or fn_name.startswith("test_"):
            return
        dyn_calls[fn_name] = dyn_calls.get(fn_name, 0) + 1
        tests_per_fn.setdefault(fn_name, [])
        if test_name not in tests_per_fn[fn_name]:
            tests_per_fn[fn_name].append(test_name)

    for test_name, entries in (traces or {}).items():
        if isinstance(entries, dict):
            entries = entries.get("events") or entries.get("trace") or entries.get("calls") or []

        if not isinstance(entries, list):
            continue

        touched_in_test = set()

        for ev in entries:
            if not isinstance(ev, dict):
                continue

            ev_type = str(ev.get("type") or ev.get("kind") or "").lower()

            fn_name = (
                ev.get("function")
                or ev.get("function_name")
                or ev.get("name")
                or ev.get("callee")
                or ""
            )
            fn_name = str(fn_name).strip()

            contract_val = str(
                ev.get("contract")
                or ev.get("contract_name")
                or ev.get("callee_contract")
                or ""
            )

            looks_like_call = (
                ev_type == "call"
                or "call" in ev_type
                or bool(fn_name)
            )

            contract_matches = (
                not contract_val
                or contract_name in contract_val
            )

            if not looks_like_call or not contract_matches:
                continue

            if fn_name:
                _record(test_name, fn_name)
                touched_in_test.add(fn_name)

        for fn_name in touched_in_test:
            tests_per_fn.setdefault(fn_name, [])
            if test_name not in tests_per_fn[fn_name]:
                tests_per_fn[fn_name].append(test_name)

    return dyn_calls, tests_per_fn


def _coverage_hits_for_function(
    coverage: Dict[str, Any],
    source_relpath: str,
    function_name: str,
) -> int:
    file_cov = coverage.get(source_relpath) or {}

    fn_map = file_cov.get("functions") or {}
    if not isinstance(fn_map, dict):
        return 0

    if function_name in fn_map:
        try:
            return int(fn_map[function_name])
        except Exception:
            return 0

    for key, value in fn_map.items():
        key_s = str(key)
        if (
            key_s == function_name
            or key_s.startswith(function_name + "(")
            or key_s.endswith("." + function_name)
            or key_s.endswith("." + function_name + "()")
            or function_name in key_s
        ):
            try:
                return int(value)
            except Exception:
                return 0

    return 0


def _runtime_relevance(
    *,
    fn_name: str,
    source_relpath: str,
    contract_name: str,
    coverage: Dict[str, Any],
    traces: Dict[str, Any],
    dyn_calls: Dict[str, int],
    tests_per_fn: Dict[str, List[str]],
) -> float:
    cov_hits = _coverage_hits_for_function(coverage, source_relpath, fn_name)
    fn_calls = dyn_calls.get(fn_name, 0)
    fn_tests = len(tests_per_fn.get(fn_name, []))

    all_cov_vals: List[int] = []
    file_cov = coverage.get(source_relpath) or {}
    for v in (file_cov.get("functions") or {}).values():
        try:
            all_cov_vals.append(int(v))
        except Exception:
            pass

    all_call_vals = list(dyn_calls.values())

    cov_norm = 0.0 if not all_cov_vals else min(1.0, cov_hits / max(1, max(all_cov_vals)))
    call_norm = 0.0 if not all_call_vals else min(1.0, fn_calls / max(1, max(all_call_vals)))
    test_norm = min(1.0, fn_tests / 3.0)

    score = (0.45 * cov_norm) + (0.45 * call_norm) + (0.10 * test_norm)
    return round(max(0.0, min(1.0, score)), 4)


# ----------------------------
# Scoring / hints / policy signals
# ----------------------------

def _issue_risk_value(issue: Dict[str, Any]) -> float:
    impact = _impact_weight(issue.get("impact"))
    confidence = _confidence_weight(issue.get("confidence"))
    return impact * confidence


def _aggregate_sec_score(fn_issues: List[Dict[str, Any]]) -> float:
    if not fn_issues:
        return 0.05

    max_single = max(_issue_risk_value(it) for it in fn_issues)
    avg_risk = sum(_issue_risk_value(it) for it in fn_issues) / max(1, len(fn_issues))

    raw = (0.70 * max_single) + (0.30 * avg_risk)
    return round(max(0.0, min(1.0, raw)), 4)


def _aggregate_confidence(fn_issues: List[Dict[str, Any]]) -> float:
    if not fn_issues:
        return 0.70
    vals = [_confidence_weight(it.get("confidence")) for it in fn_issues]
    return round(sum(vals) / max(1, len(vals)), 4)


def _build_hints(fn_issues: List[Dict[str, Any]]) -> List[str]:
    hints: List[str] = []
    checks = {str(it.get("check") or "").lower() for it in fn_issues}

    if any("reentrancy" in c for c in checks):
        hints.append("avoid_reordering_external_calls")
        hints.append("avoid_storage_motion_around_calls")

    if any("access" in c or "owner" in c for c in checks):
        hints.append("avoid_modifier_expansion")
        hints.append("preserve_require_guards")

    if any("arithmetic" in c or "overflow" in c or "underflow" in c for c in checks):
        hints.append("avoid_algebraic_rewrites_unless_proven_safe")

    if any("calls-loop" in c or "loop" in c for c in checks):
        hints.append("avoid_loop_body_expansion")

    if not hints and fn_issues:
        hints.append("prefer_lexical_or_control_flow_light_transforms")

    return sorted(set(hints))


def _extract_policy_signals(fn_issues: List[Dict[str, Any]]) -> Dict[str, bool]:
    checks = {str(it.get("check") or "").lower() for it in fn_issues}
    descs = " ".join(str(it.get("description") or "").lower() for it in fn_issues)
    blob = " ".join(sorted(checks)) + " " + descs

    return {
        "access_control_sensitive": any(
            k in blob
            for k in [
                "access-control",
                "missing-access",
                "onlyowner",
                "owner",
                "role",
                "auth",
                "permission",
            ]
        ),
        "external_call_sensitive": any(
            k in blob
            for k in [
                "external-call",
                "low-level",
                "delegatecall",
                "call.value",
                "send",
                "transfer(",
                "call(",
            ]
        ),
        "reentrancy_sensitive": "reentr" in blob,
        "arithmetic_sensitive": any(
            k in blob
            for k in [
                "overflow",
                "underflow",
                "arithmetic",
                "unchecked",
            ]
        ),
        "revert_semantics_sensitive": any(
            k in blob
            for k in [
                "revert",
                "require",
                "assert",
                "error(",
            ]
        ),
        "loop_gas_sensitive": any(
            k in blob
            for k in [
                "calls-loop",
                "costly-loop",
                "loop",
            ]
        ),
    }

def _build_line_starts(source_text: str) -> List[int]:
    starts = [0]
    for i, ch in enumerate(source_text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _parse_src(src: str) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """
    Solidity src form: 'start:length:fileIndex'
    """
    if not src or not isinstance(src, str):
        return None, None, None
    m = re.match(r"^(\d+):(\d+):(\d+)$", src.strip())
    if not m:
        return None, None, None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _src_to_lines(src: str, line_starts: List[int]) -> List[int]:
    start, length, _ = _parse_src(src)
    if start is None or length is None:
        return []
    end = start + max(length - 1, 0)
    s_line = bisect_right(line_starts, start)
    e_line = bisect_right(line_starts, end)
    if s_line <= 0:
        s_line = 1
    if e_line < s_line:
        e_line = s_line
    return list(range(s_line, e_line + 1))


def _walk(node: Any):
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            yield cur
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            for v in reversed(cur):
                if isinstance(v, (dict, list)):
                    stack.append(v)


def _node_ctx_function(node: Dict[str, Any]) -> str:
    ctx = node.get("__ctx") or {}
    if isinstance(ctx, dict):
        return str(ctx.get("function") or "")
    return ""


def _node_ctx_contract(node: Dict[str, Any]) -> str:
    ctx = node.get("__ctx") or {}
    if isinstance(ctx, dict):
        return str(ctx.get("contract") or "")
    return ""


def _render_node_text(node: Any) -> str:
    if not isinstance(node, dict):
        return ""
    nt = node.get("nodeType")

    if nt == "Identifier":
        return str(node.get("name") or "")
    if nt == "Literal":
        return str(node.get("value") or node.get("hexValue") or "")
    if nt == "MemberAccess":
        base = _render_node_text(node.get("expression"))
        member = str(node.get("memberName") or "")
        return f"{base}.{member}" if base else member
    if nt == "IndexAccess":
        base = _render_node_text(node.get("baseExpression"))
        idx = _render_node_text(node.get("indexExpression"))
        return f"{base}[{idx}]"
    if nt == "FunctionCall":
        expr = _render_node_text(node.get("expression"))
        args = node.get("arguments") or []
        return f"{expr}(" + ", ".join(_render_node_text(a) for a in args if isinstance(a, dict)) + ")"
    if nt == "BinaryOperation":
        return f"({_render_node_text(node.get('leftExpression'))} {node.get('operator') or '?'} {_render_node_text(node.get('rightExpression'))})"
    if nt == "UnaryOperation":
        return f"{node.get('operator') or ''}{_render_node_text(node.get('subExpression'))}"
    return ""


def _load_analyzer_ast_bundle(path: Optional[Path]) -> Dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_ir_bundle(path: Optional[Path]) -> Dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _find_contract_ast(ast_bundle: Dict[str, Any], contract_name: str) -> Optional[Dict[str, Any]]:
    for c in ast_bundle.get("contracts", []) or []:
        if str(c.get("name") or "") == contract_name:
            return c
    return None


def _find_function_ast(contract_ast: Optional[Dict[str, Any]], fn_name: str) -> Optional[Dict[str, Any]]:
    if not isinstance(contract_ast, dict):
        return None
    for n in _walk(contract_ast):
        if not isinstance(n, dict):
            continue
        if n.get("nodeType") == "FunctionDefinition" and str(n.get("name") or "") == fn_name:
            return n
    return None


def _find_modifier_ast(contract_ast: Optional[Dict[str, Any]], modifier_name: str) -> Optional[Dict[str, Any]]:
    if not isinstance(contract_ast, dict):
        return None
    for n in _walk(contract_ast):
        if not isinstance(n, dict):
            continue
        if n.get("nodeType") == "ModifierDefinition" and str(n.get("name") or "") == modifier_name:
            return n
    return None


def _ir_function_map(ir_bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    funcs = ((ir_bundle or {}).get("contract") or {}).get("functions") or []
    for f in funcs:
        if isinstance(f, dict):
            nm = str(f.get("name") or "")
            if nm:
                out[nm] = f
    return out


def _make_region(
    *,
    tag: str,
    fn_name: str,
    src: str,
    line_starts: List[int],
    note: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    start, length, _ = _parse_src(src)
    obj = {
        "tag": tag,
        "function": fn_name,
        "start": start,
        "length": length,
        "lines": _src_to_lines(src, line_starts),
        "src": src,
        "note": note,
    }
    if extra:
        obj.update(extra)
    return obj


def _auth_textish(s: str) -> bool:
    s = (s or "").lower()
    auth_keys = [
        "msg.sender",
        "tx.origin",
        "owner",
        "admin",
        "role",
        "onlyowner",
        "onlyadmin",
        "auth",
        "permission",
        "_checkrole",
        "hasrole",
    ]
    return any(k in s for k in auth_keys)


def _looks_external_call(fc: Dict[str, Any]) -> bool:
    expr = fc.get("expression") or {}
    if not isinstance(expr, dict):
        return False

    if expr.get("nodeType") != "MemberAccess":
        return False

    member = str(expr.get("memberName") or "").lower()
    base_node = expr.get("expression") or {}
    base_txt = _render_node_text(base_node).lower()

    # definite low-level/value transfer calls
    if member in {"call", "delegatecall", "staticcall", "send", "transfer"}:
        return True

    # do NOT treat common container / local / builtin member accesses as external calls
    safe_members = {
        "length",
        "push",
        "pop",
        "selector",
        "balance",
        "code",
        "codehash",
    }
    if member in safe_members:
        return False

    safe_bases = {
        "msg",
        "block",
        "tx",
        "abi",
        "super",
        "this",
    }
    if base_txt in safe_bases:
        return False

    # only treat as external if IR already knows this function has external calls
    return False

def _is_state_write_stmt(stmt: Dict[str, Any], ir_fn: Dict[str, Any]) -> bool:
    writes = ir_fn.get("storage_writes") or []
    write_vars = {str(w.get("var") or "") for w in writes if isinstance(w, dict)}
    if not write_vars:
        return False

    for n in _walk(stmt):
        if not isinstance(n, dict):
            continue

        nt = n.get("nodeType")

        if nt == "Assignment":
            lhs = n.get("leftHandSide") or {}
            lhs_txt = _render_node_text(lhs)
            for wv in write_vars:
                if wv and (
                    lhs_txt == wv
                    or lhs_txt.startswith(f"{wv}[")
                    or lhs_txt.startswith(f"{wv}.")
                ):
                    return True

        if nt == "UnaryOperation":
            op = str(n.get("operator") or "")
            sub = n.get("subExpression") or {}
            sub_txt = _render_node_text(sub)
            if op in {"++", "--"}:
                for wv in write_vars:
                    if wv and (
                        sub_txt == wv
                        or sub_txt.startswith(f"{wv}[")
                        or sub_txt.startswith(f"{wv}.")
                    ):
                        return True

        if nt == "FunctionCall":
            expr = n.get("expression") or {}
            expr_txt = _render_node_text(expr)
            for wv in write_vars:
                if wv and (
                    expr_txt == f"{wv}.push"
                    or expr_txt == f"{wv}.pop"
                ):
                    return True

    return False

def _semantic_policy_signals(
    *,
    fn_name: str,
    ir_fn: Dict[str, Any],
    contract_ir: Dict[str, Any],
    fn_ast: Optional[Dict[str, Any]],
) -> Dict[str, bool]:
    modifiers = [str(x) for x in (ir_fn.get("modifiers") or [])]
    requires = [str(x) for x in (ir_fn.get("requires") or [])]
    external_calls = ir_fn.get("external_calls") or []
    storage_writes = ir_fn.get("storage_writes") or []
    loops = ir_fn.get("loops") or []

    access_edges = (contract_ir.get("access_control") or [])
    has_acl_edge = any(
        isinstance(e, dict) and str(e.get("function") or "") == fn_name
        for e in access_edges
    )

    authish_requires = any(_auth_textish(r) for r in requires)
    authish_modifiers = any(_auth_textish(m) for m in modifiers)

    real_external_calls = []
    for ec in external_calls:
        if isinstance(ec, dict):
            kind = str(ec.get("kind") or ec.get("type") or ec.get("call_type") or "").lower()
            target = str(ec.get("target") or ec.get("callee") or ec.get("expression") or "").lower()

            if kind in {"call", "delegatecall", "staticcall", "send", "transfer"}:
                real_external_calls.append(ec)
                continue

            if any(tok in target for tok in ["call", "delegatecall", "staticcall", "send", "transfer"]):
                real_external_calls.append(ec)
                continue

        elif isinstance(ec, str):
            s = ec.lower()
            if any(tok in s for tok in ["call", "delegatecall", "staticcall", "send", "transfer"]):
                real_external_calls.append(ec)

    arithmetic_sensitive = False
    revert_semantics_sensitive = bool(requires)
    external_call_sensitive = bool(real_external_calls)
    reentrancy_sensitive = bool(real_external_calls) and bool(storage_writes)
    loop_gas_sensitive = bool(loops)
    access_control_sensitive = has_acl_edge or authish_requires or authish_modifiers

    if isinstance(fn_ast, dict):
        for n in _walk(fn_ast):
            if not isinstance(n, dict):
                continue
            nt = n.get("nodeType")

            if nt == "UncheckedBlock":
                arithmetic_sensitive = True

            if nt == "BinaryOperation":
                op = str(n.get("operator") or "")
                if op in {"+", "-", "*", "/", "%", "**", "<<", ">>"}:
                    arithmetic_sensitive = True

            if nt == "FunctionCall":
                expr = n.get("expression") or {}
                callee = str(expr.get("name") or expr.get("memberName") or "").lower()
                if callee in {"require", "assert", "revert"}:
                    revert_semantics_sensitive = True

            if nt == "IfStatement":
                cond_txt = _render_node_text(n.get("condition")).lower()
                if _auth_textish(cond_txt):
                    access_control_sensitive = True

            if nt in {"ForStatement", "WhileStatement", "DoWhileStatement"}:
                loop_gas_sensitive = True

    return {
        "access_control_sensitive": access_control_sensitive,
        "external_call_sensitive": external_call_sensitive,
        "reentrancy_sensitive": reentrancy_sensitive,
        "arithmetic_sensitive": arithmetic_sensitive,
        "revert_semantics_sensitive": revert_semantics_sensitive,
        "loop_gas_sensitive": loop_gas_sensitive,
    }

def _merge_policy_signals(issue_signals: Dict[str, bool], semantic_signals: Dict[str, bool]) -> Dict[str, bool]:
    keys = {
        "access_control_sensitive",
        "external_call_sensitive",
        "reentrancy_sensitive",
        "arithmetic_sensitive",
        "revert_semantics_sensitive",
        "loop_gas_sensitive",
    }
    out: Dict[str, bool] = {}
    for k in keys:
        out[k] = bool(issue_signals.get(k)) or bool(semantic_signals.get(k))
    return out


def _extract_protected_regions_semantic(
    *,
    fn_name: str,
    contract_name: str,
    fn_ast: Optional[Dict[str, Any]],
    contract_ast: Optional[Dict[str, Any]],
    ir_fn: Dict[str, Any],
    source_text: str,
) -> List[Dict[str, Any]]:
    if not isinstance(fn_ast, dict):
        return []

    line_starts = _build_line_starts(source_text)
    regions: List[Dict[str, Any]] = []

    modifiers = fn_ast.get("modifiers") or []
    for m in modifiers:
        if not isinstance(m, dict):
            continue
        mod_name = (((m.get("modifierName") or {}) if isinstance(m.get("modifierName"), dict) else {}) or {}).get("name") or ""
        src = str(m.get("src") or "")
        if src:
            regions.append(
                _make_region(
                    tag="access_control_guard",
                    fn_name=fn_name,
                    src=src,
                    line_starts=line_starts,
                    note=f"modifier_invocation:{mod_name}",
                )
            )
        if mod_name:
            mod_ast = _find_modifier_ast(contract_ast, mod_name)
            if isinstance(mod_ast, dict):
                mod_src = str(mod_ast.get("src") or "")
                if mod_src:
                    regions.append(
                        _make_region(
                            tag="access_control_guard",
                            fn_name=fn_name,
                            src=mod_src,
                            line_starts=line_starts,
                            note=f"modifier_definition:{mod_name}",
                        )
                    )

    external_call_lines: List[int] = []

    for n in _walk(fn_ast):
        if not isinstance(n, dict):
            continue
        nt = n.get("nodeType")
        src = str(n.get("src") or "")

        if not src:
            continue

        if nt == "FunctionCall":
            expr = n.get("expression") or {}
            callee = str(expr.get("name") or expr.get("memberName") or "").lower()

            if callee in {"require", "assert", "revert"}:
                cond = ""
                args = n.get("arguments") or []
                if args and isinstance(args, list) and isinstance(args[0], dict):
                    cond = _render_node_text(args[0])
                tag = "access_control_guard" if _auth_textish(cond) else "revert_semantics_region"
                regions.append(
                    _make_region(
                        tag=tag,
                        fn_name=fn_name,
                        src=src,
                        line_starts=line_starts,
                        note=f"call:{callee}",
                    )
                )

            if _looks_external_call(n):
                r = _make_region(
                    tag="external_call_site",
                    fn_name=fn_name,
                    src=src,
                    line_starts=line_starts,
                    note="external_call",
                )
                external_call_lines.extend(r.get("lines") or [])
                regions.append(r)

        elif nt == "IfStatement":
            cond_txt = _render_node_text(n.get("condition"))
            if _auth_textish(cond_txt):
                regions.append(
                    _make_region(
                        tag="access_control_guard",
                        fn_name=fn_name,
                        src=src,
                        line_starts=line_starts,
                        note="if_auth_guard",
                    )
                )

        elif nt in {"ForStatement", "WhileStatement", "DoWhileStatement"}:
            regions.append(
                _make_region(
                    tag="loop_region",
                    fn_name=fn_name,
                    src=src,
                    line_starts=line_starts,
                    note=nt,
                )
            )

        elif nt == "UncheckedBlock":
            regions.append(
                _make_region(
                    tag="arithmetic_region",
                    fn_name=fn_name,
                    src=src,
                    line_starts=line_starts,
                    note="unchecked_block",
                )
            )

        elif nt == "BinaryOperation":
            op = str(n.get("operator") or "")
            if op in {"+", "-", "*", "/", "%", "**", "<<", ">>"}:
                regions.append(
                    _make_region(
                        tag="arithmetic_region",
                        fn_name=fn_name,
                        src=src,
                        line_starts=line_starts,
                        note=f"op:{op}",
                    )
                )

        elif nt == "ExpressionStatement":
            if _is_state_write_stmt(n, ir_fn):
                r = _make_region(
                    tag="state_write_region",
                    fn_name=fn_name,
                    src=src,
                    line_starts=line_starts,
                    note="storage_write",
                )
                stmt_lines = r.get("lines") or []
                if external_call_lines and stmt_lines:
                    near_ext = any(abs(a - b) <= 3 for a in stmt_lines for b in external_call_lines)
                    if near_ext:
                        r["tag"] = "external_call_site"
                        r["note"] = "state_write_near_external_call"
                regions.append(r)

    uniq: List[Dict[str, Any]] = []
    seen = set()
    for r in regions:
        key = (
            r.get("tag"),
            r.get("start"),
            r.get("length"),
            tuple(r.get("lines") or []),
            r.get("note"),
        )
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)

    return uniq

def _aggregate_policy_sensitivity(
    *,
    policy_signals: Dict[str, bool],
    protected_regions: List[Dict[str, Any]],
    runtime_relevance: float,
) -> float:
    score = 0.0

    if policy_signals.get("access_control_sensitive"):
        score += 0.35
    if policy_signals.get("external_call_sensitive"):
        score += 0.25
    if policy_signals.get("reentrancy_sensitive"):
        score += 0.20
    if policy_signals.get("arithmetic_sensitive"):
        score += 0.12
    if policy_signals.get("revert_semantics_sensitive"):
        score += 0.12
    if policy_signals.get("loop_gas_sensitive"):
        score += 0.08

    tags = {str(r.get("tag") or "") for r in protected_regions if isinstance(r, dict)}
    if "access_control_guard" in tags:
        score += 0.12
    if "external_call_site" in tags:
        score += 0.12
    if "revert_semantics_region" in tags:
        score += 0.08
    if "arithmetic_region" in tags:
        score += 0.06

    if runtime_relevance >= 0.50 and (
        policy_signals.get("access_control_sensitive")
        or policy_signals.get("external_call_sensitive")
        or policy_signals.get("reentrancy_sensitive")
    ):
        score += 0.05

    return round(max(0.0, min(1.0, score)), 4)

def _sensitivity_to_band(score: float) -> str:
    if score >= 0.75:
        return "HIGH"
    if score >= 0.40:
        return "MEDIUM"
    if score >= 0.15:
        return "LOW"
    return "INFO"

def _build_policy_constraints(
    *,
    policy_signals: Dict[str, bool],
    protected_regions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    forbid_transform_ids = set()
    forbid_risk_tags = set()

    region_tags = {
        str(r.get("tag") or "").strip()
        for r in (protected_regions or [])
        if isinstance(r, dict) and r.get("tag")
    }

    access_sensitive = bool(policy_signals.get("access_control_sensitive")) or ("access_control_guard" in region_tags)
    external_sensitive = bool(policy_signals.get("external_call_sensitive")) or ("external_call_site" in region_tags)
    reentrancy_sensitive = bool(policy_signals.get("reentrancy_sensitive"))
    arithmetic_sensitive = bool(policy_signals.get("arithmetic_sensitive")) or ("arithmetic_region" in region_tags)
    revert_sensitive = bool(policy_signals.get("revert_semantics_sensitive")) or ("revert_semantics_region" in region_tags)
    loop_sensitive = bool(policy_signals.get("loop_gas_sensitive")) or ("loop_region" in region_tags)

    if access_sensitive:
        forbid_transform_ids.update([
            "modifier_expand_v1",
            "predicate_masking_v1",
            "opaque_predicate_v1",
            "chaotic_opaque_predicate_v1",
            "cfg_flatten_v1",
            "dispatcher_cfg_virtualization_v1",
            "dead_code_v1",
            "inline_internal_v1",
        ])
        forbid_risk_tags.update(["touches_access_control", "touches_reverts"])

    if external_sensitive or reentrancy_sensitive:
        forbid_transform_ids.update([
            "local_to_state_lift_v1",
            "cfg_flatten_v1",
            "dispatcher_cfg_virtualization_v1",
            "opaque_storage_slot_indirection_v1",
            "predicate_masking_v1",
            "opaque_predicate_v1",
            "loop_rewrite_v1",
            "dead_code_v1",
            "inline_internal_v1",
        ])
        forbid_risk_tags.update(["touches_storage", "touches_external_calls"])

    if arithmetic_sensitive:
        forbid_transform_ids.update([
            "constant_encoding_v1",
            "dynamic_constants_v1",
            "boolean_split_v1",
            "predicate_masking_v1",
        ])
        forbid_risk_tags.update(["touches_data_flow"])

    if revert_sensitive:
        forbid_transform_ids.update([
            "predicate_masking_v1",
            "opaque_predicate_v1",
            "dead_code_v1",
        ])
        forbid_risk_tags.update(["touches_reverts"])

    if loop_sensitive:
        forbid_transform_ids.update([
            "loop_rewrite_v1",
            "dead_code_v1",
            "cfg_flatten_v1",
        ])

    return {
        "forbid_transform_ids": sorted(forbid_transform_ids),
        "forbid_risk_tags": sorted(forbid_risk_tags),
        "protected_region_tags": sorted(region_tags),
    }

# ----------------------------
# Public API
# ----------------------------

def build_sec_advice(
    *,
    contract_name: str,
    source_relpath: str,
    out_json: Path,
    cwd: Path,
    target_sol: Optional[Path] = None,
    target: Optional[Path] = None,
    coverage_json: Optional[Path] = None,
    traces_json: Optional[Path] = None,
    ir_json: Optional[Path] = None,
    analyzer_ast_json: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Produce normalized sec_advice.json with:
      - function
      - severity_max
      - sec_score
      - runtime_relevance
      - confidence
      - policy_sensitivity
      - policy_sensitivity_band
      - policy_signals
      - protected_regions
      - policy_constraints
      - issues
      - hints
    """
    if target_sol is None:
        target_sol = target
    if target_sol is None:
        raise TypeError("build_sec_advice requires target_sol=... (or target=...)")

    out_json = Path(out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    raw_path = out_json.with_suffix(".slither_raw.json")

    slither_json = run_slither_json(
        target=Path(target_sol),
        out_json=raw_path,
        cwd=Path(cwd),
    )

    issues = _extract_issues(slither_json)
    by_fn = _group_by_function(
        issues=issues,
        source_relpath=source_relpath,
    )

    coverage = _load_json_if_exists(coverage_json)
    traces = _load_json_if_exists(traces_json)
    dyn_calls, tests_per_fn = _build_runtime_maps(contract_name, traces)

    ir_bundle = _load_ir_bundle(ir_json)
    ast_bundle = _load_analyzer_ast_bundle(analyzer_ast_json)

    contract_ir = (ir_bundle.get("contract") or {}) if isinstance(ir_bundle, dict) else {}
    ir_fn_map = _ir_function_map(ir_bundle)
    contract_ast = _find_contract_ast(ast_bundle, contract_name)

    source_text = ""
    try:
        source_text = Path(target_sol).read_text(encoding="utf-8")
    except Exception:
        source_text = ""

    debug_enabled = bool(coverage_json or traces_json)
    if debug_enabled:
        print(
            f"[SEC-DEBUG] coverage_json={coverage_json} loaded={bool(coverage)} "
            f"files={list(coverage.keys())[:5] if isinstance(coverage, dict) else 'n/a'}"
        )
        print(
            f"[SEC-DEBUG] traces_json={traces_json} loaded={bool(traces)} "
            f"tests={list(traces.keys())[:5] if isinstance(traces, dict) else 'n/a'}"
        )
        print(
            f"[SEC-DEBUG] dyn_calls_keys={sorted(list(dyn_calls.keys()))[:20]}"
        )

    functions_out: List[Dict[str, Any]] = []
    contract_issues = by_fn.get("__contract__", [])

    all_fn_names = set(by_fn.keys()) | set(ir_fn_map.keys())
    all_fn_names.discard("__contract__")
    all_fn_names = {
        fn for fn in all_fn_names
        if fn and not str(fn).startswith("__obf_")
    }

    for fn in sorted(all_fn_names):
        fn_issues = by_fn.get(fn, [])
        sec_score = _aggregate_sec_score(fn_issues)
        sev = _score_to_severity(sec_score)
        confidence = _aggregate_confidence(fn_issues)

        runtime_relevance = _runtime_relevance(
            fn_name=fn,
            source_relpath=source_relpath,
            contract_name=contract_name,
            coverage=coverage,
            traces=traces,
            dyn_calls=dyn_calls,
            tests_per_fn=tests_per_fn,
        )

        if debug_enabled:
            cov_hits_dbg = _coverage_hits_for_function(coverage, source_relpath, fn)
            fn_calls_dbg = dyn_calls.get(fn, 0)
            fn_tests_dbg = len(tests_per_fn.get(fn, []))
            print(
                f"[SEC-DEBUG-FN] fn={fn} cov_hits={cov_hits_dbg} "
                f"dyn_calls={fn_calls_dbg} tests={fn_tests_dbg} "
                f"runtime_relevance={runtime_relevance}"
            )

        issue_policy_signals = _extract_policy_signals(fn_issues)
        ir_fn = ir_fn_map.get(fn, {})
        fn_ast = _find_function_ast(contract_ast, fn)

        semantic_policy_signals = _semantic_policy_signals(
            fn_name=fn,
            ir_fn=ir_fn,
            contract_ir=contract_ir,
            fn_ast=fn_ast,
        )

        protected_regions = _extract_protected_regions_semantic(
            fn_name=fn,
            contract_name=contract_name,
            fn_ast=fn_ast,
            contract_ast=contract_ast,
            ir_fn=ir_fn,
            source_text=source_text,
        )

        policy_signals = _merge_policy_signals(
            issue_signals=issue_policy_signals,
            semantic_signals=semantic_policy_signals,
        )

        policy_sensitivity = _aggregate_policy_sensitivity(
            policy_signals=policy_signals,
            protected_regions=protected_regions,
            runtime_relevance=runtime_relevance,
        )

        policy_sensitivity_band = _sensitivity_to_band(policy_sensitivity)

        policy_constraints = _build_policy_constraints(
            policy_signals=policy_signals,
            protected_regions=protected_regions,
        )

        if debug_enabled:
            print(
                f"[SEC-REGIONS] fn={fn} "
                f"policy_signals={policy_signals} "
                f"policy_sensitivity={policy_sensitivity} "
                f"policy_band={policy_sensitivity_band} "
                f"protected_regions={[r.get('tag') for r in protected_regions]}"
            )

        functions_out.append(
            {
                "function": fn,
                "severity_max": sev,
                "sec_score": sec_score,
                "runtime_relevance": runtime_relevance,
                "confidence": confidence,
                "policy_sensitivity": policy_sensitivity,
                "policy_sensitivity_band": policy_sensitivity_band,
                "policy_signals": policy_signals,
                "protected_regions": protected_regions,
                "policy_constraints": policy_constraints,
                "issue_count": len(fn_issues),
                "issues": fn_issues,
                "hints": _build_hints(fn_issues),
            }
        )

    # Contract-level summary should be derived explicitly now that "__contract__"
    # is no longer emitted as a pseudo-function entry.
    if functions_out:
        contract_sec_score = round(
            max(float(x.get("sec_score", 0.0) or 0.0) for x in functions_out),
            4,
        )
        contract_severity = _score_to_severity(contract_sec_score)
    elif contract_issues:
        contract_sec_score = _aggregate_sec_score(contract_issues)
        contract_severity = _score_to_severity(contract_sec_score)
    else:
        contract_sec_score = 0.05
        contract_severity = "INFO"

    out = {
        "contract": contract_name,
        "source_relpath": source_relpath,
        "tool": "slither",
        "version": "sec_advisor_v2_lite_protected_regions_constraints",
        "raw_slither_json": str(raw_path),
        "contract_sec_score": contract_sec_score,
        "contract_severity": contract_severity,
        "contract_issue_count": len(contract_issues),
        "contract_issues": contract_issues,
        "functions": functions_out,
    }

    out_json.write_text(json.dumps(out, indent=2), encoding="utf-8")
    return out