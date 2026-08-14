from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
import os
import subprocess
import sys


def _sev_rank(sev: str) -> int:
    s = (sev or "").strip().upper()
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return order.get(s, -1)


def _issue_key(issue: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """
    Create a stable-ish key for diffing across runs.

    Tries multiple possible fields because different Slither wrappers
    might name them differently.
    """
    check = str(
        issue.get("check")
        or issue.get("type")
        or issue.get("detector")
        or issue.get("rule")
        or "unknown"
    )
    severity = str(issue.get("severity") or issue.get("impact") or "UNKNOWN").upper()
    contract = str(issue.get("contract") or issue.get("contract_name") or "")
    function = str(issue.get("function") or issue.get("function_name") or "")
    return (check, severity, contract, function)


def _flatten_issues(sec_advice: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Support multiple possible sec_advice.json shapes.

    Preferred shape (recommended):
      {
        "contract": "...",
        "source_relpath": "...",
        "tool": "slither",
        "functions": [
          {"function":"...", "issues":[{...}, ...], ...},
          ...
        ]
      }

    Also supports:
      {
        "issues":[{...}, ...]
      }
    """
    if not isinstance(sec_advice, dict):
        return []

    if isinstance(sec_advice.get("issues"), list):
        return [x for x in sec_advice["issues"] if isinstance(x, dict)]

    out: List[Dict[str, Any]] = []
    funcs = sec_advice.get("functions") or []
    if isinstance(funcs, list):
        for f in funcs:
            if not isinstance(f, dict):
                continue
            issues = f.get("issues") or []
            if not isinstance(issues, list):
                continue
            for iss in issues:
                if not isinstance(iss, dict):
                    continue
                # normalize contract/function onto issue (helps diff keys)
                if "contract" not in iss:
                    iss["contract"] = sec_advice.get("contract") or ""
                if "function" not in iss:
                    iss["function"] = f.get("function") or f.get("name") or ""
                out.append(iss)
    return out


def _get_ignored_checks(policy: Dict[str, Any]) -> set[str]:
    """
    Allow ignoring specific Slither detectors for obfuscation noise.

    You can override/extend via policy:
      policy["security_ignored_checks"] = ["incorrect-exp", ...]
    """
    default_ignored = {
        # This is the one your constant-encoding triggers (XOR patterns).
        "incorrect-exp",

        # Optional noise (uncomment if you want them ignored too):
        # "conformance-to-solidity-naming-conventions",
        # "cache-array-length",
        # "different-pragma-directives-are-used",
        # "incorrect-versions-of-solidity",
    }
    extra = policy.get("security_ignored_checks")
    if isinstance(extra, list):
        for x in extra:
            if isinstance(x, str) and x.strip():
                default_ignored.add(x.strip())
    return default_ignored


def _is_ignored_key(key: Tuple[str, str, str, str], ignored_checks: set[str]) -> bool:
    # key = (check, severity, contract, function)
    check = (key[0] or "").strip()
    return check in ignored_checks

def _run_candidate_ast_analyzer(
    *,
    sol_path: Path,
    out_dir: Path,
) -> Tuple[Optional[Path], Optional[Path]]:
    analyzer_root = os.getenv("OBLIVION_AST_ANALYZER_ROOT")
    if not analyzer_root:
        return None, None

    analyzer_root = str(Path(analyzer_root).resolve())
    ir_out = out_dir / "candidate_ir.json"
    ast_out = out_dir / "candidate_analyzer_ast.json"

    cmd = [
        sys.executable,
        "-m",
        "invsol_ast.cli",
        str(sol_path),
        "--out",
        str(ir_out),
        "--dump-ast",
        str(ast_out),
    ]

    res = subprocess.run(
        cmd,
        cwd=analyzer_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    (out_dir / "candidate_ast_analyzer.log.txt").write_text(
        res.stdout or "",
        encoding="utf-8",
    )

    if res.returncode != 0:
        return None, None

    if not ir_out.exists() or not ast_out.exists():
        return None, None

    return ir_out, ast_out

def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def _load_json_file(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return {}
    try:
        p = Path(path)
        if not p.exists():
            return {}
        obj = json.loads(p.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _function_meta_map(sec_advice: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    funcs = sec_advice.get("functions") or []
    if not isinstance(funcs, list):
        return out
    for f in funcs:
        if not isinstance(f, dict):
            continue
        fn = str(f.get("function") or f.get("name") or "").strip()
        if not fn:
            continue
        out[fn] = f
    return out


def _issue_identity_key(issue: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Identity key that ignores severity so we can detect severity escalation
    separately from 'brand new detector family' findings.
    """
    check = str(
        issue.get("check")
        or issue.get("type")
        or issue.get("detector")
        or issue.get("rule")
        or "unknown"
    )
    contract = str(issue.get("contract") or issue.get("contract_name") or "")
    function = str(issue.get("function") or issue.get("function_name") or "")
    return (check, contract, function)


def _issue_lines(issue: Dict[str, Any]) -> Set[int]:
    lines: Set[int] = set()
    for loc in issue.get("locations", []):
        if not isinstance(loc, dict):
            continue
        sm = loc.get("source_mapping") or {}
        if not isinstance(sm, dict):
            continue

        vals = sm.get("lines")
        if isinstance(vals, list):
            for x in vals:
                try:
                    lines.add(int(x))
                except Exception:
                    pass

        start_ln = sm.get("starting_line")
        end_ln = sm.get("ending_line")
        try:
            s = int(start_ln) if start_ln is not None else None
            e = int(end_ln) if end_ln is not None else None
            if s is not None:
                if e is None or e < s:
                    e = s
                lines.update(range(s, e + 1))
        except Exception:
            pass

    return lines


def _region_lines(region: Dict[str, Any]) -> Set[int]:
    vals = region.get("lines") or []
    out: Set[int] = set()
    if isinstance(vals, list):
        for x in vals:
            try:
                out.add(int(x))
            except Exception:
                pass
    return out


def _span_to_lines(span: Dict[str, Any], source_text: str) -> Set[int]:
    """
    Transform-map spans are approximate source offsets. Convert to line numbers.
    Works with start/end or start_byte/end_byte or offset/length style data.
    """
    if not isinstance(span, dict) or not source_text:
        return set()

    start = (
        span.get("start")
        if span.get("start") is not None
        else span.get("start_byte")
    )
    if start is None:
        start = span.get("offset")

    end = (
        span.get("end")
        if span.get("end") is not None
        else span.get("end_byte")
    )

    if end is None:
        length = span.get("length")
        try:
            if start is not None and length is not None:
                end = int(start) + int(length)
        except Exception:
            end = start

    try:
        s = max(0, int(start))
        e = max(s, int(end if end is not None else s))
    except Exception:
        return set()

    s = min(s, len(source_text))
    e = min(e, len(source_text))

    start_line = source_text.count("\n", 0, s) + 1
    end_line = source_text.count("\n", 0, e) + 1

    return set(range(start_line, end_line + 1))


def _lines_overlap(a: Set[int], b: Set[int], window: int = 0) -> bool:
    if not a or not b:
        return False
    if window <= 0:
        return bool(a & b)
    for x in a:
        for y in b:
            if abs(x - y) <= window:
                return True
    return False


def _merge_function_context(
    baseline_fn: Optional[Dict[str, Any]],
    candidate_fn: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    baseline_fn = baseline_fn or {}
    candidate_fn = candidate_fn or {}

    baseline_regions = baseline_fn.get("protected_regions") or []
    candidate_regions = candidate_fn.get("protected_regions") or []

    return {
        "runtime_relevance": max(
            _safe_float(baseline_fn.get("runtime_relevance")),
            _safe_float(candidate_fn.get("runtime_relevance")),
        ),
        "policy_sensitivity": max(
            _safe_float(baseline_fn.get("policy_sensitivity")),
            _safe_float(candidate_fn.get("policy_sensitivity")),
        ),
        "policy_sensitivity_band": (
            candidate_fn.get("policy_sensitivity_band")
            or baseline_fn.get("policy_sensitivity_band")
            or "INFO"
        ),
        "protected_regions": candidate_regions if candidate_regions else baseline_regions,
        "policy_signals": candidate_fn.get("policy_signals") or baseline_fn.get("policy_signals") or {},
    }


def _load_transform_context(
    transform_map_json: Optional[Path],
    obfuscated_src: Path,
) -> Dict[str, Any]:
    ctx = {
        "exists": False,
        "functions_touched": set(),
        "new_lines_by_function": {},
        "raw": {},
    }
    if transform_map_json is None:
        return ctx

    obj = _load_json_file(transform_map_json)
    if not obj:
        return ctx

    try:
        source_text = Path(obfuscated_src).read_text(encoding="utf-8")
    except Exception:
        source_text = ""

    ctx["exists"] = True
    ctx["raw"] = obj

    applied = obj.get("applied") or []
    if isinstance(applied, list):
        for row in applied:
            if not isinstance(row, dict):
                continue
            fn = str(row.get("function") or "").strip()
            if fn:
                ctx["functions_touched"].add(fn)
            new_span = row.get("new_span") or {}
            new_lines = _span_to_lines(new_span, source_text)
            if fn and new_lines:
                prev = ctx["new_lines_by_function"].setdefault(fn, set())
                prev.update(new_lines)

    return ctx


def _protected_tags_hit(
    issue_lines: Set[int],
    protected_regions: List[Dict[str, Any]],
    strict_tags: Set[str],
    window: int,
) -> List[str]:
    hits: List[str] = []
    for r in protected_regions:
        if not isinstance(r, dict):
            continue
        tag = str(r.get("tag") or "")
        if strict_tags and tag not in strict_tags:
            continue
        if _lines_overlap(issue_lines, _region_lines(r), window=window):
            hits.append(tag)
    return sorted(set(hits))

def _transform_touches_protected_regions(
    transform_ctx: Dict[str, Any],
    fn_meta_map: Dict[str, Dict[str, Any]],
    strict_tags: Set[str],
    overlap_window: int,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    new_lines_by_function = transform_ctx.get("new_lines_by_function") or {}
    functions_touched = transform_ctx.get("functions_touched") or set()

    # First preference: line-aware mode when spans exist
    if new_lines_by_function:
        for fn, changed_lines in new_lines_by_function.items():
            meta = fn_meta_map.get(fn) or {}
            protected_regions = meta.get("protected_regions") or []
            touched_tags: List[str] = []

            for r in protected_regions:
                if not isinstance(r, dict):
                    continue
                tag = str(r.get("tag") or "")
                if strict_tags and tag not in strict_tags:
                    continue
                if _lines_overlap(changed_lines, _region_lines(r), window=overlap_window):
                    touched_tags.append(tag)

            if touched_tags:
                out.append(
                    {
                        "function": fn,
                        "changed_lines": sorted(changed_lines),
                        "protected_tags": sorted(set(touched_tags)),
                        "policy_sensitivity": _safe_float(meta.get("policy_sensitivity")),
                        "runtime_relevance": _safe_float(meta.get("runtime_relevance")),
                        "mode": "line-aware",
                    }
                )
        return out

    # Fallback: function-aware mode when transform_map lacks usable spans
    for fn in sorted(functions_touched):
        meta = fn_meta_map.get(fn) or {}
        protected_regions = meta.get("protected_regions") or []
        touched_tags: List[str] = []

        for r in protected_regions:
            if not isinstance(r, dict):
                continue
            tag = str(r.get("tag") or "")
            if strict_tags and tag not in strict_tags:
                continue
            touched_tags.append(tag)

        if touched_tags:
            out.append(
                {
                    "function": fn,
                    "changed_lines": [],
                    "protected_tags": sorted(set(touched_tags)),
                    "policy_sensitivity": _safe_float(meta.get("policy_sensitivity")),
                    "runtime_relevance": _safe_float(meta.get("runtime_relevance")),
                    "mode": "function-aware-fallback",
                }
            )

    return out

def check_security(
    *,
    original_src: Path,
    obfuscated_src: Path,
    out_dir: Path,
    policy: Optional[Dict[str, Any]] = None,
    baseline_sec_advice_json: Optional[Path] = None,
    contract_name: Optional[str] = None,
    source_relpath: Optional[str] = None,
    foundry_root: Optional[Path] = None,
    transform_map_json: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Security gate (Slither baseline + candidate + diff).

    IMPORTANT behavior for your current debugging state:
      - If baseline_sec_advice_json is None -> SKIP (no slither calls)
      - If baseline exists, but candidate slither fails -> SKIP (so pipeline doesn't crash)
      - If slither is working -> diff and reject on new HIGH/CRITICAL (policy controlled)

    Artifacts written to out_dir:
      - candidate_sec_advice.json (when slither succeeds)
      - diff_report.json (always; even when skipped, it explains why)
    """
    policy = policy or {}
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    reject_on_new_high = bool(policy.get("reject_on_new_high_vuln", True))
    ignored_checks = _get_ignored_checks(policy)

    reject_on_new_medium_in_high_sensitivity_fn = bool(
        policy.get("reject_on_new_medium_in_high_sensitivity_fn", True)
    )
    reject_on_new_medium_in_hot_fn = bool(
        policy.get("reject_on_new_medium_in_hot_fn", True)
    )
    reject_on_new_issue_in_protected_region = bool(
        policy.get("reject_on_new_issue_in_protected_region", True)
    )
    reject_on_transform_touching_protected_region = bool(
        policy.get("reject_on_transform_touching_protected_region", False)
    )

    high_sensitivity_threshold = _safe_float(
        policy.get("security_high_sensitivity_threshold", 0.65), 0.65
    )
    hot_runtime_threshold = _safe_float(
        policy.get("security_hot_runtime_threshold", 0.50), 0.50
    )

    protected_region_overlap_window = int(
        policy.get("security_protected_region_overlap_window", 1)
    )
    issue_transform_line_window = int(
        policy.get("security_issue_transform_line_window", 3)
    )

    strict_protected_tags = set(
        policy.get(
            "security_strict_protected_region_tags",
            [
                "access_control_guard",
                "external_call_site",
                "revert_semantics_region",
            ],
        )
    )

    diff_path = out_dir / "diff_report.json"

    # ---------------------------
    # If baseline not provided -> skip cleanly
    # ---------------------------
    if baseline_sec_advice_json is None:
        diff_path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "skipped": True,
                    "reason": "baseline_sec_advice_json_not_provided",
                    "note": "Security gate skipped because baseline wasn't generated (Slither disabled or failed earlier).",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return {
            "ok": True,
            "skipped": True,
            "note": "Security gate skipped (baseline_sec_advice_json is None).",
            "diff_report": str(diff_path),
        }

    baseline_path = Path(baseline_sec_advice_json)
    if not baseline_path.exists():
        diff_path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "skipped": True,
                    "reason": "baseline_sec_advice_json_missing_on_disk",
                    "baseline": str(baseline_path),
                    "note": "Security gate skipped because baseline file does not exist.",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return {
            "ok": True,
            "skipped": True,
            "note": f"Security gate skipped (missing baseline file: {baseline_path}).",
            "diff_report": str(diff_path),
        }

    # ---------------------------
    # Load baseline
    # ---------------------------
    try:
        baseline_data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception as e:
        diff_path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "skipped": True,
                    "reason": "failed_to_load_baseline_json",
                    "baseline": str(baseline_path),
                    "error": str(e),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return {
            "ok": True,
            "skipped": True,
            "note": f"Security gate skipped (could not parse baseline JSON: {e}).",
            "diff_report": str(diff_path),
        }

    # ---------------------------
    # Import advisor lazily
    # ---------------------------
    try:
        from security_advisor import build_sec_advice  # type: ignore
    except Exception as e:
        diff_path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "skipped": True,
                    "reason": "security_advisor_import_failed",
                    "error": str(e),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return {
            "ok": True,
            "skipped": True,
            "note": f"Security gate skipped (security_advisor import failed: {e}).",
            "diff_report": str(diff_path),
        }

    # ---------------------------
    # Candidate scan
    # ---------------------------
    candidate_path = out_dir / "candidate_sec_advice.json"
    cwd = Path(foundry_root) if foundry_root is not None else Path(original_src).parent

    candidate_ir_json, candidate_ast_json = _run_candidate_ast_analyzer(
        sol_path=obfuscated_src,
        out_dir=out_dir,
    )

    try:
        build_sec_advice(
            contract_name=contract_name or original_src.stem,
            source_relpath=source_relpath or f"src/{original_src.name}",
            target_sol=obfuscated_src,
            out_json=candidate_path,
            cwd=cwd,
            ir_json=candidate_ir_json,
            analyzer_ast_json=candidate_ast_json,
        )
        candidate_data = json.loads(candidate_path.read_text(encoding="utf-8"))
    except Exception as e:
        # Do NOT crash pipeline while Slither is broken.
        diff_path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "skipped": True,
                    "reason": "candidate_slither_failed",
                    "error": str(e),
                    "baseline": str(baseline_path),
                    "note": "Security gate skipped because candidate scan failed (Slither not working yet).",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return {
            "ok": True,
            "skipped": True,
            "note": f"Security gate skipped (candidate Slither failed: {e}).",
            "diff_report": str(diff_path),
        }

    # ---------------------------
    # Diff
    # ---------------------------
    base_issues = _flatten_issues(baseline_data)
    cand_issues = _flatten_issues(candidate_data)

    base_fn_meta = _function_meta_map(baseline_data)
    cand_fn_meta = _function_meta_map(candidate_data)

    transform_ctx = _load_transform_context(transform_map_json, obfuscated_src)

    print("[SEC-DIFF-DEBUG] transform_ctx_exists=", transform_ctx.get("exists"))
    print("[SEC-DIFF-DEBUG] functions_touched=", sorted(transform_ctx.get("functions_touched") or []))
    print("[SEC-DIFF-DEBUG] new_lines_by_function=", {k: sorted(v) for k, v in (transform_ctx.get("new_lines_by_function") or {}).items()})

    base_keys = {_issue_key(i) for i in base_issues}
    cand_keys = {_issue_key(i) for i in cand_issues}

    raw_added_keys = sorted(cand_keys - base_keys)
    raw_removed_keys = sorted(base_keys - cand_keys)

    added_keys = [k for k in raw_added_keys if not _is_ignored_key(k, ignored_checks)]
    removed_keys = [k for k in raw_removed_keys if not _is_ignored_key(k, ignored_checks)]

    # Keep object-level added issues too, so we can do risk-aware decisions.
    base_identity_keys = {_issue_identity_key(i) for i in base_issues}
    added_issue_objs: List[Dict[str, Any]] = []
    for issue in cand_issues:
        k = _issue_key(issue)
        if k in base_keys:
            continue
        if _is_ignored_key(k, ignored_checks):
            continue
        added_issue_objs.append(issue)

    added_issue_assessments: List[Dict[str, Any]] = []
    risk_rejections: List[Dict[str, Any]] = []

    functions_touched = transform_ctx.get("functions_touched") or set()
    new_lines_by_function = transform_ctx.get("new_lines_by_function") or {}

    for issue in added_issue_objs:
        k = _issue_key(issue)
        severity = k[1]
        severity_rank = _sev_rank(severity)
        fn = k[3]

        merged_meta = _merge_function_context(
            base_fn_meta.get(fn),
            cand_fn_meta.get(fn),
        )

        runtime_relevance = _safe_float(merged_meta.get("runtime_relevance"))
        policy_sensitivity = _safe_float(merged_meta.get("policy_sensitivity"))
        protected_regions = merged_meta.get("protected_regions") or []

        issue_lines = _issue_lines(issue)
        fn_touched_by_transform = fn in functions_touched
        near_changed_region = fn_touched_by_transform

        protected_tags_hit = _protected_tags_hit(
            issue_lines=issue_lines,
            protected_regions=protected_regions,
            strict_tags=strict_protected_tags,
            window=protected_region_overlap_window,
        )

        is_high_sensitivity_fn = (
            policy_sensitivity >= high_sensitivity_threshold
            or str(merged_meta.get("policy_sensitivity_band") or "").upper() == "HIGH"
        )
        is_hot_fn = runtime_relevance >= hot_runtime_threshold

        triggers: List[str] = []
        reject = False

        if reject_on_new_high and severity_rank >= _sev_rank("HIGH"):
            triggers.append("new_high_or_critical")
            reject = True

        if (
            not reject
            and reject_on_new_medium_in_high_sensitivity_fn
            and severity_rank >= _sev_rank("MEDIUM")
            and is_high_sensitivity_fn
            and (fn_touched_by_transform or near_changed_region)
        ):
            triggers.append("new_medium_in_high_sensitivity_function")
            reject = True

        if (
            not reject
            and reject_on_new_medium_in_hot_fn
            and severity_rank >= _sev_rank("MEDIUM")
            and is_hot_fn
            and (fn_touched_by_transform or near_changed_region)
        ):
            triggers.append("new_medium_in_hot_function")
            reject = True

        if (
            not reject
            and reject_on_new_issue_in_protected_region
            and severity_rank >= _sev_rank("LOW")
            and bool(protected_tags_hit)
            and (fn_touched_by_transform or near_changed_region)
        ):
            triggers.append("new_issue_overlaps_strict_protected_region")
            reject = True

        assessment = {
            "check": k[0],
            "severity": severity,
            "contract": k[2],
            "function": fn,
            "issue_lines": sorted(issue_lines),
            "runtime_relevance": runtime_relevance,
            "policy_sensitivity": policy_sensitivity,
            "policy_sensitivity_band": merged_meta.get("policy_sensitivity_band"),
            "function_touched_by_transform": fn_touched_by_transform,
            "near_changed_region": near_changed_region,
            "protected_tags_hit": protected_tags_hit,
            "reject": reject,
            "triggers": triggers,
        }
        added_issue_assessments.append(assessment)

        if reject:
            risk_rejections.append(assessment)

    transform_sensitive_touches = _transform_touches_protected_regions(
        transform_ctx=transform_ctx,
        fn_meta_map=cand_fn_meta if cand_fn_meta else base_fn_meta,
        strict_tags=strict_protected_tags,
        overlap_window=issue_transform_line_window,
    )

    transform_touch_rejections: List[Dict[str, Any]] = []
    if reject_on_transform_touching_protected_region:
        for row in transform_sensitive_touches:
            policy_sensitivity = _safe_float(row.get("policy_sensitivity"))
            runtime_relevance = _safe_float(row.get("runtime_relevance"))
            if (
                policy_sensitivity >= high_sensitivity_threshold
                or runtime_relevance >= hot_runtime_threshold
            ):
                transform_touch_rejections.append(row)

    ok = True
    reason = "ok"

    if risk_rejections:
        ok = False
        reason = "risk_policy_security_regression"
    elif transform_touch_rejections:
        ok = False
        reason = "transform_touched_strict_protected_region"

    new_high = [a for a in added_issue_assessments if _sev_rank(a["severity"]) >= _sev_rank("HIGH")]

    diff_report = {
        "ok": ok,
        "skipped": False,
        "reason": reason,
        "policy": {
            "reject_on_new_high_vuln": reject_on_new_high,
            "reject_on_new_medium_in_high_sensitivity_fn": reject_on_new_medium_in_high_sensitivity_fn,
            "reject_on_new_medium_in_hot_fn": reject_on_new_medium_in_hot_fn,
            "reject_on_new_issue_in_protected_region": reject_on_new_issue_in_protected_region,
            "reject_on_transform_touching_protected_region": reject_on_transform_touching_protected_region,
            "ignored_checks": sorted(ignored_checks),
            "high_sensitivity_threshold": high_sensitivity_threshold,
            "hot_runtime_threshold": hot_runtime_threshold,
            "strict_protected_tags": sorted(strict_protected_tags),
            "protected_region_overlap_window": protected_region_overlap_window,
            "issue_transform_line_window": issue_transform_line_window,
        },
        "paths": {
            "baseline_sec_advice": str(baseline_path),
            "candidate_sec_advice": str(candidate_path),
            "transform_map": str(transform_map_json) if transform_map_json is not None else None,
        },
        "counts": {
            "baseline_issues": len(base_issues),
            "candidate_issues": len(cand_issues),
            "added_raw": len(raw_added_keys),
            "removed_raw": len(raw_removed_keys),
            "added": len(added_keys),
            "removed": len(removed_keys),
            "new_high_or_critical": len(new_high),
            "risk_rejections": len(risk_rejections),
            "transform_sensitive_touches": len(transform_sensitive_touches),
            "transform_touch_rejections": len(transform_touch_rejections),
        },
        "added": [
            {"check": k[0], "severity": k[1], "contract": k[2], "function": k[3]}
            for k in added_keys
        ],
        "removed": [
            {"check": k[0], "severity": k[1], "contract": k[2], "function": k[3]}
            for k in removed_keys
        ],
        "added_issue_assessments": added_issue_assessments,
        "risk_rejections": risk_rejections,
        "transform_sensitive_touches": transform_sensitive_touches,
        "transform_touch_rejections": transform_touch_rejections,
        "note": (
            "Security diff is now risk-aware: "
            "severity + function sensitivity + runtime relevance + protected-region overlap + transform proximity."
        ),
    }

    diff_path.write_text(json.dumps(diff_report, indent=2), encoding="utf-8")

    return {
        "ok": ok,
        "skipped": False,
        "baseline_sec_advice": str(baseline_path),
        "candidate_sec_advice": str(candidate_path),
        "diff_report": str(diff_path),
        "added": len(added_keys),
        "removed": len(removed_keys),
        "new_high_or_critical": len(new_high),
        "risk_rejections": len(risk_rejections),
        "transform_sensitive_touches": len(transform_sensitive_touches),
        "note": "Security gate uses risk-aware differential analysis with transform-map context.",
    }