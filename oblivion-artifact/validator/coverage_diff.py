from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Set, Tuple


def _normalize_fn_name(name: str) -> str:
    """
    LCOV FN entries may contain:
      - "Contract.func"
      - "func"
      - "func(type1,type2)"

    Normalize to just the identifier part.
    """
    name = (name or "").strip()
    if "(" in name:
        name = name.split("(", 1)[0].strip()
    if "." in name:
        name = name.split(".")[-1].strip()
    return name


def covered_functions_from_lcov(lcov_path: Path) -> Set[str]:
    """
    Treat function as covered if FNDA count > 0.
    """
    lcov_path = Path(lcov_path)
    if not lcov_path.exists():
        raise FileNotFoundError(f"LCOV not found: {lcov_path}")

    covered: Set[str] = set()

    for raw in lcov_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = raw.strip()
        if raw.startswith("FNDA:"):
            rest = raw[len("FNDA:") :]
            if "," not in rest:
                continue
            count_s, name = rest.split(",", 1)
            try:
                count = int(count_s.strip())
            except Exception:
                continue
            if count > 0:
                covered.add(_normalize_fn_name(name))

    covered.discard("")
    return covered


def line_hits_from_lcov(lcov_path: Path) -> Dict[int, int]:
    """
    Parse DA:<line>,<count> entries.
    """
    lcov_path = Path(lcov_path)
    if not lcov_path.exists():
        raise FileNotFoundError(f"LCOV not found: {lcov_path}")

    hits: Dict[int, int] = {}
    for raw in lcov_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = raw.strip()
        if not raw.startswith("DA:"):
            continue
        rest = raw[len("DA:") :]
        if "," not in rest:
            continue
        line_s, count_s = rest.split(",", 1)
        try:
            line_no = int(line_s.strip())
            count = int(count_s.strip())
        except Exception:
            continue
        hits[line_no] = hits.get(line_no, 0) + count
    return hits


def covered_line_count_from_hits(hits: Dict[int, int]) -> int:
    return sum(1 for _ln, cnt in hits.items() if cnt > 0)


@dataclass(frozen=True)
class CoverageDiffResult:
    ok: bool
    skipped: bool
    reason: str
    baseline_lcov: str
    candidate_lcov: str
    baseline_count: int
    candidate_count: int
    dropped: Tuple[str, ...]
    added: Tuple[str, ...]
    baseline_line_count: int
    candidate_line_count: int
    dropped_lines: int
    added_lines: int
    line_coverage_ratio: float
    line_drop_ratio: float


def diff_coverage(
    *,
    baseline_lcov: Path,
    candidate_lcov: Path,
    out_json: Path,
    policy: Dict[str, bool] | None = None,
) -> CoverageDiffResult:
    """
    Obfuscation-friendly coverage diff.

    Important design:
    - Function-name drift is allowed.
    - Exact line-number matching is NOT used for acceptance because obfuscation
      can shift line numbers while preserving semantics.
    - Acceptance is based mainly on covered-line-count ratio.

    Supported policy keys:
      - reject_on_drop: bool                (default False)
      - use_line_coverage_gate: bool        (default True)
      - min_line_coverage_ratio: float      (default 0.70)
      - max_dropped_lines: int              (default 50)
      - allow_function_name_drift: bool     (default True)
    """
    policy = policy or {}

    reject_on_drop = bool(policy.get("reject_on_drop", False))
    use_line_coverage_gate = bool(policy.get("use_line_coverage_gate", True))
    min_line_coverage_ratio = float(policy.get("min_line_coverage_ratio", 0.70))
    max_dropped_lines = int(policy.get("max_dropped_lines", 50))
    allow_function_name_drift = bool(policy.get("allow_function_name_drift", True))

    out_json = Path(out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    if not Path(baseline_lcov).exists() or not Path(candidate_lcov).exists():
        res = CoverageDiffResult(
            ok=True,
            skipped=True,
            reason="missing_lcov_file",
            baseline_lcov=str(baseline_lcov),
            candidate_lcov=str(candidate_lcov),
            baseline_count=0,
            candidate_count=0,
            dropped=tuple(),
            added=tuple(),
            baseline_line_count=0,
            candidate_line_count=0,
            dropped_lines=0,
            added_lines=0,
            line_coverage_ratio=1.0,
            line_drop_ratio=0.0,
        )
        out_json.write_text(json.dumps(res.__dict__, indent=2), encoding="utf-8")
        return res

    base = covered_functions_from_lcov(Path(baseline_lcov))
    cand = covered_functions_from_lcov(Path(candidate_lcov))

    dropped = sorted(base - cand)
    added = sorted(cand - base)

    base_line_hits = line_hits_from_lcov(Path(baseline_lcov))
    cand_line_hits = line_hits_from_lcov(Path(candidate_lcov))

    baseline_line_count = covered_line_count_from_hits(base_line_hits)
    candidate_line_count = covered_line_count_from_hits(cand_line_hits)

    dropped_lines = max(0, baseline_line_count - candidate_line_count)
    added_lines = max(0, candidate_line_count - baseline_line_count)

    if baseline_line_count > 0:
        line_coverage_ratio = candidate_line_count / baseline_line_count
        line_drop_ratio = dropped_lines / baseline_line_count
    else:
        line_coverage_ratio = 1.0
        line_drop_ratio = 0.0

    ok = True
    reason = "ok"

    if use_line_coverage_gate:
        if line_coverage_ratio < min_line_coverage_ratio:
            ok = False
            reason = "candidate_line_coverage_ratio_too_low"
        elif dropped_lines > max_dropped_lines:
            ok = False
            reason = "candidate_dropped_too_many_covered_lines"
    elif reject_on_drop and not allow_function_name_drift:
        if len(dropped) > 0:
            ok = False
            reason = "candidate_dropped_covered_functions"

    if allow_function_name_drift and ok:
        reason = "ok_function_name_drift_allowed"

    res = CoverageDiffResult(
        ok=ok,
        skipped=False,
        reason=reason,
        baseline_lcov=str(baseline_lcov),
        candidate_lcov=str(candidate_lcov),
        baseline_count=len(base),
        candidate_count=len(cand),
        dropped=tuple(dropped),
        added=tuple(added),
        baseline_line_count=baseline_line_count,
        candidate_line_count=candidate_line_count,
        dropped_lines=dropped_lines,
        added_lines=added_lines,
        line_coverage_ratio=line_coverage_ratio,
        line_drop_ratio=line_drop_ratio,
    )
    out_json.write_text(json.dumps(res.__dict__, indent=2), encoding="utf-8")
    return res