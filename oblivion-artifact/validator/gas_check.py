# validator/gas_check.py

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _pct_overhead(baseline: int, candidate: int) -> float:
    if baseline <= 0:
        return 0.0
    return ((candidate - baseline) / baseline) * 100.0


def _mean(xs: List[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _median(xs: List[float]) -> float:
    if not xs:
        return 0.0
    ys = sorted(xs)
    n = len(ys)
    mid = n // 2
    if n % 2 == 1:
        return ys[mid]
    return (ys[mid - 1] + ys[mid]) / 2.0


def check_gas(
    *,
    baseline_gas_by_test: Dict[str, int],
    candidate_gas_by_test: Dict[str, int],
    out_dir: Path,
    policy: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Compare baseline vs candidate per-test gas.

    Policy:
      - gas_budget_pct: float (default 25.0)
      - gas_metric: "median" | "mean" (default "median")
      - min_common_tests: int (default 1)
    """
    policy = policy or {}
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    budget = float(policy.get("gas_budget_pct", 25.0))
    metric = str(policy.get("gas_metric", "median")).lower()
    min_common = int(policy.get("min_common_tests", 1))

    common = sorted(set(baseline_gas_by_test.keys()) & set(candidate_gas_by_test.keys()))
    missing_in_candidate = sorted(set(baseline_gas_by_test.keys()) - set(candidate_gas_by_test.keys()))
    missing_in_baseline = sorted(set(candidate_gas_by_test.keys()) - set(baseline_gas_by_test.keys()))

    per_test: List[Dict[str, Any]] = []
    overheads: List[float] = []

    for t in common:
        b = int(baseline_gas_by_test.get(t, 0))
        c = int(candidate_gas_by_test.get(t, 0))
        pct = _pct_overhead(b, c)
        per_test.append(
            {
                "test": t,
                "baseline_gas": b,
                "candidate_gas": c,
                "overhead_pct": pct,
            }
        )
        overheads.append(pct)

    mean_pct = _mean(overheads)
    median_pct = _median(overheads)
    used_metric = median_pct if metric == "median" else mean_pct

    ok = True
    reason = "ok"

    if len(common) < min_common:
        ok = False
        reason = f"insufficient_common_tests(common={len(common)} < min_common_tests={min_common})"
    elif used_metric > budget:
        ok = False
        reason = f"gas_over_budget({metric}={used_metric:.2f}% > {budget:.2f}%)"

    diff_path = out_dir / "gas_diff.json"
    diff_path.write_text(
        json.dumps(
            {
                "ok": ok,
                "reason": reason,
                "policy": {
                    "gas_budget_pct": budget,
                    "gas_metric": metric,
                    "min_common_tests": min_common,
                },
                "counts": {
                    "baseline_tests": len(baseline_gas_by_test),
                    "candidate_tests": len(candidate_gas_by_test),
                    "common_tests": len(common),
                },
                "metric": {
                    "mean_overhead_pct": mean_pct,
                    "median_overhead_pct": median_pct,
                    "used_metric": metric,
                    "used_value": used_metric,
                },
                "missing": {
                    "missing_in_candidate": missing_in_candidate,
                    "missing_in_baseline": missing_in_baseline,
                },
                "per_test": per_test,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return {
        "ok": ok,
        "skipped": False,
        "reason": reason,
        "paths": {"diff_json": str(diff_path)},
        "counts": {
            "baseline_tests": len(baseline_gas_by_test),
            "candidate_tests": len(candidate_gas_by_test),
            "common_tests": len(common),
        },
        "metric": {
            "mean_overhead_pct": mean_pct,
            "median_overhead_pct": median_pct,
            "used_metric": metric,
            "used_value": used_metric,
            "budget_pct": budget,
        },
    }
