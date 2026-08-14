# decision_planner/scores.py
# NOTE:
# This module is now legacy for the main OBLIVION pipeline.
# Canonical tier computation lives in obfuscation_advisor/tiering.py
# and is consumed read-only by downstream planners.
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


# -----------------------------
# Utilities
# -----------------------------

_SEV_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


# -----------------------------
# Optional container (useful for debugging / future refactors)
# -----------------------------

@dataclass(frozen=True)
class FunctionScores:
    econ_score: float
    sec_score: float
    sec_severity_max: str
    tier: int
    tier_reason: str


# -----------------------------
# Security scoring
# -----------------------------

def severity_to_sec_score(sev: str) -> float:
    """
    Map Slither severity_max to a normalized [0,1] security risk score.
    """
    s = (sev or "INFO").upper().strip()
    r = _SEV_RANK.get(s, 0)

    # Linear normalization: INFO=0.0 … CRITICAL=1.0
    return clamp01(r / 4.0)


def compute_sec_score(fn_sec: Optional[Dict[str, Any]]) -> Tuple[float, str]:
    """
    Compute security score for a function.

    fn_sec: one entry from sec_advice["functions"], e.g.
      {
        "function": "deposit",
        "severity_max": "LOW",
        "issues": [...]
      }

    Returns:
      (sec_score [0..1], severity_max)
    """
    if not fn_sec:
        return 0.0, "INFO"

    sev = (fn_sec.get("severity_max") or "INFO").upper()
    base = severity_to_sec_score(sev)

    # Small bounded bump based on issue count
    issues = fn_sec.get("issues") or []
    bump = 0.0
    if isinstance(issues, list):
        bump = min(0.15, 0.03 * len(issues))

    return clamp01(base + bump), sev


# -----------------------------
# Economic / importance scoring
# -----------------------------

def compute_econ_score(
    fn_advice: Dict[str, Any],
    *,
    ir: Optional[Dict[str, Any]] = None,
    coverage: Optional[Dict[str, Any]] = None,
) -> float:
    """
    Compute an economic / importance score in [0,1].

    v1 policy:
      - Use per-function fields when present (dynamic_calls/static_hits/coverage_pct).
      - Otherwise (optional): fall back to using coverage JSON + IR to derive a weak signal.
        (Kept best-effort + non-fatal; if formats differ, we just ignore.)

    Signals used (v1):
      - dynamic_calls: runtime hotness (from traces)
      - static_hits / coverage_pct: coverage presence
      - visibility: public/external are more valuable
      - state_mutability: non-view/pure mutates state
      - has_loops: heuristic for algorithmic complexity
    """
    # NOTE: your previous version had a variable typo: fn_adv vs fn_advice.
    fn_adv = fn_advice

    # Prefer fields from advisor output
    dyn = int(fn_adv.get("dynamic_calls") or 0)
    hits = int(fn_adv.get("static_hits") or 0)

    # If you track percent coverage in advisor output, treat it as a better signal than hits
    cov_pct = fn_adv.get("coverage_pct")
    cov_pct_f: Optional[float] = None
    try:
        if cov_pct is not None:
            cov_pct_f = float(cov_pct)
    except Exception:
        cov_pct_f = None

    vis = (fn_adv.get("visibility") or "").lower()
    mut = (fn_adv.get("state_mutability") or "").lower()
    has_loops = bool(fn_adv.get("has_loops"))

    # -----------------
    # Fallback coverage signal (best-effort)
    # -----------------
    # If static_hits isn't populated, but we have coverage JSON, try to get a weak proxy.
    # This is intentionally conservative because coverage formats vary.
    if hits == 0 and cov_pct_f is None and isinstance(coverage, dict):
        # Common patterns you might produce:
        # - coverage["functions"][<full_name or function>] = {"hits": N, "pct": ...}
        # - coverage["by_function"][...]
        # - coverage["function_coverage"][...]
        fn_key_candidates = [
            fn_adv.get("full_name") or "",
            fn_adv.get("function") or "",
        ]
        for root_key in ("functions", "by_function", "function_coverage"):
            table = coverage.get(root_key)
            if not isinstance(table, dict):
                continue
            for k in fn_key_candidates:
                if not k:
                    continue
                rec = table.get(k)
                if isinstance(rec, dict):
                    try:
                        if cov_pct_f is None and rec.get("pct") is not None:
                            cov_pct_f = float(rec.get("pct"))
                        if hits == 0 and rec.get("hits") is not None:
                            hits = int(rec.get("hits"))
                    except Exception:
                        pass

    # Hotness (saturating curve)
    # dyn: 0→0.0, 5→0.33, 20→0.66, 50+→~0.83
    hot = dyn / (dyn + 10.0)

    # Coverage signal (saturating)
    if cov_pct_f is not None:
        # Treat percent as already [0..100] or [0..1] (best-effort)
        cov_norm = cov_pct_f
        if cov_norm > 1.0:
            cov_norm = cov_norm / 100.0
        cov = clamp01(cov_norm)
    else:
        cov = hits / (hits + 10.0)

    # Criticality bonuses
    crit = 0.0
    if vis in ("public", "external"):
        crit += 0.15
    if mut not in ("view", "pure"):
        crit += 0.20
    if has_loops:
        crit += 0.05

    score = 0.55 * hot + 0.35 * cov + crit
    return clamp01(score)


# -----------------------------
# Tier fusion logic
# -----------------------------

def fuse_tier(
    *,
    econ_score: float,
    sec_score: float,
    sev: str,
) -> Tuple[int, str]:
    """
    Fuse econ_score + security severity into a final obfuscation tier.

    Policy (v1):

    Security clamp:
      - CRITICAL / HIGH   → tier 0 (no obfuscation)
      - MEDIUM            → at most tier 1

    Econ-driven (LOW / INFO only):
      econ ≥ 0.70 → tier 3
      econ ≥ 0.40 → tier 2
      econ ≥ 0.15 → tier 1
      else        → tier 0
    """
    s = (sev or "INFO").upper()

    if s in ("CRITICAL", "HIGH"):
        return 0, f"clamped_to_tier0_due_to_severity_{s}"

    if s == "MEDIUM":
        if econ_score >= 0.15:
            return 1, "tier1_due_to_medium_severity"
        return 0, "tier0_due_to_medium_severity_and_low_econ"

    # LOW / INFO
    if econ_score >= 0.70:
        return 3, "tier3_high_econ_low_risk"
    if econ_score >= 0.40:
        return 2, "tier2_mid_econ_low_risk"
    if econ_score >= 0.15:
        return 1, "tier1_low_econ_low_risk"

    return 0, "tier0_too_cold"
