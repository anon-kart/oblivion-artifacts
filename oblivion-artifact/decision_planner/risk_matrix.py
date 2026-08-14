# decision_planner/risk_matrix.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .catalog import TransformSpec


# ---------------------------------------------------------------------
# Coarse signals extracted from security advice (Slither-style)
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class IssueSignals:
    has_external_call_risk: bool = False
    has_reentrancy_risk: bool = False
    has_access_control_risk: bool = False
    has_arithmetic_risk: bool = False
    has_revert_semantics_risk: bool = False

    @classmethod
    def from_sec_entry(cls, sec_entry: Optional[Dict[str, Any]]) -> "IssueSignals":
        if not sec_entry:
            return cls()

        sig = {
            "has_external_call_risk": False,
            "has_reentrancy_risk": False,
            "has_access_control_risk": False,
            "has_arithmetic_risk": False,
            "has_revert_semantics_risk": False,
        }

        issues = sec_entry.get("issues") or []
        for iss in issues:
            chk = str(iss.get("check", "")).lower()
            desc = str(iss.get("description", "")).lower()
            blob = f"{chk} {desc}"

            # external calls / reentrancy-ish signals (heuristic)
            if any(
                k in blob
                for k in [
                    "reentr",
                    "external-call",
                    "low-level",
                    "call.value",
                    "delegatecall",
                    "send",
                    "transfer(",
                ]
            ):
                sig["has_external_call_risk"] = True
                if "reentr" in blob:
                    sig["has_reentrancy_risk"] = True

            # access control / auth checks
            if any(
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
            ):
                sig["has_access_control_risk"] = True

            # arithmetic/overflow/underflow
            if any(
                k in blob
                for k in [
                    "overflow",
                    "underflow",
                    "divide",
                    "mul",
                    "add",
                    "sub",
                    "arithmetic",
                    "unchecked",
                ]
            ):
                sig["has_arithmetic_risk"] = True

            # revert/require semantics risk (tests may require exact revert reasons / structure)
            if any(k in blob for k in ["revert", "require", "assert", "error("]):
                sig["has_revert_semantics_risk"] = True

        return cls(**sig)


# ---------------------------------------------------------------------
# Risk matrix policy
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class RiskMatrixPolicy:
    """
    Central "risk-aware claim" rules.

    Goal:
    - Always allow "always_safe" transforms (renaming/layout/simple constant transforms).
    - Contextual transforms are allowed unless blocked by concrete risk signals.
    - Heavy transforms are allowed only when tier allows AND no critical signals are present.
    """
    # Whether view/pure functions should ever get contextual control-flow transforms
    allow_contextual_control_in_view_pure: bool = False

    # For tier2, allow contextual transforms by default (unless blocked)
    allow_contextual_by_default: bool = True

    # If true, do not allow heavy transforms unless sec severity is LOW
    heavy_requires_low_severity: bool = True


# ---------------------------------------------------------------------
# Core decision: should a transform be allowed?
# ---------------------------------------------------------------------

def allow_transform(
    *,
    spec: TransformSpec,
    tier: int,
    sec_severity_max: str,
    signals: IssueSignals,
    fn_advice: Dict[str, Any],
    policy: Optional[RiskMatrixPolicy] = None,
) -> Tuple[bool, str]:
    """
    Returns (ok, reason_if_blocked).
    This is the *only* place that should encode 'risk-aware' gating logic.

    Important principle:
      - We DO NOT block always_safe transforms due to security signals.
      - We block only transforms that *can plausibly change semantics or auditability*
        under certain risk contexts.
    """
    pol = policy or RiskMatrixPolicy()

    sev = (sec_severity_max or "").upper().strip()
    mut = (fn_advice.get("state_mutability") or "").lower()
    has_loops = bool(fn_advice.get("has_loops"))

    # Tier 0: never
    if tier <= 0:
        return False, "tier0"

    # Respect tier bounds from catalog
    if tier < int(spec.tier_min) or tier > int(spec.tier_max):
        return False, "tier_out_of_bounds"

    # Always-safe transforms: never blocked by coarse signals
    if getattr(spec, "safety_class", "contextual") == "always_safe":
        # Still block loop-only transforms on no-loops? (none are always_safe currently)
        return True, ""

    safety_class = getattr(spec, "safety_class", "contextual")

    # Heavy transforms: very conservative
    if safety_class == "heavy":
        if tier < 3:
            return False, "heavy_requires_tier3"
        if pol.heavy_requires_low_severity and sev not in ("LOW", ""):
            return False, f"heavy_requires_low_severity_got_{sev or 'UNKNOWN'}"

        # Block heavy if any high-risk signals exist
        if signals.has_access_control_risk:
            return False, "heavy_blocked_access_control_risk"
        if signals.has_external_call_risk or signals.has_reentrancy_risk:
            return False, "heavy_blocked_external_call_or_reentrancy_risk"
        if signals.has_revert_semantics_risk and "touches_reverts" in (spec.risk_tags or []):
            return False, "heavy_blocked_revert_semantics_risk"

        # Yul is heavy and also special-case (avoid in non-low severity anyway)
        if "uses_yul" in (spec.risk_tags or []) and sev not in ("LOW", ""):
            return False, "yul_blocked_nonlow_severity"

        return True, ""

    # Contextual transforms: allow by default, then block based on concrete risks
    if safety_class == "contextual":
        # If policy says don't allow contextual by default, you'd restrict here
        if not pol.allow_contextual_by_default:
            return False, "contextual_disabled_by_policy"

        # Feature gating (not "risk", just "doesn't make sense")
        if spec.id == "loop_rewrite_v1" and not has_loops:
            return False, "no_loops"

        # View/pure: keep as stable as possible (optional)
        if mut in ("view", "pure"):
            # Always allow non-control-flow contextual (e.g., string_split/algebraic)
            if "touches_control_flow" in (spec.risk_tags or []):
                if not pol.allow_contextual_control_in_view_pure:
                    return False, "view_pure_blocks_control_flow_contextual"

        # Access control risk: avoid messing with guards / conditions
        if signals.has_access_control_risk:
            if "touches_control_flow" in (spec.risk_tags or []):
                return False, "access_control_risk_blocks_control_flow"

        # External call / reentrancy signals:
        # Avoid transforms that can obscure call-sites or reorder logic substantially.
        if signals.has_external_call_risk or signals.has_reentrancy_risk:
            if spec.id in ("inline_internal_v1",):
                return False, "external_or_reentrancy_blocks_inlining"
            # If you later add storage transforms as contextual, block them here.
            if "touches_storage" in (spec.risk_tags or []):
                return False, "external_or_reentrancy_blocks_storage_touching"

        # Arithmetic risk: block algebraic identities (could change overflow behavior)
        if signals.has_arithmetic_risk:
            if spec.id in ("algebraic_identities_v1",):
                return False, "arithmetic_risk_blocks_algebraic_identities"

        # Revert semantics risk: block transforms that can disturb revert strings/paths
        if signals.has_revert_semantics_risk:
            if spec.id in ("string_split_v1",):
                return False, "revert_semantics_blocks_string_split"
            if "touches_reverts" in (spec.risk_tags or []):
                return False, "revert_semantics_blocks_revert_touching"

        return True, ""

    # Unknown safety_class => be conservative but not over-blocking
    # Treat as contextual
    return True, ""
