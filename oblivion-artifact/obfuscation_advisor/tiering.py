from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


def clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


@dataclass(frozen=True)
class TierInputs:
    function: str
    visibility: str
    state_mutability: str

    econ_score: float
    sec_score: float
    coverage_score: float
    exec_weight: float

    sec_severity: str
    runtime_relevance: float

    has_loops: bool
    loop_count: int
    is_access_controlled: bool

    static_hits: int
    dynamic_calls: int

    policy_sensitivity: float
    policy_sensitivity_band: str
    protected_region_count: int
    protected_region_tags: tuple[str, ...]


@dataclass(frozen=True)
class TierResult:
    tier: int
    reason: str


DEFAULT_TIER_POLICY: Dict[str, Any] = {
    "econ_thresholds": {
        "tier1": 0.15,
        "tier2": 0.40,
        "tier3": 0.70,
    },
    "security_caps": {
        "INFO": 3,
        "LOW": 3,
        "MEDIUM": 1,
        "HIGH": 0,
        "CRITICAL": 0,
    },
    "coverage_guards": {
        "min_coverage_for_tier1": 0.10,
        "min_coverage_for_tier2": 0.30,
        "min_coverage_for_tier3": 0.45,
        "min_exec_weight_for_tier1": 0.05,
    },
    "view_pure_max_tier": 1,
    "internal_like_max_tier": 0,
    "access_controlled_medium_plus_max_tier": 0,
    "require_loops_for_tier3": True,
    "runtime_relevance_modifiers": {
        "promote_threshold": 0.60,
        "demote_threshold": 0.05,
        "enabled": True,
    },
    "policy_sensitivity_caps": {
        "INFO": 3,
        "LOW": 2,
        "MEDIUM": 1,
        "HIGH": 0,
    },
    "protected_region_caps": {
        "any": 1,
        "access_control_or_external_call": 0,
    },
}


def merge_tier_policy(user_policy: Dict[str, Any] | None) -> Dict[str, Any]:
    merged = {
        "econ_thresholds": dict(DEFAULT_TIER_POLICY["econ_thresholds"]),
        "security_caps": dict(DEFAULT_TIER_POLICY["security_caps"]),
        "coverage_guards": dict(DEFAULT_TIER_POLICY["coverage_guards"]),
        "runtime_relevance_modifiers": dict(DEFAULT_TIER_POLICY["runtime_relevance_modifiers"]),
        "policy_sensitivity_caps": dict(DEFAULT_TIER_POLICY["policy_sensitivity_caps"]),
        "protected_region_caps": dict(DEFAULT_TIER_POLICY["protected_region_caps"]),
        "view_pure_max_tier": DEFAULT_TIER_POLICY["view_pure_max_tier"],
        "internal_like_max_tier": DEFAULT_TIER_POLICY["internal_like_max_tier"],
        "access_controlled_medium_plus_max_tier": DEFAULT_TIER_POLICY["access_controlled_medium_plus_max_tier"],
        "require_loops_for_tier3": DEFAULT_TIER_POLICY["require_loops_for_tier3"],
    }

    if not isinstance(user_policy, dict):
        return merged

    for top_key in (
        "econ_thresholds",
        "security_caps",
        "coverage_guards",
        "runtime_relevance_modifiers",
        "policy_sensitivity_caps",
        "protected_region_caps",
    ):
        if isinstance(user_policy.get(top_key), dict):
            merged[top_key].update(user_policy[top_key])

    for top_key in (
        "view_pure_max_tier",
        "internal_like_max_tier",
        "access_controlled_medium_plus_max_tier",
        "require_loops_for_tier3",
    ):
        if top_key in user_policy:
            merged[top_key] = user_policy[top_key]

    return merged


def compute_tier(inputs: TierInputs, policy: Dict[str, Any] | None = None) -> TierResult:
    p = merge_tier_policy(policy)

    fn = (inputs.function or "").strip()
    vis = (inputs.visibility or "").lower().strip()
    mut = (inputs.state_mutability or "").lower().strip()
    sev = (inputs.sec_severity or "INFO").upper().strip()

    econ = clamp01(float(inputs.econ_score))
    sec = clamp01(float(inputs.sec_score))
    cov = clamp01(float(inputs.coverage_score))
    exec_weight = clamp01(float(inputs.exec_weight))
    runtime_relevance = clamp01(float(inputs.runtime_relevance))

    base_reason = ""
    runtime_note = "none"
    sensitivity_note = "none"
    protected_region_note = "none"
    security_note = "none"
    structural_note = "none"

    # ------------------------------------------------------------
    # Hard structural guards
    # ------------------------------------------------------------
    if fn == "constructor":
        return TierResult(
            tier=int(p["internal_like_max_tier"]),
            reason="internal_like_or_constructor_guard",
        )

    if vis in ("internal", "private") or fn.startswith("_"):
        helper_cap = int(p["internal_like_max_tier"])
        if (
            runtime_relevance >= 0.20
            and econ >= float(p["econ_thresholds"]["tier2"])
            and sev in ("INFO", "LOW")
        ):
            helper_cap = max(helper_cap, 2)
        return TierResult(
            tier=helper_cap,
            reason="internal_like_or_constructor_guard",
        )

    if int(inputs.static_hits) == 0 and int(inputs.dynamic_calls) == 0:
        return TierResult(
            tier=0,
            reason="no_runtime_evidence",
        )

    # ------------------------------------------------------------
    # Base tier from econ score
    # ------------------------------------------------------------
    econ_thr = p["econ_thresholds"]

    if econ >= float(econ_thr["tier3"]):
        base_tier = 3
        base_reason = "econ_base_tier3"
    elif econ >= float(econ_thr["tier2"]):
        base_tier = 2
        base_reason = "econ_base_tier2"
    elif econ >= float(econ_thr["tier1"]):
        base_tier = 1
        base_reason = "econ_base_tier1"
    else:
        base_tier = 0
        base_reason = "econ_too_low"

    tier = base_tier

    # ------------------------------------------------------------
    # Confidence / evidence guards
    # ------------------------------------------------------------
    cov_guards = p["coverage_guards"]

    if exec_weight < float(cov_guards["min_exec_weight_for_tier1"]):
        tier = 0
        base_reason = "exec_weight_too_low"

    if tier >= 1 and cov < float(cov_guards["min_coverage_for_tier1"]):
        tier = 0
        base_reason = "coverage_below_tier1_floor"

    if tier >= 2 and cov < float(cov_guards["min_coverage_for_tier2"]):
        tier = 1
        base_reason = "coverage_caps_at_tier1"

    if tier >= 3 and cov < float(cov_guards["min_coverage_for_tier3"]):
        tier = 2
        base_reason = "coverage_caps_at_tier2"

    # ------------------------------------------------------------
    # Runtime relevance modifiers
    # ------------------------------------------------------------
    rr_cfg = p["runtime_relevance_modifiers"]
    if bool(rr_cfg.get("enabled", True)):
        promote_threshold = clamp01(float(rr_cfg.get("promote_threshold", 0.60)))
        demote_threshold = clamp01(float(rr_cfg.get("demote_threshold", 0.05)))

        if runtime_relevance >= promote_threshold:
            tier = min(tier + 1, 3)
            runtime_note = "promoted_by_runtime_relevance"
        elif runtime_relevance <= demote_threshold and tier >= 2:
            tier = max(0, tier - 1)
            runtime_note = "demoted_by_low_runtime_relevance"

    # ------------------------------------------------------------
    # Policy sensitivity caps
    # applied separately from vulnerability risk
    # ------------------------------------------------------------
    ps = clamp01(float(inputs.policy_sensitivity))
    ps_band = (inputs.policy_sensitivity_band or "INFO").upper().strip()

    policy_caps = p.get("policy_sensitivity_caps", {})
    if ps_band in policy_caps:
        cap = int(policy_caps[ps_band])
        if tier > cap:
            tier = cap
            sensitivity_note = f"policy_sensitivity_cap_{ps_band.lower()}"

    if ps >= 0.75 and tier > 0:
        tier = 0
        sensitivity_note = "policy_sensitivity_hard_cap"
    elif ps >= 0.40 and tier > 1:
        tier = 1
        sensitivity_note = "policy_sensitivity_medium_cap"

    # ------------------------------------------------------------
    # Protected-region caps
    # semantically meaningful handling based on tags, not only count
    # ------------------------------------------------------------
    pr_count = max(0, int(inputs.protected_region_count))
    pr_caps = p.get("protected_region_caps", {})
    pr_tags = {
        str(x).strip()
        for x in (inputs.protected_region_tags or ())
        if str(x).strip()
    }

    hard_region_tags = {
        "access_control_guard",
        "external_call_site",
    }

    medium_region_tags = {
        "revert_semantics_region",
        "state_write_region",
    }

    if hard_region_tags & pr_tags:
        pr_cap = int(pr_caps.get("access_control_or_external_call", 0))
        if tier > pr_cap:
            tier = pr_cap
            protected_region_note = "protected_region_cap_hard_sensitive_region"

    elif medium_region_tags & pr_tags:
        pr_cap = int(pr_caps.get("any", 1))
        if runtime_relevance >= 0.20 and sev in ("INFO", "LOW"):
            pr_cap = max(pr_cap, 2)
        if tier > pr_cap:
            tier = pr_cap
            protected_region_note = "protected_region_cap_medium_sensitive_region"

    else:
        # arithmetic_region / loop_region alone should not hard-cap the function
        # they are important for compatibility gating, but not enough to collapse tiering
        pass

    # ------------------------------------------------------------
    # Security caps
    # sec_score / sec_severity remain vulnerability-risk signals
    # ------------------------------------------------------------
    security_caps = p["security_caps"]
    if sev in security_caps:
        cap = int(security_caps[sev])
        if tier > cap:
            tier = cap
            security_note = f"security_cap_{sev.lower()}"

    # Extra clamp when access-controlled and already risky
    if inputs.is_access_controlled and sev in ("MEDIUM", "HIGH", "CRITICAL"):
        cap = int(p["access_controlled_medium_plus_max_tier"])
        if tier > cap:
            tier = cap
            security_note = "access_controlled_security_cap"

    # ------------------------------------------------------------
    # Pure/view clamp
    # ------------------------------------------------------------
    if mut in ("view", "pure"):
        cap = int(p["view_pure_max_tier"])
        if tier > cap:
            tier = cap
            structural_note = "view_pure_cap"

    # ------------------------------------------------------------
    # Tier-3 structural requirement
    # ------------------------------------------------------------
    if tier >= 3 and bool(p["require_loops_for_tier3"]) and not inputs.has_loops:
        tier = 2
        structural_note = "tier3_requires_loops"

    # Slightly conservative cap for very high sec_score even if severity text is weak
    if sec >= 0.85 and tier > 0:
        tier = 0
        security_note = "sec_score_hard_cap"
    elif sec >= 0.50 and tier > 1:
        tier = 1
        security_note = "sec_score_medium_cap"

    final_tier = int(max(0, min(3, tier)))

    reason_parts = [base_reason]

    if runtime_note != "none":
        reason_parts.append(runtime_note)
    if sensitivity_note != "none":
        reason_parts.append(sensitivity_note)
    if protected_region_note != "none":
        reason_parts.append(protected_region_note)
    if security_note != "none":
        reason_parts.append(security_note)
    if structural_note != "none":
        reason_parts.append(structural_note)

    final_reason = "+".join(reason_parts)

    return TierResult(tier=final_tier, reason=final_reason)