from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List

from .catalog import TransformSpec


@dataclass(frozen=True)
class SecSignals:
    has_external_call_risk: bool = False
    has_reentrancy_risk: bool = False
    has_access_control_risk: bool = False
    has_arithmetic_risk: bool = False
    has_revert_semantics_risk: bool = False


VULN_REENTRANCY = "reentrancy"
VULN_EXTERNAL_CALL = "external_call"
VULN_ACCESS_CONTROL = "access_control"
VULN_ARITHMETIC = "arithmetic"
VULN_REVERT_SEMANTICS = "revert_semantics"


DEFAULT_TRANSFORM_VULN_MATRIX: Dict[str, Dict[str, Any]] = {
    VULN_REENTRANCY: {
        "forbidden_transform_ids": [
            "dispatcher_cfg_virtualization_v1",
            "cfg_flatten_v1",
            "cfg_flatten_v2_hybrid",
            "yul_microblock_v1",
            "local_to_state_lift_v1",
            "scalar_to_struct_indirection_v1",
            "public_state_accessor_indirection_v1",
            "opaque_storage_slot_indirection_v1",
        ],
        "forbidden_risk_tags": [
            "touches_storage",
            "touches_control_flow",
        ],
    },
    VULN_EXTERNAL_CALL: {
        "forbidden_transform_ids": [
            "dispatcher_cfg_virtualization_v1",
            "cfg_flatten_v1",
            "cfg_flatten_v2_hybrid",
            "yul_microblock_v1",
            "local_to_state_lift_v1",
            "opaque_storage_slot_indirection_v1",
            "inline_internal_v2_diversified",
        ],
        "forbidden_risk_tags": [
            "touches_storage",
        ],
    },
    VULN_ACCESS_CONTROL: {
        "forbidden_transform_ids": [
            "modifier_expand_v1",
            "predicate_masking_v1",
            "opaque_predicate_v1",
            "opaque_predicate_v2_entangled",
            "chaotic_opaque_predicate_v1",
            "cfg_flatten_v1",
            "cfg_flatten_v2_hybrid",
            "dispatcher_cfg_virtualization_v1",
        ],
        "forbidden_risk_tags": [
            "touches_access_control",
            "touches_reverts",
        ],
    },

    # IMPORTANT FIX:
    # Do NOT blanket-block safe constant/literal transforms just because a function
    # contains arithmetic-sensitive regions. Engine-level applicability + validation
    # should decide whether the literal site is safe.
    VULN_ARITHMETIC: {
        "forbidden_transform_ids": [
            "algebraic_identities_v1",
            "predicate_masking_v1",
        ],
        "forbidden_risk_tags": [],
    },

    VULN_REVERT_SEMANTICS: {
        "forbidden_transform_ids": [
            "modifier_expand_v1",
            "predicate_masking_v1",
            "string_split_v1",
        ],
        "forbidden_risk_tags": [
            "touches_reverts",
        ],
    },
}


def active_vulnerability_labels(signals: SecSignals) -> List[str]:
    labels: List[str] = []

    if signals.has_reentrancy_risk:
        labels.append(VULN_REENTRANCY)
    if signals.has_external_call_risk:
        labels.append(VULN_EXTERNAL_CALL)
    if signals.has_access_control_risk:
        labels.append(VULN_ACCESS_CONTROL)
    if signals.has_arithmetic_risk:
        labels.append(VULN_ARITHMETIC)
    if signals.has_revert_semantics_risk:
        labels.append(VULN_REVERT_SEMANTICS)

    return labels


def matrix_block_reason(
    *,
    spec: TransformSpec,
    vuln_labels: List[str],
    matrix: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[bool, str]:
    mat = matrix or DEFAULT_TRANSFORM_VULN_MATRIX

    for vuln in vuln_labels:
        row = mat.get(vuln) or {}
        forbidden_ids = set(row.get("forbidden_transform_ids") or [])
        forbidden_tags = set(row.get("forbidden_risk_tags") or [])

        if spec.id in forbidden_ids:
            return True, f"compat_matrix_blocks_{spec.id}_for_{vuln}"

        for tag in spec.risk_tags:
            if tag in forbidden_tags:
                return True, f"compat_matrix_blocks_risk_tag_{tag}_for_{vuln}"

    return False, ""


def explicit_constraint_block_reason(
    *,
    spec: TransformSpec,
    policy_constraints: Optional[Dict[str, Any]],
) -> Tuple[bool, str]:
    if not isinstance(policy_constraints, dict):
        return False, ""

    forbidden_ids = set(policy_constraints.get("forbid_transform_ids") or [])
    forbidden_tags = set(policy_constraints.get("forbid_risk_tags") or [])

    if spec.id in forbidden_ids:
        return True, f"policy_constraints_block_{spec.id}"

    for tag in spec.risk_tags:
        if tag in forbidden_tags:
            return True, f"policy_constraints_block_risk_tag_{tag}"

    return False, ""


def protected_region_block_reason(
    *,
    spec: TransformSpec,
    protected_regions: List[Dict[str, Any]],
) -> Tuple[bool, str]:
    tags = {str(r.get("tag") or "").strip() for r in protected_regions or []}
    for blocked_tag in getattr(spec, "protected_region_conflicts", []) or []:
        if blocked_tag in tags:
            return True, f"protected_region_blocks_{spec.id}_on_{blocked_tag}"
    return False, ""


def extract_signals(sec_entry: Optional[Dict[str, Any]]) -> SecSignals:
    if not sec_entry:
        return SecSignals()

    issues = sec_entry.get("issues") or []
    policy_signals = sec_entry.get("policy_signals") or {}
    protected_regions = sec_entry.get("protected_regions") or []

    ext = False
    reent = False
    acc = False
    arith = False
    rev = False

    for iss in issues:
        chk = str(iss.get("check", "")).lower()
        desc = str(iss.get("description", "")).lower()
        blob = f"{chk} {desc}"

        if any(k in blob for k in ["reentr", "external-call", "low-level", "delegatecall", "call.value", "send", "transfer("]):
            ext = True
            if "reentr" in blob:
                reent = True

        if any(k in blob for k in ["access-control", "missing-access", "onlyowner", "owner", "role", "auth", "permission"]):
            acc = True

        if any(k in blob for k in ["overflow", "underflow", "divide", "mul", "add", "sub", "arithmetic", "unchecked"]):
            arith = True

        if any(k in blob for k in ["revert", "require", "assert", "error("]):
            rev = True

    ext = ext or bool(policy_signals.get("external_call_sensitive"))
    reent = reent or bool(policy_signals.get("reentrancy_sensitive"))
    acc = acc or bool(policy_signals.get("access_control_sensitive"))
    arith = arith or bool(policy_signals.get("arithmetic_sensitive"))
    rev = rev or bool(policy_signals.get("revert_semantics_sensitive"))

    region_tags = {
        str(r.get("tag") or "").strip()
        for r in protected_regions
        if isinstance(r, dict) and r.get("tag")
    }

    if "external_call_site" in region_tags:
        ext = True
    if "access_control_guard" in region_tags:
        acc = True
    if "arithmetic_region" in region_tags:
        arith = True
    if "revert_semantics_region" in region_tags:
        rev = True

    return SecSignals(
        has_external_call_risk=ext,
        has_reentrancy_risk=reent,
        has_access_control_risk=acc,
        has_arithmetic_risk=arith,
        has_revert_semantics_risk=rev,
    )


def _boolish(d: Dict[str, Any], *keys: str) -> bool:
    for k in keys:
        if bool(d.get(k)):
            return True
    return False


def _intish(d: Dict[str, Any], *keys: str) -> int:
    for k in keys:
        if k in d:
            try:
                return int(d.get(k) or 0)
            except Exception:
                return 0
    return 0


def compatible(
    *,
    spec: TransformSpec,
    tier: int,
    signals: SecSignals,
    fn_advice: Dict[str, Any],
    sec_severity_max: str,
    protected_regions: Optional[List[Dict[str, Any]]] = None,
    policy_constraints: Optional[Dict[str, Any]] = None,
    matrix: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[bool, str]:

    sev = (sec_severity_max or "").upper().strip()

    if tier <= 0:
        return False, "tier0"

    if tier < spec.tier_min or tier > spec.tier_max:
        return False, "tier_out_of_range"

    vuln_labels = active_vulnerability_labels(signals)
    blocked, reason = matrix_block_reason(
        spec=spec,
        vuln_labels=vuln_labels,
        matrix=matrix,
    )
    if blocked:
        return False, reason

    blocked, reason = explicit_constraint_block_reason(
        spec=spec,
        policy_constraints=policy_constraints,
    )
    if blocked:
        return False, reason

    blocked, reason = protected_region_block_reason(
        spec=spec,
        protected_regions=protected_regions or [],
    )
    if blocked:
        return False, reason

    mut = (fn_advice.get("state_mutability") or fn_advice.get("mutability") or "").lower().strip()

    has_loops = bool(fn_advice.get("has_loops"))
    if not has_loops:
        loop_count = _intish(fn_advice, "loop_count", "loops_count", "num_loops", "n_loops")
        if loop_count > 0:
            has_loops = True
        elif isinstance(fn_advice.get("loops"), list) and len(fn_advice.get("loops") or []) > 0:
            has_loops = True

    has_external_calls = _boolish(fn_advice, "has_external_calls", "calls_external")
    if not has_external_calls:
        for k in ("external_calls", "call_sites", "calls"):
            v = fn_advice.get(k)
            if isinstance(v, list) and len(v) > 0:
                has_external_calls = True
                break

    has_modifiers = False
    for k in ("modifiers", "modifier_invocations", "applied_modifiers", "modifiers_full"):
        v = fn_advice.get(k)
        if isinstance(v, list) and len(v) > 0:
            has_modifiers = True
            break

    has_storage_refs = False
    for k in ("reads_storage", "writes_storage", "storage_reads", "storage_writes"):
        v = fn_advice.get(k)
        if isinstance(v, list) and len(v) > 0:
            has_storage_refs = True
            break

    return_var_count = 0
    for k in ("return_vars", "returns_named", "named_returns"):
        v = fn_advice.get(k)
        if isinstance(v, list):
            return_var_count = max(return_var_count, len(v))

    has_public_state_abi_risk = _boolish(
        fn_advice,
        "has_public_state_abi_risk",
        "touches_public_state_getter",
        "public_state_getter_risk",
    )
    has_inheritance_complexity = _boolish(
        fn_advice,
        "has_inheritance_complexity",
        "inheritance_complexity",
        "has_override",
        "override_complexity",
    )
    constructor_state_complexity = _boolish(
        fn_advice,
        "constructor_state_complexity",
        "constructor_writes_complex",
        "has_immutable_state",
        "immutable_state_present",
    )
    modifier_complexity = _boolish(
        fn_advice,
        "modifier_has_post_placeholder_code",
        "modifier_has_external_calls",
        "modifier_has_loops",
        "multiple_modifiers_stacked",
        "modifier_complexity",
    )

    if sev in ("HIGH", "CRITICAL"):
        if spec.risk == "high":
            return False, f"sev_{sev}_blocks_high_risk_transform"
        if "uses_yul" in spec.risk_tags:
            return False, f"sev_{sev}_blocks_yul"

    if spec.safety_class == "heavy":
        if tier < 3:
            return False, "heavy_requires_tier3"
        if sev in ("MEDIUM", "HIGH", "CRITICAL"):
            return False, f"sev_{sev}_blocks_heavy_transform"

    if signals.has_access_control_risk:
        if "touches_control_flow" in spec.risk_tags or "touches_reverts" in spec.risk_tags:
            return False, "access_control_risk_blocks_controlflow_or_reverts"

    if signals.has_external_call_risk or signals.has_reentrancy_risk:
        if "touches_storage" in spec.risk_tags:
            return False, "external_or_reentrancy_risk_blocks_storage_transforms"
        if spec.id in (
            "cfg_flatten_v1",
            "cfg_flatten_v2_hybrid",
            "cfg_flatten_partial_v1",
            "yul_microblock_v1",
            "dispatcher_cfg_virtualization_v1",
        ):
            return False, "external_or_reentrancy_risk_blocks_heavy_controlflow"

    if signals.has_arithmetic_risk:
        if spec.id in ("algebraic_identities_v1",):
            return False, "arithmetic_risk_blocks_algebraic_identities"

    if signals.has_revert_semantics_risk:
        if spec.id in ("string_split_v1",):
            return False, "revert_semantics_risk_blocks_string_split"

    if mut in ("view", "pure"):
        if spec.id in (
            "yul_microblock_v1",
            "local_to_state_lift_v1",
            "scalar_to_struct_indirection_v1",
            "modifier_expand_v1",
        ):
            return False, "pure_view_blocks_state_or_yul_transform"

    if not has_loops and spec.id in ("loop_rewrite_v1",):
        return False, "no_loops_for_loop_rewrite"

    if spec.id in ("inline_internal_v1", "inline_internal_v2_diversified"):
        if mut in ("view", "pure"):
            return False, "pure_view_blocks_inline_internal"

    if spec.id in ("opaque_predicate_v1", "opaque_predicate_v2_entangled", "chaotic_opaque_predicate_v1"):
        if signals.has_access_control_risk:
            return False, "opaque_predicate_blocks_access_control_risk"

    if spec.id == "local_to_state_lift_v1":
        if mut in ("view", "pure"):
            return False, "local_to_state_lift_blocks_view_pure"
        if signals.has_external_call_risk or signals.has_reentrancy_risk:
            return False, "local_to_state_lift_blocks_external_or_reentrancy_risk"
        if signals.has_access_control_risk:
            return False, "local_to_state_lift_blocks_access_control_risk"
        if has_external_calls:
            return False, "local_to_state_lift_blocks_external_calls"
        if return_var_count > 0:
            return False, "local_to_state_lift_blocks_named_return_vars"
        if has_storage_refs:
            return False, "local_to_state_lift_blocks_complex_storage_refs"

    if spec.id == "scalar_to_struct_indirection_v1":
        if signals.has_access_control_risk:
            return False, "scalar_to_struct_indirection_blocks_access_control_risk"
        if has_public_state_abi_risk:
            return False, "scalar_to_struct_indirection_blocks_public_abi_getter_risk"
        if has_inheritance_complexity:
            return False, "scalar_to_struct_indirection_blocks_inheritance_complexity"
        if constructor_state_complexity:
            return False, "scalar_to_struct_indirection_blocks_constructor_or_immutable_complexity"

    if spec.id == "modifier_expand_v1":
        if signals.has_access_control_risk:
            return False, "modifier_expand_blocks_access_control_risk"
        if not has_modifiers:
            return False, "modifier_expand_requires_modifier"
        if modifier_complexity:
            return False, "modifier_expand_blocks_complex_modifier"

    if spec.id == "public_state_accessor_indirection_v1":
        if signals.has_access_control_risk:
            return False, "public_state_accessor_indirection_blocks_access_control_risk"
        if signals.has_external_call_risk or signals.has_reentrancy_risk:
            return False, "public_state_accessor_indirection_blocks_external_or_reentrancy_risk"
        if mut in ("pure",):
            return False, "public_state_accessor_indirection_blocks_pure"

    return True, ""