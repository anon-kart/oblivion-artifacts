from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class TransformSpec:
    id: str
    tier_min: int
    tier_max: int
    risk: str
    family: str
    targets: List[str]
    description: str
    risk_tags: List[str]
    weight: int = 0
    # strict safety classification for predictable gating
    # - always_safe: should never be blocked by coarse vuln signals
    # - contextual: can be blocked by certain signals (e.g., access control, external call)
    # - heavy: aggressive / high chance of breaking semantics or analyzers; tier3-only + extra gating
    safety_class: str = "contextual"
    # protected-region semantics live in the catalog so planner/engine can reason uniformly
    protected_region_conflicts: List[str] = field(default_factory=list)

    # semantic meaning / composition metadata
    semantic_preserves: List[str] = field(default_factory=list)
    semantic_risks: List[str] = field(default_factory=list)

    # composition knowledge
    compose_safe_with: List[str] = field(default_factory=list)
    compose_unsafe_with: Dict[str, str] = field(default_factory=dict)

    # ordering knowledge
    must_run_before: List[str] = field(default_factory=list)
    must_run_after: List[str] = field(default_factory=list)


def default_transform_catalog() -> Dict[str, TransformSpec]:
    specs = [
        # -----------------
        # Tier 1 (safe/cheap variety)
        # -----------------
        TransformSpec(
            id="rename_identifiers_v2_scoped",
            tier_min=1, tier_max=3,
            risk="low", family="layout",
            targets=["function_scope"],
            description="Rename identifiers with scope-safe unique names (prevents collisions/shadowing).",
            risk_tags=["layout_only"],
            weight=10,
            safety_class="always_safe",
            semantic_preserves=[
                "abi_surface",
                "storage_layout",
                "return_values",
                "events",
                "revert_behavior",
                "loop_termination",
            ],
            semantic_risks=[],
            compose_safe_with=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
                "dynamic_constants_v1",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
                "predicate_masking_v1",
            ],
            compose_unsafe_with={},
            must_run_before=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
                "dynamic_constants_v1",
                "predicate_masking_v1",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[],
        ),
        TransformSpec(
            id="rename_identifiers_sha1_v1",
            tier_min=1, tier_max=3,
            risk="low", family="layout",
            targets=["function_scope"],
            description="Rename locals to sha1-like names (BiAn-style hashed identifiers).",
            risk_tags=["layout_only"],
            weight=7,
            safety_class="always_safe",
            semantic_preserves=[
                "abi_surface",
                "storage_layout",
                "return_values",
                "events",
                "revert_behavior",
                "loop_termination",
            ],
            semantic_risks=[],
            compose_safe_with=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
                "dynamic_constants_v1",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
                "predicate_masking_v1",
            ],
            compose_unsafe_with={},
            must_run_before=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
                "dynamic_constants_v1",
                "predicate_masking_v1",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[],
        ),
        TransformSpec(
            id="rename_identifiers_v1",
            tier_min=1, tier_max=3,
            risk="low", family="layout",
            targets=["function_scope"],
            description="(Legacy) Rename locals/temps (may collide; kept only for fallback/testing).",
            risk_tags=["layout_only"],
            weight=1,
            safety_class="always_safe",
            semantic_preserves=[
                "abi_surface",
                "storage_layout",
                "return_values",
                "events",
                "revert_behavior",
                "loop_termination",
            ],
            semantic_risks=["name_collision_if_engine_is_unsafe"],
            compose_safe_with=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
                "dynamic_constants_v1",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
                "predicate_masking_v1",
            ],
            compose_unsafe_with={},
            must_run_before=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
                "dynamic_constants_v1",
                "predicate_masking_v1",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[],
        ),
        TransformSpec(
            id="layout_scramble_v1",
            tier_min=1, tier_max=3,
            risk="low", family="layout",
            targets=["contract_file", "function_body"],
            description="Scramble formatting (whitespace/comments/newlines) without semantic changes.",
            risk_tags=["layout_only"],
            weight=4,
            safety_class="always_safe",
            semantic_preserves=[
                "abi_surface",
                "storage_layout",
                "return_values",
                "events",
                "revert_behavior",
                "loop_termination",
            ],
            semantic_risks=[],
            compose_safe_with=[],
            compose_unsafe_with={},
            must_run_before=[],
            must_run_after=[],
        ),
        TransformSpec(
            id="constant_encoding_v1",
            tier_min=1, tier_max=3,
            risk="low", family="data",
            targets=["expression"],
            description="Encode constants into equivalent expressions (low risk).",
            risk_tags=["touches_data_flow"],
            weight=7,
            safety_class="always_safe",
            semantic_preserves=[
                "abi_surface",
                "storage_layout",
                "return_values",
            ],
            semantic_risks=[
                "arithmetic_guard_meaning",
                "loop_bound_arithmetic",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
            compose_unsafe_with={
                "predicate_masking_v1": "combined value/guard rewriting can obscure arithmetic guard semantics",
            },
            must_run_before=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
        ),
        TransformSpec(
            id="constant_encoding_v2_layered",
            tier_min=2, tier_max=3,
            risk="medium", family="data",
            targets=["expression"],
            description="Layered, context-sensitive constant virtualization with polymorphic equivalent encodings.",
            risk_tags=["touches_data_flow"],
            weight=10,
            safety_class="contextual",
            protected_region_conflicts=["arithmetic_region"],
            semantic_preserves=[
                "abi_surface",
                "storage_layout",
                "return_values",
            ],
            semantic_risks=[
                "arithmetic_guard_meaning",
                "loop_bound_arithmetic",
                "overflow_behavior",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
            compose_unsafe_with={
                "predicate_masking_v1": "combined value/guard rewriting can obscure arithmetic guard semantics",
                "dynamic_constants_v1": "multiple constant virtualization passes can reduce predictability and validator clarity",
            },
            must_run_before=[
                "opaque_predicate_v2_entangled",
                "cfg_flatten_v2_hybrid",
                "cfg_flatten_v1",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
        ),
        TransformSpec(
            id="dynamic_constants_v1",
            tier_min=1, tier_max=3,
            risk="low", family="data",
            targets=["expression"],
            description="Replace literals with helper-based dynamic accessors (__obf_u/__obf_b/__obf_s/__obf_x) (BiAn-style static->dynamic).",
            risk_tags=["touches_data_flow"],
            weight=8,
            safety_class="always_safe",
            semantic_preserves=[
                "abi_surface",
                "storage_layout",
                "return_values",
            ],
            semantic_risks=[
                "arithmetic_guard_meaning",
                "loop_bound_arithmetic",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
            compose_unsafe_with={
                "predicate_masking_v1": "combined value/guard rewriting can obscure arithmetic guard semantics",
                "constant_encoding_v2_layered": "multiple constant virtualization passes can reduce predictability and validator clarity",
            },
            must_run_before=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
        ),
        TransformSpec(
            id="boolean_split_v1",
            tier_min=2, tier_max=3,
            risk="medium", family="data",
            targets=["expression"],
            description="Split boolean literals into equivalent boolean expressions (BiAn Algorithm 4 style).",
            risk_tags=["touches_data_flow"],
            weight=6,
            safety_class="always_safe",
            semantic_preserves=[
                "return_values",
                "storage_layout",
                "events",
            ],
            semantic_risks=[
                "guard_truth_conditions",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
            compose_unsafe_with={
                "cfg_flatten_v1": "boolean rewriting before flattening may complicate dispatch-guard semantics",
                "cfg_flatten_v2_hybrid": "boolean rewriting before hybrid flattening may complicate dispatch-guard semantics",
            },
            must_run_before=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
        ),
        TransformSpec(
            id="boolean_split_v2_distributed",
            tier_min=2, tier_max=3,
            risk="medium", family="data",
            targets=["if_condition"],
            description="Distributed predicate encoding using multi-variable boolean carriers.",
            risk_tags=["touches_data_flow", "touches_control_flow"],
            weight=10,
            safety_class="contextual",
            protected_region_conflicts=[
                "access_control_guard",
                "revert_semantics_region",
                "arithmetic_region",
                "loop_region",
            ],
            semantic_preserves=[
                "return_values",
                "storage_layout",
                "events",
            ],
            semantic_risks=[
                "guard_truth_conditions",
                "revert_behavior",
                "loop_termination",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
            compose_unsafe_with={
                "predicate_masking_v1": "two predicate/guard rewriting transforms together are high risk",
                "opaque_predicate_v1": "distributed predicate encoding plus opaque predicates can over-distort guard semantics",
                "opaque_predicate_v2_entangled": "distributed predicate encoding plus opaque predicates can over-distort guard semantics",
                "cfg_flatten_v1": "distributed guard encoding before flattening may complicate dispatch-guard semantics",
                "cfg_flatten_v2_hybrid": "distributed guard encoding before hybrid flattening may complicate dispatch-guard semantics",
            },
            must_run_before=[
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
        ),

        # -----------------
        # Tier 2 (stronger, still safe with gating)
        # -----------------
        TransformSpec(
            id="opaque_predicate_v1",
            tier_min=2, tier_max=3,
            risk="medium", family="control",
            targets=["function_body", "if_condition"],
            description="Insert always-true/always-false predicate guards to distort control flow.",
            risk_tags=["touches_control_flow"],
            weight=10,
            safety_class="contextual",
            protected_region_conflicts=["access_control_guard", "revert_semantics_region"],
            semantic_preserves=[
                "return_values",
                "events",
                "storage_layout",
            ],
            semantic_risks=[
                "guard_truth_conditions",
                "loop_termination",
                "revert_behavior",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
            compose_unsafe_with={
                "cfg_flatten_v1": "opaque predicates combined with flattening may alter reachable guard structure and loop termination reasoning",
                "cfg_flatten_v2_hybrid": "opaque predicates combined with hybrid flattening may alter reachable guard structure and loop termination reasoning",
                "predicate_masking_v1": "double rewriting of conditions risks changing guard semantics",
                "boolean_split_v2_distributed": "distributed predicate encoding plus opaque predicates can over-distort guard semantics",
                "loop_rewrite_v1": "predicate insertion plus loop rewriting may interfere with loop termination semantics",
            },
            must_run_before=[],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
            ],
        ),
        TransformSpec(
            id="opaque_predicate_v2_entangled",
            tier_min=2, tier_max=3,
            risk="medium", family="control",
            targets=["function_body", "if_condition"],
            description="Inject entangled multi-stage opaque predicates with cross-block dependencies.",
            risk_tags=["touches_control_flow"],
            weight=12,
            safety_class="contextual",
            protected_region_conflicts=["access_control_guard", "revert_semantics_region"],
            semantic_preserves=[
                "return_values",
                "events",
                "storage_layout",
            ],
            semantic_risks=[
                "guard_truth_conditions",
                "loop_termination",
                "revert_behavior",
                "control_flow_shape",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
            ],
            compose_unsafe_with={
                "cfg_flatten_v1": "entangled opaque predicates combined with flattening may alter reachable guard structure and loop termination reasoning",
                "cfg_flatten_v2_hybrid": "entangled opaque predicates combined with hybrid flattening may alter reachable guard structure and loop termination reasoning",
                "predicate_masking_v1": "double rewriting of conditions risks changing guard semantics",
                "boolean_split_v2_distributed": "distributed predicate encoding plus opaque predicates can over-distort guard semantics",
                "loop_rewrite_v1": "predicate insertion plus loop rewriting may interfere with loop termination semantics",
            },
            must_run_before=[],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
            ],
        ),
        TransformSpec(
            id="chaotic_opaque_predicate_v1",
            tier_min=2, tier_max=3,
            risk="medium", family="control",
            targets=["function_body", "if_condition"],
            description="Insert deterministic CPM-style chaotic opaque predicates to strengthen control-flow obfuscation.",
            risk_tags=["touches_control_flow"],
            weight=9,
            safety_class="contextual",
            protected_region_conflicts=["access_control_guard", "revert_semantics_region"],
            semantic_preserves=[
                "return_values",
                "events",
                "storage_layout",
            ],
            semantic_risks=[
                "guard_truth_conditions",
                "loop_termination",
                "revert_behavior",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
            compose_unsafe_with={
                "cfg_flatten_v1": "chaotic opaque predicates combined with flattening may alter reachable guard structure and loop termination reasoning",
                "cfg_flatten_v2_hybrid": "chaotic opaque predicates combined with hybrid flattening may alter reachable guard structure and loop termination reasoning",
                "predicate_masking_v1": "double rewriting of conditions risks changing guard semantics",
                "loop_rewrite_v1": "predicate insertion plus loop rewriting may interfere with loop termination semantics",
            },
            must_run_before=[],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "constant_encoding_v1",
            ],
        ),
        TransformSpec(
            id="dead_code_v1",
            tier_min=2, tier_max=3,
            risk="medium", family="control",
            targets=["function_body"],
            description="Insert semantically-dead blocks guarded by opaque-false predicates.",
            risk_tags=["touches_control_flow"],
            weight=8,
            safety_class="contextual",
            protected_region_conflicts=["access_control_guard", "external_call_site", "revert_semantics_region"],
            semantic_preserves=[
                "return_values",
                "events",
                "storage_layout",
            ],
            semantic_risks=[
                "revert_behavior",
                "control_flow_shape",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
            compose_unsafe_with={
                "cfg_flatten_v1": "dead-code insertion combined with flattening can distort control-flow assumptions and validator reachability",
                "cfg_flatten_v2_hybrid": "dead-code insertion combined with hybrid flattening can distort control-flow assumptions and validator reachability",
            },
            must_run_before=[],
            must_run_after=[
                "rename_identifiers_v2_scoped",
            ],
        ),
        TransformSpec(
            id="predicate_masking_v1",
            tier_min=2, tier_max=3,
            risk="medium", family="control",
            targets=["if_condition"],
            description="Rewrite conditions into equivalent masked/arithmetic form.",
            risk_tags=["touches_control_flow"],
            weight=7,
            safety_class="contextual",
            protected_region_conflicts=[
                "access_control_guard",
                "revert_semantics_region",
                "arithmetic_region",
            ],
            semantic_preserves=[
                "storage_layout",
            ],
            semantic_risks=[
                "guard_truth_conditions",
                "arithmetic_guard_meaning",
                "loop_termination",
                "revert_behavior",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
            ],
            compose_unsafe_with={
                "cfg_flatten_v1": "masked predicates plus flattened dispatch can obscure and destabilize condition semantics",
                "cfg_flatten_v2_hybrid": "masked predicates plus hybrid flattened dispatch can obscure and destabilize condition semantics",
                "opaque_predicate_v1": "two condition-rewriting transforms together are high risk",
                "opaque_predicate_v2_entangled": "two condition-rewriting transforms together are high risk",
                "chaotic_opaque_predicate_v1": "two condition-rewriting transforms together are high risk",
                "boolean_split_v2_distributed": "two condition-rewriting transforms together are high risk",
                "loop_rewrite_v1": "condition masking on rewritten loops may affect termination semantics",
                "constant_encoding_v1": "guard arithmetic may be rewritten twice",
                "constant_encoding_v2_layered": "guard arithmetic may be rewritten twice",
                "dynamic_constants_v1": "guard arithmetic may be rewritten twice",
            },
            must_run_before=[],
            must_run_after=[
                "rename_identifiers_v2_scoped",
            ],
        ),
        TransformSpec(
            id="loop_rewrite_v1",
            tier_min=2, tier_max=3,
            risk="medium", family="control",
            targets=["function_body"],
            description="Rewrite loops (for<->while, redundant induction vars) to confuse analyzers.",
            risk_tags=["touches_control_flow"],
            weight=6,
            safety_class="contextual",
            protected_region_conflicts=["loop_region"],
            semantic_preserves=[
                "storage_layout",
                "events",
            ],
            semantic_risks=[
                "loop_termination",
                "arithmetic_guard_meaning",
                "control_flow_shape",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
            compose_unsafe_with={
                "opaque_predicate_v1": "loop rewriting plus predicate insertion may interfere with loop termination semantics",
                "opaque_predicate_v2_entangled": "loop rewriting plus predicate insertion may interfere with loop termination semantics",
                "chaotic_opaque_predicate_v1": "loop rewriting plus predicate insertion may interfere with loop termination semantics",
                "predicate_masking_v1": "condition masking on rewritten loops may affect termination semantics",
                "cfg_flatten_v1": "loop rewriting before flattening is high risk for dispatch and termination semantics",
                "cfg_flatten_v2_hybrid": "loop rewriting before hybrid flattening is high risk for dispatch and termination semantics",
            },
            must_run_before=[],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
            ],
        ),
        TransformSpec(
            id="inline_internal_v1",
            tier_min=2, tier_max=3,
            risk="medium", family="control",
            targets=["function_body"],
            description="Inline simple internal/private function calls (call graph obfuscation, BiAn-style).",
            risk_tags=["touches_control_flow"],
            weight=5,
            safety_class="contextual",
            protected_region_conflicts=["access_control_guard", "external_call_site"],
            semantic_preserves=[
                "return_values",
                "events",
                "storage_layout",
            ],
            semantic_risks=[
                "revert_behavior",
                "control_flow_shape",
                "call_order",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
                "constant_encoding_v1",
            ],
            compose_unsafe_with={
                "cfg_flatten_v1": "inlining before flattening can destabilize control-flow restructuring",
                "cfg_flatten_v2_hybrid": "inlining before hybrid flattening can destabilize control-flow restructuring",
            },
            must_run_before=[
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
            ],
        ),
        TransformSpec(
            id="inline_internal_v2_diversified",
            tier_min=2, tier_max=3,
            risk="medium", family="control",
            targets=["function_body"],
            description="Diversified semantic cloning of internal/private callees after inlining.",
            risk_tags=["touches_control_flow"],
            weight=9,
            safety_class="contextual",
            protected_region_conflicts=["access_control_guard", "external_call_site"],
            semantic_preserves=[
                "return_values",
                "events",
                "storage_layout",
            ],
            semantic_risks=[
                "revert_behavior",
                "control_flow_shape",
                "call_order",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
            ],
            compose_unsafe_with={
                "cfg_flatten_v1": "diversified inlining before flattening can destabilize control-flow restructuring",
                "cfg_flatten_v2_hybrid": "diversified inlining before hybrid flattening can destabilize control-flow restructuring",
            },
            must_run_before=[
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
            ],
        ),
        TransformSpec(
            id="modifier_expand_v1",
            tier_min=2, tier_max=2,
            risk="medium", family="control",
            targets=["function_signature", "function_body"],
            description="Inline simple modifiers into the function prelude so later transforms can obfuscate the expanded control flow.",
            risk_tags=["touches_control_flow", "touches_reverts", "touches_access_control"],
            weight=6,
            safety_class="contextual",
            protected_region_conflicts=["access_control_guard", "revert_semantics_region"],
            semantic_preserves=[
                "return_values",
                "events",
                "storage_layout",
            ],
            semantic_risks=[
                "access_control_behavior",
                "revert_behavior",
                "guard_truth_conditions",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
            ],
            compose_unsafe_with={
                "opaque_predicate_v1": "modifier expansion followed by predicate injection is risky around access-control and revert prelude logic",
                "opaque_predicate_v2_entangled": "modifier expansion followed by predicate injection is risky around access-control and revert prelude logic",
                "chaotic_opaque_predicate_v1": "modifier expansion followed by predicate injection is risky around access-control and revert prelude logic",
                "cfg_flatten_v1": "modifier expansion before flattening is risky around revert and access-control semantics",
                "cfg_flatten_v2_hybrid": "modifier expansion before hybrid flattening is risky around revert and access-control semantics",
            },
            must_run_before=[
                "rename_identifiers_v2_scoped",
            ],
            must_run_after=[],
        ),
        TransformSpec(
            id="local_to_state_lift_v1",
            tier_min=2, tier_max=2,
            risk="medium", family="data",
            targets=["function_body"],
            description="Lift eligible locals into contract state variables (BiAn local->global/state style).",
            risk_tags=["touches_storage", "touches_data_flow"],
            weight=7,
            safety_class="contextual",
            protected_region_conflicts=["external_call_site"],
            semantic_preserves=[],
            semantic_risks=[
                "storage_layout",
                "storage_effects",
                "reentrancy_surface",
            ],
            compose_safe_with=[],
            compose_unsafe_with={
                "storage_indirection_v1": "combining local-to-state lifting with storage indirection can alter storage semantics too aggressively",
                "opaque_storage_slot_indirection_v1": "combining local-to-state lifting with opaque slot indirection can alter storage semantics too aggressively",
            },
            must_run_before=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[],
        ),
        TransformSpec(
            id="scalar_to_struct_indirection_v1",
            tier_min=2, tier_max=3,
            risk="medium", family="data",
            targets=["contract_state", "function_body"],
            description="Rewrite scalar state accesses through struct-member indirection (BiAn scalar->vector/struct style).",
            risk_tags=["touches_storage", "touches_data_flow"],
            weight=6,
            safety_class="contextual",
            semantic_preserves=[],
            semantic_risks=[
                "storage_layout",
                "storage_effects",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
            ],
            compose_unsafe_with={
                "storage_indirection_v1": "two storage-shape transforms together can alter layout assumptions",
                "opaque_storage_slot_indirection_v1": "two storage-shape transforms together can alter layout assumptions",
            },
            must_run_before=[
                "predicate_masking_v1",
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
            ],
        ),
        TransformSpec(
            id="public_state_accessor_indirection_v1",
            tier_min=2, tier_max=3,
            risk="medium", family="data",
            targets=["function_body", "contract_state"],
            description="Rewrite public array/mapping read sites through internal accessor helpers (safer public-state indirection).",
            risk_tags=["touches_storage", "touches_data_flow"],
            weight=6,
            safety_class="contextual",
            semantic_preserves=[
                "abi_surface",
                "return_values",
            ],
            semantic_risks=[
                "storage_read_semantics",
                "call_order",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
            ],
            compose_unsafe_with={
                "cfg_flatten_v1": "public-state accessor insertion before flattening may complicate helper-call dispatch and equivalence",
                "cfg_flatten_v2_hybrid": "public-state accessor insertion before hybrid flattening may complicate helper-call dispatch and equivalence",
            },
            must_run_before=[
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
            ],
        ),

        # -----------------
        # Tier 3 (aggressive / heavy gating)
        # -----------------
        TransformSpec(
            id="cfg_flatten_v1",
            tier_min=1, tier_max=3,
            risk="medium", family="control",
            targets=["function_body"],
            description="Risk-aware conservative CFG flattening wrapper. Preserves statement order and is validator-gated.",
            risk_tags=["touches_control_flow"],
            weight=10,
            safety_class="contextual",
            protected_region_conflicts=["access_control_guard"],
            semantic_preserves=[
                "storage_layout",
            ],
            semantic_risks=[
                "guard_truth_conditions",
                "loop_termination",
                "revert_behavior",
                "control_flow_shape",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
            ],
            compose_unsafe_with={
                "opaque_predicate_v1": "flattening after predicate injection can distort guard reachability assumptions",
                "opaque_predicate_v2_entangled": "flattening after predicate injection can distort guard reachability assumptions",
                "chaotic_opaque_predicate_v1": "flattening after predicate injection can distort guard reachability assumptions",
                "predicate_masking_v1": "flattening plus predicate masking is high risk for condition semantics",
                "boolean_split_v2_distributed": "flattening plus distributed predicate encoding is high risk for condition semantics",
                "loop_rewrite_v1": "flattening with loop rewriting is high risk for loop termination reasoning",
                "inline_internal_v2_diversified": "flattening after diversified inlining is high risk for control-flow equivalence",
                "dispatcher_cfg_virtualization_v1": "two heavy control-flow virtualization/flattening transforms should not be combined",
                "cfg_flatten_v2_hybrid": "two flattening transforms should not be combined",
            },
            must_run_before=[],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
            ],
        ),
        TransformSpec(
            id="cfg_flatten_v2_hybrid",
            tier_min=3, tier_max=3,
            risk="high", family="control",
            targets=["function_body"],
            description="Hybrid selective flattening with split dispatcher states and mixed structured/unstructured regions.",
            risk_tags=["touches_control_flow", "touches_reverts"],
            weight=12,
            safety_class="heavy",
            protected_region_conflicts=["access_control_guard", "revert_semantics_region"],
            semantic_preserves=[
                "storage_layout",
            ],
            semantic_risks=[
                "guard_truth_conditions",
                "loop_termination",
                "revert_behavior",
                "control_flow_shape",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
            ],
            compose_unsafe_with={
                "opaque_predicate_v1": "hybrid flattening after predicate injection can distort guard reachability assumptions",
                "opaque_predicate_v2_entangled": "hybrid flattening after predicate injection can distort guard reachability assumptions",
                "chaotic_opaque_predicate_v1": "hybrid flattening after predicate injection can distort guard reachability assumptions",
                "predicate_masking_v1": "hybrid flattening plus predicate masking is high risk for condition semantics",
                "boolean_split_v2_distributed": "hybrid flattening plus distributed predicate encoding is high risk for condition semantics",
                "loop_rewrite_v1": "hybrid flattening with loop rewriting is high risk for loop termination reasoning",
                "inline_internal_v2_diversified": "hybrid flattening after diversified inlining is high risk for control-flow equivalence",
                "dispatcher_cfg_virtualization_v1": "two heavy control-flow virtualization/flattening transforms should not be combined",
                "cfg_flatten_v1": "two flattening transforms should not be combined",
            },
            must_run_before=[],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
            ],
        ),
        TransformSpec(
            id="yul_microblock_v1",
            tier_min=3, tier_max=3,
            risk="high", family="control",
            targets=["function_body"],
            description="Insert tiny Yul micro-blocks computing equivalent values to confuse decompilers.",
            risk_tags=["touches_control_flow", "uses_yul"],
            weight=6,
            safety_class="heavy",
            semantic_preserves=[
                "return_values",
                "events",
            ],
            semantic_risks=[
                "memory_semantics",
                "stack_semantics",
                "revert_behavior",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
            ],
            compose_unsafe_with={
                "cfg_flatten_v1": "heavy control-flow rewriting plus Yul microblocks is difficult to validate soundly",
                "cfg_flatten_v2_hybrid": "heavy control-flow rewriting plus Yul microblocks is difficult to validate soundly",
            },
            must_run_before=[],
            must_run_after=[
                "rename_identifiers_v2_scoped",
            ],
        ),
        TransformSpec(
            id="storage_indirection_v1",
            tier_min=3, tier_max=3,
            risk="high", family="data",
            targets=["function_body"],
            description="Introduce storage key indirection (very risky; only for low-risk functions).",
            risk_tags=["touches_storage"],
            weight=1,
            safety_class="heavy",
            semantic_preserves=[],
            semantic_risks=[
                "storage_layout",
                "storage_effects",
                "reentrancy_surface",
            ],
            compose_safe_with=[],
            compose_unsafe_with={
                "local_to_state_lift_v1": "combining local-to-state lifting with storage indirection can alter storage semantics too aggressively",
                "scalar_to_struct_indirection_v1": "multiple storage-shape transforms together can alter layout assumptions",
                "opaque_storage_slot_indirection_v1": "multiple storage indirection transforms together are too risky",
            },
            must_run_before=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[],
        ),

        # -----------------
        # Existing research / outperform transforms
        # -----------------
        TransformSpec(
            id="dispatcher_cfg_virtualization_v1",
            tier_min=3, tier_max=3,
            risk="high", family="control",
            targets=["function_body"],
            description="Virtualize dispatch through a dispatcher-style CFG trampoline.",
            risk_tags=["touches_control_flow", "touches_reverts"],
            weight=2,
            safety_class="heavy",
            protected_region_conflicts=["access_control_guard", "revert_semantics_region"],
            semantic_preserves=[
                "storage_layout",
            ],
            semantic_risks=[
                "guard_truth_conditions",
                "loop_termination",
                "revert_behavior",
                "control_flow_shape",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
            ],
            compose_unsafe_with={
                "opaque_predicate_v1": "dispatcher virtualization plus predicate injection is high risk for control-flow equivalence",
                "opaque_predicate_v2_entangled": "dispatcher virtualization plus predicate injection is high risk for control-flow equivalence",
                "chaotic_opaque_predicate_v1": "dispatcher virtualization plus predicate injection is high risk for control-flow equivalence",
                "predicate_masking_v1": "dispatcher virtualization plus predicate masking is high risk for control-flow equivalence",
                "cfg_flatten_v1": "two heavy control-flow virtualization/flattening transforms should not be combined",
                "cfg_flatten_v2_hybrid": "two heavy control-flow virtualization/flattening transforms should not be combined",
            },
            must_run_before=[],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "constant_encoding_v1",
                "constant_encoding_v2_layered",
            ],
        ),
        TransformSpec(
            id="opaque_storage_slot_indirection_v1",
            tier_min=3, tier_max=3,
            risk="high", family="data",
            targets=["function_body", "contract_state"],
            description="Introduce opaque indirection for storage-slot-like accesses.",
            risk_tags=["touches_storage", "touches_data_flow"],
            weight=1,
            safety_class="heavy",
            protected_region_conflicts=["external_call_site"],
            semantic_preserves=[],
            semantic_risks=[
                "storage_layout",
                "storage_effects",
                "reentrancy_surface",
            ],
            compose_safe_with=[],
            compose_unsafe_with={
                "local_to_state_lift_v1": "combining local-to-state lifting with opaque slot indirection can alter storage semantics too aggressively",
                "scalar_to_struct_indirection_v1": "two storage-shape transforms together can alter layout assumptions",
                "storage_indirection_v1": "multiple storage indirection transforms together are too risky",
            },
            must_run_before=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[],
        ),
        TransformSpec(
            id="stack_variable_aliasing_v1",
            tier_min=2, tier_max=3,
            risk="medium", family="data",
            targets=["function_body"],
            description="Introduce alias-style stack/local rewrites to increase variable-tracking difficulty.",
            risk_tags=["touches_data_flow"],
            weight=5,
            safety_class="contextual",
            protected_region_conflicts=["loop_region"],
            semantic_preserves=[
                "return_values",
                "events",
                "storage_layout",
            ],
            semantic_risks=[
                "dataflow_equivalence",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
            compose_unsafe_with={
                "cfg_flatten_v1": "alias-style variable rewrites combined with flattening increase validation difficulty substantially",
                "cfg_flatten_v2_hybrid": "alias-style variable rewrites combined with hybrid flattening increase validation difficulty substantially",
            },
            must_run_before=[
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
        ),

        # -----------------
        # Optional placeholders (planner will auto-skip if not implemented)
        # -----------------
        TransformSpec(
            id="string_split_v1",
            tier_min=1, tier_max=3,
            risk="low", family="data",
            targets=["expression"],
            description="Split string literals and reconstruct (avoid revert strings if exact-match required).",
            risk_tags=["touches_data_flow"],
            weight=5,
            safety_class="contextual",
            semantic_preserves=[
                "return_values",
                "storage_layout",
            ],
            semantic_risks=[
                "revert_behavior",
                "exact_string_semantics",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
            ],
            compose_unsafe_with={
                "predicate_masking_v1": "string-sensitive condition paths may become harder to validate when combined with condition masking",
            },
            must_run_before=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
            ],
        ),
        TransformSpec(
            id="algebraic_identities_v1",
            tier_min=1, tier_max=3,
            risk="medium", family="data",
            targets=["expression"],
            description="Replace expressions with algebraic identities (safe only when overflow behavior preserved).",
            risk_tags=["touches_data_flow"],
            weight=5,
            safety_class="contextual",
            protected_region_conflicts=["arithmetic_region"],
            semantic_preserves=[
                "return_values",
                "storage_layout",
            ],
            semantic_risks=[
                "arithmetic_semantics",
                "overflow_behavior",
                "loop_bound_arithmetic",
            ],
            compose_safe_with=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
            compose_unsafe_with={
                "predicate_masking_v1": "algebraic rewrites plus predicate masking can distort arithmetic guard semantics",
                "constant_encoding_v1": "multiple arithmetic-expression rewrites can distort arithmetic guard semantics",
                "constant_encoding_v2_layered": "multiple arithmetic-expression rewrites can distort arithmetic guard semantics",
                "dynamic_constants_v1": "multiple arithmetic-expression rewrites can distort arithmetic guard semantics",
            },
            must_run_before=[
                "opaque_predicate_v1",
                "opaque_predicate_v2_entangled",
                "cfg_flatten_v1",
                "cfg_flatten_v2_hybrid",
            ],
            must_run_after=[
                "rename_identifiers_v2_scoped",
                "rename_identifiers_sha1_v1",
            ],
        ),
    ]
    return {s.id: s for s in specs}