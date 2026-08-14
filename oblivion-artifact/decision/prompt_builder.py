# decision/prompt_builder.py
import json
from typing import Dict, List


def build_prompt(
    *,
    contract_name: str,
    function_name: str,
    function_ir: Dict,
    obf_advice: Dict,
    sec_advice: Dict,
    tier: int,
    allowed_transforms: List[Dict],
    forbidden_transforms: List[Dict] | None,
    vulnerability_labels: List[str] | None,
    policy: Dict,
) -> str:
    """
    Build a STRICT prompt for Option-A:
    LLM outputs a JSON transform plan (NOT Solidity code),
    including:
      - selected transforms
      - semantic safety reasoning
      - invariants to preserve
      - composition compatibility guidance
    """

    max_t = int(policy.get("max_transforms_per_function", 2))
    min_t = int(policy.get("min_transforms_per_function", 0))

    # Identify mutability for tier-aware constraints.
    mut = (function_ir.get("state_mutability") or "").lower()

    # Build tier-aware "strength" requirements.
    # These are soft constraints: "if safe, include at least one..."
    cf_required_if_safe = [
        "opaque_predicate_v1",
        "predicate_masking_v1",
        "dead_code_v1",
        "loop_rewrite_v1",
        "dispatcher_cfg_virtualization_v1",
    ]
    heavy_required_if_safe = [
        "cfg_flatten_v1",
        "inline_internal_v1",
        "yul_microblock_v1",
        "storage_indirection_v1",
        "dispatcher_cfg_virtualization_v1",
        "opaque_storage_slot_indirection_v1",
        "stack_variable_aliasing_v1",
    ]

    prompt = {
        "task": (
            "You are an assistant that selects SAFE obfuscation transforms for a Solidity function. "
            "You must output a JSON transform plan, semantic safety contract, and transform composition graph."
        ),
        "rules": [
            "Output MUST be valid JSON only (no markdown, no code fences).",
            "Do NOT output Solidity code.",
            "Select only from the provided transform catalog.",
            "Preserve exact semantics of the function.",
            (
                "You MAY introduce additional local variables, branches, loops, and helper expressions "
                "ONLY if they are semantically neutral (i.e., do not change observable behavior)."
            ),
            "Do NOT introduce new EXTERNAL calls or change existing external call ordering.",
            (
                "Do NOT introduce new STATE writes (storage) or change storage access patterns, "
                "UNLESS the chosen transform explicitly targets storage obfuscation AND tier==3 AND "
                "security advice indicates it is safe."
            ),
            (
                "Do NOT change revert behavior on reachable paths (i.e., do not add new reachable reverts "
                "or remove reachable reverts). Unreachable dead branches are allowed."
            ),
            "Respect security constraints strictly.",
            "You MUST NOT select any transform listed under forbidden_transforms.",
            "If a vulnerability label is present, treat the compatibility matrix as a hard policy, not a suggestion.",
            f"Choose BETWEEN {min_t} and {max_t} transforms, inclusive.",
            "IMPORTANT: The plan must be NON-EMPTY whenever at least one safe transform exists.",
            (
                "If and ONLY IF no safe transform exists, you may return an empty plan, but then you MUST set "
                "rationale to start with: 'NO_SAFE_TRANSFORM:' and explain why."
            ),
            (
                "STRENGTH REQUIREMENT (tier>=2): If at least one control-flow transform is safe, "
                f"include AT LEAST ONE of: {cf_required_if_safe}."
            ),
            (
                "STRENGTH REQUIREMENT (tier==3): If at least one heavy transform is safe, "
                f"include AT LEAST ONE of: {heavy_required_if_safe}. "
                "If the function is view/pure, prefer non-heavy transforms unless you are confident the heavy transform is safe."
            ),
            (
                "TIER-3 GUIDANCE: When tier==3 and security severity is not HIGH/CRITICAL, you SHOULD consider "
                "including at least one of: dispatcher_cfg_virtualization_v1, stack_variable_aliasing_v1, "
                "opaque_storage_slot_indirection_v1 (ONLY if it preserves storage semantics)."
            ),
            (
                "For EACH selected transform, you MUST explain why it is safe for this function "
                "and list the semantic invariants that must be preserved."
            ),
            (
                "You MUST output a semantic_contract object containing global invariants, "
                "protected region tags, and per-transform safety justifications."
            ),
            (
                "You MUST output a composition_graph object describing safe transform pairs, "
                "unsafe transform pairs, ordering constraints, and pair compatibility scores."
            ),
            (
                "unsafe_pairs in composition_graph are HARD negatives: if you select both transforms "
                "in an unsafe pair, the plan is invalid."
            ),
            (
                "ordering_constraints must reflect preferred application order among selected transforms."
            ),
            (
                "When assessing transform safety, pay special attention to access control guards, "
                "revert conditions, loop termination, arithmetic updates, state writes, storage indexing, "
                "event emission behavior, and external-call-adjacent logic."
            ),
            (
                "Protected region tags should be drawn from the provided security/policy context when possible, "
                "such as access_control_guard, revert_semantics_region, arithmetic_region, loop_region, state_write_region."
            ),
            (
                "Prefer composition-aware reasoning: some transforms may be safe individually but unsafe together. "
                "Capture that explicitly in composition_graph."
            ),
        ],
        "context": {
            "contract": contract_name,
            "function": function_name,
            "tier": tier,
            "function_properties": {
                "visibility": function_ir.get("visibility"),
                "state_mutability": function_ir.get("state_mutability"),
                "writes_storage": function_ir.get("writes_storage", []),
                "reads_storage": function_ir.get("reads_storage", []),
                "loops": function_ir.get("loops", []),
                "external_calls": function_ir.get("external_calls", []),
                "modifiers": function_ir.get("modifiers", []),
                "returns": function_ir.get("returns", []),
                "body_summary": function_ir.get("body_summary", {}),
                "protected_regions": sec_advice.get("protected_regions", []),
                "policy_signals": sec_advice.get("policy_signals", {}),
                "policy_constraints": sec_advice.get("policy_constraints", {}),
            },
            "dynamic_evidence": {
                "coverage_pct": obf_advice.get("coverage_pct"),
                "call_count": obf_advice.get("dynamic_calls"),
                "tests_touching": obf_advice.get("tests_touching", []),
                "runtime_relevance": obf_advice.get("runtime_relevance"),
                "econ_score": obf_advice.get("econ_score"),
            },
            "security_advice": {
                "severity": sec_advice.get("severity"),
                "issues": sec_advice.get("issues", []),
                "vulnerability_labels": vulnerability_labels or [],
                "forbidden_transforms": forbidden_transforms or [],
                "protected_regions": sec_advice.get("protected_regions", []),
                "policy_signals": sec_advice.get("policy_signals", {}),
                "policy_constraints": sec_advice.get("policy_constraints", {}),
                "sec_score": sec_advice.get("sec_score"),
            },
            "obfuscation_advice": {
                "econ_score": obf_advice.get("econ_score"),
                "sec_score": obf_advice.get("sec_score"),
                "sec_severity": obf_advice.get("sec_severity"),
                "tier_reason": obf_advice.get("tier_reason"),
                "candidate_transforms": obf_advice.get("candidate_transforms", []),
                "policy_sensitivity": obf_advice.get("policy_sensitivity"),
                "policy_sensitivity_band": obf_advice.get("policy_sensitivity_band"),
                "protected_regions": obf_advice.get("protected_regions", []),
                "policy_signals": obf_advice.get("policy_signals", {}),
                "policy_constraints": obf_advice.get("policy_constraints", {}),
            },
            "allowed_transforms": allowed_transforms,
            "policy_constraints": {
                "min_transforms": min_t,
                "max_transforms": max_t,
                "forbidden_if_severity_at_least": policy.get("reject_on_severity", "HIGH"),
                "reject_on_new_high_vuln": policy.get("reject_on_new_high_vuln", True),
                "gas_budget_pct": policy.get("gas_budget_pct", 25.0),
                "llm_require_semantic_contract": policy.get("llm_require_semantic_contract", True),
                "llm_require_composition_graph": policy.get("llm_require_composition_graph", True),
                "composition_enforce_hard_unsafe_pairs": policy.get("composition_enforce_hard_unsafe_pairs", True),
                "composition_use_ordering_constraints": policy.get("composition_use_ordering_constraints", True),
            },
            "selection_guidance": {
                "mutability_hint": mut,
                "control_flow_required_if_safe_when_tier_at_least_2": cf_required_if_safe,
                "heavy_required_if_safe_when_tier_is_3": heavy_required_if_safe,
                "notes": [
                    "Prefer transforms that increase structural diversity (control-flow/data-flow) when safe.",
                    "Avoid heavy transforms for view/pure functions unless clearly safe.",
                    "Avoid storage-related transforms unless tier==3 and security advice is not HIGH/CRITICAL.",
                    "If tier==3 and safe, prefer at least one: dispatcher_cfg_virtualization_v1 or stack_variable_aliasing_v1.",
                    "Only choose opaque_storage_slot_indirection_v1 if it does NOT change storage layout/meaning and is semantics-preserving.",
                    "Explain why each selected transform is safe for this specific function.",
                    "List invariants that deterministic validation should later preserve/check.",
                    "Model transform interactions explicitly; do not assume pairwise composition is always safe.",
                    "If a transform is safe alone but risky in composition, record that in composition_graph.",
                    "Ordering matters: if one transform should run before another, express it in ordering_constraints.",
                ],
            },
        },
        "output_schema": {
            "type": "object",
            "required": [
                "function",
                "plan",
                "rationale",
                "semantic_contract",
                "composition_graph",
            ],
            "properties": {
                "function": {"type": "string"},
                "plan": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["transform_id"],
                        "properties": {
                            "transform_id": {"type": "string"},
                            "params": {"type": "object"},
                        },
                    },
                },
                "rationale": {"type": "string"},
                "semantic_contract": {
                    "type": "object",
                    "required": [
                        "global_invariants",
                        "protected_region_tags",
                        "transform_safety",
                    ],
                    "properties": {
                        "global_invariants": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "protected_region_tags": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "transform_safety": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["transform_id", "why_safe", "preserve_invariants"],
                                "properties": {
                                    "transform_id": {"type": "string"},
                                    "why_safe": {"type": "string"},
                                    "preserve_invariants": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                    "avoid_regions": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                },
                            },
                        },
                    },
                },
                "composition_graph": {
                    "type": "object",
                    "required": ["safe_pairs", "unsafe_pairs", "ordering_constraints"],
                    "properties": {
                        "safe_pairs": {
                            "type": "array",
                            "items": {
                                "type": "array",
                                "minItems": 2,
                                "maxItems": 2,
                                "items": {"type": "string"},
                            },
                        },
                        "unsafe_pairs": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["pair", "reason", "risk"],
                                "properties": {
                                    "pair": {
                                        "type": "array",
                                        "minItems": 2,
                                        "maxItems": 2,
                                        "items": {"type": "string"},
                                    },
                                    "reason": {"type": "string"},
                                    "risk": {"type": "number"},
                                },
                            },
                        },
                        "ordering_constraints": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["before", "after", "reason"],
                                "properties": {
                                    "before": {"type": "string"},
                                    "after": {"type": "string"},
                                    "reason": {"type": "string"},
                                },
                            },
                        },
                        "pair_scores": {
                            "type": "object",
                            "additionalProperties": {"type": "number"},
                        },
                    },
                },
            },
        },
        "examples": [
            {
                "function": function_name,
                "plan": [
                    {"transform_id": "opaque_predicate_v1", "params": {}},
                    {"transform_id": "predicate_masking_v1", "params": {}},
                    {"transform_id": "constant_encoding_v1", "params": {}},
                ],
                "rationale": (
                    "Picked control-flow + data-flow safe transforms to increase structural diversity while preserving semantics."
                ),
                "semantic_contract": {
                    "global_invariants": [
                        "return values unchanged",
                        "reachable revert behavior unchanged",
                        "storage writes unchanged",
                        "external call ordering unchanged",
                    ],
                    "protected_region_tags": [
                        "revert_semantics_region",
                        "arithmetic_region",
                    ],
                    "transform_safety": [
                        {
                            "transform_id": "opaque_predicate_v1",
                            "why_safe": (
                                "Opaque predicates are safe when inserted as semantically dead control-flow that does not alter reachable outcomes."
                            ),
                            "preserve_invariants": [
                                "reachable branch behavior unchanged",
                                "loop termination unchanged",
                                "revert behavior unchanged",
                            ],
                            "avoid_regions": [
                                "revert_semantics_region",
                                "arithmetic_region",
                            ],
                        },
                        {
                            "transform_id": "predicate_masking_v1",
                            "why_safe": (
                                "Predicate masking is safe when it does not alter effective truth conditions on reachable paths."
                            ),
                            "preserve_invariants": [
                                "guard semantics unchanged",
                                "loop bounds unchanged",
                                "return equivalence preserved",
                            ],
                            "avoid_regions": [
                                "arithmetic_region",
                            ],
                        },
                        {
                            "transform_id": "constant_encoding_v1",
                            "why_safe": (
                                "Constant encoding is safe when compile-time or runtime decoding preserves identical numeric values."
                            ),
                            "preserve_invariants": [
                                "literal values unchanged",
                                "storage key/value semantics unchanged",
                            ],
                            "avoid_regions": [],
                        },
                    ],
                },
                "composition_graph": {
                    "safe_pairs": [
                        ["opaque_predicate_v1", "constant_encoding_v1"],
                        ["predicate_masking_v1", "constant_encoding_v1"],
                    ],
                    "unsafe_pairs": [
                        {
                            "pair": ["opaque_predicate_v1", "predicate_masking_v1"],
                            "reason": "combined control-flow guard rewriting may become brittle near arithmetic or loop-sensitive regions",
                            "risk": 0.42,
                        }
                    ],
                    "ordering_constraints": [
                        {
                            "before": "opaque_predicate_v1",
                            "after": "constant_encoding_v1",
                            "reason": "insert control-flow scaffolding before final literal rewriting",
                        }
                    ],
                    "pair_scores": {
                        "constant_encoding_v1|opaque_predicate_v1": 0.71,
                        "constant_encoding_v1|predicate_masking_v1": 0.64,
                        "opaque_predicate_v1|predicate_masking_v1": -0.42,
                    },
                },
            },
            {
                "function": function_name,
                "plan": [
                    {"transform_id": "dispatcher_cfg_virtualization_v1", "params": {}},
                    {"transform_id": "dead_code_v1", "params": {}},
                    {"transform_id": "rename_identifiers_v2_scoped", "params": {}},
                ],
                "rationale": (
                    "Tier 3 allows heavy transforms; chose dispatcher-based CFG virtualization plus safe padding transforms while preserving behavior."
                ),
                "semantic_contract": {
                    "global_invariants": [
                        "return values unchanged",
                        "event behavior unchanged",
                        "storage write set unchanged",
                        "revert reachability unchanged",
                    ],
                    "protected_region_tags": [
                        "access_control_guard",
                        "state_write_region",
                    ],
                    "transform_safety": [
                        {
                            "transform_id": "dispatcher_cfg_virtualization_v1",
                            "why_safe": (
                                "CFG virtualization is safe only if dispatcher rewrites preserve original execution order and side effects."
                            ),
                            "preserve_invariants": [
                                "basic-block semantic equivalence",
                                "state update ordering unchanged",
                                "external-call ordering unchanged",
                            ],
                            "avoid_regions": [
                                "access_control_guard",
                                "state_write_region",
                            ],
                        },
                        {
                            "transform_id": "dead_code_v1",
                            "why_safe": (
                                "Dead code is safe if unreachable and side-effect free."
                            ),
                            "preserve_invariants": [
                                "reachable paths unchanged",
                                "gas increase within budget",
                            ],
                            "avoid_regions": [],
                        },
                        {
                            "transform_id": "rename_identifiers_v2_scoped",
                            "why_safe": (
                                "Scoped identifier renaming changes names only and preserves semantics."
                            ),
                            "preserve_invariants": [
                                "ABI-visible behavior unchanged",
                                "event behavior unchanged",
                            ],
                            "avoid_regions": [],
                        },
                    ],
                },
                "composition_graph": {
                    "safe_pairs": [
                        ["dispatcher_cfg_virtualization_v1", "dead_code_v1"],
                        ["rename_identifiers_v2_scoped", "dead_code_v1"],
                    ],
                    "unsafe_pairs": [],
                    "ordering_constraints": [
                        {
                            "before": "dispatcher_cfg_virtualization_v1",
                            "after": "rename_identifiers_v2_scoped",
                            "reason": "perform structural rewrites before final identifier renaming",
                        }
                    ],
                    "pair_scores": {
                        "dead_code_v1|dispatcher_cfg_virtualization_v1": 0.66,
                        "dead_code_v1|rename_identifiers_v2_scoped": 0.58,
                        "dispatcher_cfg_virtualization_v1|rename_identifiers_v2_scoped": 0.61,
                    },
                },
            },
            {
                "function": function_name,
                "plan": [
                    {"transform_id": "stack_variable_aliasing_v1", "params": {}},
                    {"transform_id": "opaque_predicate_v1", "params": {}},
                ],
                "rationale": (
                    "Introduced stack variable aliasing (locals only) plus a semantically-neutral control-flow guard to increase obfuscation without altering behavior."
                ),
                "semantic_contract": {
                    "global_invariants": [
                        "local variable value flow unchanged",
                        "return values unchanged",
                        "reachable revert behavior unchanged",
                    ],
                    "protected_region_tags": [
                        "arithmetic_region",
                        "loop_region",
                    ],
                    "transform_safety": [
                        {
                            "transform_id": "stack_variable_aliasing_v1",
                            "why_safe": (
                                "Stack variable aliasing is safe when confined to locals and when def-use semantics are preserved."
                            ),
                            "preserve_invariants": [
                                "def-use chains preserved",
                                "returned values unchanged",
                            ],
                            "avoid_regions": [
                                "arithmetic_region",
                            ],
                        },
                        {
                            "transform_id": "opaque_predicate_v1",
                            "why_safe": (
                                "Opaque predicates are safe when inserted as semantically dead guards outside protected arithmetic/loop regions."
                            ),
                            "preserve_invariants": [
                                "loop termination unchanged",
                                "revert behavior unchanged",
                                "reachable branch semantics unchanged",
                            ],
                            "avoid_regions": [
                                "arithmetic_region",
                                "loop_region",
                            ],
                        },
                    ],
                },
                "composition_graph": {
                    "safe_pairs": [
                        ["stack_variable_aliasing_v1", "opaque_predicate_v1"]
                    ],
                    "unsafe_pairs": [],
                    "ordering_constraints": [
                        {
                            "before": "opaque_predicate_v1",
                            "after": "stack_variable_aliasing_v1",
                            "reason": "establish control-flow wrapper before local alias rewrites",
                        }
                    ],
                    "pair_scores": {
                        "opaque_predicate_v1|stack_variable_aliasing_v1": 0.69
                    },
                },
            },
            {
                "function": function_name,
                "plan": [],
                "rationale": (
                    "NO_SAFE_TRANSFORM: All transforms would violate constraints "
                    "(e.g., would change reachable revert behavior, alter protected regions, "
                    "or create unsafe transform compositions)."
                ),
                "semantic_contract": {
                    "global_invariants": [
                        "return values unchanged",
                        "reachable revert behavior unchanged",
                        "storage writes unchanged",
                        "external call ordering unchanged",
                    ],
                    "protected_region_tags": [],
                    "transform_safety": [],
                },
                "composition_graph": {
                    "safe_pairs": [],
                    "unsafe_pairs": [],
                    "ordering_constraints": [],
                    "pair_scores": {},
                },
            },
        ],
    }

    return json.dumps(prompt, indent=2)