from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from decision_planner.catalog import default_transform_catalog
from collections import defaultdict
from decision.composition_graph import order_plan_steps
from decision.semantic_rules import (
    build_deterministic_composition_graph,
    merge_composition_graphs,
)
from decision_planner.compat_matrix import (
    extract_signals,
    compatible as compat_matrix_compatible,
)

from .transforms import apply_rename_identifiers_v1

try:
    from .transforms import apply_rename_identifiers_v2_scoped  # type: ignore
except Exception:
    apply_rename_identifiers_v2_scoped = None  # type: ignore

try:
    from .transforms import apply_constant_encoding_v1  # type: ignore
except Exception:
    apply_constant_encoding_v1 = None  # type: ignore

try:
    from .transforms import apply_opaque_predicate_v1  # type: ignore
except Exception:
    apply_opaque_predicate_v1 = None  # type: ignore

try:
    from .transforms import apply_dead_code_v1  # type: ignore
except Exception:
    apply_dead_code_v1 = None  # type: ignore

try:
    from .transforms import apply_predicate_masking_v1  # type: ignore
except Exception:
    apply_predicate_masking_v1 = None  # type: ignore

try:
    from .transforms import apply_loop_rewrite_v1  # type: ignore
except Exception:
    apply_loop_rewrite_v1 = None  # type: ignore

try:
    from .transforms import apply_layout_scramble_v1  # type: ignore
except Exception:
    apply_layout_scramble_v1 = None  # type: ignore

try:
    from .transforms import apply_cfg_flatten_v1  # type: ignore
except Exception:
    apply_cfg_flatten_v1 = None  # type: ignore

try:
    from .transforms import apply_yul_microblock_v1  # type: ignore
except Exception:
    apply_yul_microblock_v1 = None  # type: ignore

# Existing BiAn-parity transforms
try:
    from .transforms import apply_boolean_split_v1  # type: ignore
except Exception:
    apply_boolean_split_v1 = None  # type: ignore

try:
    from .transforms import apply_dynamic_constants_v1  # type: ignore
except Exception:
    apply_dynamic_constants_v1 = None  # type: ignore

try:
    from .transforms import apply_inline_internal_v1  # type: ignore
except Exception:
    apply_inline_internal_v1 = None  # type: ignore

try:
    from .transforms import apply_rename_identifiers_sha1_v1  # type: ignore
except Exception:
    apply_rename_identifiers_sha1_v1 = None  # type: ignore

# NEW: missing BiAn-parity transforms
try:
    from .transforms import apply_local_to_state_lift_v1  # type: ignore
except Exception:
    apply_local_to_state_lift_v1 = None  # type: ignore

try:
    from .transforms import apply_scalar_to_struct_indirection_v1  # type: ignore
except Exception:
    apply_scalar_to_struct_indirection_v1 = None  # type: ignore

try:
    from .transforms import apply_modifier_expand_v1  # type: ignore
except Exception:
    apply_modifier_expand_v1 = None  # type: ignore

# Existing research techniques
try:
    from .transforms import apply_dispatcher_cfg_virtualization_v1  # type: ignore
except Exception:
    apply_dispatcher_cfg_virtualization_v1 = None  # type: ignore

try:
    from .transforms import apply_opaque_storage_slot_indirection_v1  # type: ignore
except Exception:
    apply_opaque_storage_slot_indirection_v1 = None  # type: ignore

try:
    from .transforms import apply_stack_variable_aliasing_v1  # type: ignore
except Exception:
    apply_stack_variable_aliasing_v1 = None  # type: ignore

try:
    from .transforms import apply_public_state_accessor_indirection_v1  # type: ignore
except Exception:
    apply_public_state_accessor_indirection_v1 = None  # type: ignore

try:
    from .transforms import apply_storage_indirection_v1  # type: ignore
except Exception:
    apply_storage_indirection_v1 = None  # type: ignore

try:
    from .transforms import apply_chaotic_opaque_predicate_v1  # type: ignore
except Exception:
    apply_chaotic_opaque_predicate_v1 = None  # type: ignore

try:
    from .transforms import apply_string_split_v1  # type: ignore
except Exception:
    apply_string_split_v1 = None  # type: ignore

try:
    from .transforms import apply_algebraic_identities_v1  # type: ignore
except Exception:
    apply_algebraic_identities_v1 = None  # type: ignore

try:
    from .transforms import apply_opaque_predicate_v2_entangled  # type: ignore
except Exception:
    apply_opaque_predicate_v2_entangled = None  # type: ignore

try:
    from .transforms import apply_cfg_flatten_v2_hybrid  # type: ignore
except Exception:
    apply_cfg_flatten_v2_hybrid = None  # type: ignore

try:
    from .transforms import apply_constant_encoding_v2_layered  # type: ignore
except Exception:
    apply_constant_encoding_v2_layered = None  # type: ignore

try:
    from .transforms import apply_boolean_split_v2_distributed  # type: ignore
except Exception:
    apply_boolean_split_v2_distributed = None  # type: ignore

try:
    from .transforms import apply_inline_internal_v2_diversified  # type: ignore
except Exception:
    apply_inline_internal_v2_diversified = None  # type: ignore


@dataclass
class AppliedEdit:
    sequence: int
    function: str
    transform_id: str
    target: Dict[str, Any]
    target_kind: str
    params: Dict[str, Any]
    details: Dict[str, Any]
    status: str
    changed: bool
    effect_kind: str
    before_signature: Optional[str]
    after_signature: Optional[str]
    original_span: Optional[Dict[str, int]]
    new_span: Optional[Dict[str, int]]
    before_excerpt: Optional[str]
    after_excerpt: Optional[str]
    source_hash_before: str
    source_hash_after: str


def _apply_rename_v1(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    seed = int((params or {}).get("seed", 1337))
    res = apply_rename_identifiers_v1(source=source, contract_name=contract, fn_name=fn, seed=seed)
    return {"new_source": res.new_source, "details": {"rename_map": getattr(res, "rename_map", {})}}


def _apply_rename_v2_scoped(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_rename_identifiers_v2_scoped is None:
        raise NotImplementedError("apply_rename_identifiers_v2_scoped is not available yet")
    seed = int((params or {}).get("seed", 1337))
    res = apply_rename_identifiers_v2_scoped(source=source, contract_name=contract, fn_name=fn, seed=seed)
    details: Dict[str, Any] = {}
    if hasattr(res, "details"):
        details = res.details
    if hasattr(res, "rename_map"):
        details = {**details, "rename_map": res.rename_map}
    return {"new_source": res.new_source, "details": details or {"note": "rename_identifiers_v2_scoped applied"}}


def _apply_rename_sha1(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_rename_identifiers_sha1_v1 is None:
        raise NotImplementedError("apply_rename_identifiers_sha1_v1 is not available yet")
    seed = int((params or {}).get("seed", 1337))
    res = apply_rename_identifiers_sha1_v1(source=source, contract_name=contract, fn_name=fn, seed=seed)
    details: Dict[str, Any] = {}
    if hasattr(res, "details"):
        details = res.details
    return {"new_source": res.new_source, "details": details or {"note": "rename_identifiers_sha1_v1 applied"}}


def _apply_constant_encoding(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_constant_encoding_v1 is None:
        raise NotImplementedError("apply_constant_encoding_v1 is not available yet")
    res = apply_constant_encoding_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "constant_encoding_v1 applied"}}


def _apply_dynamic_constants(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_dynamic_constants_v1 is None:
        raise NotImplementedError("apply_dynamic_constants_v1 is not available yet")
    res = apply_dynamic_constants_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "dynamic_constants_v1 applied"}}


def _apply_boolean_split(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_boolean_split_v1 is None:
        raise NotImplementedError("apply_boolean_split_v1 is not available yet")
    res = apply_boolean_split_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "boolean_split_v1 applied"}}


def _apply_inline_internal(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_inline_internal_v1 is None:
        raise NotImplementedError("apply_inline_internal_v1 is not available yet")
    res = apply_inline_internal_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "inline_internal_v1 applied"}}


def _apply_local_to_state_lift(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_local_to_state_lift_v1 is None:
        raise NotImplementedError("apply_local_to_state_lift_v1 is not available yet")
    res = apply_local_to_state_lift_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "local_to_state_lift_v1 applied"}}


def _apply_scalar_to_struct_indirection(
    *, source: str, contract: str, fn: str, params: Dict[str, Any]
) -> Dict[str, Any]:
    if apply_scalar_to_struct_indirection_v1 is None:
        raise NotImplementedError("apply_scalar_to_struct_indirection_v1 is not available yet")
    res = apply_scalar_to_struct_indirection_v1(
        source=source,
        contract_name=contract,
        fn_name=fn,
        **(params or {}),
    )
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "scalar_to_struct_indirection_v1 applied"}}


def _apply_modifier_expand(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_modifier_expand_v1 is None:
        raise NotImplementedError("apply_modifier_expand_v1 is not available yet")
    res = apply_modifier_expand_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "modifier_expand_v1 applied"}}


def _apply_public_state_accessor_indirection(
    *, source: str, contract: str, fn: str, params: Dict[str, Any]
) -> Dict[str, Any]:
    if apply_public_state_accessor_indirection_v1 is None:
        raise NotImplementedError("apply_public_state_accessor_indirection_v1 is not available yet")
    res = apply_public_state_accessor_indirection_v1(
        source=source,
        contract_name=contract,
        fn_name=fn,
        **(params or {}),
    )
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {
        "new_source": res.new_source,
        "details": details or {"note": "public_state_accessor_indirection_v1 applied"},
    }


def _apply_storage_indirection(
    *, source: str, contract: str, fn: str, params: Dict[str, Any]
) -> Dict[str, Any]:
    if apply_storage_indirection_v1 is None:
        raise NotImplementedError("apply_storage_indirection_v1 is not available yet")
    res = apply_storage_indirection_v1(
        source=source,
        contract_name=contract,
        fn_name=fn,
        **(params or {}),
    )
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "storage_indirection_v1 applied"}}


def _apply_opaque_predicate(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_opaque_predicate_v1 is None:
        raise NotImplementedError("apply_opaque_predicate_v1 is not available yet")
    res = apply_opaque_predicate_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details: Dict[str, Any] = getattr(res, "details", {}) if hasattr(res, "details") else {}
    if hasattr(res, "meta") and isinstance(getattr(res, "meta"), dict):
        details = {**details, **getattr(res, "meta")}
    return {"new_source": res.new_source, "details": details or {"note": "opaque_predicate_v1 applied"}}


def _apply_dead_code(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_dead_code_v1 is None:
        raise NotImplementedError("apply_dead_code_v1 is not available yet")
    res = apply_dead_code_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details: Dict[str, Any] = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "dead_code_v1 applied"}}


def _apply_predicate_masking(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_predicate_masking_v1 is None:
        raise NotImplementedError("apply_predicate_masking_v1 is not available yet")
    seed = int((params or {}).get("seed", 1337))
    res = apply_predicate_masking_v1(source=source, contract_name=contract, fn_name=fn, seed=seed)
    details: Dict[str, Any] = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "predicate_masking_v1 applied"}}


def _apply_loop_rewrite(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_loop_rewrite_v1 is None:
        raise NotImplementedError("apply_loop_rewrite_v1 is not available yet")
    res = apply_loop_rewrite_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details: Dict[str, Any] = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "loop_rewrite_v1 applied"}}


def _apply_layout_scramble(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_layout_scramble_v1 is None:
        raise NotImplementedError("apply_layout_scramble_v1 is not available yet")
    res = apply_layout_scramble_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details: Dict[str, Any] = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "layout_scramble_v1 applied"}}


def _apply_cfg_flatten(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_cfg_flatten_v1 is None:
        raise NotImplementedError("apply_cfg_flatten_v1 is not available yet")
    res = apply_cfg_flatten_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details: Dict[str, Any] = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "cfg_flatten_v1 applied"}}


def _apply_yul_microblock(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_yul_microblock_v1 is None:
        raise NotImplementedError("apply_yul_microblock_v1 is not available yet")
    res = apply_yul_microblock_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details: Dict[str, Any] = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "yul_microblock_v1 applied"}}


def _apply_dispatcher_cfg_virtualization(
    *, source: str, contract: str, fn: str, params: Dict[str, Any]
) -> Dict[str, Any]:
    if apply_dispatcher_cfg_virtualization_v1 is None:
        raise NotImplementedError("apply_dispatcher_cfg_virtualization_v1 is not available yet")
    res = apply_dispatcher_cfg_virtualization_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details: Dict[str, Any] = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "dispatcher_cfg_virtualization_v1 applied"}}


def _apply_opaque_storage_slot_indirection(
    *, source: str, contract: str, fn: str, params: Dict[str, Any]
) -> Dict[str, Any]:
    if apply_opaque_storage_slot_indirection_v1 is None:
        raise NotImplementedError("apply_opaque_storage_slot_indirection_v1 is not available yet")
    res = apply_opaque_storage_slot_indirection_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details: Dict[str, Any] = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "opaque_storage_slot_indirection_v1 applied"}}


def _apply_stack_variable_aliasing(
    *, source: str, contract: str, fn: str, params: Dict[str, Any]
) -> Dict[str, Any]:
    if apply_stack_variable_aliasing_v1 is None:
        raise NotImplementedError("apply_stack_variable_aliasing_v1 is not available yet")
    res = apply_stack_variable_aliasing_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details: Dict[str, Any] = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "stack_variable_aliasing_v1 applied"}}


def _apply_chaotic_opaque_predicate(
    *,
    source: str,
    contract: str,
    fn: str,
    params: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    if apply_chaotic_opaque_predicate_v1 is None:
        raise NotImplementedError("apply_chaotic_opaque_predicate_v1 is not available yet")
    res = apply_chaotic_opaque_predicate_v1(
        source=source,
        contract_name=contract,
        fn_name=fn,
        **(params or {}),
    )
    details = getattr(res, "meta", None) or getattr(res, "details", {}) or {}
    return {
        "new_source": res.new_source,
        "details": details or {"note": "chaotic_opaque_predicate_v1 applied"},
    }


def _apply_string_split(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_string_split_v1 is None:
        raise NotImplementedError("apply_string_split_v1 is not available yet")
    res = apply_string_split_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "string_split_v1 applied"}}


def _apply_algebraic_identities(*, source: str, contract: str, fn: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if apply_algebraic_identities_v1 is None:
        raise NotImplementedError("apply_algebraic_identities_v1 is not available yet")
    res = apply_algebraic_identities_v1(source=source, contract_name=contract, fn_name=fn, **(params or {}))
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {"new_source": res.new_source, "details": details or {"note": "algebraic_identities_v1 applied"}}


def _apply_constant_encoding_v2_layered(
    *, source: str, contract: str, fn: str, params: Dict[str, Any]
) -> Dict[str, Any]:
    if apply_constant_encoding_v2_layered is None:
        raise NotImplementedError("apply_constant_encoding_v2_layered is not available yet")
    res = apply_constant_encoding_v2_layered(
        source=source,
        contract_name=contract,
        fn_name=fn,
        **(params or {}),
    )
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {
        "new_source": res.new_source,
        "details": details or {"note": "constant_encoding_v2_layered applied"},
    }


def _apply_boolean_split_v2_distributed(
    *, source: str, contract: str, fn: str, params: Dict[str, Any]
) -> Dict[str, Any]:
    if apply_boolean_split_v2_distributed is None:
        raise NotImplementedError("apply_boolean_split_v2_distributed is not available yet")
    res = apply_boolean_split_v2_distributed(
        source=source,
        contract_name=contract,
        fn_name=fn,
        **(params or {}),
    )
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {
        "new_source": res.new_source,
        "details": details or {"note": "boolean_split_v2_distributed applied"},
    }


def _apply_opaque_predicate_v2_entangled(
    *, source: str, contract: str, fn: str, params: Dict[str, Any]
) -> Dict[str, Any]:
    if apply_opaque_predicate_v2_entangled is None:
        raise NotImplementedError("apply_opaque_predicate_v2_entangled is not available yet")
    res = apply_opaque_predicate_v2_entangled(
        source=source,
        contract_name=contract,
        fn_name=fn,
        **(params or {}),
    )
    details: Dict[str, Any] = getattr(res, "details", {}) if hasattr(res, "details") else {}
    if hasattr(res, "meta") and isinstance(getattr(res, "meta"), dict):
        details = {**details, **getattr(res, "meta")}
    return {
        "new_source": res.new_source,
        "details": details or {"note": "opaque_predicate_v2_entangled applied"},
    }


def _apply_inline_internal_v2_diversified(
    *, source: str, contract: str, fn: str, params: Dict[str, Any]
) -> Dict[str, Any]:
    if apply_inline_internal_v2_diversified is None:
        raise NotImplementedError("apply_inline_internal_v2_diversified is not available yet")
    res = apply_inline_internal_v2_diversified(
        source=source,
        contract_name=contract,
        fn_name=fn,
        **(params or {}),
    )
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {
        "new_source": res.new_source,
        "details": details or {"note": "inline_internal_v2_diversified applied"},
    }


def _apply_cfg_flatten_v2_hybrid(
    *, source: str, contract: str, fn: str, params: Dict[str, Any]
) -> Dict[str, Any]:
    if apply_cfg_flatten_v2_hybrid is None:
        raise NotImplementedError("apply_cfg_flatten_v2_hybrid is not available yet")
    res = apply_cfg_flatten_v2_hybrid(
        source=source,
        contract_name=contract,
        fn_name=fn,
        **(params or {}),
    )
    details = getattr(res, "details", {}) if hasattr(res, "details") else {}
    return {
        "new_source": res.new_source,
        "details": details or {"note": "cfg_flatten_v2_hybrid applied"},
    }


TRANSFORMS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "rename_identifiers_v2_scoped": _apply_rename_v2_scoped,
    "rename_identifiers_sha1_v1": _apply_rename_sha1,
    "rename_identifiers_v1": _apply_rename_v1,
    "dynamic_constants_v1": _apply_dynamic_constants,
    "constant_encoding_v1": _apply_constant_encoding,
    "constant_encoding_v2_layered": _apply_constant_encoding_v2_layered,
    "boolean_split_v1": _apply_boolean_split,
    "boolean_split_v2_distributed": _apply_boolean_split_v2_distributed,
    "string_split_v1": _apply_string_split,
    "algebraic_identities_v1": _apply_algebraic_identities,
    "opaque_predicate_v1": _apply_opaque_predicate,
    "opaque_predicate_v2_entangled": _apply_opaque_predicate_v2_entangled,
    "dead_code_v1": _apply_dead_code,
    "predicate_masking_v1": _apply_predicate_masking,
    "loop_rewrite_v1": _apply_loop_rewrite,
    "layout_scramble_v1": _apply_layout_scramble,
    "inline_internal_v1": _apply_inline_internal,
    "inline_internal_v2_diversified": _apply_inline_internal_v2_diversified,

    # NEW: missing BiAn-parity transforms
    "local_to_state_lift_v1": _apply_local_to_state_lift,
    "scalar_to_struct_indirection_v1": _apply_scalar_to_struct_indirection,
    "modifier_expand_v1": _apply_modifier_expand,
    "public_state_accessor_indirection_v1": _apply_public_state_accessor_indirection,
    "storage_indirection_v1": _apply_storage_indirection,

    "cfg_flatten_v2_hybrid": _apply_cfg_flatten_v2_hybrid,
    "cfg_flatten_v1": _apply_cfg_flatten,
    "yul_microblock_v1": _apply_yul_microblock,

    # Existing research-grade techniques
    "dispatcher_cfg_virtualization_v1": _apply_dispatcher_cfg_virtualization,
    "opaque_storage_slot_indirection_v1": _apply_opaque_storage_slot_indirection,
    "stack_variable_aliasing_v1": _apply_stack_variable_aliasing,
    "chaotic_opaque_predicate_v1": _apply_chaotic_opaque_predicate,
}

# --- POLICY ALIAS (maps v2 transforms to v1 policy rules) ---
POLICY_ALIAS = {
    "constant_encoding_v2_layered": "constant_encoding_v1",
    "boolean_split_v2_distributed": "boolean_split_v1",
    "opaque_predicate_v2_entangled": "opaque_predicate_v1",
    "inline_internal_v2_diversified": "inline_internal_v1",
    "cfg_flatten_v2_hybrid": "cfg_flatten_v1",
}

# ----------------------------
# Risk-aware transform classes
# ----------------------------
# Tier-0 no longer means "no obfuscation". It means: cosmetic/syntactic only.
_ALWAYS_SAFE_TRANSFORMS = {
    "layout_scramble_v1",
    "rename_identifiers_v2_scoped",
    "rename_identifiers_sha1_v1",
    "rename_identifiers_v1",
}

_CONTEXT_SAFE_TRANSFORMS = {
    "constant_encoding_v1",
    "constant_encoding_v2_layered",
    "dynamic_constants_v1",
    "string_split_v1",
    "boolean_split_v1",
    "boolean_split_v2_distributed",
    "opaque_predicate_v1",
    "dead_code_v1",
    "stack_variable_aliasing_v1",
}

_RISKY_TRANSFORMS = {
    "algebraic_identities_v1",
    "predicate_masking_v1",
    "loop_rewrite_v1",
    "inline_internal_v1",
    "inline_internal_v2_diversified",
    "local_to_state_lift_v1",
    "scalar_to_struct_indirection_v1",
    "modifier_expand_v1",
    "public_state_accessor_indirection_v1",
    "storage_indirection_v1",
    "cfg_flatten_v1",
    "cfg_flatten_v2_hybrid",
    "yul_microblock_v1",
    "dispatcher_cfg_virtualization_v1",
    "opaque_storage_slot_indirection_v1",
    "opaque_predicate_v2_entangled",
    "chaotic_opaque_predicate_v1",
}

_HARD_PROTECTED_TAGS = {
    "access_control_guard",
    "external_call_region",
    "reentrancy_sensitive_region",
    "state_write_region",
}

_SOFT_PROTECTED_TAGS = {
    "arithmetic_region",
    "revert_semantics_region",
    "loop_gas_region",
}

_SAFE_AUTO_TRANSFORMS = [
    "layout_scramble_v1",
    "string_split_v1",
    "rename_identifiers_v2_scoped",
]


def _tid_from_obj(tr: Dict[str, Any]) -> str:
    """
    Normalize transform id across schemas:
      - engine-native: {"id": "..."}
      - LLM planner schema: {"transform_id": "..."}
      - older schema: {"type": "..."}
    """
    if not isinstance(tr, dict):
        return ""
    tid = tr.get("id") or tr.get("transform_id") or tr.get("type")
    return str(tid).strip() if tid else ""


def _normalize_selected_schema(selected: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Ensure every selected transform entry has:
      - "id" (normalized)
      - "params" dict
      - optional "target" dict (preserved)
      - auto_added flag preserved when present
    """
    out: List[Dict[str, Any]] = []
    for tr in selected or []:
        if not isinstance(tr, dict):
            continue
        tid = _tid_from_obj(tr)
        if not tid:
            continue
        params = tr.get("params") if isinstance(tr.get("params"), dict) else {}
        target = tr.get("target") if isinstance(tr.get("target"), dict) else {}
        row = {"id": tid, "params": params, "target": target}
        if tr.get("auto_added") is not None:
            row["auto_added"] = bool(tr.get("auto_added"))
        out.append(row)
    return out


def _auto_add_safe_transforms(fp: Dict[str, Any], selected: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Attempt safe transforms even if the LLM/optimizer omitted them.
    The engine still records noops and validation still gets final say.
    """
    existing = {_tid_from_obj(x) for x in selected if isinstance(x, dict)}
    out = list(selected)
    fn = str(fp.get("function") or "")

    for tid in _SAFE_AUTO_TRANSFORMS:
        if tid not in TRANSFORMS:
            continue
        if tid in existing:
            continue
        out.append(
            {
                "id": tid,
                "params": {"seed": 1337},
                "target": {"function": fn},
                "auto_added": True,
            }
        )
        existing.add(tid)

    return out


def _dedupe_selected(selected: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for tr in selected:
        if not isinstance(tr, dict):
            continue
        tid = _tid_from_obj(tr)
        if not tid:
            continue
        if tid in seen:
            continue
        seen.add(tid)
        params = tr.get("params") if isinstance(tr.get("params"), dict) else {}
        target = tr.get("target") if isinstance(tr.get("target"), dict) else {}
        row = {"id": tid, "params": params, "target": target}
        if tr.get("auto_added") is not None:
            row["auto_added"] = bool(tr.get("auto_added"))
        out.append(row)
    return out


# Safe composition order:
# data/layout first, then control-flow, then renaming last.
_ORDER = {
    "dynamic_constants_v1": 0,
    "constant_encoding_v1": 1,
    "constant_encoding_v2_layered": 2,
    "boolean_split_v1": 2,
    "string_split_v1": 2,
    "algebraic_identities_v1": 3,
    "boolean_split_v2_distributed": 4,
    "local_to_state_lift_v1": 3,
    "scalar_to_struct_indirection_v1": 4,
    "public_state_accessor_indirection_v1": 5,
    "storage_indirection_v1": 6,

    "layout_scramble_v1": 10,
    "stack_variable_aliasing_v1": 12,
    "opaque_storage_slot_indirection_v1": 15,

    "modifier_expand_v1": 18,
    "opaque_predicate_v1": 20,
    "dead_code_v1": 21,
    "predicate_masking_v1": 22,
    "loop_rewrite_v1": 23,
    "chaotic_opaque_predicate_v1": 24,
    "opaque_predicate_v2_entangled": 25,
    "inline_internal_v1": 30,
    "inline_internal_v2_diversified": 32,

    "dispatcher_cfg_virtualization_v1": 70,
    "cfg_flatten_v2_hybrid": 78,
    "cfg_flatten_v1": 80,
    "yul_microblock_v1": 90,

    "rename_identifiers_v2_scoped": 100,
    "rename_identifiers_sha1_v1": 101,
    "rename_identifiers_v1": 110,
}


def _order_selected(selected: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(selected, key=lambda tr: _ORDER.get(_tid_from_obj(tr), 10_000))


def _debug_selected_ids(selected: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for tr in selected or []:
        tid = _tid_from_obj(tr)
        if tid:
            out.append(tid)
    return out


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    return []


def _protected_tags_from_fp(fp: Dict[str, Any]) -> set[str]:
    tags: set[str] = set()

    sec_entry = fp.get("sec_entry") if isinstance(fp.get("sec_entry"), dict) else {}
    policy_constraints = sec_entry.get("policy_constraints") if isinstance(sec_entry.get("policy_constraints"), dict) else {}

    # protected_regions may be a list[str] or list[dict]
    for container in (fp, sec_entry, policy_constraints):
        for key in ("protected_region_tags", "protected_regions"):
            vals = _as_list(container.get(key)) if isinstance(container, dict) else []
            for item in vals:
                if isinstance(item, str) and item.strip():
                    tags.add(item.strip())
                elif isinstance(item, dict):
                    tag = item.get("tag") or item.get("kind") or item.get("type")
                    if isinstance(tag, str) and tag.strip():
                        tags.add(tag.strip())

    return tags


def _severity_from_fp(fp: Dict[str, Any]) -> str:
    sec_entry = fp.get("sec_entry") if isinstance(fp.get("sec_entry"), dict) else {}
    raw = fp.get("sec_severity_max") or fp.get("sec_severity") or sec_entry.get("sec_severity")
    return str(raw or "LOW").upper().strip()


def _tier_from_fp(fp: Dict[str, Any]) -> int:
    raw_tier = fp.get("tier")
    try:
        return int(raw_tier) if raw_tier is not None else 2
    except Exception:
        return 2


def _compat_matrix_gate(fp: Dict[str, Any], tid: str, tier: int, sev: str) -> Tuple[bool, str]:
    """
    Keep your existing catalog/compat-matrix policy as a backstop, but allow
    always-safe transforms to survive Tier-0/protected functions.
    """
    catalog = default_transform_catalog()
    policy_tid = tid
    spec = catalog.get(policy_tid)

    if spec is None and tid in POLICY_ALIAS:
        policy_tid = POLICY_ALIAS[tid]
        spec = catalog.get(policy_tid)

    # Some local transforms may exist before they are catalogued. Let the handler/noop path decide.
    if spec is None:
        if tid in TRANSFORMS:
            return True, "not_in_catalog_but_registered"
        return False, "unknown_transform"

    sec_entry = fp.get("sec_entry") if isinstance(fp.get("sec_entry"), dict) else {}
    policy_context = fp.get("policy_context") if isinstance(fp.get("policy_context"), dict) else {}
    matrix = policy_context.get("transform_vulnerability_matrix") if isinstance(policy_context, dict) else None

    sec_signals = extract_signals(sec_entry or {})
    ok, reason = compat_matrix_compatible(
        spec=spec,
        tier=tier,
        signals=sec_signals,
        fn_advice=fp if isinstance(fp, dict) else {},
        sec_severity_max=sev,
        matrix=matrix,
    )
    return bool(ok), str(reason or "")


def _engine_allow_transform(fp: Dict[str, Any], tid: str) -> Tuple[bool, str, str]:
    """
    Final safety gate.

    Returns:
      allowed, reason, skip_category

    skip_category values are intentionally terminal/report-friendly:
      skipped_by_risk | skipped_by_conflict | skipped_no_handler | unknown_transform
    """
    tier = _tier_from_fp(fp)
    sev = _severity_from_fp(fp)
    protected_tags = _protected_tags_from_fp(fp)
    hard_overlap = protected_tags & _HARD_PROTECTED_TAGS
    soft_overlap = protected_tags & _SOFT_PROTECTED_TAGS

    if tid not in TRANSFORMS:
        return False, "unknown_transform", "unknown_transform"

    # Always-safe transforms are allowed even for Tier-0/protected functions.
    if tid in _ALWAYS_SAFE_TRANSFORMS:
        return True, "always_safe", ""

    # HIGH/CRITICAL means only always-safe transforms.
    if sev in {"HIGH", "CRITICAL"}:
        return False, f"blocked_non_cosmetic_due_to_severity_{sev}", "skipped_by_risk"

    # Tier-0 means only always-safe transforms.
    if tier <= 0:
        return False, "tier0_allows_only_always_safe", "skipped_by_risk"

    if tid in _RISKY_TRANSFORMS and hard_overlap:
        return (
            False,
            f"risky_transform_overlaps_hard_protected_region:{','.join(sorted(hard_overlap))}",
            "skipped_by_risk",
        )

    if tid in _RISKY_TRANSFORMS and soft_overlap and tier < 3:
        return (
            False,
            f"risky_transform_overlaps_soft_protected_region:{','.join(sorted(soft_overlap))}",
            "skipped_by_risk",
        )

    if tid in _RISKY_TRANSFORMS and tier < 2:
        return False, "risky_requires_tier2", "skipped_by_risk"

    ok, reason = _compat_matrix_gate(fp, tid, tier, sev)
    if not ok:
        # Compat matrix reasons are usually risk/conflict reasons.
        cat = "skipped_by_conflict" if "conflict" in reason.lower() else "skipped_by_risk"
        return False, reason or "compat_matrix_blocked", cat

    return True, "allowed", ""


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _offset_to_line_col(source: str, offset: int) -> Dict[str, int]:
    if offset < 0:
        offset = 0
    if offset > len(source):
        offset = len(source)

    line = source.count("\n", 0, offset) + 1
    last_nl = source.rfind("\n", 0, offset)
    col = offset + 1 if last_nl < 0 else offset - last_nl
    return {"offset": offset, "line": line, "column": col}


def _make_span(source: str, start: int, end: int) -> Dict[str, int]:
    s = _offset_to_line_col(source, start)
    e = _offset_to_line_col(source, end)
    return {
        "start_offset": s["offset"],
        "end_offset": e["offset"],
        "start_line": s["line"],
        "end_line": e["line"],
        "start_column": s["column"],
        "end_column": e["column"],
    }


def _short_excerpt(text: str, limit: int = 240) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + " ..."


def _find_matching_brace(source: str, open_brace_idx: int) -> int:
    depth = 0
    for i in range(open_brace_idx, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _find_function_region(source: str, fn_name: str) -> Optional[Dict[str, Any]]:
    """
    Approximate function-region locator.
    This is NOT a formal AST span mapper.
    It is a stable, reviewer-friendly function-level source mapping artifact.
    """
    pattern = re.compile(rf"\bfunction\s+{re.escape(fn_name)}\b")
    m = pattern.search(source)
    if not m:
        return None

    start_idx = m.start()
    sig_end = source.find("{", m.end())
    if sig_end < 0:
        return None

    end_idx = _find_matching_brace(source, sig_end)
    if end_idx < 0:
        return None

    signature = source[m.start():sig_end].strip()
    body = source[start_idx:end_idx + 1]

    return {
        "signature": signature,
        "span": _make_span(source, start_idx, end_idx + 1),
        "excerpt": _short_excerpt(body),
    }


def _get_function_text(source: str, fn_name: str) -> str:
    meta = _find_function_region(source, fn_name)
    if not meta or not meta.get("span"):
        return ""
    span = meta["span"]
    start = int(span.get("start_offset", 0))
    end = int(span.get("end_offset", 0))
    return source[start:end]


def _infer_identifier_rename_candidates(fn_text: str) -> bool:
    if not fn_text:
        return False

    candidate_count = 0

    # parameters / returns
    m = re.search(r"\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*\((.*?)\)\s*([^{}]*)\{", fn_text, re.DOTALL)
    if m:
        params_src = m.group(1) or ""
        returns_src = m.group(2) or ""
        for src in (params_src, returns_src):
            for nm in re.findall(r"\b(?:memory|storage|calldata)?\s*([A-Za-z_][A-Za-z0-9_]*)\b", src):
                if nm and not nm.startswith("__obf_") and not re.match(r"^v_\d+_\d+$", nm):
                    candidate_count += 1

    # locals
    local_decl_re = re.compile(
        r"\b(?:uint(?:8|16|32|64|128|256)?|int(?:8|16|32|64|128|256)?|bool|address|string|bytes(?:[1-9]|[12][0-9]|3[0-2])?|bytes|mapping\s*\([^)]*\)|[A-Za-z_][A-Za-z0-9_]*\[\]?)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
    )
    for nm in local_decl_re.findall(fn_text):
        if nm and not nm.startswith("__obf_") and not re.match(r"^v_\d+_\d+$", nm):
            candidate_count += 1

    return candidate_count > 0


def _infer_internal_call_presence(fn_text: str, fn_name: str) -> bool:
    if not fn_text:
        return False

    exclude = {
        fn_name,
        "require",
        "assert",
        "revert",
        "if",
        "for",
        "while",
        "emit",
        "return",
        "new",
        "keccak256",
        "sha256",
        "ripemd160",
        "ecrecover",
        "addmod",
        "mulmod",
        "abi",
        "super",
    }

    for callee in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", fn_text):
        if callee in exclude:
            continue
        # crude but useful: method calls object.fn(...) are likely external/lib style; skip those
        if re.search(rf"\.\s*{re.escape(callee)}\s*\(", fn_text):
            continue
        return True
    return False


def _infer_storage_like_presence(fn_text: str) -> bool:
    if not fn_text:
        return False

    patterns = [
        r"\.\s*push\s*\(",
        r"\.\s*pop\s*\(",
        r"\.\s*length\b",
        r"\[[^\]]+\]",
        r"\bdelete\b",
        r"\bstorage\b",
    ]
    return any(re.search(p, fn_text) for p in patterns)


def _infer_literal_presence(fn_text: str) -> bool:
    if not fn_text:
        return False
    return bool(
        re.search(r"\b\d+\b", fn_text)
        or re.search(r"\b(?:true|false)\b", fn_text)
        or re.search(r'"(?:\\.|[^"\\])*"', fn_text)
        or re.search(r'hex"(?:[0-9a-fA-F]{2})*"', fn_text)
        or re.search(r"\b0x[0-9a-fA-F]+\b", fn_text)
    )


def _infer_booleanish_presence(fn_text: str) -> bool:
    if not fn_text:
        return False
    return bool(
        re.search(r"\bif\s*\(", fn_text)
        or re.search(r"\brequire\s*\(", fn_text)
        or re.search(r"\bassert\s*\(", fn_text)
        or re.search(r"\?\s*[^:]+\s*:", fn_text)
        or re.search(r"(==|!=|<=|>=|<|>|&&|\|\|)", fn_text)
    )


def _infer_loop_presence(fn_text: str) -> bool:
    if not fn_text:
        return False
    return bool(re.search(r"\b(for|while|do)\b", fn_text))


def _infer_modifier_presence(fn_text: str) -> bool:
    if not fn_text:
        return False
    header = fn_text.split("{", 1)[0]
    ignore = {
        "function",
        "external",
        "public",
        "private",
        "internal",
        "pure",
        "view",
        "payable",
        "virtual",
        "override",
        "returns",
        "memory",
        "storage",
        "calldata",
    }
    after_params = ""
    m = re.search(r"\)\s*(.*?)$", header, re.DOTALL)
    if m:
        after_params = m.group(1)
    toks = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", after_params)
    toks = [t for t in toks if t not in ignore]
    return len(toks) > 0


def _engine_applicable_transform(source: str, fp: Dict[str, Any], fn: str, tid: str) -> bool:
    """
    Heuristic applicability backstop for refill.
    This is intentionally conservative and only engine-local.
    """
    if tid == "layout_scramble_v1":
        return True

    fn_text = _get_function_text(source, fn)
    if not fn_text:
        return False

    has_lifted_state_refs = "__obf_state." in fn_text or "__obf_g_" in fn_text
    has_generated_accessor_refs = "__obf_" in fn_text and "_get(" in fn_text

    is_viewish = bool(re.search(r"\b(view|pure)\b", fn_text.split("{", 1)[0]))
    has_literals = _infer_literal_presence(fn_text)
    has_boolish = _infer_booleanish_presence(fn_text)
    has_loops = _infer_loop_presence(fn_text)
    has_storage = _infer_storage_like_presence(fn_text)
    has_internal_calls = _infer_internal_call_presence(fn_text, fn)
    has_rename_candidates = _infer_identifier_rename_candidates(fn_text)
    has_modifiers = _infer_modifier_presence(fn_text)

    if tid in {"rename_identifiers_v2_scoped", "rename_identifiers_sha1_v1", "rename_identifiers_v1"}:
        return has_rename_candidates

    if tid in {"dynamic_constants_v1", "constant_encoding_v1", "constant_encoding_v2_layered"}:
        return has_literals

    if tid == "string_split_v1":
        return bool(re.search(r'"(?:\\.|[^"\\])*"', fn_text))

    if tid in {"boolean_split_v1", "boolean_split_v2_distributed"}:
        return has_boolish

    if tid in {"opaque_predicate_v1", "opaque_predicate_v2_entangled", "chaotic_opaque_predicate_v1", "dead_code_v1", "predicate_masking_v1"}:
        return has_boolish or has_loops

    if tid == "loop_rewrite_v1":
        if has_lifted_state_refs:
            return False
        return has_loops

    if tid in {"inline_internal_v1", "inline_internal_v2_diversified"}:
        if is_viewish:
            return False
        return has_internal_calls

    if tid == "modifier_expand_v1":
        return has_modifiers

    if tid == "public_state_accessor_indirection_v1":
        if has_lifted_state_refs or has_generated_accessor_refs:
            return False
        if is_viewish:
            return False
        return has_storage

    if tid in {
        "local_to_state_lift_v1",
        "scalar_to_struct_indirection_v1",
        "storage_indirection_v1",
        "opaque_storage_slot_indirection_v1",
    }:
        if is_viewish:
            return False
        return has_storage

    if tid in {"cfg_flatten_v1", "cfg_flatten_v2_hybrid", "dispatcher_cfg_virtualization_v1"}:
        if has_lifted_state_refs:
            return False
        return has_loops or has_boolish or bool(re.search(r"\breturn\s+.+?;", fn_text, flags=re.DOTALL))

    if tid == "yul_microblock_v1":
        return not is_viewish

    if tid == "stack_variable_aliasing_v1":
        if has_lifted_state_refs:
            return False
        return has_rename_candidates or has_literals

    return True


def _safe_refill_ids_for_tier(tier: int) -> List[str]:
    # Always try safe visual transforms first.
    light = [
        "layout_scramble_v1",
        "string_split_v1",
        "dynamic_constants_v1",
        "constant_encoding_v1",
        "rename_identifiers_v2_scoped",
        "rename_identifiers_sha1_v1",
    ]

    tier1_promotion = [
        "boolean_split_v1",
        "stack_variable_aliasing_v1",
        "dead_code_v1",
        "opaque_predicate_v1",
    ]

    moderate = light + [
        "boolean_split_v1",
        "inline_internal_v1",
        "opaque_predicate_v1",
        "loop_rewrite_v1",
        "modifier_expand_v1",
        "local_to_state_lift_v1",
        "stack_variable_aliasing_v1",
        "predicate_masking_v1",
        "dead_code_v1",
        "public_state_accessor_indirection_v1",
    ]

    aggressive = moderate + [
        "cfg_flatten_v1",
        "scalar_to_struct_indirection_v1",
        "yul_microblock_v1",
        "storage_indirection_v1",
        "dispatcher_cfg_virtualization_v1",
        "opaque_storage_slot_indirection_v1",
    ]

    # Tier-0 gets safe cosmetic only.
    if tier <= 0:
        return list(_SAFE_AUTO_TRANSFORMS)
    if tier <= 1:
        return light + tier1_promotion
    if tier == 2:
        return moderate
    return aggressive


def _conflicts_with_attempted(tid: str, attempted_ids: set[str]) -> bool:
    rename_family = {
        "rename_identifiers_v2_scoped",
        "rename_identifiers_sha1_v1",
        "rename_identifiers_v1",
    }
    if tid in rename_family and any(x in attempted_ids for x in rename_family if x != tid):
        return True

    # local lifting and stack aliasing are unsafe in combination
    if tid == "stack_variable_aliasing_v1" and "local_to_state_lift_v1" in attempted_ids:
        return True
    if tid == "local_to_state_lift_v1" and "stack_variable_aliasing_v1" in attempted_ids:
        return True

    # once local lifting has happened, do not run rename passes afterward
    if tid in rename_family and "local_to_state_lift_v1" in attempted_ids:
        return True

    # scalar-to-struct also conflicts with lifted state refs
    if tid == "scalar_to_struct_indirection_v1" and "local_to_state_lift_v1" in attempted_ids:
        return True
    if tid == "local_to_state_lift_v1" and "scalar_to_struct_indirection_v1" in attempted_ids:
        return True

    # public accessor indirection conflicts with lifted state refs
    if tid == "public_state_accessor_indirection_v1" and "local_to_state_lift_v1" in attempted_ids:
        return True
    if tid == "local_to_state_lift_v1" and "public_state_accessor_indirection_v1" in attempted_ids:
        return True

    # cfg flattening after local lifting is unsafe in current implementation
    if tid == "cfg_flatten_v1" and "local_to_state_lift_v1" in attempted_ids:
        return True
    if tid == "local_to_state_lift_v1" and "cfg_flatten_v1" in attempted_ids:
        return True

    # loop rewriting after local lifting is unsafe in current implementation
    if tid == "loop_rewrite_v1" and "local_to_state_lift_v1" in attempted_ids:
        return True
    if tid == "local_to_state_lift_v1" and "loop_rewrite_v1" in attempted_ids:
        return True

    return False


def _serialize_applied_edit(e: AppliedEdit) -> Dict[str, Any]:
    return {
        "sequence": e.sequence,
        "function": e.function,
        "id": e.transform_id,
        "transform_id": e.transform_id,
        "target": e.target,
        "target_kind": e.target_kind,
        "params": e.params,
        "details": e.details,
        "status": e.status,
        "changed": e.changed,
        "result_category": "applied" if e.changed else "noop",
        "effect_kind": e.effect_kind,
        "before_signature": e.before_signature,
        "after_signature": e.after_signature,
        "original_span": e.original_span,
        "new_span": e.new_span,
        "before_excerpt": e.before_excerpt,
        "after_excerpt": e.after_excerpt,
        "source_hash_before": e.source_hash_before,
        "source_hash_after": e.source_hash_after,
    }


def _serialize_selected_transform(function_name: str, tr: Dict[str, Any]) -> Dict[str, Any]:
    tid = _tid_from_obj(tr)
    target = tr.get("target") if isinstance(tr.get("target"), dict) else {}
    params = tr.get("params") if isinstance(tr.get("params"), dict) else {}
    return {
        "id": tid,
        "function": function_name,
        "target": target,
        "params": params,
        "transform_id": tid,
        "auto_added": bool(tr.get("auto_added")),
        "final_outcome": "selected",
        "final_reason": "",
        "skip_category": "",
        "changed": False,
    }


def _is_transform_noop(before: str, after: str, details: Dict[str, Any]) -> Tuple[bool, str]:
    if before == after:
        return True, "source_unchanged"

    if not isinstance(details, dict):
        return False, ""

    note = str(details.get("note") or details.get("reason") or "").lower()
    if "noop" in note or "no eligible" in note or "skipped" in note:
        return True, note or "reported_noop"

    for k in ("replaced", "replacements", "changed", "inserted", "edits", "count"):
        if k in details:
            try:
                val = details.get(k)
                if isinstance(val, bool):
                    if val is False:
                        return True, f"{k}=false"
                elif int(val or 0) == 0:
                    return True, f"{k}=0"
            except Exception:
                pass

    return False, ""


def _make_terminal_row(
    *,
    fn: str,
    tid: str,
    target: Dict[str, Any],
    params: Dict[str, Any],
    outcome: str,
    reason: str = "",
    skip_category: str = "",
    details: Optional[Dict[str, Any]] = None,
    auto_added: bool = False,
    changed: bool = False,
) -> Dict[str, Any]:
    return {
        "id": tid,
        "transform_id": tid,
        "function": fn,
        "target": target,
        "params": params,
        "auto_added": auto_added,
        "details": details or {},
        "final_outcome": outcome,
        "final_reason": reason,
        "reason": reason,
        "skip_category": skip_category,
        "changed": changed,
    }


class ObfuscationEngine:
    def __init__(
        self,
        *,
        source_path: Path,
        plan_path: Path,
        out_dir: Path,
        sec_by_function: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self.source_path = Path(source_path)
        self.plan_path = Path(plan_path)
        self.out_dir = Path(out_dir)
        self.sec_by_function = sec_by_function or {}

    def run(self) -> Dict[str, Any]:
        source = self.source_path.read_text(encoding="utf-8")
        plan = json.loads(self.plan_path.read_text(encoding="utf-8"))

        contract = plan.get("contract", "")
        plans = plan.get("plans", []) or []

        # default tier/severity/sec_entry for all per-function plans
        for fp in plans:
            if not isinstance(fp, dict):
                continue
            fn = str(fp.get("function") or "")
            if fp.get("tier") is None:
                fp["tier"] = 2
            if fp.get("sec_severity_max") is None:
                fp["sec_severity_max"] = "LOW"
            if fn and not isinstance(fp.get("sec_entry"), dict) and fn in self.sec_by_function:
                fp["sec_entry"] = self.sec_by_function[fn]

        # normalize per-function selected_transforms schema first
        for fp in plans:
            if not isinstance(fp, dict):
                continue
            sel = fp.get("selected_transforms")
            if not isinstance(sel, list):
                sel = []
            sel = _normalize_selected_schema(sel)
            sel = _auto_add_safe_transforms(fp, sel)
            fp["selected_transforms"] = _dedupe_selected(sel)

        # Accept either:
        #   A) per-function plan["plans"][i]["selected_transforms"]
        #   B) flat plan["transforms"] emitted by optimizer/repair loop
        flat_transforms = plan.get("transforms")
        if isinstance(flat_transforms, list) and flat_transforms:
            by_fn: Dict[str, List[Dict[str, Any]]] = {}
            for tr in flat_transforms:
                if not isinstance(tr, dict):
                    continue
                tid = _tid_from_obj(tr)
                if not tid:
                    continue
                target = tr.get("target") if isinstance(tr.get("target"), dict) else {}
                fn = target.get("function")
                if not fn or not isinstance(fn, str):
                    continue
                by_fn.setdefault(fn, []).append(tr)

            existing = {
                str(fp.get("function")): fp
                for fp in (plans or [])
                if isinstance(fp, dict) and fp.get("function")
            }

            for fn, trs in by_fn.items():
                fp = existing.get(fn)
                if fp is None:
                    fp = {
                        "function": fn,
                        "tier": 2,
                        "sec_severity_max": "LOW",
                        "selected_transforms": [],
                    }
                    if fn in self.sec_by_function:
                        fp["sec_entry"] = self.sec_by_function[fn]
                    plans.append(fp)
                    existing[fn] = fp
                else:
                    if fp.get("tier") is None:
                        fp["tier"] = 2
                    if fp.get("sec_severity_max") is None:
                        fp["sec_severity_max"] = "LOW"

                fp_selected = fp.get("selected_transforms")
                if not isinstance(fp_selected, list):
                    fp_selected = []

                for tr in trs:
                    tid = _tid_from_obj(tr)
                    if not tid:
                        continue
                    fp_selected.append(
                        {
                            "id": tid,
                            "params": tr.get("params", {}) if isinstance(tr.get("params"), dict) else {},
                            "target": tr.get("target", {}) if isinstance(tr.get("target"), dict) else {},
                        }
                    )

                fp_selected = _normalize_selected_schema(fp_selected)
                fp_selected = _auto_add_safe_transforms(fp, fp_selected)
                fp["selected_transforms"] = _dedupe_selected(fp_selected)

        applied: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        selected_rows: List[Dict[str, Any]] = []

        new_source = source

        for fp in plans:
            if not isinstance(fp, dict):
                continue

            fn = str(fp.get("function") or "")
            selected = fp.get("selected_transforms", []) or []
            selected = _normalize_selected_schema(selected)
            selected = _auto_add_safe_transforms(fp, selected)
            selected = _order_selected(_dedupe_selected(selected))

            llm_meta = fp.get("llm_meta") if isinstance(fp.get("llm_meta"), dict) else {}
            llm_graph = (
                llm_meta.get("composition_graph")
                if isinstance(llm_meta.get("composition_graph"), dict)
                else {}
            )

            function_ir = fp.get("function_ir") if isinstance(fp.get("function_ir"), dict) else {}
            sec_entry = fp.get("sec_entry") if isinstance(fp.get("sec_entry"), dict) else {}

            selected_ids_for_graph = [
                t.get("id")
                for t in selected
                if isinstance(t, dict) and isinstance(t.get("id"), str) and t.get("id").strip()
            ]

            det_graph = build_deterministic_composition_graph(
                selected_ids=selected_ids_for_graph,
                function_ir=function_ir,
                sec_advice=sec_entry,
            )

            graph = merge_composition_graphs(llm_graph, det_graph)

            # Persist the merged graph back into metadata so transform_map / downstream consumers
            # are aligned with the actual order used by the engine.
            llm_meta["composition_graph"] = graph
            fp["llm_meta"] = llm_meta

            try:
                ordered_selected = order_plan_steps(
                    [
                        {
                            "transform_id": t.get("id"),
                            "params": t.get("params", {}),
                        }
                        for t in selected
                        if isinstance(t, dict) and isinstance(t.get("id"), str) and t.get("id").strip()
                    ],
                    graph,
                ) if graph else []

                ordered_ids = [
                    x.get("transform_id")
                    for x in ordered_selected or []
                    if isinstance(x, dict) and isinstance(x.get("transform_id"), str) and x.get("transform_id").strip()
                ]

                if ordered_ids:
                    by_id: Dict[str, Dict[str, Any]] = {}
                    for t in selected:
                        if not isinstance(t, dict):
                            continue
                        tid0 = t.get("id")
                        if isinstance(tid0, str) and tid0.strip():
                            by_id[tid0] = t

                    reordered: List[Dict[str, Any]] = []
                    seen_ids = set()

                    for tid0 in ordered_ids:
                        row = by_id.get(tid0)
                        if row is None or tid0 in seen_ids:
                            continue
                        seen_ids.add(tid0)
                        reordered.append(row)

                    # preserve any leftovers not mentioned by order_plan_steps
                    for t in selected:
                        if not isinstance(t, dict):
                            continue
                        tid0 = t.get("id")
                        if not isinstance(tid0, str) or not tid0.strip() or tid0 in seen_ids:
                            continue
                        seen_ids.add(tid0)
                        reordered.append(t)

                    selected = reordered
            except Exception:
                pass

            tier = _tier_from_fp(fp)

            # IMPORTANT CHANGE:
            # Do not skip tier-0 functions. Tier-0 functions still get safe cosmetic transforms.
            if not selected or not fn:
                continue

            attempted_ids: set[str] = set()

            for tr in selected:
                tid = _tid_from_obj(tr)
                params = tr.get("params", {}) if isinstance(tr.get("params"), dict) else {}
                target_in = tr.get("target") if isinstance(tr.get("target"), dict) else {}
                auto_added = bool(tr.get("auto_added"))

                disable_safe_refill = bool(params.get("disable_safe_refill")) if isinstance(params, dict) else False

                if not tid:
                    continue

                target: Dict[str, Any] = dict(target_in)
                target.setdefault("function", fn)

                base_try_ids: List[str] = [tid]

                if not _engine_applicable_transform(new_source, fp, fn, tid):
                    reason = "not_applicable_preflight"
                    skipped.append({
                        "function": fn,
                        "transform_id": tid,
                        "reason": reason,
                        "skip_category": "noop_no_eligible_site",
                    })
                    selected_rows.append(
                        _make_terminal_row(
                            fn=fn,
                            tid=tid,
                            target=target,
                            params=params,
                            outcome="noop_no_eligible_site",
                            reason=reason,
                            skip_category="noop_no_eligible_site",
                            auto_added=auto_added,
                        )
                    )
                    base_try_ids = []

                # Safe refill: replace non-applicable/no-op transforms with applicable safe transforms.
                refill_ids: List[str] = []

                if not disable_safe_refill:
                    for rid in _safe_refill_ids_for_tier(tier):
                        if rid == tid or rid in attempted_ids:
                            continue
                        if _conflicts_with_attempted(rid, attempted_ids):
                            continue
                        if not _engine_applicable_transform(new_source, fp, fn, rid):
                            continue
                        ok_refill, _, _ = _engine_allow_transform(fp, rid)
                        if ok_refill:
                            refill_ids.append(rid)
                        if len(refill_ids) >= 2:
                            break

                try_ids = base_try_ids + refill_ids

                for real_tid in try_ids:
                    if real_tid in attempted_ids:
                        continue
                    attempted_ids.add(real_tid)

                    real_auto_added = auto_added or (real_tid != tid)
                    row_params = dict(params) if isinstance(params, dict) else {}
                    row_target = dict(target)

                    ok, reason, skip_category = _engine_allow_transform(fp, real_tid)
                    if not ok:
                        skip_category = skip_category or "skipped_by_risk"
                        skipped.append({
                            "function": fn,
                            "transform_id": real_tid,
                            "reason": f"Engine gate blocked: {reason}",
                            "skip_category": skip_category,
                        })
                        selected_rows.append(
                            _make_terminal_row(
                                fn=fn,
                                tid=real_tid,
                                target=row_target,
                                params=row_params,
                                outcome=skip_category,
                                reason=f"Engine gate blocked: {reason}",
                                skip_category=skip_category,
                                auto_added=real_auto_added,
                            )
                        )
                        continue

                    handler = TRANSFORMS.get(real_tid)
                    if handler is None:
                        skipped.append({
                            "function": fn,
                            "transform_id": real_tid,
                            "reason": "Unknown transform_id (not registered).",
                            "skip_category": "skipped_no_handler",
                        })
                        selected_rows.append(
                            _make_terminal_row(
                                fn=fn,
                                tid=real_tid,
                                target=row_target,
                                params=row_params,
                                outcome="skipped_no_handler",
                                reason="Unknown transform_id (not registered).",
                                skip_category="skipped_no_handler",
                                auto_added=real_auto_added,
                            )
                        )
                        continue

                    try:
                        before_source = new_source
                        handler_params = dict(params) if isinstance(params, dict) else {}
                        handler_params.pop("disable_safe_refill", None)

                        out = handler(source=new_source, contract=contract, fn=fn, params=handler_params)
                        details = out.get("details") or {}
                        candidate_source = out["new_source"]

                        is_noop, noop_reason = _is_transform_noop(before_source, candidate_source, details)

                        if is_noop:
                            skipped.append({
                                "function": fn,
                                "transform_id": real_tid,
                                "reason": f"selected_noop:{noop_reason}",
                                "details": details,
                                "skip_category": "noop_no_eligible_site",
                            })
                            selected_rows.append(
                                _make_terminal_row(
                                    fn=fn,
                                    tid=real_tid,
                                    target=row_target,
                                    params=row_params,
                                    outcome="noop_no_eligible_site",
                                    reason=noop_reason,
                                    skip_category="noop_no_eligible_site",
                                    details=details if isinstance(details, dict) else {},
                                    auto_added=real_auto_added,
                                    changed=False,
                                )
                            )
                            continue

                        new_source = candidate_source

                        applied_row = {
                            "id": real_tid,
                            "transform_id": real_tid,
                            "function": fn,
                            "target": row_target,
                            "params": row_params,
                            "details": details if isinstance(details, dict) else {},
                            "final_outcome": "applied",
                            "changed": True,
                            "source_hash_before": _sha256_text(before_source),
                            "source_hash_after": _sha256_text(new_source),
                        }
                        applied.append(applied_row)

                        selected_rows.append(
                            _make_terminal_row(
                                fn=fn,
                                tid=real_tid,
                                target=row_target,
                                params=row_params,
                                outcome="applied",
                                reason="changed_source",
                                details=details if isinstance(details, dict) else {},
                                auto_added=real_auto_added,
                                changed=True,
                            )
                        )

                        # Preserve old behavior: after one real successful change from this tr/refill set,
                        # move to the next selected transform instead of stacking every refill candidate.
                        break

                    except NotImplementedError as e:
                        reason2 = f"Transform registered but not implemented: {e}"
                        skipped.append({
                            "function": fn,
                            "transform_id": real_tid,
                            "reason": reason2,
                            "skip_category": "skipped_unimplemented",
                        })
                        selected_rows.append(
                            _make_terminal_row(
                                fn=fn,
                                tid=real_tid,
                                target=row_target,
                                params=row_params,
                                outcome="skipped_unimplemented",
                                reason=reason2,
                                skip_category="skipped_unimplemented",
                                auto_added=real_auto_added,
                            )
                        )
                    except Exception as e:
                        reason2 = f"Transform failed at runtime: {e}"
                        skipped.append({
                            "function": fn,
                            "transform_id": real_tid,
                            "reason": reason2,
                            "skip_category": "transform_failed",
                        })
                        selected_rows.append(
                            _make_terminal_row(
                                fn=fn,
                                tid=real_tid,
                                target=row_target,
                                params=row_params,
                                outcome="transform_failed",
                                reason=reason2,
                                skip_category="transform_failed",
                                auto_added=real_auto_added,
                            )
                        )

        self.out_dir.mkdir(parents=True, exist_ok=True)
        obf_path = self.out_dir / "obfuscated.sol"
        map_path = self.out_dir / "transform_map.json"

        obf_path.write_text(new_source, encoding="utf-8")

        final_function_plans: List[Dict[str, Any]] = []
        by_fn: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for row in selected_rows:
            if not isinstance(row, dict):
                continue

            target = row.get("target") if isinstance(row.get("target"), dict) else {}
            fn = target.get("function") or row.get("function")
            if not isinstance(fn, str) or not fn.strip():
                continue

            outcome = str(row.get("final_outcome") or "").strip()
            if outcome != "applied":
                continue

            by_fn[fn].append(row)

        for fn_name, rows in by_fn.items():
            final_ids: List[str] = []
            for row in rows:
                tid = row.get("id") or row.get("transform_id")
                if isinstance(tid, str) and tid.strip():
                    final_ids.append(tid)

            dedup_ids: List[str] = []
            seen = set()
            for tid in final_ids:
                if tid in seen:
                    continue
                seen.add(tid)
                dedup_ids.append(tid)

            final_function_plans.append(
                {
                    "function": fn_name,
                    "final_transform_ids": dedup_ids,
                    "final_ordered_transform_ids": dedup_ids,
                    "final_transform_rows": rows,
                }
            )

        applied_count = len(applied)
        selected_count = len(selected_rows)
        noop_count = sum(1 for r in selected_rows if r.get("final_outcome") == "noop_no_eligible_site")
        noop_ratio = float(noop_count) / float(max(selected_count, 1))

        with open(map_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "source": str(self.source_path),
                    "plan": str(self.plan_path),
                    "mapping_kind": "terminal_transform_outcome_map",
                    "engine_kind": "risk_aware_max_safe_application",
                    "implemented_transform_ids": sorted(TRANSFORMS.keys()),
                    "safe_auto_transforms": list(_SAFE_AUTO_TRANSFORMS),
                    "selected": selected_rows,
                    "applied": applied,
                    "skipped": skipped,
                    "final_function_plans": final_function_plans,
                    "transform_quality_gate": {
                        "selected": selected_count,
                        "applied": applied_count,
                        "selected_noop": noop_count,
                        "noop_ratio": noop_ratio,
                        "ok": not (selected_count > 0 and noop_ratio > 0.40) and not (selected_count > 0 and applied_count == 0),
                        "reasons": [
                            *( [f"too_many_noop_transforms:{noop_ratio:.2f}"] if selected_count > 0 and noop_ratio > 0.40 else [] ),
                            *( ["no_applied_transforms"] if selected_count > 0 and applied_count == 0 else [] ),
                        ],
                    },
                },
                f,
                indent=2,
            )
            f.write("\n")

        return {
            "obfuscated_sol": str(obf_path),
            "transform_map": str(map_path),
            "applied_count": len(applied),
            "skipped_count": len(skipped),
            "selected_count": len(selected_rows),
            "noop_count": noop_count,
            "noop_ratio": noop_ratio,
        }


def apply_variants_plan(
    source_path: Path,
    plan_path: Path,
    out_dir: Path,
    sec_by_function: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return ObfuscationEngine(
        source_path=source_path,
        plan_path=plan_path,
        out_dir=out_dir,
        sec_by_function=sec_by_function,
    ).run()