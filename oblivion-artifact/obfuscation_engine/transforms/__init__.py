from __future__ import annotations

from importlib import import_module
from typing import Any, Callable, Dict, Optional

# ----------------------------
# Always-present transforms
# ----------------------------
from .rename_identifiers_v1 import apply_rename_identifiers_v1
from .rename_identifiers_v2_scoped import apply_rename_identifiers_v2_scoped

Applier = Callable[..., Any]


def _safe_import(module_path: str, name: str) -> Optional[Applier]:
    try:
        module = import_module(module_path, package=__name__)
        sym = getattr(module, name)
        return sym
    except Exception:
        return None


# Optional transforms
apply_constant_encoding_v1 = _safe_import(".constant_encoding_v1", "apply_constant_encoding_v1")
apply_opaque_predicate_v1 = _safe_import(".opaque_predicate_v1", "apply_opaque_predicate_v1")
apply_dead_code_v1 = _safe_import(".dead_code_v1", "apply_dead_code_v1")
apply_predicate_masking_v1 = _safe_import(".predicate_masking_v1", "apply_predicate_masking_v1")
apply_loop_rewrite_v1 = _safe_import(".loop_rewrite_v1", "apply_loop_rewrite_v1")
apply_layout_scramble_v1 = _safe_import(".layout_scramble_v1", "apply_layout_scramble_v1")
apply_cfg_flatten_v1 = _safe_import(".cfg_flatten_v1", "apply_cfg_flatten_v1")
apply_yul_microblock_v1 = _safe_import(".yul_microblock_v1", "apply_yul_microblock_v1")

# Existing BiAn-parity transforms
apply_boolean_split_v1 = _safe_import(".boolean_split_v1", "apply_boolean_split_v1")
apply_dynamic_constants_v1 = _safe_import(".dynamic_constants_v1", "apply_dynamic_constants_v1")
apply_inline_internal_v1 = _safe_import(".inline_internal_v1", "apply_inline_internal_v1")
apply_rename_identifiers_sha1_v1 = _safe_import(".rename_identifiers_sha1_v1", "apply_rename_identifiers_sha1_v1")

# Existing newer transforms
apply_local_to_state_lift_v1 = _safe_import(".local_to_state_lift_v1", "apply_local_to_state_lift_v1")
apply_scalar_to_struct_indirection_v1 = _safe_import(
    ".scalar_to_struct_indirection_v1",
    "apply_scalar_to_struct_indirection_v1",
)
apply_modifier_expand_v1 = _safe_import(".modifier_expand_v1", "apply_modifier_expand_v1")
apply_public_state_accessor_indirection_v1 = _safe_import(
    ".public_state_accessor_indirection_v1",
    "apply_public_state_accessor_indirection_v1",
)

# Optional placeholders (may not exist yet)
apply_string_split_v1 = _safe_import(".string_split_v1", "apply_string_split_v1")
apply_algebraic_identities_v1 = _safe_import(".algebraic_identities_v1", "apply_algebraic_identities_v1")
apply_storage_indirection_v1 = _safe_import(".storage_indirection_v1", "apply_storage_indirection_v1")

# Existing research / outperform transforms
apply_dispatcher_cfg_virtualization_v1 = _safe_import(
    ".dispatcher_cfg_virtualization_v1",
    "apply_dispatcher_cfg_virtualization_v1",
)
apply_opaque_storage_slot_indirection_v1 = _safe_import(
    ".opaque_storage_slot_indirection_v1",
    "apply_opaque_storage_slot_indirection_v1",
)
apply_stack_variable_aliasing_v1 = _safe_import(
    ".stack_variable_aliasing_v1",
    "apply_stack_variable_aliasing_v1",
)
apply_chaotic_opaque_predicate_v1 = _safe_import(
    ".chaotic_opaque_predicate_v1",
    "apply_chaotic_opaque_predicate_v1",
)

# New v2 transforms
apply_opaque_predicate_v2_entangled = _safe_import(
    ".opaque_predicate_v2_entangled",
    "apply_opaque_predicate_v2_entangled",
)
apply_cfg_flatten_v2_hybrid = _safe_import(
    ".cfg_flatten_v2_hybrid",
    "apply_cfg_flatten_v2_hybrid",
)
apply_constant_encoding_v2_layered = _safe_import(
    ".constant_encoding_v2_layered",
    "apply_constant_encoding_v2_layered",
)
apply_boolean_split_v2_distributed = _safe_import(
    ".boolean_split_v2_distributed",
    "apply_boolean_split_v2_distributed",
)
apply_inline_internal_v2_diversified = _safe_import(
    ".inline_internal_v2_diversified",
    "apply_inline_internal_v2_diversified",
)


# -------------------------------------------------------------------
# APPLIERS: definitive "implemented transforms" registry for planner
# -------------------------------------------------------------------
APPLIERS: Dict[str, Applier] = {
    "rename_identifiers_v1": apply_rename_identifiers_v1,
    "rename_identifiers_v2_scoped": apply_rename_identifiers_v2_scoped,
}


def _add_if_present(tid: str, applier: Optional[Applier]) -> None:
    if applier is not None:
        APPLIERS[tid] = applier


# Known optional transforms
_add_if_present("constant_encoding_v1", apply_constant_encoding_v1)
_add_if_present("dynamic_constants_v1", apply_dynamic_constants_v1)
_add_if_present("boolean_split_v1", apply_boolean_split_v1)

_add_if_present("layout_scramble_v1", apply_layout_scramble_v1)

_add_if_present("opaque_predicate_v1", apply_opaque_predicate_v1)
_add_if_present("dead_code_v1", apply_dead_code_v1)
_add_if_present("predicate_masking_v1", apply_predicate_masking_v1)
_add_if_present("loop_rewrite_v1", apply_loop_rewrite_v1)
_add_if_present("inline_internal_v1", apply_inline_internal_v1)

_add_if_present("cfg_flatten_v1", apply_cfg_flatten_v1)
_add_if_present("yul_microblock_v1", apply_yul_microblock_v1)

_add_if_present("rename_identifiers_sha1_v1", apply_rename_identifiers_sha1_v1)

# Newer transforms
_add_if_present("local_to_state_lift_v1", apply_local_to_state_lift_v1)
_add_if_present("scalar_to_struct_indirection_v1", apply_scalar_to_struct_indirection_v1)
_add_if_present("modifier_expand_v1", apply_modifier_expand_v1)
_add_if_present("public_state_accessor_indirection_v1", apply_public_state_accessor_indirection_v1)

# Existing research / outperform transforms
_add_if_present("dispatcher_cfg_virtualization_v1", apply_dispatcher_cfg_virtualization_v1)
_add_if_present("opaque_storage_slot_indirection_v1", apply_opaque_storage_slot_indirection_v1)
_add_if_present("stack_variable_aliasing_v1", apply_stack_variable_aliasing_v1)
_add_if_present("chaotic_opaque_predicate_v1", apply_chaotic_opaque_predicate_v1)

# Placeholders (only added if implemented)
_add_if_present("string_split_v1", apply_string_split_v1)
_add_if_present("algebraic_identities_v1", apply_algebraic_identities_v1)
_add_if_present("storage_indirection_v1", apply_storage_indirection_v1)

# New v2 transforms
_add_if_present("opaque_predicate_v2_entangled", apply_opaque_predicate_v2_entangled)
_add_if_present("cfg_flatten_v2_hybrid", apply_cfg_flatten_v2_hybrid)
_add_if_present("constant_encoding_v2_layered", apply_constant_encoding_v2_layered)
_add_if_present("boolean_split_v2_distributed", apply_boolean_split_v2_distributed)
_add_if_present("inline_internal_v2_diversified", apply_inline_internal_v2_diversified)

__all__ = [
    "apply_rename_identifiers_v1",
    "apply_rename_identifiers_v2_scoped",

    "apply_constant_encoding_v1",
    "apply_dynamic_constants_v1",
    "apply_boolean_split_v1",

    "apply_layout_scramble_v1",

    "apply_opaque_predicate_v1",
    "apply_dead_code_v1",
    "apply_predicate_masking_v1",
    "apply_loop_rewrite_v1",
    "apply_inline_internal_v1",

    "apply_cfg_flatten_v1",
    "apply_yul_microblock_v1",

    "apply_rename_identifiers_sha1_v1",

    "apply_local_to_state_lift_v1",
    "apply_scalar_to_struct_indirection_v1",
    "apply_modifier_expand_v1",
    "apply_public_state_accessor_indirection_v1",

    "apply_dispatcher_cfg_virtualization_v1",
    "apply_opaque_storage_slot_indirection_v1",
    "apply_stack_variable_aliasing_v1",
    "apply_chaotic_opaque_predicate_v1",

    "apply_string_split_v1",
    "apply_algebraic_identities_v1",
    "apply_storage_indirection_v1",

    "apply_opaque_predicate_v2_entangled",
    "apply_cfg_flatten_v2_hybrid",
    "apply_constant_encoding_v2_layered",
    "apply_boolean_split_v2_distributed",
    "apply_inline_internal_v2_diversified",

    "APPLIERS",
]