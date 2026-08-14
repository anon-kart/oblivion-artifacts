# decision/llm_plan_validator.py
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Set

try:
    import jsonschema
    from jsonschema import ValidationError
except Exception:
    jsonschema = None  # type: ignore
    ValidationError = Exception  # type: ignore


LLM_PLAN_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "LLM Transform Plan Schema",
    "type": "object",
    "required": [
        "function",
        "plan",
        "rationale",
        "semantic_contract",
        "composition_graph",
    ],
    "additionalProperties": False,
    "properties": {
        "function": {"type": "string"},
        "plan": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["transform_id"],
                "additionalProperties": False,
                "properties": {
                    "transform_id": {"type": "string"},
                    "params": {
                        "type": "object",
                        "additionalProperties": True,
                    },
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
            "additionalProperties": False,
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
                        "required": [
                            "transform_id",
                            "why_safe",
                            "preserve_invariants",
                        ],
                        "additionalProperties": False,
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
            "additionalProperties": False,
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
                        "additionalProperties": False,
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
                        "additionalProperties": False,
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
}


def validate_plan_schema(plan: Dict[str, Any], *, schema_path: Optional[Path] = None) -> None:
    """
    Validate LLM transform-plan output.

    Raises ValueError on ANY violation.
    """
    if jsonschema is None:
        raise ImportError("jsonschema is required for validate_plan_schema. Install with: pip install jsonschema")

    schema: Dict[str, Any] = LLM_PLAN_SCHEMA
    if schema_path is not None:
        sp = Path(schema_path)
        if not sp.exists():
            raise FileNotFoundError(f"Plan schema not found: {sp}")
        schema = json.loads(sp.read_text(encoding="utf-8"))

    try:
        jsonschema.validate(instance=plan, schema=schema)
    except ValidationError as e:
        raise ValueError(f"LLM plan schema violation: {e.message}") from e

    if not isinstance(plan.get("plan"), list):
        raise ValueError("LLM plan 'plan' must be a list")


def enforce_transform_whitelist(
    plan: Dict[str, Any],
    *,
    allowed_transform_ids: Set[str],
) -> None:
    """
    Ensure the LLM only selects transforms from the allowed catalog.
    """
    for step in plan.get("plan", []) or []:
        if not isinstance(step, dict):
            raise ValueError("LLM plan step must be an object")
        tid = step.get("transform_id")
        if not isinstance(tid, str) or not tid.strip():
            raise ValueError("LLM plan step missing transform_id")
        if tid not in allowed_transform_ids:
            raise ValueError(f"LLM selected forbidden transform: {tid}")


def enforce_basic_safety_rules(plan: Dict[str, Any]) -> None:
    """
    Extra defensive checks to prevent degenerate plans.
    """
    seen: Set[str] = set()
    for step in plan.get("plan", []) or []:
        if not isinstance(step, dict):
            raise ValueError("LLM plan step must be an object")
        tid = step.get("transform_id")
        if not isinstance(tid, str) or not tid.strip():
            raise ValueError("LLM plan step missing transform_id")

        # Prevent duplicate transforms unless explicitly allowed later
        if tid in seen:
            raise ValueError(f"Duplicate transform in plan: {tid}")
        seen.add(tid)


@dataclass
class LLMPlanValidator:
    """
    Validates an LLM-produced plan dict against a JSON Schema file.
    """
    schema_path: Path

    def __post_init__(self) -> None:
        if jsonschema is None:
            raise ImportError(
                "jsonschema is required for LLMPlanValidator. Install with: pip install jsonschema"
            )
        sp = Path(self.schema_path)
        if not sp.exists():
            raise FileNotFoundError(f"Plan schema not found: {sp}")

        schema = json.loads(sp.read_text(encoding="utf-8"))
        self._validator = jsonschema.Draft202012Validator(schema)

    def validate(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Returns:
          {"ok": True} on success
          {"ok": False, "errors": [...]} on failure
        """
        errors = []
        for err in self._validator.iter_errors(plan):
            loc = "/".join([str(x) for x in err.absolute_path]) if err.absolute_path else ""
            errors.append({"path": loc, "message": err.message})

        if errors:
            return {"ok": False, "errors": errors}
        return {"ok": True}


# Alias for versioned import style
LLMPlanValidatorV1 = LLMPlanValidator