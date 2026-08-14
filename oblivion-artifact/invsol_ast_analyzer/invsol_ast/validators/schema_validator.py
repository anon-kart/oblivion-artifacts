"""
Schema validator for the AST Analyzer IR.

Uses an internal JSON Schema to validate the IR produced by build_ir.build(...).
Returns a list of human-readable errors, or raises ValidationError in strict mode.
"""

from __future__ import annotations
from typing import Any, Dict, List

from jsonschema import Draft7Validator
from ..utils.errors import ValidationError


def _schema() -> Dict[str, Any]:
    # JSON Schema for IR v0.1 (aligned with invsol_ast/ir/model.py and recent enhancements)
    return {
        "type": "object",
        "required": ["ir_version", "contract"],
        "properties": {
            "ir_version": {"type": "string"},
            "contract": {
                "type": "object",
                "required": ["name", "functions", "state", "access_control"],
                "properties": {
                    "name": {"type": "string"},
                    "solidity_version": {"type": ["string", "null"]},
                    "functions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": [
                                "contract",
                                "name",
                                "visibility",
                                "mutability",
                                "modifiers",
                                "params",
                                "loops",
                                "requires",
                                # effects + storage touches are included by builder, but not required here
                            ],
                            "properties": {
                                "contract": {"type": "string"},
                                "name": {"type": "string"},
                                "visibility": {"type": "string"},
                                "mutability": {"type": "string"},
                                "modifiers": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "params": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["name", "type"],
                                        "properties": {
                                            "name": {"type": "string"},
                                            "type": {"type": "string"},
                                        },
                                    },
                                },
                                # NEW: returns array
                                "returns": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["type"],
                                        "properties": {
                                            "type": {"type": "string"},
                                        },
                                        "additionalProperties": True,
                                    },
                                },
                                "loops": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["type"],
                                        "properties": {
                                            "type": {
                                                "type": "string",
                                                "enum": ["for", "while", "loop"],
                                            },
                                            "init": {"type": "string"},
                                            "guard": {"type": "string"},
                                            "update": {"type": "string"},
                                            # body summary + bounds
                                            "body_summary": {"type": "object"},
                                            "bounds": {
                                                "type": "object",
                                                "properties": {
                                                    "index": {"type": ["string", "null"]},
                                                    "lower": {"type": ["string", "null"]},
                                                    "upper": {"type": ["string", "null"]},
                                                    "inclusive_upper": {"type": ["boolean", "null"]},
                                                },
                                                "additionalProperties": True,
                                            },
                                        },
                                        "additionalProperties": True,
                                    },
                                },
                                "requires": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                # Effects
                                "reads": {"type": "array", "items": {"type": "string"}},
                                "writes": {"type": "array", "items": {"type": "string"}},
                                "member_accesses": {"type": "array", "items": {"type": "string"}},
                                "internal_calls": {"type": "array", "items": {"type": "string"}},
                                "external_calls": {"type": "array", "items": {"type": "string"}},
                                "events_emitted": {"type": "array", "items": {"type": "string"}},
                                # Storage touches (key is optional / nullable)
                                "storage_reads": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["var"],
                                        "properties": {
                                            "var": {"type": "string"},
                                            "key": {"type": ["string", "null"]},
                                        },
                                        "additionalProperties": True,
                                    },
                                },
                                "storage_writes": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["var"],
                                        "properties": {
                                            "var": {"type": "string"},
                                            "key": {"type": ["string", "null"]},
                                        },
                                        "additionalProperties": True,
                                    },
                                },
                                # NEW: synthetic flag for synthesized getters
                                "synthetic": {"type": "boolean"},
                            },
                            "additionalProperties": True,
                        },
                    },
                    "state": {
                        "type": "object",
                        "required": ["variables", "mappings"],
                        "properties": {
                            "variables": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["contract", "name", "type"],
                                    "properties": {
                                        "contract": {"type": "string"},
                                        "name": {"type": "string"},
                                        "type": {"type": "string"},
                                    },
                                    "additionalProperties": True,
                                },
                            },
                            "mappings": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["contract", "name", "key", "value"],
                                    "properties": {
                                        "contract": {"type": "string"},
                                        "name": {"type": "string"},
                                        "key": {"type": "string"},
                                        "value": {"type": "string"},
                                    },
                                    "additionalProperties": True,
                                },
                            },
                        },
                        "additionalProperties": True,
                    },
                    "access_control": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["contract", "function", "modifier", "role"],
                            "properties": {
                                "contract": {"type": "string"},
                                "function": {"type": "string"},
                                "modifier": {"type": "string"},
                                "role": {"type": "string"},
                            },
                            "additionalProperties": True,
                        },
                    },
                    # Explicit dependencies for pranks etc.
                    "access_dependencies": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["function", "source"],
                            "properties": {
                                "function": {"type": "string"},
                                "source": {"type": "string"},
                                "condition": {"type": "string"},
                                "role": {"type": ["string", "null"]},
                            },
                            "additionalProperties": True,
                        },
                    },
                },
                "additionalProperties": True,
            },
        },
        "additionalProperties": True,
    }


def validate(ir: Dict[str, Any]) -> List[str]:
    """
    Validate IR against the JSON Schema.
    Returns a list of error strings. Empty list means valid.
    """
    validator = Draft7Validator(_schema())
    errors: List[str] = []
    for err in validator.iter_errors(ir):
        path = ".".join(str(p) for p in err.absolute_path)
        loc = f" at '{path}'" if path else ""
        errors.append(f"{err.message}{loc}")
    return errors


def validate_or_raise(ir: Dict[str, Any]) -> None:
    """
    Validate IR and raise ValidationError if any issues found.
    """
    errs = validate(ir)
    if errs:
        raise ValidationError("IR schema validation failed:\n- " + "\n- ".join(errs))