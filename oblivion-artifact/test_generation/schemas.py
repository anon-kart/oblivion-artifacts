from __future__ import annotations

from typing import Any, Dict, List


def uncovered_target_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "required": ["target_type", "contract", "reason", "priority"],
        "properties": {
            "target_type": {
                "type": "string",
                "enum": ["function", "line_cluster", "contract"],
            },
            "contract": {"type": "string"},
            "source": {"type": "string"},
            "function": {"type": "string"},
            "signature": {"type": "string"},
            "visibility": {"type": "string"},
            "state_mutability": {"type": "string"},
            "hits": {"type": "integer"},
            "reason": {"type": "string"},
            "priority": {"type": "number"},
            "target_id": {"type": "string"},
            "semantic_tags": {
                "type": "array",
                "items": {"type": "string"},
            },
            "constructor_context_required": {"type": "boolean"},
            "loop_count": {"type": "integer"},
            "require_count": {"type": "integer"},
            "storage_write_count": {"type": "integer"},
            "external_call_count": {"type": "integer"},
            "lines": {
                "type": "array",
                "items": {"type": "integer"},
            },
            "owner_function": {"type": ["string", "null"]},
            "suggested_test_intent": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "additionalProperties": True,
    }


def uncovered_targets_document_schema() -> Dict[str, Any]:
    return {
        "type": "array",
        "items": uncovered_target_schema(),
    }


def generated_test_candidate_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "required": ["name", "filename", "kind", "target", "code"],
        "properties": {
            "name": {"type": "string"},
            "filename": {"type": "string"},
            "kind": {
                "type": "string",
                "enum": ["llm_generated", "llm_fallback", "fallback_generated"],
            },
            "target": uncovered_target_schema(),
            "code": {"type": "string"},
            "llm_error": {"type": "string"},
        },
        "additionalProperties": True,
    }


def generated_test_candidates_document_schema() -> Dict[str, Any]:
    return {
        "type": "array",
        "items": generated_test_candidate_schema(),
    }


def verification_result_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "required": [
            "name",
            "filename",
            "kind",
            "target",
            "compile_ok",
            "isolated_test_ok",
            "merged_suite_ok",
            "verification_status",
            "retained",
            "coverage_gain_lines",
            "coverage_gain_functions",
            "newly_hit_lines_by_file",
            "newly_hit_functions_by_file",
            "target_cluster_touched",
        ],
        "properties": {
            "name": {"type": "string"},
            "filename": {"type": "string"},
            "kind": {"type": "string"},
            "target": uncovered_target_schema(),
            "compile_ok": {"type": "boolean"},
            "isolated_test_ok": {"type": "boolean"},
            "merged_suite_ok": {"type": "boolean"},
            "verification_status": {
                "type": "string",
                "enum": [
                    "COMPILE_FAIL",
                    "TEST_FAIL",
                    "MERGED_FAIL",
                    "NO_GAIN",
                    "RETAINED",
                    "REJECTED_DUPLICATE",
                ],
            },
            "retained": {"type": "boolean"},
            "coverage_gain_lines": {"type": "integer"},
            "coverage_gain_functions": {
                "type": "array",
                "items": {"type": "string"},
            },
            "newly_hit_lines_by_file": {
                "type": "object",
                "additionalProperties": {
                    "type": "array",
                    "items": {"type": "integer"},
                },
            },
            "newly_hit_functions_by_file": {
                "type": "object",
                "additionalProperties": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "target_cluster_touched": {"type": "boolean"},
            "generated_test_path": {"type": ["string", "null"]},
            "merged_test_path": {"type": ["string", "null"]},
            "build_stdout_path": {"type": ["string", "null"]},
            "isolated_stdout_path": {"type": ["string", "null"]},
            "merged_stdout_path": {"type": ["string", "null"]},
            "isolated_coverage_lcov_path": {"type": ["string", "null"]},
            "error": {"type": ["string", "null"]},
        },
        "additionalProperties": True,
    }


def verification_manifest_schema() -> Dict[str, Any]:
    return {
        "type": "array",
        "items": verification_result_schema(),
    }


def retained_tests_document_schema() -> Dict[str, Any]:
    return verification_manifest_schema()


def merged_manifest_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "required": ["retained_tests", "num_retained_tests", "coverage_gain_summary"],
        "properties": {
            "retained_tests": {
                "type": "array",
                "items": verification_result_schema(),
            },
            "num_retained_tests": {"type": "integer"},
            "coverage_gain_summary": {
                "type": "object",
                "required": [
                    "files",
                    "total_newly_hit_lines",
                    "total_improved_functions",
                ],
                "properties": {
                    "files": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "required": [
                                "newly_hit_lines",
                                "num_newly_hit_lines",
                                "improved_functions",
                                "num_improved_functions",
                            ],
                            "properties": {
                                "newly_hit_lines": {
                                    "type": "array",
                                    "items": {"type": "integer"},
                                },
                                "num_newly_hit_lines": {"type": "integer"},
                                "improved_functions": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "num_improved_functions": {"type": "integer"},
                            },
                            "additionalProperties": True,
                        },
                    },
                    "total_newly_hit_lines": {"type": "integer"},
                    "total_improved_functions": {"type": "integer"},
                },
                "additionalProperties": True,
            },
        },
        "additionalProperties": True,
    }


def baseline_snapshot_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "required": ["tests", "traces", "coverage"],
        "properties": {
            "tests": {"type": "object"},
            "traces": {"type": "object"},
            "coverage": {"type": "object"},
        },
        "additionalProperties": True,
    }


def test_generation_summary_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "required": [
            "baseline_targets",
            "generated_candidates",
            "verified_generated_tests",
            "retained_generated_tests",
            "post_merge_remaining_targets",
            "new_lines_hit",
            "new_functions_hit",
            "target_clusters_touched",
            "rounds",
        ],
        "properties": {
            "baseline_targets": {"type": "integer"},
            "generated_candidates": {"type": "integer"},
            "verified_generated_tests": {"type": "integer"},
            "retained_generated_tests": {"type": "integer"},
            "post_merge_remaining_targets": {"type": "integer"},
            "new_lines_hit": {"type": "integer"},
            "new_functions_hit": {
                "type": "array",
                "items": {"type": "string"},
            },
            "target_clusters_touched": {"type": "integer"},
            "rounds": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "round",
                        "generated_candidates",
                        "retained_generated_tests",
                        "remaining_targets_before_round",
                        "remaining_targets_after_round",
                    ],
                    "properties": {
                        "round": {"type": "integer"},
                        "generated_candidates": {"type": "integer"},
                        "retained_generated_tests": {"type": "integer"},
                        "remaining_targets_before_round": {"type": "integer"},
                        "remaining_targets_after_round": {"type": "integer"},
                    },
                    "additionalProperties": True,
                },
            },
        },
        "additionalProperties": True,
    }


def all_test_generation_schemas() -> Dict[str, Dict[str, Any]]:
    return {
        "uncovered_target": uncovered_target_schema(),
        "uncovered_targets_document": uncovered_targets_document_schema(),
        "generated_test_candidate": generated_test_candidate_schema(),
        "generated_test_candidates_document": generated_test_candidates_document_schema(),
        "verification_result": verification_result_schema(),
        "verification_manifest": verification_manifest_schema(),
        "retained_tests_document": retained_tests_document_schema(),
        "merged_manifest": merged_manifest_schema(),
        "baseline_snapshot": baseline_snapshot_schema(),
        "test_generation_summary": test_generation_summary_schema(),
    }


def validate_with_jsonschema(
    data: Any,
    schema: Dict[str, Any],
) -> List[str]:
    """
    Optional lightweight wrapper.
    If jsonschema is installed, returns validation errors as strings.
    If not installed, returns [] and stays non-fatal.
    """
    try:
        import jsonschema  # type: ignore
    except Exception:
        return []

    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    return [
        f"{err.message} at path={'/'.join(str(x) for x in err.path)}"
        for err in errors
    ]