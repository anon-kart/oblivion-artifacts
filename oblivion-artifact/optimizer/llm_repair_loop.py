import json
import time
import uuid
from typing import Dict, Any, List, Optional

from decision.llm_planner import LLMPlanner
from decision.llm_plan_validator import (
    enforce_transform_whitelist,
    enforce_basic_safety_rules,
)


class LLMRepairLoop:
    """
    Implements:
        LLM propose → apply → validate → repair (bounded)

    This loop NEVER trusts the LLM.
    The validator is the final authority.
    """

    def __init__(
        self,
        *,
        planner: LLMPlanner,
        validator,
        allowed_transform_ids: List[str],
        policy: Dict[str, Any],
        artifact_dir: Optional[str] = None,
    ):
        self.planner = planner
        self.validator = validator
        self.allowed_transform_ids = set(allowed_transform_ids)
        self.policy = policy
        self.artifact_dir = artifact_dir

    def run_for_function(
        self,
        *,
        contract_name: str,
        function_name: str,
        function_ir: Dict,
        obf_advice: Dict,
        sec_advice: Dict,
        tier: int,
        apply_plan_fn,
    ) -> Dict[str, Any]:
        """
        Run bounded LLM repair loop for ONE function.

        Parameters
        ----------
        apply_plan_fn:
            Callable(plan_dict) -> candidate_context
            (Responsible for applying transforms + preparing validation context)

        Returns
        -------
        {
            "ok": bool,
            "attempts": int,
            "best_plan": Optional[Dict],
            "validation_report": Optional[Dict]
        }
        """

        max_rounds = self.policy.get("llm_max_rounds", 2)
        attempt = 0
        last_error = None

        for attempt in range(1, max_rounds + 1):
            attempt_id = f"{function_name}_attempt_{attempt}_{uuid.uuid4().hex[:8]}"

            try:
                plan = self.planner.propose_plan(
                    contract_name=contract_name,
                    function_name=function_name,
                    function_ir=function_ir,
                    obf_advice=obf_advice,
                    sec_advice=sec_advice,
                    tier=tier,
                    allowed_transforms=[
                        {"id": t} for t in self.allowed_transform_ids
                    ],
                )

                # Enforce hard safety gates
                enforce_transform_whitelist(
                    plan,
                    allowed_transform_ids=self.allowed_transform_ids,
                )
                enforce_basic_safety_rules(plan)

                # Apply transforms (AST-safe engine lives outside)
                candidate_ctx = apply_plan_fn(plan)

                # Validate candidate
                validation_result = self.validator.validate(candidate_ctx)

                if validation_result.ok:
                    self._log_success(attempt_id, plan, validation_result)
                    return {
                        "ok": True,
                        "attempts": attempt,
                        "best_plan": plan,
                        "validation_report": validation_result.to_dict(),
                    }

                # Failed validation → prepare feedback
                last_error = self._extract_feedback(validation_result)
                self._log_failure(attempt_id, plan, last_error)

            except Exception as e:
                last_error = str(e)
                self._log_exception(attempt_id, e)

        # All attempts exhausted
        return {
            "ok": False,
            "attempts": attempt,
            "best_plan": None,
            "validation_report": {
                "error": last_error,
                "reason": "llm_repair_exhausted",
            },
        }

    # ------------------------------------------------------------------
    # Logging helpers (artifact-friendly, ICSE-auditable)
    # ------------------------------------------------------------------

    def _log_success(self, attempt_id: str, plan: Dict, validation_result):
        if not self.artifact_dir:
            return

        path = f"{self.artifact_dir}/{attempt_id}_SUCCESS.json"
        with open(path, "w") as f:
            json.dump(
                {
                    "attempt_id": attempt_id,
                    "timestamp": time.time(),
                    "plan": plan,
                    "validation": validation_result.to_dict(),
                },
                f,
                indent=2,
            )

    def _log_failure(self, attempt_id: str, plan: Dict, error: Dict):
        if not self.artifact_dir:
            return

        path = f"{self.artifact_dir}/{attempt_id}_FAIL.json"
        with open(path, "w") as f:
            json.dump(
                {
                    "attempt_id": attempt_id,
                    "timestamp": time.time(),
                    "plan": plan,
                    "error": error,
                },
                f,
                indent=2,
            )

    def _log_exception(self, attempt_id: str, exc: Exception):
        if not self.artifact_dir:
            return

        path = f"{self.artifact_dir}/{attempt_id}_EXCEPTION.json"
        with open(path, "w") as f:
            json.dump(
                {
                    "attempt_id": attempt_id,
                    "timestamp": time.time(),
                    "exception": str(exc),
                },
                f,
                indent=2,
            )

    # ------------------------------------------------------------------
    # Feedback extraction (what the LLM *would* see on reprompt)
    # ------------------------------------------------------------------

    def _extract_feedback(self, validation_result) -> Dict[str, Any]:
        """
        Convert ValidationResult into minimal, structured feedback.
        This is intentionally small to avoid prompt bloat.
        """

        feedback = {
            "compile_ok": validation_result.compile_ok,
            "tests_ok": validation_result.tests_ok,
            "security_ok": validation_result.security_ok,
            "gas_ok": validation_result.gas_ok,
        }

        if not validation_result.compile_ok:
            feedback["compiler_error"] = validation_result.compiler_error

        if not validation_result.tests_ok:
            feedback["failing_tests"] = validation_result.failing_tests

        if not validation_result.security_ok:
            feedback["new_security_findings"] = (
                validation_result.security_diff or []
            )

        if not validation_result.gas_ok:
            feedback["gas_delta_pct"] = validation_result.gas_delta_pct

        return feedback
