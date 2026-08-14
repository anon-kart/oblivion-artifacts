# decision/llm_planner.py
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Union

from decision.prompt_builder import build_prompt
from decision.llm_client import call_llm
from decision.llm_plan_validator import validate_plan_schema
from decision_planner.compat_matrix import (
    extract_signals,
    active_vulnerability_labels,
    compatible as compat_matrix_compatible,
)
from decision.composition_graph import (
    normalize_composition_graph,
    filter_graph_to_selected_ids,
    prune_unsafe_plan_steps,
    order_plan_steps,
)
from decision_planner.catalog import default_transform_catalog
from decision.semantic_rules import (
    build_deterministic_semantic_contract,
    build_deterministic_composition_graph,
    merge_semantic_contracts,
    merge_composition_graphs,
)


class LLMPlanner:
    """
    Option-A planner:
    LLM proposes a transform PLAN (JSON),
    engine applies transforms,
    validator decides accept/reject.

    Updated behavior:
    - prefers richer advisor-side fields such as:
        econ_score
        sec_score
        sec_severity
        tier
        tier_inputs
        candidate_transforms
    - still remains backward-compatible with older obf_advice payloads
    - supports repair_plan(), which re-prompts the LLM with failure feedback
    - enforces semantic_contract coverage for selected transforms
    - normalizes and uses composition_graph to prune unsafe transform pairs
      and apply ordering constraints
    - robustly parses JSON-only responses even if the model wraps them in fences
      or emits minor trailing-comma issues
    """

    def __init__(self, *, policy: Dict[str, Any]):
        self.policy = policy or {}

    def _resolve_schema_path(self) -> Path | None:
        """
        Resolve policy["llm_plan_schema"] (relative to repo root) if present.
        This is optional; validate_plan_schema can fall back to inline schema.
        """
        p = self.policy.get("llm_plan_schema") or self.policy.get("llm_plan_schema_path")
        if not isinstance(p, str) or not p.strip():
            return None

        path = Path(p).expanduser()
        if path.is_absolute():
            return path

        # Resolve relative to repo root (parent of /decision)
        repo_root = Path(__file__).resolve().parent.parent
        return (repo_root / path).resolve()

    def _normalize_allowed_transforms(
        self,
        allowed_transforms: Union[Dict[str, Any], List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """
        Normalize allowed_transforms into a list[dict] with stable keys.

        Input may be:
          - dict[str, dict]
          - list[dict]
        """
        out: List[Dict[str, Any]] = []

        if isinstance(allowed_transforms, dict):
            for tid, meta in allowed_transforms.items():
                if isinstance(meta, dict):
                    item = dict(meta)
                    item.setdefault("id", tid)
                    out.append(item)
                else:
                    out.append({"id": str(tid), "description": str(meta)})
            return out

        if isinstance(allowed_transforms, list):
            for item in allowed_transforms:
                if isinstance(item, dict):
                    out.append(dict(item))
            return out

        return out
    
    def _clip_json_for_prompt(self, obj: Any, max_chars: int = 4000) -> str:
        try:
            s = json.dumps(obj, indent=2)
        except Exception:
            s = str(obj)
        if len(s) <= max_chars:
            return s
        return s[:max_chars] + "\n...<clipped>..."

    def _extract_largest_json_object(self, raw: str) -> str:
        text = (raw or "").strip()

        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text.strip())

        start = text.find("{")
        if start < 0:
            raise ValueError("No JSON object start found in LLM response")

        best = None
        stack = 0
        in_str = False
        esc = False
        obj_start = None

        for i, ch in enumerate(text[start:], start=start):
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue

            if ch == '"':
                in_str = True
                continue

            if ch == "{":
                if stack == 0:
                    obj_start = i
                stack += 1
            elif ch == "}":
                stack -= 1
                if stack == 0 and obj_start is not None:
                    cand = text[obj_start:i + 1]
                    best = cand

        if best is None:
            raise ValueError("No balanced JSON object found in LLM response")
        return best

    def _parse_llm_json_object(self, raw: str) -> Dict[str, Any]:
        obj_text = self._extract_largest_json_object(raw)
        try:
            parsed = json.loads(obj_text)
        except json.JSONDecodeError:
            cleaned = obj_text.replace("\r\n", "\n").replace("\r", "\n")
            cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
            try:
                parsed = json.loads(cleaned)
            except json.JSONDecodeError as e:
                raise ValueError(f"LLM returned invalid JSON: {e}") from e

        if not isinstance(parsed, dict):
            raise ValueError(f"LLM returned non-dict JSON: {type(parsed)}")
        return parsed

    def _normalize_plan_steps(self, raw_steps: Any) -> List[Dict[str, Any]]:
        """
        Accept either:
          - ["opaque_predicate_v1", "constant_encoding_v1"]
          - [{"transform_id": "opaque_predicate_v1", "params": {...}}, ...]

        and normalize to:
          [{"transform_id": "...", "params": {...}}, ...]
        """
        if not isinstance(raw_steps, list):
            return []

        out: List[Dict[str, Any]] = []
        for step in raw_steps:
            if isinstance(step, str):
                tid = step.strip()
                if tid:
                    out.append({"transform_id": tid, "params": {}})
                continue

            if isinstance(step, dict):
                tid = (
                    step.get("transform_id")
                    or step.get("id")
                    or step.get("type")
                    or step.get("transformId")
                )
                if isinstance(tid, str) and tid.strip():
                    params = step.get("params")
                    if not isinstance(params, dict):
                        params = {}
                    out.append(
                        {
                            "transform_id": tid.strip(),
                            "params": params,
                        }
                    )

        seen = set()
        deduped: List[Dict[str, Any]] = []
        for step in out:
            tid = step["transform_id"]
            key = (tid, json.dumps(step.get("params", {}), sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(step)
        return deduped

    def _normalize_semantic_contract(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        sc = plan.get("semantic_contract") or {}
        if not isinstance(sc, dict):
            sc = {}

        out = {
            "global_invariants": list(sc.get("global_invariants") or []),
            "protected_region_tags": list(sc.get("protected_region_tags") or []),
            "transform_safety": list(sc.get("transform_safety") or []),
        }

        cleaned = []
        for item in out["transform_safety"]:
            if not isinstance(item, dict):
                continue

            tid = item.get("transform_id")
            why = item.get("why_safe")
            invs = item.get("preserve_invariants") or []
            avoid = item.get("avoid_regions") or []

            if isinstance(tid, str) and isinstance(why, str):
                cleaned.append(
                    {
                        "transform_id": tid,
                        "why_safe": why,
                        "preserve_invariants": list(invs) if isinstance(invs, list) else [],
                        "avoid_regions": list(avoid) if isinstance(avoid, list) else [],
                    }
                )

        out["transform_safety"] = cleaned
        return out

    def _require_semantic_entries_for_selected(self, plan: Dict[str, Any]) -> None:
        selected_ids: List[str] = []
        for step in plan.get("plan", []) or []:
            if isinstance(step, dict):
                tid = step.get("transform_id")
                if isinstance(tid, str):
                    selected_ids.append(tid)

        sc = plan.get("semantic_contract") or {}
        by_id: Dict[str, Dict[str, Any]] = {}
        for item in sc.get("transform_safety", []) or []:
            if isinstance(item, dict) and isinstance(item.get("transform_id"), str):
                by_id[item["transform_id"]] = item

        missing = [tid for tid in selected_ids if tid not in by_id]
        if missing:
            raise ValueError(f"Missing semantic_contract entries for selected transforms: {missing}")

    def _extract_candidate_transform_ids(self, obf_advice: Dict[str, Any]) -> List[str]:
        ids: List[str] = []
        if not isinstance(obf_advice, dict):
            return ids

        cands = obf_advice.get("candidate_transforms") or []
        if not isinstance(cands, list):
            return ids

        for item in cands:
            if not isinstance(item, dict):
                continue
            if item.get("enabled", True) is False:
                continue
            tid = item.get("id")
            if isinstance(tid, str) and tid.strip():
                ids.append(tid.strip())

        seen = set()
        out: List[str] = []
        for tid in ids:
            if tid in seen:
                continue
            seen.add(tid)
            out.append(tid)
        return out

    def _filter_plan_by_advisor_candidates(
        self,
        *,
        plan: Dict[str, Any],
        obf_advice: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        If advisor emitted candidate_transforms, use them as a soft allowlist
        over the LLM plan. This strengthens planner alignment with the richer
        advisor without making the pipeline brittle when the advisor payload
        is sparse.
        """
        if not isinstance(plan, dict):
            return plan

        candidate_ids = set(self._extract_candidate_transform_ids(obf_advice))
        if not candidate_ids:
            return plan

        plan_list = plan.get("plan", [])
        if not isinstance(plan_list, list):
            return plan

        filtered: List[Any] = []
        for item in plan_list:
            if isinstance(item, str):
                if item in candidate_ids:
                    filtered.append({"transform_id": item, "params": {}})
                continue

            if isinstance(item, dict):
                tid = (
                    item.get("id")
                    or item.get("transform_id")
                    or item.get("type")
                    or item.get("transformId")
                )
                if isinstance(tid, str) and tid in candidate_ids:
                    params = item.get("params")
                    if not isinstance(params, dict):
                        params = {}
                    filtered.append({"transform_id": tid, "params": params})

        plan2 = dict(plan)
        plan2["plan"] = filtered
        return plan2

    def _effective_tier(self, *, requested_tier: int, obf_advice: Dict[str, Any]) -> int:
        """
        Prefer advisor tier if present, otherwise use the caller-provided tier.
        """
        try:
            advisor_tier = obf_advice.get("tier") if isinstance(obf_advice, dict) else None
            if advisor_tier is not None:
                return int(advisor_tier)
        except Exception:
            pass
        return int(requested_tier)

    def _min_required_transforms_for_tier(self, tier: int) -> int:
        """
        Tier-aware lower bound for acceptable LLM plan size.
        Tier-1 plans are intentionally allowed to be smaller.
        """
        try:
            tier = int(tier)
        except Exception:
            tier = 0

        if tier <= 0:
            return 0
        if tier == 1:
            return 1
        if tier == 2:
            return 2
        return 2

    def _call_llm_json(self, *, prompt: str) -> Dict[str, Any]:
        """
        Shared JSON-only LLM call path used by both propose_plan() and repair_plan().
        """
        raw_response = call_llm(
            prompt=prompt,
            model=self.policy.get("llm_model", "gpt-4"),
            temperature=self.policy.get("llm_temperature", 0.4),
            max_tokens=self.policy.get("llm_max_tokens", 800),
        )

        parsed = self._parse_llm_json_object(raw_response)

        allowed_top = {"function", "plan", "rationale", "semantic_contract", "composition_graph"}
        parsed = {k: v for k, v in parsed.items() if k in allowed_top}

        parsed.setdefault("function", "")
        parsed.setdefault("plan", [])
        parsed.setdefault("rationale", "")
        parsed.setdefault("semantic_contract", {})
        parsed.setdefault("composition_graph", {})

        parsed["plan"] = self._normalize_plan_steps(parsed.get("plan"))

        return parsed

    def _finalize_plan(
        self,
        *,
        plan: Dict[str, Any],
        function_name: str,
        function_ir: Dict[str, Any],
        sec_advice: Dict[str, Any],
        obf_advice: Dict[str, Any],
        tier: int,
    ) -> Dict[str, Any]:
        """
        Common post-processing and validation for both propose_plan() and repair_plan().
        """
        plan = dict(plan or {})
        plan["plan"] = self._normalize_plan_steps(plan.get("plan"))

        schema_path = self._resolve_schema_path()
        validate_plan_schema(plan, schema_path=schema_path)

        if plan.get("function") != function_name:
            raise ValueError("LLM plan function name mismatch")

        plan = self._filter_plan_by_advisor_candidates(
            plan=plan,
            obf_advice=obf_advice,
        )
        plan["plan"] = self._normalize_plan_steps(plan.get("plan"))

        selected_ids: List[str] = []
        for step in plan.get("plan", []) or []:
            if isinstance(step, dict) and isinstance(step.get("transform_id"), str):
                selected_ids.append(step["transform_id"])

        llm_sc = self._normalize_semantic_contract(plan)
        llm_graph = normalize_composition_graph(plan.get("composition_graph"))

        det_sc = build_deterministic_semantic_contract(
            selected_ids=selected_ids,
            function_ir=function_ir,
            sec_advice=sec_advice,
        )
        det_graph = build_deterministic_composition_graph(
            selected_ids=selected_ids,
            function_ir=function_ir,
            sec_advice=sec_advice,
        )

        plan["semantic_contract"] = merge_semantic_contracts(llm_sc, det_sc, selected_ids)
        merged_graph = merge_composition_graphs(llm_graph, det_graph)
        plan["composition_graph"] = filter_graph_to_selected_ids(merged_graph, selected_ids)

        if self.policy.get("llm_require_semantic_contract", True):
            self._require_semantic_entries_for_selected(plan)

        pruned_steps, composition_drops = prune_unsafe_plan_steps(
            plan.get("plan", []) or [],
            plan["composition_graph"],
        )
        plan["plan"] = self._normalize_plan_steps(pruned_steps)

        if self.policy.get("composition_use_ordering_constraints", True):
            ordered_steps = order_plan_steps(plan["plan"], plan["composition_graph"])
            plan["plan"] = self._normalize_plan_steps(ordered_steps)

        if composition_drops:
            plan.setdefault("composition_audit", [])
            if isinstance(plan["composition_audit"], list):
                plan["composition_audit"].extend(composition_drops)

        max_t = int(self.policy.get("max_transforms_per_function", 2))
        min_t = self._min_required_transforms_for_tier(tier)

        plan_list = plan.get("plan", [])
        if not isinstance(plan_list, list):
            raise ValueError("LLM plan['plan'] must be a list")

        if len(plan_list) > max_t:
            raise ValueError("LLM plan exceeds max allowed transforms")

        if len(plan_list) < min_t:
            rationale = str(plan.get("rationale", "")).strip()
            if len(plan_list) == 0 and rationale.startswith("NO_SAFE_TRANSFORM:"):
                return plan
            raise ValueError(
                f"LLM plan below min required transforms (min={min_t}, got={len(plan_list)})"
            )

        return plan

    def propose_plan(
        self,
        *,
        contract_name: str,
        function_name: str,
        function_ir: Dict[str, Any],
        obf_advice: Dict[str, Any],
        sec_advice: Dict[str, Any],
        tier: int,
        allowed_transforms: Union[Dict[str, Any], List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Returns a validated transform-plan dict.
        Raises ValueError on invalid LLM output.

        Updated semantics:
        - richer obf_advice fields are forwarded into prompt building
        - advisor tier may override the caller tier
        - advisor candidate_transforms act as a soft allowlist filter
        """
        normalized_allowed_transforms = self._normalize_allowed_transforms(allowed_transforms)
        effective_tier = self._effective_tier(requested_tier=tier, obf_advice=obf_advice)

        sec_signals = extract_signals(sec_advice or {})
        vuln_labels = active_vulnerability_labels(sec_signals)
        catalog = default_transform_catalog()

        forbidden_transforms: List[Dict[str, str]] = []
        for item in normalized_allowed_transforms:
            tid = item.get("id")
            if not isinstance(tid, str):
                continue
            spec = catalog.get(tid)
            if not spec:
                continue

            ok, reason = compat_matrix_compatible(
                spec=spec,
                tier=effective_tier,
                signals=sec_signals,
                fn_advice=function_ir,
                sec_severity_max=str((sec_advice or {}).get("severity") or ""),
                matrix=self.policy.get("transform_vulnerability_matrix"),
            )
            if not ok:
                forbidden_transforms.append({"id": tid, "reason": reason})

        prompt = build_prompt(
            contract_name=contract_name,
            function_name=function_name,
            function_ir=function_ir,
            obf_advice=obf_advice,
            sec_advice=sec_advice,
            tier=effective_tier,
            allowed_transforms=normalized_allowed_transforms,
            policy=self.policy,
            forbidden_transforms=forbidden_transforms,
            vulnerability_labels=vuln_labels,
        )

        prompt += """

Return exactly one JSON object and nothing else.
No markdown fences. No comments. No prose.

Required top-level keys:
"function", "plan", "rationale", "semantic_contract", "composition_graph"

Rules:
- "plan" must be a JSON array of objects
- every plan item must be {"transform_id": "...", "params": {}}
- do not output bare transform-id strings
- keep rationale short
- keep semantic_contract compact
- keep composition_graph compact
- no trailing commas
"""

        plan = self._call_llm_json(prompt=prompt)
        return self._finalize_plan(
            plan=plan,
            function_name=function_name,
            function_ir=function_ir,
            sec_advice=sec_advice,
            obf_advice=obf_advice,
            tier=tier,
        )

    def repair_plan(
        self,
        *,
        contract_name: str,
        function_name: str,
        function_ir: Dict[str, Any],
        obf_advice: Dict[str, Any],
        sec_advice: Dict[str, Any],
        tier: int,
        allowed_transforms: Union[Dict[str, Any], List[Dict[str, Any]]],
        previous_plan: List[Dict[str, Any]],
        previous_semantic_contract: Dict[str, Any] | None,
        previous_composition_graph: Dict[str, Any] | None,
        failure_reason: str,
        reject_reasons: List[str],
        validator_summary: str,
    ) -> Dict[str, Any]:
        """
        Ask the LLM to revise a previously proposed transform plan after failure feedback.

        Returns the same validated schema as propose_plan():
            {
              "function": "...",
              "plan": [...],
              "rationale": "...",
              "semantic_contract": {...},
              "composition_graph": {...}
            }
        """
        normalized_allowed_transforms = self._normalize_allowed_transforms(allowed_transforms)
        effective_tier = self._effective_tier(requested_tier=tier, obf_advice=obf_advice)

        prompt = f"""
You are revising an obfuscation transform plan for a Solidity function.

Contract: {contract_name}
Function: {function_name}
Tier: {effective_tier}

Function IR:
{self._clip_json_for_prompt(function_ir, max_chars=3000)}

Obfuscation advice:
{self._clip_json_for_prompt(obf_advice, max_chars=2500)}

Security advice:
{self._clip_json_for_prompt(sec_advice, max_chars=2500)}

Allowed transforms:
{self._clip_json_for_prompt(normalized_allowed_transforms, max_chars=2500)}

Previous transform plan:
{self._clip_json_for_prompt(previous_plan, max_chars=2000)}

Previous semantic contract:
{self._clip_json_for_prompt(previous_semantic_contract or {}, max_chars=2000)}

Previous composition graph:
{self._clip_json_for_prompt(previous_composition_graph or {}, max_chars=2000)}

The previous proposal or candidate failed.

Failure reason:
{failure_reason}

Reject reasons:
{json.dumps(reject_reasons, indent=2)}

Validator summary:
{validator_summary}

Revise the transform plan so it is more likely to pass.

Rules:
- Preserve functionality.
- Avoid transforms likely to trigger the reported failure.
- Keep the plan compact and safe for the given tier.
- Use only the allowed transforms.
- You MUST revise semantic_contract and composition_graph consistently with the revised plan.
- For EACH selected transform, explain why it is safe and what invariants must be preserved.
- unsafe_pairs in composition_graph are hard negatives.
- Return exactly one JSON object and nothing else.
- Do not wrap the response in markdown fences.
- Do not include comments.
- Every item in "plan" must be an object with "transform_id" and optional "params".
- Never output bare transform ids.
- Never output trailing commas.
- Return JSON only with keys:
  {{
    "function": "{function_name}",
    "plan": [{{"transform_id": "...", "params": {{}}}}],
    "rationale": "...",
    "semantic_contract": {{
      "global_invariants": ["..."],
      "protected_region_tags": ["..."],
      "transform_safety": [
        {{
          "transform_id": "...",
          "why_safe": "...",
          "preserve_invariants": ["..."],
          "avoid_regions": ["..."]
        }}
      ]
    }},
    "composition_graph": {{
      "safe_pairs": [["...", "..."]],
      "unsafe_pairs": [
        {{
          "pair": ["...", "..."],
          "reason": "...",
          "risk": 0.0
        }}
      ],
      "ordering_constraints": [
        {{
          "before": "...",
          "after": "...",
          "reason": "..."
        }}
      ],
      "pair_scores": {{
        "...|...": 0.0
      }}
    }}
  }}
"""

        plan = self._call_llm_json(prompt=prompt)
        return self._finalize_plan(
            plan=plan,
            function_name=function_name,
            function_ir=function_ir,
            sec_advice=sec_advice,
            obf_advice=obf_advice,
            tier=tier,
        )