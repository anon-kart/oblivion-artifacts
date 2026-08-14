# decision_planner/planner.py
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .catalog import TransformSpec, default_transform_catalog
from .compat_matrix import (
    extract_signals,
    compatible as compat_matrix_compatible,
    active_vulnerability_labels,
    DEFAULT_TRANSFORM_VULN_MATRIX,
)


# ---------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------

@dataclass
class PlannerPolicy:
    """
    Planner policy (can be loaded from JSON later).

    NOTE: max_variants_per_function is kept for backward compatibility,
    but the planner now uses a tier-based budget to be more aggressive
    on non-risky functions.
    """
    # backward-compatible default; tier budgets below can override
    max_variants_per_function: int = 12  # baseline cap (can be overridden by policy.json)

    category_to_tier: Dict[str, int] = None
    tier_allow_risk: Dict[int, List[str]] = None

    # deterministic diversity and safety knobs
    prefer_diverse_families: bool = True
    seed: int = 1337

    # soft diversity (instead of hard "one per family")
    max_per_family: int = 12

    # tier-based budgets (aggressiveness)
    tier_transform_budget: Dict[int, int] = None

    # NEW: declarative transform-vulnerability compatibility policy
    transform_vulnerability_matrix: Dict[str, Dict[str, Any]] = None

    # LLM knobs (used by LLMDecisionPlanner)
    llm_model: str = "gpt-4o-mini"
    llm_temperature: float = 0.4
    llm_max_tokens: int = 900
    llm_max_steps: int = 3  # max transforms per function in LLM plan

    def __post_init__(self):
        if self.category_to_tier is None:
            self.category_to_tier = {
                "no_obfuscation": 0,
                "unused_or_uncovered": 0,
                "light_obfuscation_ok": 1,
                "moderate_obfuscation_ok": 2,
                "aggressive_obfuscation_ok": 3,
            }
        if self.tier_allow_risk is None:
            self.tier_allow_risk = {
                0: [],
                1: ["low"],
                2: ["low", "medium"],
                3: ["low", "medium", "high"],
            }
        if self.tier_transform_budget is None:
            # IMPORTANT: keep aggressive, but operationally safer defaults than 12/16
            # (You can still set these higher via policy.json if your machine can handle it.)
            self.tier_transform_budget = {
                0: 0,
                1: 6,
                2: 8,    # ✅ CHANGED: was 12 (reduces tool thrash while still "apply most safe")
                3: 12,   # ✅ CHANGED: was 16
            }
        if self.transform_vulnerability_matrix is None:
            self.transform_vulnerability_matrix = dict(DEFAULT_TRANSFORM_VULN_MATRIX)


# ---------------------------------------------------------------------
# Planner output structures
# ---------------------------------------------------------------------

@dataclass
class PlannedTransform:
    id: str
    target: Dict[str, Any]
    params: Dict[str, Any]


@dataclass
class FunctionPlan:
    function: str
    full_name: str

    tier: int
    tier_reason: str

    category: str
    rationale: str

    econ_score: float
    sec_score: float
    sec_severity_max: str

    tests_to_run: List[str]

    allowed_transforms: List[str]
    selected_transforms: List[PlannedTransform]

    # NEW: observability for compatibility-policy decisions
    blocked_transforms: List[Dict[str, str]]
    active_vulnerability_labels: List[str]


@dataclass
class VariantsPlan:
    contract: str
    source_file: str
    plans: List[FunctionPlan]


# ---------------------------------------------------------------------
# Decision Planner (deterministic baseline)
# ---------------------------------------------------------------------

class DecisionPlanner:
    # Transforms that may be semantics-safe but can explode code size / compile time / analyzer time
    _EXPANSIVE_TRANSFORMS = {
        "inline_internal_v1",
        "loop_rewrite_v1",
        "cfg_flatten_v1",
        "yul_microblock_v1",
        "storage_indirection_v1",
    }
    _MAX_EXPANSIVE_PER_FUNCTION = 1  # ✅ NEW: keep "apply all safe" but avoid runaway blowups

    # Cheap transforms you usually want everywhere (if allowed)
    _ALWAYS_CHEAP = {
        "dynamic_constants_v1",
        "constant_encoding_v1",
        "boolean_split_v1",
        "layout_scramble_v1",
        "string_split_v1",
        "algebraic_identities_v1",
    }

    def __init__(
        self,
        advice: Dict[str, Any],
        catalog: Dict[str, TransformSpec],
        policy: Optional[PlannerPolicy],
        sec_advice: Optional[Dict[str, Any]],
        ir: Optional[Dict[str, Any]],
        coverage: Optional[Dict[str, Any]],
    ) -> None:
        self.advice = advice
        self.catalog = catalog
        self.policy = policy or PlannerPolicy()
        self.sec_advice = sec_advice or {}
        self.ir = ir or {}
        self.coverage = coverage or {}
        self.transform_vulnerability_matrix = (
            (self.advice or {}).get("transform_vulnerability_matrix")
            or getattr(self.policy, "transform_vulnerability_matrix", None)
            or DEFAULT_TRANSFORM_VULN_MATRIX
        )

        self.global_econ_score = 0.0
        self._appliers = self._try_get_appliers()

    # ------------------------------------------------------------

    @classmethod
    def from_files(
        cls,
        advice_json: Path,
        policy_json: Optional[Path] = None,
        catalog_json: Optional[Path] = None,
        sec_advice_json: Optional[Path] = None,
        ir_json: Optional[Path] = None,
        coverage_json: Optional[Path] = None,
    ) -> "DecisionPlanner":

        advice = json.loads(advice_json.read_text(encoding="utf-8"))

        policy = PlannerPolicy()
        if policy_json and policy_json.exists():
            raw = json.loads(policy_json.read_text(encoding="utf-8"))
            if "max_variants_per_function" in raw:
                policy.max_variants_per_function = int(raw["max_variants_per_function"])
            if "seed" in raw:
                policy.seed = int(raw["seed"])
            if "prefer_diverse_families" in raw:
                policy.prefer_diverse_families = bool(raw["prefer_diverse_families"])
            if "max_per_family" in raw:
                policy.max_per_family = int(raw["max_per_family"])
            if "tier_transform_budget" in raw and isinstance(raw["tier_transform_budget"], dict):
                policy.tier_transform_budget = {int(k): int(v) for k, v in raw["tier_transform_budget"].items()}
            if "transform_vulnerability_matrix" in raw and isinstance(raw["transform_vulnerability_matrix"], dict):
                policy.transform_vulnerability_matrix = raw["transform_vulnerability_matrix"]
            # LLM knobs (optional)
            if "llm_model" in raw:
                policy.llm_model = str(raw["llm_model"])
            if "llm_temperature" in raw:
                policy.llm_temperature = float(raw["llm_temperature"])
            if "llm_max_tokens" in raw:
                policy.llm_max_tokens = int(raw["llm_max_tokens"])
            if "llm_max_steps" in raw:
                policy.llm_max_steps = int(raw["llm_max_steps"])

        _ = catalog_json
        catalog = default_transform_catalog()

        sec_advice = {}
        if sec_advice_json and sec_advice_json.exists():
            sec_advice = json.loads(sec_advice_json.read_text(encoding="utf-8"))

        ir = {}
        if ir_json and ir_json.exists():
            ir = json.loads(ir_json.read_text(encoding="utf-8"))

        coverage = {}
        if coverage_json and coverage_json.exists():
            coverage = json.loads(coverage_json.read_text(encoding="utf-8"))

        return cls(
            advice=advice,
            catalog=catalog,
            policy=policy,
            sec_advice=sec_advice,
            ir=ir,
            coverage=coverage,
        )

    # ------------------------------------------------------------

    def _tier_for_category(self, category: str) -> int:
        return int(self.policy.category_to_tier.get(category, 0))

    def _budget_for_tier(self, tier: int) -> int:
        """
        Tier-based transform budget, with backward-compat fallback.

        ✅ FIX:
        If tier budget exists, use it directly (it can be LOWER or HIGHER than max_variants_per_function).
        The old code accidentally did: max(budget, max_variants_per_function) which forces budget >= 12 always.
        """
        b = int((self.policy.tier_transform_budget or {}).get(int(tier), 0))
        if b <= 0:
            return 0
        return b

    def _try_get_appliers(self) -> Optional[Dict[str, Any]]:
        """
        Best-effort import: lets the planner avoid selecting transforms that
        aren't implemented/registered yet.

        Supports both older APPLIERS-based engines and the current
        TRANSFORMS-based engine registry.
        """
        try:
            from obfuscation_engine.engine import TRANSFORMS  # type: ignore
            if isinstance(TRANSFORMS, dict):
                return TRANSFORMS
        except Exception:
            pass

        try:
            from obfuscation_engine.transforms import APPLIERS  # type: ignore
            if isinstance(APPLIERS, dict):
                return APPLIERS
        except Exception:
            pass

        return None

    def _allowed_transforms_for_tier(self, tier: int) -> List[str]:
        """
        Deterministic list of transform IDs that pass tier+risk gating.
        Sorted by (-weight, id) for stability.

        Filters out transforms not implemented (if APPLIERS is available).
        """
        allowed_risks = set(self.policy.tier_allow_risk.get(tier, []))
        out: List[TransformSpec] = []
        for _tid, spec in self.catalog.items():
            if tier < spec.tier_min or tier > spec.tier_max:
                continue
            if spec.risk not in allowed_risks:
                continue
            if self._appliers is not None and spec.id not in self._appliers:
                continue
            out.append(spec)

        out_sorted = sorted(out, key=lambda s: (-int(s.weight), s.id))
        return [s.id for s in out_sorted]

    def _sec_map(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        funcs = (self.sec_advice or {}).get("functions") or []
        for f in funcs:
            if isinstance(f, dict) and f.get("function"):
                out[str(f["function"])] = f
        return out

    # ------------------------------------------------------------
    # Security signals (heuristic v1)
    # ------------------------------------------------------------

    def _extract_issue_signals(self, sec_entry: Optional[Dict[str, Any]]) -> Dict[str, bool]:
        signals = {
            "has_external_call_risk": False,
            "has_reentrancy_risk": False,
            "has_access_control_risk": False,
            "has_arithmetic_risk": False,
            "has_revert_semantics_risk": False,
        }
        if not sec_entry:
            return signals

        issues = sec_entry.get("issues") or []
        for iss in issues:
            chk = str(iss.get("check", "")).lower()
            desc = str(iss.get("description", "")).lower()
            blob = f"{chk} {desc}"

            if any(
                k in blob
                for k in [
                    "reentr",
                    "external-call",
                    "low-level",
                    "call.value",
                    "delegatecall",
                    "send",
                    "transfer(",
                ]
            ):
                signals["has_external_call_risk"] = True
                if "reentr" in blob:
                    signals["has_reentrancy_risk"] = True

            if any(
                k in blob
                for k in [
                    "access-control",
                    "missing-access",
                    "onlyowner",
                    "owner",
                    "role",
                    "auth",
                    "permission",
                ]
            ):
                signals["has_access_control_risk"] = True

            if any(
                k in blob
                for k in [
                    "overflow",
                    "underflow",
                    "divide",
                    "mul",
                    "add",
                    "sub",
                    "arithmetic",
                    "unchecked",
                ]
            ):
                signals["has_arithmetic_risk"] = True

            if any(k in blob for k in ["revert", "require", "assert", "error("]):
                signals["has_revert_semantics_risk"] = True

        return signals

    # ------------------------------------------------------------
    # Compatibility gating (now delegated to compat_matrix.py)
    # ------------------------------------------------------------

    _ALWAYS_SAFE_TRANSFORMS = {
        "layout_scramble_v1",
        "rename_identifiers_v2_scoped",
        "rename_identifiers_sha1_v1",
        "rename_identifiers_v1",
        "constant_encoding_v1",
        "dynamic_constants_v1",
        "boolean_split_v1",
    }

    _HEAVY_TRANSFORMS = {
        "cfg_flatten_v1",
        "yul_microblock_v1",
        "storage_indirection_v1",
    }

    def _is_transform_compatible(
        self,
        spec: TransformSpec,
        tier: int,
        signals: Dict[str, bool],
        fn_advice: Dict[str, Any],
        sec_entry: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        _ = signals  # compatibility source of truth is now compat_matrix.extract_signals(sec_entry)
        sec_signals = extract_signals(sec_entry)

        return compat_matrix_compatible(
            spec=spec,
            tier=tier,
            signals=sec_signals,
            fn_advice=fn_advice,
            sec_severity_max=str((sec_entry or {}).get("severity") or ""),
            matrix=self.transform_vulnerability_matrix,
        )

    # ------------------------------------------------------------
    # deterministic selection (aggressive but operationally safe)
    # ------------------------------------------------------------

    def _stable_int(self, s: str) -> int:
        h = hashlib.sha256(s.encode("utf-8")).hexdigest()
        return int(h[:16], 16)

    def _should_force_control(self, tier: int, signals: Dict[str, bool]) -> bool:
        if tier < 2:
            return False
        if signals.get("has_external_call_risk") or signals.get("has_reentrancy_risk"):
            return False
        if signals.get("has_access_control_risk"):
            return False
        if signals.get("has_revert_semantics_risk"):
            return False
        return True

    def _is_cosmetic_transform(self, tid: str) -> bool:
        return tid in {
            "rename_identifiers_v2_scoped",
            "rename_identifiers_sha1_v1",
            "rename_identifiers_v1",
            "layout_scramble_v1",
        }

    def _select_transforms(
        self,
        contract: str,
        fn_name: str,
        tier: int,
        allowed_ids: List[str],
        fn_advice: Dict[str, Any],
        sec_entry: Optional[Dict[str, Any]],
        seed: int,
    ) -> Tuple[List[PlannedTransform], List[Dict[str, str]], List[str]]:

        if tier == 0:
            return [], [], []

        signals = self._extract_issue_signals(sec_entry)
        sec_signals = extract_signals(sec_entry)
        vuln_labels = active_vulnerability_labels(sec_signals)

        budget = self._budget_for_tier(tier)
        if budget <= 0:
            return [], [], vuln_labels

        candidates: List[TransformSpec] = []
        blocked_transforms: List[Dict[str, str]] = []

        for tid in allowed_ids:
            spec = self.catalog.get(tid)
            if not spec:
                continue
            ok, reason = self._is_transform_compatible(
                spec,
                tier,
                signals,
                fn_advice,
                sec_entry=sec_entry,
            )
            if ok:
                candidates.append(spec)
            else:
                blocked_transforms.append({"id": spec.id, "reason": reason})

        if not candidates:
            return [], blocked_transforms, vuln_labels

        salt = f"{contract}::{fn_name}::{seed}"
        salt_int = self._stable_int(salt)

        family_pri = {"control": 0, "data": 1, "layout": 2}

        def rank(spec: TransformSpec) -> Tuple[int, int, int]:
            fam = int(family_pri.get(spec.family, 9))
            h = self._stable_int(f"{salt}::{spec.id}")
            return (fam, -int(spec.weight), h)

        candidates_sorted = sorted(candidates, key=rank)

        rename_ids = {
            "rename_identifiers_v2_scoped",
            "rename_identifiers_sha1_v1",
            "rename_identifiers_v1",
        }
        core_sorted = [s for s in candidates_sorted if s.id not in rename_ids]
        rename_sorted = [s for s in candidates_sorted if s.id in rename_ids]

        selected: List[PlannedTransform] = []
        family_counts: Dict[str, int] = {}
        expansive_count = 0

        def params_seed() -> int:
            return (salt_int % 10_000) + int(seed)

        def pick(spec: TransformSpec, target_kind: str, params: Optional[Dict[str, Any]] = None):
            nonlocal expansive_count
            if len(selected) >= budget:
                return
            if spec.id in self._EXPANSIVE_TRANSFORMS:
                if expansive_count >= self._MAX_EXPANSIVE_PER_FUNCTION:
                    return
            if self.policy.prefer_diverse_families:
                if family_counts.get(spec.family, 0) >= int(self.policy.max_per_family):
                    return

            selected.append(
                PlannedTransform(
                    id=spec.id,
                    target={"kind": target_kind},
                    params=params or {},
                )
            )
            family_counts[spec.family] = family_counts.get(spec.family, 0) + 1
            if spec.id in self._EXPANSIVE_TRANSFORMS:
                expansive_count += 1

        has_loops = bool(fn_advice.get("has_loops"))
        mut = (fn_advice.get("state_mutability") or "").lower()

        reserve_rename_slot = (tier <= 1)
        core_budget = max(0, budget - (1 if reserve_rename_slot else 0))

        cheap_first = [s for s in core_sorted if s.id in self._ALWAYS_CHEAP]
        rest = [s for s in core_sorted if s.id not in self._ALWAYS_CHEAP]

        # --- BiAn-parity reservation ---
        # For tier-3 functions, force at least one candidate path to include
        # the named BiAn-style transforms when they are compatible.
        parity_ids = (
            "chaotic_opaque_predicate_v1",
            "cfg_flatten_v1",
            "scalar_to_struct_indirection_v1",
        )

        if tier >= 3:
            for wanted_id in parity_ids:
                if len(selected) >= core_budget:
                    break
                spec = next((s for s in rest if s.id == wanted_id), None)
                if spec is None:
                    continue
                tr_seed = params_seed()
                if wanted_id == "chaotic_opaque_predicate_v1":
                    if has_loops and mut not in ("view", "pure"):
                        pick(spec, "function_body", {"seed": tr_seed})
                    else:
                        pick(spec, "if_condition", {"seed": tr_seed})
                else:
                    pick(spec, "function_body", {"seed": tr_seed})

        for spec in cheap_first:
            tr_seed = params_seed()
            if spec.id == "dynamic_constants_v1":
                pick(spec, "expression", {"seed": tr_seed, "max_consts": 24, "avoid_in_require": True})
            elif spec.id == "constant_encoding_v1":
                pick(spec, "expression", {"seed": tr_seed})
            elif spec.id == "boolean_split_v1":
                pick(spec, "expression", {"seed": tr_seed})
            elif spec.id == "layout_scramble_v1":
                pick(spec, "function_body", {"seed": tr_seed})
            elif spec.id == "string_split_v1":
                pick(spec, "expression", {"seed": tr_seed, "min_len": 8, "max_literals": 4})
            elif spec.id == "algebraic_identities_v1":
                pick(spec, "expression", {"seed": tr_seed, "max_rewrites": 6})

        if self._should_force_control(tier, signals):
            for spec in rest:
                if spec.family != "control":
                    continue
                tr_seed = params_seed()

                if spec.id in ("opaque_predicate_v1", "chaotic_opaque_predicate_v1"):
                    if has_loops and mut not in ("view", "pure"):
                        pick(spec, "function_body", {"seed": tr_seed})
                    else:
                        pick(spec, "if_condition", {"seed": tr_seed})
                    break
                if spec.id == "dead_code_v1":
                    pick(spec, "function_body", {"seed": tr_seed, "nops": 2})
                    break
                if spec.id == "predicate_masking_v1":
                    pick(spec, "if_condition", {"seed": tr_seed})
                    break
                if spec.id == "loop_rewrite_v1":
                    pick(spec, "function_body", {"seed": tr_seed})
                    break
                if spec.id == "inline_internal_v1":
                    pick(spec, "function_body", {"seed": tr_seed, "max_inline": 2})
                    break
                if spec.id == "cfg_flatten_v1":
                    pick(spec, "function_body", {"seed": tr_seed})
                    break
                if spec.id == "yul_microblock_v1":
                    pick(spec, "function_body", {"seed": tr_seed})
                    break

        for spec in rest:
            if len(selected) >= core_budget:
                break
            if any(t.id == spec.id for t in selected):
                continue

            tr_seed = params_seed()

            if spec.id == "string_split_v1":
                pick(spec, "expression", {"seed": tr_seed, "min_len": 8, "max_literals": 4})
            elif spec.id in ("opaque_predicate_v1", "chaotic_opaque_predicate_v1"):
                if has_loops and mut not in ("view", "pure"):
                    pick(spec, "function_body", {"seed": tr_seed})
                else:
                    pick(spec, "if_condition", {"seed": tr_seed})
            elif spec.id == "dead_code_v1":
                pick(spec, "function_body", {"seed": tr_seed, "nops": 2})
            elif spec.id == "predicate_masking_v1":
                pick(spec, "if_condition", {"seed": tr_seed})
            elif spec.id == "loop_rewrite_v1":
                pick(spec, "function_body", {"seed": tr_seed})
            elif spec.id == "inline_internal_v1":
                pick(spec, "function_body", {"seed": tr_seed, "max_inline": 2})
            elif spec.id == "algebraic_identities_v1":
                pick(spec, "expression", {"seed": tr_seed, "max_rewrites": 6})
            elif spec.id == "cfg_flatten_v1":
                pick(spec, "function_body", {"seed": tr_seed})
            elif spec.id == "yul_microblock_v1":
                pick(spec, "function_body", {"seed": tr_seed})
            elif spec.id == "storage_indirection_v1":
                pick(spec, "function_body", {"seed": tr_seed})
            else:
                if spec.targets:
                    pick(spec, spec.targets[0], {"seed": tr_seed})

        should_add_rename = (
            reserve_rename_slot
            or (
                len(selected) < max(1, budget)
                and not any(t.id in rename_ids for t in selected)
                and tier <= 1
            )
        )

        if should_add_rename and len(selected) < budget:
            tr_seed = params_seed()
            for spec in rename_sorted:
                if spec.id == "rename_identifiers_v2_scoped":
                    selected.append(
                        PlannedTransform(
                            id=spec.id,
                            target={"kind": "function_scope"},
                            params={"seed": tr_seed},
                        )
                    )
                    break
                if spec.id == "rename_identifiers_sha1_v1":
                    selected.append(
                        PlannedTransform(
                            id=spec.id,
                            target={"kind": "function_scope"},
                            params={"seed": tr_seed},
                        )
                    )
                    break
                if spec.id == "rename_identifiers_v1":
                    selected.append(
                        PlannedTransform(
                            id=spec.id,
                            target={"kind": "function_scope"},
                            params={"seed": tr_seed},
                        )
                    )
                    break

        if not selected:
            fallback_sorted = sorted(
                candidates_sorted,
                key=lambda s: (1 if self._is_cosmetic_transform(s.id) else 0, -int(s.weight), s.id),
            )
            for spec in fallback_sorted[:budget]:
                tr_seed = params_seed()
                kind = spec.targets[0] if spec.targets else "function_body"
                selected.append(
                    PlannedTransform(id=spec.id, target={"kind": kind}, params={"seed": tr_seed})
                )

        return selected, blocked_transforms, vuln_labels

    # ------------------------------------------------------------

    def build(self) -> Dict[str, Any]:
        contract = self.advice.get("contract", "")
        source_file = self.advice.get("source_file", "")
        plans: List[FunctionPlan] = []

        sec_map = self._sec_map()
        contract_sec = sec_map.get("__contract__")

        for fn in self.advice.get("functions", []) or []:
            fn_name = fn.get("function", "") or ""
            full_name = fn.get("full_name", "") or ""
            category = fn.get("category", "no_obfuscation")
            rationale = fn.get("rationale", "")

            sec_entry = sec_map.get(fn_name) or contract_sec

            try:
                tier = int(fn.get("tier"))
            except Exception:
                raise RuntimeError(
                    f"Canonical tier missing for function '{fn_name}'. "
                    "Tier must be computed by obfuscation_advisor."
                )

            tier_reason = str(fn.get("tier_reason") or "provided_by_obfuscation_advisor")
            econ_score = float(fn.get("econ_score") or 0.0)
            sec_score = float(fn.get("sec_score") or 0.0)
            sev = str(
                fn.get("sec_severity")
                or fn.get("sec_severity_max")
                or "INFO"
            ).upper()

            allowed = self._allowed_transforms_for_tier(tier)

            selected, blocked_transforms, vuln_labels = self._select_transforms(
                contract=contract,
                fn_name=fn_name,
                tier=tier,
                allowed_ids=allowed,
                fn_advice=fn,
                sec_entry=sec_entry,
                seed=int(self.policy.seed),
            )

            tests_to_run = fn.get("tests_touching", []) or []

            plans.append(
                FunctionPlan(
                    function=fn_name,
                    full_name=full_name,
                    tier=tier,
                    tier_reason=tier_reason,
                    category=category,
                    rationale=rationale,
                    econ_score=round(econ_score, 4),
                    sec_score=round(float(sec_score), 4),
                    sec_severity_max=sev,
                    tests_to_run=tests_to_run,
                    allowed_transforms=allowed,
                    selected_transforms=selected,
                    blocked_transforms=blocked_transforms,
                    active_vulnerability_labels=vuln_labels,
                )
            )

        out = VariantsPlan(contract=contract, source_file=source_file, plans=plans)

        return {
            "contract": out.contract,
            "source_file": out.source_file,
            "meta": {
                "planner": "DecisionPlanner",
                "tiering": "canonical tier provided by obfuscation_advisor.compute_tier (read-only downstream)",
            },
            "plans": [
                {
                    **{k: v for k, v in asdict(p).items() if k != "selected_transforms"},
                    "selected_transforms": [asdict(t) for t in p.selected_transforms],
                    "category_tier": self._tier_for_category(p.category),
                    "tier_source": "obfuscation_advisor",
                }
                for p in out.plans
            ],
        }


# ---------------------------------------------------------------------
# LLM Decision Planner (Option A: LLM outputs a transform plan)
# ---------------------------------------------------------------------

class LLMDecisionPlanner(DecisionPlanner):
    """
    Same inputs/outputs as DecisionPlanner, but replaces _select_transforms()
    with an LLM call constrained by allowed transforms (tier/risk gating).
    """

    def __init__(
        self,
        advice: Dict[str, Any],
        catalog: Dict[str, TransformSpec],
        policy: Optional[PlannerPolicy],
        sec_advice: Optional[Dict[str, Any]],
        ir: Optional[Dict[str, Any]],
        coverage: Optional[Dict[str, Any]],
    ) -> None:
        super().__init__(
            advice=advice,
            catalog=catalog,
            policy=policy,
            sec_advice=sec_advice,
            ir=ir,
            coverage=coverage,
        )

        # Best-effort import: if the user didn't create decision/llm_planner.py yet,
        # we fall back to deterministic selection.
        self._llm_available = True
        try:
            from decision.llm_planner import LLMPlanner  # type: ignore
            self._llm = LLMPlanner(
                model=self.policy.llm_model,
                temperature=float(self.policy.llm_temperature),
                max_tokens=int(self.policy.llm_max_tokens),
            )
        except Exception:
            self._llm_available = False
            self._llm = None

    def _llm_select_transforms(
        self,
        *,
        contract: str,
        fn_name: str,
        tier: int,
        allowed_ids: List[str],
        fn_advice: Dict[str, Any],
        sec_entry: Optional[Dict[str, Any]],
        seed: int,
    ) -> Tuple[List[PlannedTransform], List[Dict[str, str]], List[str]]:
        if not self._llm_available or self._llm is None:
            return super()._select_transforms(
                contract=contract,
                fn_name=fn_name,
                tier=tier,
                allowed_ids=allowed_ids,
                fn_advice=fn_advice,
                sec_entry=sec_entry,
                seed=seed,
            )

        if tier <= 0:
            return [], [], []

        # LLM budget: keep small and safe (actual aggressiveness still comes from optimizer/search)
        max_steps = int(getattr(self.policy, "llm_max_steps", 3))
        if max_steps <= 0:
            return [], [], []

        allowed_transforms = [{"id": tid} for tid in allowed_ids]

        sec_signals = extract_signals(sec_entry or {})
        vuln_labels = active_vulnerability_labels(sec_signals)

        blocked_transforms: List[Dict[str, str]] = []
        for tid in allowed_ids:
            spec = self.catalog.get(tid)
            if not spec:
                continue
            ok, reason = compat_matrix_compatible(
                spec=spec,
                tier=tier,
                signals=sec_signals,
                fn_advice=fn_advice,
                sec_severity_max=str((sec_entry or {}).get("severity") or ""),
                matrix=self.transform_vulnerability_matrix,
            )
            if not ok:
                blocked_transforms.append({"id": tid, "reason": reason})

        # Give the LLM the function context (compact)
        # NOTE: no code emission; only transform IDs + params.
        try:
            plan_obj = self._llm.propose_plan(
                contract_name=contract,
                function_name=fn_name,
                function_ir=fn_advice,
                obf_advice=fn_advice,
                sec_advice=sec_entry or {},
                tier=tier,
                allowed_transforms=allowed_transforms,
                max_steps=max_steps,
            )
        except Exception:
            # Fail closed: revert to deterministic
            return super()._select_transforms(
                contract=contract,
                fn_name=fn_name,
                tier=tier,
                allowed_ids=allowed_ids,
                fn_advice=fn_advice,
                sec_entry=sec_entry,
                seed=seed,
            )

        steps = plan_obj.get("plan") if isinstance(plan_obj, dict) else None
        if not isinstance(steps, list) or not steps:
            return super()._select_transforms(
                contract=contract,
                fn_name=fn_name,
                tier=tier,
                allowed_ids=allowed_ids,
                fn_advice=fn_advice,
                sec_entry=sec_entry,
                seed=seed,
            )

        out: List[PlannedTransform] = []
        used = set()
        for step in steps[:max_steps]:
            if not isinstance(step, dict):
                continue
            tid = step.get("transform_id")
            if not tid or not isinstance(tid, str):
                continue
            if tid not in allowed_ids:
                continue
            if tid in used:
                continue

            spec = self.catalog.get(tid)
            if spec is None:
                continue

            ok, _reason = compat_matrix_compatible(
                spec=spec,
                tier=tier,
                signals=sec_signals,
                fn_advice=fn_advice,
                sec_severity_max=str((sec_entry or {}).get("severity") or ""),
                matrix=self.transform_vulnerability_matrix,
            )
            if not ok:
                continue

            used.add(tid)
            params = step.get("params") if isinstance(step.get("params"), dict) else {}

            # Keep target scoping simple: your _ensure_plan_has_transforms attaches function anyway.
            out.append(PlannedTransform(id=tid, target={"kind": "function_body"}, params=params))

        if out:
            return out, blocked_transforms, vuln_labels

        # Fall back deterministic if LLM output collapses to nothing
        return super()._select_transforms(
            contract=contract,
            fn_name=fn_name,
            tier=tier,
            allowed_ids=allowed_ids,
            fn_advice=fn_advice,
            sec_entry=sec_entry,
            seed=seed,
        )

    def build(self) -> Dict[str, Any]:
        contract = self.advice.get("contract", "")
        source_file = self.advice.get("source_file", "")
        plans: List[FunctionPlan] = []

        sec_map = self._sec_map()
        contract_sec = sec_map.get("__contract__")

        for fn in self.advice.get("functions", []) or []:
            fn_name = fn.get("function", "") or ""
            full_name = fn.get("full_name", "") or ""
            category = fn.get("category", "no_obfuscation")
            rationale = fn.get("rationale", "")

            sec_entry = sec_map.get(fn_name) or contract_sec

            try:
                tier = int(fn.get("tier"))
            except Exception:
                raise RuntimeError(
                    f"Canonical tier missing for function '{fn_name}'. "
                    "Tier must be computed by obfuscation_advisor."
                )

            tier_reason = str(fn.get("tier_reason") or "provided_by_obfuscation_advisor")
            econ_score = float(fn.get("econ_score") or 0.0)
            sec_score = float(fn.get("sec_score") or 0.0)
            sev = str(
                fn.get("sec_severity")
                or fn.get("sec_severity_max")
                or "INFO"
            ).upper()

            allowed = self._allowed_transforms_for_tier(tier)

            selected, blocked_transforms, vuln_labels = self._llm_select_transforms(
                contract=contract,
                fn_name=fn_name,
                tier=tier,
                allowed_ids=allowed,
                fn_advice=fn,
                sec_entry=sec_entry,
                seed=int(self.policy.seed),
            )

            tests_to_run = fn.get("tests_touching", []) or []

            plans.append(
                FunctionPlan(
                    function=fn_name,
                    full_name=full_name,
                    tier=tier,
                    tier_reason=tier_reason,
                    category=category,
                    rationale=rationale,
                    econ_score=round(econ_score, 4),
                    sec_score=round(float(sec_score), 4),
                    sec_severity_max=sev,
                    tests_to_run=tests_to_run,
                    allowed_transforms=allowed,
                    selected_transforms=selected,
                    blocked_transforms=blocked_transforms,
                    active_vulnerability_labels=vuln_labels,
                )
            )

        out = VariantsPlan(contract=contract, source_file=source_file, plans=plans)

        return {
            "contract": out.contract,
            "source_file": out.source_file,
            "meta": {
                "planner": "LLMDecisionPlanner" if self._llm_available else "DecisionPlanner(fallback)",
                "tiering": "canonical tier provided by obfuscation_advisor.compute_tier (read-only downstream)",
                "llm": {
                    "enabled": bool(self._llm_available),
                    "model": getattr(self.policy, "llm_model", None),
                    "temperature": getattr(self.policy, "llm_temperature", None),
                    "max_steps": getattr(self.policy, "llm_max_steps", None),
                },
            },
            "plans": [
                {
                    **{k: v for k, v in asdict(p).items() if k != "selected_transforms"},
                    "selected_transforms": [asdict(t) for t in p.selected_transforms],
                    "category_tier": self._tier_for_category(p.category),
                    "tier_source": "obfuscation_advisor",
                }
                for p in out.plans
            ],
        }


# ---------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------

def build_variants_plan_deterministic(
    advice_json: Path,
    out_json: Path,
    policy_json: Optional[Path] = None,
    sec_advice_json: Optional[Path] = None,
    ir_json: Optional[Path] = None,
    coverage_json: Optional[Path] = None,
) -> Dict[str, Any]:
    planner = DecisionPlanner.from_files(
        advice_json=advice_json,
        policy_json=policy_json,
        sec_advice_json=sec_advice_json,
        ir_json=ir_json,
        coverage_json=coverage_json,
    )
    plan = planner.build()
    out_json.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return plan


def build_variants_plan(
    advice_json: Path,
    out_json: Path,
    policy_json: Optional[Path] = None,
    sec_advice_json: Optional[Path] = None,
    ir_json: Optional[Path] = None,
    coverage_json: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Default planner entrypoint.

    REQUIRED CHANGE:
    - Use LLMDecisionPlanner by default (Option A),
      but allow deterministic mode for ablations via env:
        OBLIVION_PLANNER_MODE=deterministic
    """
    mode = (os.environ.get("OBLIVION_PLANNER_MODE") or "llm").strip().lower()
    if mode in ("deterministic", "baseline"):
        return build_variants_plan_deterministic(
            advice_json=advice_json,
            out_json=out_json,
            policy_json=policy_json,
            sec_advice_json=sec_advice_json,
            ir_json=ir_json,
            coverage_json=coverage_json,
        )

    planner = LLMDecisionPlanner.from_files(
        advice_json=advice_json,
        policy_json=policy_json,
        sec_advice_json=sec_advice_json,
        ir_json=ir_json,
        coverage_json=coverage_json,
    )
    plan = planner.build()
    out_json.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return plan