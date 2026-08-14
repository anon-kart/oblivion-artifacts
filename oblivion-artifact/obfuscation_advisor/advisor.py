from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .tiering import TierInputs, TierResult, compute_tier, merge_tier_policy


@dataclass
class CandidateTransform:
    id: str
    desc: str
    estimated_gas_delta_pct: float
    risk_tags: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class FunctionAdvice:
    function: str
    full_name: str
    visibility: str
    state_mutability: str
    has_loops: bool
    loop_count: int
    static_hits: int
    dynamic_calls: int

    # legacy fields kept for backward compatibility
    category: str
    rationale: str
    tests_touching: List[str]

    # richer advisor fields
    exec_weight: float
    coverage_score: float
    impact_score: float
    econ_score: float
    sec_score: float
    sec_severity: str
    runtime_relevance: float
    tier_inputs: Dict[str, Any]
    tier: int
    tier_reason: str
    candidate_transforms: List[Dict[str, Any]]

    # new role-1 security-policy outputs
    policy_sensitivity: float
    policy_sensitivity_band: str
    policy_signals: Dict[str, Any]
    protected_regions: List[Dict[str, Any]]


@dataclass
class ContractAdvice:
    contract: str
    source_file: str
    functions: List[FunctionAdvice]


class ObfuscationAdvisor:
    """
    Deterministic obfuscation advisor that combines:
      - IR JSON        (structure, loops, visibility, mutability, storage, external calls)
      - coverage.json  (static per-function hit counts)
      - traces.json    (dynamic per-function call counts + tests)
      - optional sec_advice.json (function-level severity / sec_score / runtime_relevance /
                                  policy_sensitivity / policy_signals / protected_regions)
    into per-function obfuscation recommendations.

    Backward-compatible legacy field:
      - category

    Richer planned fields:
      - exec_weight
      - coverage_score
      - impact_score
      - econ_score
      - sec_score
      - sec_severity
      - runtime_relevance
      - tier_inputs
      - tier
      - candidate_transforms
      - policy_sensitivity
      - policy_sensitivity_band
      - policy_signals
      - protected_regions
    """

    def __init__(
        self,
        ir: Dict[str, Any],
        coverage: Dict[str, Any],
        traces: Dict[str, Any],
        contract_name: str,
        source_relpath: str,
        sec_advice: Optional[Dict[str, Any]] = None,
        tier_policy: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.ir = ir
        self.coverage = coverage
        self.traces = traces
        self.contract_name = contract_name
        self.source_relpath = source_relpath
        self.sec_advice = sec_advice or {}
        self.tier_policy = merge_tier_policy(tier_policy or {})

        self._cov_for_contract: Dict[str, Any] = coverage.get(
            source_relpath, {}
        ) or coverage.get(f"src/{contract_name}.sol", {})

        self._dyn_calls, self._tests_per_function = self._build_dynamic_maps()
        self._all_static_hits = self._all_static_hit_values()
        self._all_dynamic_calls = list(self._dyn_calls.values())

    # ---------- construction helpers ----------

    @classmethod
    def from_files(
        cls,
        ir_json: Path,
        coverage_json: Path,
        traces_json: Path,
        contract_name: str,
        source_relpath: str,
        test_summary_json: Path | None = None,
        sec_advice_json: Path | None = None,
        tier_policy: Optional[Dict[str, Any]] = None,
    ) -> "ObfuscationAdvisor":
        with open(ir_json, "r", encoding="utf-8") as f:
            ir = json.load(f)

        with open(coverage_json, "r", encoding="utf-8") as f:
            coverage = json.load(f)

        with open(traces_json, "r", encoding="utf-8") as f:
            traces = json.load(f)

        sec_advice: Dict[str, Any] = {}
        if sec_advice_json and Path(sec_advice_json).exists():
            try:
                with open(sec_advice_json, "r", encoding="utf-8") as f:
                    sec_advice = json.load(f)
            except Exception:
                sec_advice = {}

        _ = test_summary_json

        return cls(
            ir=ir,
            coverage=coverage,
            traces=traces,
            contract_name=contract_name,
            source_relpath=source_relpath,
            sec_advice=sec_advice,
            tier_policy=tier_policy,
        )

    # ---------- dynamic usage from traces.json ----------

    def _build_dynamic_maps(self) -> Tuple[Dict[str, int], Dict[str, Set[str]]]:
        dyn_calls: Dict[str, int] = {}
        tests_per_fn: Dict[str, Set[str]] = {}

        for test_name, entries in self.traces.items():
            if not isinstance(entries, list):
                continue
            for ev in entries:
                if ev.get("type") != "call":
                    continue

                c = (ev.get("contract") or "")
                if not c:
                    continue
                if self.contract_name not in c:
                    continue

                fn_name = ev.get("function") or ""
                if not fn_name:
                    continue
                if fn_name.startswith("test_"):
                    continue

                dyn_calls[fn_name] = dyn_calls.get(fn_name, 0) + 1
                tests_per_fn.setdefault(fn_name, set()).add(test_name)

        return dyn_calls, tests_per_fn

    # ---------- coverage lookups ----------

    def _static_hits_for(self, full_name: str) -> int:
        if not self._cov_for_contract:
            for _src, data in self.coverage.items():
                fns = (data or {}).get("functions", {})
                if full_name in fns:
                    return int(fns.get(full_name) or 0)
            return 0

        fns = self._cov_for_contract.get("functions", {})
        return int(fns.get(full_name) or 0)

    def _all_static_hit_values(self) -> List[int]:
        vals: List[int] = []
        if isinstance(self._cov_for_contract, dict):
            fns = self._cov_for_contract.get("functions", {}) or {}
            for v in fns.values():
                try:
                    vals.append(int(v))
                except Exception:
                    pass
        return vals

    # ---------- loop info from IR ----------

    @staticmethod
    def _loop_count(fn: Dict[str, Any]) -> int:
        loops = fn.get("loops")
        if loops is None:
            return 0
        if isinstance(loops, list):
            return len(loops)
        if isinstance(loops, dict):
            return int(loops.get("count", 0))
        return 0

    # ---------- effect helpers from IR ----------

    @staticmethod
    def _storage_write_count(fn: Dict[str, Any]) -> int:
        for key in ("storage_writes", "writes_storage"):
            v = fn.get(key)
            if isinstance(v, list):
                return len(v)
        return 0

    @staticmethod
    def _external_call_count(fn: Dict[str, Any]) -> int:
        for key in ("external_calls", "calls_external"):
            v = fn.get(key)
            if isinstance(v, list):
                return len(v)
        return 0

    @staticmethod
    def _require_count(fn: Dict[str, Any]) -> int:
        reqs = fn.get("requires")
        if isinstance(reqs, list):
            return len(reqs)
        return 0

    # ---------- access-control heuristics from IR ----------

    @staticmethod
    def _has_only_owner_modifier(fn: Dict[str, Any]) -> bool:
        mods = fn.get("modifiers") or []
        if isinstance(mods, list):
            for m in mods:
                if isinstance(m, str) and "onlyowner" in m.lower():
                    return True

        ac = fn.get("access_control") or {}
        if isinstance(ac, dict):
            joined = " ".join(str(v) for v in ac.values()).lower()
            if "onlyowner" in joined or "owner" in joined or "admin" in joined:
                return True

        reqs = fn.get("requires") or []
        if isinstance(reqs, list):
            for r in reqs:
                if isinstance(r, str):
                    if "onlyowner" in r.lower():
                        return True
                elif isinstance(r, dict):
                    joined = " ".join(str(v) for v in r.values()).lower()
                    if "onlyowner" in joined or "owner" in joined:
                        return True

        return False

    def _is_access_controlled(self, fn: Dict[str, Any], fn_name: str) -> bool:
        if self._has_only_owner_modifier(fn):
            return True

        sec_entry = self._sec_entry_for_function(fn_name)
        if isinstance(sec_entry, dict):
            ps = sec_entry.get("policy_signals") or {}
            if isinstance(ps, dict) and bool(ps.get("access_control_sensitive")):
                return True

            regions = sec_entry.get("protected_regions") or []
            if isinstance(regions, list):
                for r in regions:
                    if isinstance(r, dict) and str(r.get("tag") or "") == "access_control_guard":
                        return True

        return False

    # ---------- security fusion ----------

    def _sec_entry_for_function(self, fn_name: str) -> Dict[str, Any]:
        if not isinstance(self.sec_advice, dict):
            return {}

        fns = self.sec_advice.get("functions")
        if isinstance(fns, list):
            for item in fns:
                if isinstance(item, dict) and item.get("function") == fn_name:
                    return item

        by_fn = self.sec_advice.get("by_function")
        if isinstance(by_fn, dict):
            item = by_fn.get(fn_name)
            if isinstance(item, dict):
                return item

        return {}

    @staticmethod
    def _severity_to_score(sev: str) -> float:
        sev_u = (sev or "").strip().upper()
        if sev_u == "HIGH":
            return 0.90
        if sev_u == "MEDIUM":
            return 0.60
        if sev_u == "LOW":
            return 0.25
        if sev_u == "INFO":
            return 0.10
        return 0.20

    def _security_fields_for(
        self, fn_name: str
    ) -> Tuple[float, str, float, str, Dict[str, Any], List[Dict[str, Any]]]:
        entry = self._sec_entry_for_function(fn_name)

        sec_score_f: Optional[float] = None
        if isinstance(entry, dict):
            val = entry.get("sec_score")
            if val is not None:
                try:
                    sec_score_f = float(val)
                except Exception:
                    sec_score_f = None

        sec_sev = ""
        if isinstance(entry, dict):
            sec_sev = (
                entry.get("severity_max")
                or entry.get("severity")
                or entry.get("sec_severity")
                or ""
            )
        sec_sev = str(sec_sev or "").strip().upper()

        # Fallback only if advisor did not emit canonical score
        if sec_score_f is None:
            if sec_sev:
                sec_score_f = self._severity_to_score(sec_sev)
            else:
                sec_score_f = 0.20

        if not sec_sev:
            if sec_score_f >= 0.85:
                sec_sev = "HIGH"
            elif sec_score_f >= 0.50:
                sec_sev = "MEDIUM"
            elif sec_score_f >= 0.15:
                sec_sev = "LOW"
            else:
                sec_sev = "INFO"

        policy_sensitivity = 0.0
        policy_sensitivity_band = "INFO"
        policy_signals: Dict[str, Any] = {}
        protected_regions: List[Dict[str, Any]] = []

        if isinstance(entry, dict):
            try:
                policy_sensitivity = float(entry.get("policy_sensitivity", 0.0) or 0.0)
            except Exception:
                policy_sensitivity = 0.0

            policy_sensitivity_band = str(
                entry.get("policy_sensitivity_band") or "INFO"
            ).upper().strip()

            raw_policy_signals = entry.get("policy_signals") or {}
            if isinstance(raw_policy_signals, dict):
                policy_signals = raw_policy_signals

            raw_protected_regions = entry.get("protected_regions") or []
            if isinstance(raw_protected_regions, list):
                protected_regions = [
                    r for r in raw_protected_regions if isinstance(r, dict)
                ]

        sec_score_f = max(0.0, min(1.0, sec_score_f))
        policy_sensitivity = max(0.0, min(1.0, policy_sensitivity))

        if policy_sensitivity_band not in {"INFO", "LOW", "MEDIUM", "HIGH"}:
            if policy_sensitivity >= 0.75:
                policy_sensitivity_band = "HIGH"
            elif policy_sensitivity >= 0.40:
                policy_sensitivity_band = "MEDIUM"
            elif policy_sensitivity >= 0.15:
                policy_sensitivity_band = "LOW"
            else:
                policy_sensitivity_band = "INFO"

        return (
            sec_score_f,
            sec_sev,
            policy_sensitivity,
            policy_sensitivity_band,
            policy_signals,
            protected_regions,
        )

    def _security_runtime_relevance_for(self, fn_name: str) -> float:
        entry = self._sec_entry_for_function(fn_name)
        try:
            return max(0.0, min(1.0, float(entry.get("runtime_relevance", 0.0))))
        except Exception:
            return 0.0

    # ---------- normalization helpers ----------

    @staticmethod
    def _normalize_ratio(value: int, population: List[int]) -> float:
        clean = [max(0, int(x)) for x in population if isinstance(x, int)]
        if not clean:
            return 0.0
        vmax = max(clean)
        if vmax <= 0:
            return 0.0
        return max(0.0, min(1.0, float(value) / float(vmax)))

    @staticmethod
    def _clamp01(x: float) -> float:
        return max(0.0, min(1.0, x))

    # ---------- legacy classification rules ----------

    @staticmethod
    def _is_internal_like(visibility: str, name: str) -> bool:
        vis = (visibility or "").lower()
        if vis in ("internal", "private"):
            return True
        if name in ("constructor", "_requireBound"):
            return True
        return False

    def _classify(
        self,
        fn_name: str,
        full_name: str,
        visibility: str,
        state_mutability: str,
        loop_count: int,
        static_hits: int,
        dynamic_calls: int,
        is_access_controlled: bool,
        tests_count: int,
    ) -> Tuple[str, str]:
        has_loops = loop_count > 0
        vis = (visibility or "").lower()
        mut = (state_mutability or "").lower()

        if self._is_internal_like(vis, fn_name):
            return (
                "no_obfuscation",
                "Constructor / internal helper: obfuscation could hurt clarity more than it helps.",
            )

        if static_hits == 0 and dynamic_calls == 0:
            return (
                "unused_or_uncovered",
                "Function not exercised by tests or coverage; improve tests before deciding obfuscation.",
            )

        usage_score = 0
        if dynamic_calls >= 50 or static_hits >= 50:
            usage_score += 3
        elif dynamic_calls >= 10 or static_hits >= 10:
            usage_score += 2
        elif dynamic_calls > 0 or static_hits > 0:
            usage_score += 1

        if vis in ("external", "public") and mut not in ("view", "pure"):
            usage_score += 1

        if is_access_controlled:
            usage_score += 1

        if loop_count >= 3:
            loop_score = 2
        elif loop_count >= 1:
            loop_score = 1
        else:
            loop_score = 0

        if tests_count >= 3:
            coverage_strength = "strong"
        elif tests_count == 2:
            coverage_strength = "medium"
        elif tests_count == 1:
            coverage_strength = "weak"
        else:
            coverage_strength = "none"

        is_critical_mut = mut not in ("view", "pure")
        is_external_like = vis in ("external", "public")
        is_critical = is_external_like and is_critical_mut and is_access_controlled

        if is_critical and usage_score >= 3:
            return (
                "no_obfuscation",
                "Access-controlled or admin-like function with significant usage; avoid obfuscation to keep behavior debuggable and auditable.",
            )

        if has_loops:
            if (
                loop_score >= 2
                and usage_score >= 2
                and coverage_strength in ("medium", "strong")
                and not is_access_controlled
            ):
                return (
                    "aggressive_obfuscation_ok",
                    f"Loop-heavy and reasonably well-tested (tests={tests_count}, usage_score={usage_score}); aggressive obfuscation is acceptable.",
                )

            if usage_score <= 2:
                return (
                    "light_obfuscation_ok",
                    f"Loop-heavy but low/medium usage (usage_score={usage_score}); light obfuscation is acceptable.",
                )

            return (
                "no_obfuscation",
                "Loop-heavy and high-usage or sensitive; obfuscation may harm debuggability or gas clarity.",
            )

        if usage_score >= 3 and (is_critical_mut or is_access_controlled):
            return (
                "no_obfuscation",
                "High-usage or critical path (state-changing or access-controlled); avoid obfuscation to keep behavior debuggable.",
            )

        return (
            "light_obfuscation_ok",
            "Low/medium usage and no heavy looping; safe candidate for light obfuscation.",
        )

    # ---------- richer scoring ----------

    def _compute_exec_weight(self, static_hits: int, dynamic_calls: int) -> float:
        static_norm = self._normalize_ratio(static_hits, self._all_static_hits)
        dyn_norm = self._normalize_ratio(dynamic_calls, self._all_dynamic_calls)
        return self._clamp01(0.45 * static_norm + 0.55 * dyn_norm)

    def _compute_coverage_score(self, tests_count: int, static_hits: int, dynamic_calls: int) -> float:
        test_component = min(1.0, float(tests_count) / 3.0)
        exec_weight = self._compute_exec_weight(static_hits, dynamic_calls)
        return self._clamp01(0.50 * test_component + 0.50 * exec_weight)

    def _compute_runtime_relevance(
        self,
        *,
        static_hits: int,
        dynamic_calls: int,
        tests_count: int,
    ) -> float:
        static_norm = self._normalize_ratio(static_hits, self._all_static_hits)
        dyn_norm = self._normalize_ratio(dynamic_calls, self._all_dynamic_calls)
        test_norm = min(1.0, float(tests_count) / 3.0)
        return self._clamp01(0.45 * static_norm + 0.45 * dyn_norm + 0.10 * test_norm)

    def _compute_impact_score(
        self,
        *,
        visibility: str,
        state_mutability: str,
        loop_count: int,
        storage_write_count: int,
        external_call_count: int,
        require_count: int,
        is_access_controlled: bool,
    ) -> float:
        vis = (visibility or "").lower()
        mut = (state_mutability or "").lower()

        score = 0.0

        if vis in ("public", "external"):
            score += 0.20
        if mut not in ("view", "pure"):
            score += 0.20
        if loop_count > 0:
            score += min(0.20, 0.08 * float(loop_count))
        if storage_write_count > 0:
            score += min(0.20, 0.10 + 0.05 * float(storage_write_count))
        if external_call_count > 0:
            score += min(0.15, 0.08 + 0.04 * float(external_call_count))
        if require_count > 0:
            score += min(0.10, 0.03 * float(require_count))
        if is_access_controlled:
            score += 0.10

        return self._clamp01(score)

    def _compute_econ_score(
        self,
        *,
        exec_weight: float,
        impact_score: float,
        coverage_score: float,
    ) -> float:
        return self._clamp01(0.45 * exec_weight + 0.40 * impact_score + 0.15 * coverage_score)

    def _candidate_transforms_for(
        self,
        *,
        tier: int,
        has_loops: bool,
        state_mutability: str,
        storage_write_count: int,
        external_call_count: int,
        is_access_controlled: bool,
        sec_severity: str,
        policy_signals: Dict[str, Any],
        protected_regions: List[Dict[str, Any]],
    ) -> List[CandidateTransform]:
        mut = (state_mutability or "").lower()
        sev = (sec_severity or "").upper()

        items: List[CandidateTransform] = []

        # Tier 1 / safe lexical-light
        if tier >= 1:
            items.append(
                CandidateTransform(
                    id="rename_identifiers_v2_scoped",
                    desc="Scoped identifier renaming",
                    estimated_gas_delta_pct=0.0,
                    risk_tags=["lexical", "low_risk"],
                )
            )
            items.append(
                CandidateTransform(
                    id="constant_encoding_v1",
                    desc="Literal / constant encoding where safe",
                    estimated_gas_delta_pct=1.5,
                    risk_tags=["data_flow", "low_risk"],
                )
            )

        # Tier 2 / moderate
        if tier >= 2:
            items.append(
                CandidateTransform(
                    id="opaque_predicate_v1",
                    desc="Guard-flow obfuscation via opaque predicates",
                    estimated_gas_delta_pct=6.0,
                    risk_tags=["control_flow", "moderate_risk"],
                )
            )
            items.append(
                CandidateTransform(
                    id="stack_variable_aliasing_v1",
                    desc="Introduce stack/local aliasing to distort variable flow",
                    estimated_gas_delta_pct=0.5,
                    risk_tags=["data_flow", "low_risk"],
                )
            )
            items.append(
                CandidateTransform(
                    id="predicate_masking_v1",
                    desc="Predicate masking for branch conditions",
                    estimated_gas_delta_pct=3.5,
                    risk_tags=["control_flow", "moderate_risk"],
                )
            )

        # Tier 3 / aggressive but still policy-aware
        if tier >= 3 and has_loops and sev in ("INFO", "LOW"):
            items.append(
                CandidateTransform(
                    id="loop_rewrite_v1",
                    desc="Loop-shape rewriting for iterative control-flow distortion",
                    estimated_gas_delta_pct=7.5,
                    risk_tags=["control_flow", "loop_sensitive"],
                )
            )

        # Disable riskier suggestions when function is more sensitive
        region_tags = {
            str(r.get("tag") or "").strip()
            for r in protected_regions
            if isinstance(r, dict) and r.get("tag")
        }

        access_control_sensitive = bool(policy_signals.get("access_control_sensitive")) or (
            "access_control_guard" in region_tags
        )
        external_call_sensitive = bool(policy_signals.get("external_call_sensitive")) or (
            "external_call_site" in region_tags
        )
        reentrancy_sensitive = bool(policy_signals.get("reentrancy_sensitive"))
        arithmetic_sensitive = bool(policy_signals.get("arithmetic_sensitive")) or (
            "arithmetic_region" in region_tags
        )
        revert_sensitive = bool(policy_signals.get("revert_semantics_sensitive")) or (
            "revert_semantics_region" in region_tags
        )

        for item in items:
            if mut in ("view", "pure") and item.id not in {
                "rename_identifiers_v2_scoped",
                "constant_encoding_v1",
            }:
                item.enabled = False
                continue

            if access_control_sensitive and item.id in {
                "opaque_predicate_v1",
                "predicate_masking_v1",
            }:
                item.enabled = False
                continue

            if external_call_sensitive and item.id in {
                "opaque_predicate_v1",
                "predicate_masking_v1",
                "loop_rewrite_v1",
            }:
                item.enabled = False
                continue

            if reentrancy_sensitive and item.id in {
                "opaque_predicate_v1",
                "predicate_masking_v1",
                "loop_rewrite_v1",
            }:
                item.enabled = False
                continue

            if arithmetic_sensitive and item.id in {
                "constant_encoding_v1",
                "predicate_masking_v1",
            }:
                item.enabled = False
                continue

            if revert_sensitive and item.id in {
                "opaque_predicate_v1",
                "predicate_masking_v1",
            }:
                item.enabled = False
                continue

            if is_access_controlled and "control_flow" in item.risk_tags:
                item.enabled = False
                continue

            if external_call_count > 0 and "control_flow" in item.risk_tags and sev in ("MEDIUM", "HIGH"):
                item.enabled = False
                continue

            if storage_write_count > 0 and item.id == "predicate_masking_v1" and sev in ("MEDIUM", "HIGH"):
                item.enabled = False
                continue

        enabled_first = [x for x in items if x.enabled]
        disabled_rest = [x for x in items if not x.enabled]
        ordered = enabled_first + disabled_rest

        return ordered

    # ---------- main builder ----------

    def build(self) -> Dict[str, Any]:
        contract_ir = self.ir.get("contract") or {}
        if not contract_ir:
            raise ValueError("IR JSON missing 'contract' section")

        fn_items: List[FunctionAdvice] = []

        for fn in contract_ir.get("functions", []) or []:
            fn_name = fn.get("name", "")
            if fn_name.startswith("__obf_"):
                continue

            full_name = fn.get("full_name") or f"{self.contract_name}.{fn_name}"
            visibility = fn.get("visibility", "")
            state_mutability = fn.get("state_mutability", "")

            loop_count = self._loop_count(fn)
            has_loops = loop_count > 0

            static_hits = self._static_hits_for(full_name)
            dynamic_calls = self._dyn_calls.get(fn_name, 0)
            tests_touching_set = self._tests_per_function.get(fn_name, set())
            tests_touching = sorted(tests_touching_set)
            tests_count = len(tests_touching)

            is_access_controlled = self._is_access_controlled(fn, fn_name)
            storage_write_count = self._storage_write_count(fn)
            external_call_count = self._external_call_count(fn)
            require_count = self._require_count(fn)

            category, rationale = self._classify(
                fn_name=fn_name,
                full_name=full_name,
                visibility=visibility,
                state_mutability=state_mutability,
                loop_count=loop_count,
                static_hits=static_hits,
                dynamic_calls=dynamic_calls,
                is_access_controlled=is_access_controlled,
                tests_count=tests_count,
            )

            exec_weight = self._compute_exec_weight(static_hits, dynamic_calls)
            coverage_score = self._compute_coverage_score(tests_count, static_hits, dynamic_calls)
            impact_score = self._compute_impact_score(
                visibility=visibility,
                state_mutability=state_mutability,
                loop_count=loop_count,
                storage_write_count=storage_write_count,
                external_call_count=external_call_count,
                require_count=require_count,
                is_access_controlled=is_access_controlled,
            )
            econ_score = self._compute_econ_score(
                exec_weight=exec_weight,
                impact_score=impact_score,
                coverage_score=coverage_score,
            )

            (
                sec_score,
                sec_severity,
                policy_sensitivity,
                policy_sensitivity_band,
                policy_signals,
                protected_regions,
            ) = self._security_fields_for(fn_name)

            sec_runtime_relevance = self._security_runtime_relevance_for(fn_name)
            local_runtime_relevance = self._compute_runtime_relevance(
                static_hits=static_hits,
                dynamic_calls=dynamic_calls,
                tests_count=tests_count,
            )
            runtime_relevance = max(local_runtime_relevance, sec_runtime_relevance)

            tier_inputs_obj = TierInputs(
                function=fn_name,
                visibility=visibility,
                state_mutability=state_mutability,
                econ_score=econ_score,
                sec_score=sec_score,
                coverage_score=coverage_score,
                exec_weight=exec_weight,
                sec_severity=sec_severity,
                runtime_relevance=runtime_relevance,
                has_loops=has_loops,
                loop_count=loop_count,
                is_access_controlled=is_access_controlled,
                static_hits=static_hits,
                dynamic_calls=dynamic_calls,
                policy_sensitivity=policy_sensitivity,
                policy_sensitivity_band=policy_sensitivity_band,
                protected_region_count=len(protected_regions),
                protected_region_tags=tuple(
                    sorted(
                        {
                            str(r.get("tag") or "")
                            for r in protected_regions
                            if isinstance(r, dict) and r.get("tag")
                        }
                    )
                ),
            )

            tier_result = compute_tier(tier_inputs_obj, policy=self.tier_policy)
            tier = int(tier_result.tier)
            tier_reason = tier_result.reason

            candidate_transforms = [
                asdict(x)
                for x in self._candidate_transforms_for(
                    tier=tier,
                    has_loops=has_loops,
                    state_mutability=state_mutability,
                    storage_write_count=storage_write_count,
                    external_call_count=external_call_count,
                    is_access_controlled=is_access_controlled,
                    sec_severity=sec_severity,
                    policy_signals=policy_signals,
                    protected_regions=protected_regions,
                )
            ]

            tier_inputs = {
                "function": fn_name,
                "visibility": visibility,
                "state_mutability": state_mutability,
                "exec_weight": round(exec_weight, 4),
                "coverage_score": round(coverage_score, 4),
                "impact_score": round(impact_score, 4),
                "econ_score": round(econ_score, 4),
                "sec_score": round(sec_score, 4),
                "sec_severity": sec_severity,
                "runtime_relevance": round(runtime_relevance, 4),
                "sec_runtime_relevance": round(sec_runtime_relevance, 4),
                "local_runtime_relevance": round(local_runtime_relevance, 4),
                "has_loops": has_loops,
                "loop_count": loop_count,
                "storage_write_count": storage_write_count,
                "external_call_count": external_call_count,
                "require_count": require_count,
                "is_access_controlled": is_access_controlled,
                "tests_touching_count": tests_count,
                "static_hits": static_hits,
                "dynamic_calls": dynamic_calls,
                "policy_sensitivity": round(policy_sensitivity, 4),
                "policy_sensitivity_band": policy_sensitivity_band,
                "protected_region_count": len(protected_regions),
                "protected_region_tags": sorted(
                    {
                        str(r.get("tag") or "")
                        for r in protected_regions
                        if isinstance(r, dict) and r.get("tag")
                    }
                ),
            }

            fn_items.append(
                FunctionAdvice(
                    function=fn_name,
                    full_name=full_name,
                    visibility=visibility,
                    state_mutability=state_mutability,
                    has_loops=has_loops,
                    loop_count=loop_count,
                    static_hits=static_hits,
                    dynamic_calls=dynamic_calls,
                    category=category,
                    rationale=rationale,
                    tests_touching=tests_touching,
                    exec_weight=round(exec_weight, 4),
                    coverage_score=round(coverage_score, 4),
                    impact_score=round(impact_score, 4),
                    econ_score=round(econ_score, 4),
                    sec_score=round(sec_score, 4),
                    sec_severity=sec_severity,
                    runtime_relevance=round(runtime_relevance, 4),
                    tier_inputs=tier_inputs,
                    tier=tier,
                    tier_reason=tier_reason,
                    candidate_transforms=candidate_transforms,
                    policy_sensitivity=round(policy_sensitivity, 4),
                    policy_sensitivity_band=policy_sensitivity_band,
                    policy_signals=policy_signals,
                    protected_regions=protected_regions,
                )
            )

        advice = ContractAdvice(
            contract=self.contract_name,
            source_file=self.source_relpath,
            functions=fn_items,
        )

        return {
            "contract": advice.contract,
            "source_file": advice.source_file,
            "meta": {
                "tiering": {
                    "source": "obfuscation_advisor.compute_tier",
                    "version": "v2_canonical_runtime_aware_policy_sensitive",
                    "policy": self.tier_policy,
                }
            },
            "functions": [asdict(f) for f in advice.functions],
        }


# ---------- public entrypoint used by oblivion_run.py ----------

def build_contract_advice(
    ir_json: Path,
    coverage_json: Path,
    test_summary_json: Path,
    traces_json: Path,
    contract_name: str,
    source_relpath: str,
    sec_advice_json: Path | None = None,
    tier_policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Thin wrapper around ObfuscationAdvisor.from_files().build()

    Backward-compatible with existing callsites:
      - sec_advice_json is optional
      - legacy fields (category/rationale/tests_touching) are preserved
    """
    advisor = ObfuscationAdvisor.from_files(
        ir_json=ir_json,
        coverage_json=coverage_json,
        traces_json=traces_json,
        contract_name=contract_name,
        source_relpath=source_relpath,
        test_summary_json=test_summary_json,
        sec_advice_json=sec_advice_json,
        tier_policy=tier_policy,
    )
    return advisor.build()