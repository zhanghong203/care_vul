from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


CWE_ANALYSIS_PLANS: dict[str, tuple[str, tuple[str, ...]]] = {
    "CWE-78": ("taint_injection", ("sensitive_call", "backward_slice", "control_dependency")),
    "CWE-120": ("bounds_numeric", ("call_roles", "backward_slice", "dominance", "buffer_capacity", "path_constraint")),
    "CWE-787": ("bounds_numeric", ("call_roles", "backward_slice", "dominance", "buffer_capacity", "path_constraint")),
    "CWE-416": ("pointer_lifetime", ("call_roles", "lifetime_events", "path_order")),
}


# Router labels are risk families, not individual CWEs. Map them directly to
# analysis capabilities so broad families such as ``memory`` can enable both
# bounds and lifetime reasoning.
ROUTER_FAMILY_ANALYSIS_PLANS: dict[str, dict[str, Any]] = {
    "memory": {
        "families": ("bounds_numeric", "pointer_lifetime"),
        "analyzers": ("call_roles", "backward_slice", "dominance", "buffer_capacity", "path_constraint", "bounds_property", "lifetime_events", "path_order"),
        "generic_queries": (), "coverage": "SPECIALIZED", "knowledge_guidance": (),
    },
    "injection": {
        "families": ("taint_injection",),
        "analyzers": ("sensitive_call", "backward_slice", "control_dependency"),
        "generic_queries": ("source_sink_query", "sanitizer_guard_query"), "coverage": "PARTIAL",
        "knowledge_guidance": ("Check whether untrusted data reaches an interpreter or command sink without an effective sanitizer.",),
    },
    "input": {
        "families": ("taint_injection", "bounds_numeric"),
        "analyzers": ("backward_slice", "dominance", "control_dependency", "path_constraint", "bounds_property"),
        "generic_queries": ("input_origin_query", "validation_guard_query"), "coverage": "PARTIAL",
        "knowledge_guidance": ("Check validation completeness, canonicalization order, and whether validation dominates every sensitive use.",),
    },
    "numeric": {
        "families": ("bounds_numeric",),
        "analyzers": ("call_roles", "backward_slice", "buffer_capacity", "path_constraint", "bounds_property"),
        "generic_queries": ("arithmetic_expression_query", "constant_and_cast_query"), "coverage": "PARTIAL",
        "knowledge_guidance": ("Check overflow, underflow, signedness conversion, truncation, and arithmetic used in allocation or copy sizes.",),
    },
    "resource": {
        "families": ("resource_state", "pointer_lifetime"),
        "analyzers": ("lifetime_events", "path_order"),
        "generic_queries": ("resource_exit_path_query",), "coverage": "PARTIAL",
        "knowledge_guidance": ("Check acquisition and release balance on normal, error, and early-return paths.",),
    },
    "concurrency": {
        "families": ("resource_state",),
        "analyzers": ("lifetime_events", "path_order"),
        "generic_queries": ("lock_event_query", "shared_state_access_query", "lock_order_query"), "coverage": "PARTIAL",
        "knowledge_guidance": ("Check shared accesses, missing locks, inconsistent lock order, and blocking operations in critical sections.",),
    },
    "access": {
        "families": (), "analyzers": (),
        "generic_queries": ("sensitive_operation_query", "authorization_guard_query", "guard_dominance_query"), "coverage": "GENERIC_ONLY",
        "knowledge_guidance": ("Check whether authentication and authorization dominate every privileged operation and use the correct subject and object.",),
    },
    "crypto": {
        "families": (), "analyzers": (),
        "generic_queries": ("crypto_api_query", "constant_argument_query", "randomness_origin_query"), "coverage": "GENERIC_ONLY",
        "knowledge_guidance": ("Check deprecated algorithms, hard-coded keys or IVs, nonce reuse, weak randomness, and unsafe modes or parameters.",),
    },
    "information": {
        "families": (), "analyzers": (),
        "generic_queries": ("sensitive_data_query", "logging_and_output_sink_query", "backward_slice"), "coverage": "GENERIC_ONLY",
        "knowledge_guidance": ("Check whether secrets or personal data reach logs, errors, files, or network outputs without redaction or authorization.",),
    },
    "logic": {
        "families": (), "analyzers": (),
        "generic_queries": ("critical_branch_query", "return_value_query", "error_path_query", "state_transition_query"), "coverage": "GENERIC_ONLY",
        "knowledge_guidance": ("Check invalid state transitions, ignored return values, fail-open handling, and inconsistent checks across paths.",),
    },
}


@dataclass(frozen=True, slots=True)
class AnalysisPlan:
    candidate_cwes: tuple[str, ...]
    families: frozenset[str]
    analyzers: tuple[str, ...]
    router_families: tuple[str, ...] = ()
    generic_queries: tuple[str, ...] = ()
    knowledge_guidance: tuple[str, ...] = ()
    coverage: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_cwes": list(self.candidate_cwes),
            "router_families": list(self.router_families),
            "families": sorted(self.families),
            "analyzers": list(self.analyzers),
            "generic_queries": list(self.generic_queries),
            "knowledge_guidance": list(self.knowledge_guidance),
            "coverage": dict(self.coverage),
        }


class AnalysisPlanner:
    """Union deterministic capabilities from CWE candidates and Router families."""

    @staticmethod
    def _router_family(value: Any) -> str:
        if hasattr(value, "family"):
            return str(value.family)
        if isinstance(value, dict):
            return str(value.get("family", ""))
        return str(value)

    def create_plan(
        self,
        candidates: Iterable[Any],
        router_predictions: Iterable[Any] = (),
    ) -> AnalysisPlan:
        cwes: set[str] = set()
        for candidate in candidates:
            if hasattr(candidate, "cwe"):
                cwes.add(str(candidate.cwe))
            elif isinstance(candidate, dict):
                cwes.add(str(candidate.get("cwe", "")))
            else:
                cwes.add(str(candidate))
        cwes.discard("")
        ordered_cwes = sorted(cwes)
        families: set[str] = set()
        analyzers: set[str] = set()
        for cwe in ordered_cwes:
            plan = CWE_ANALYSIS_PLANS.get(cwe)
            if not plan:
                continue
            family, required = plan
            families.add(family)
            analyzers.update(required)

        router_families = sorted({
            family
            for value in router_predictions
            if (family := self._router_family(value))
        })
        generic_queries: set[str] = set()
        knowledge_guidance: set[str] = set()
        coverage: dict[str, str] = {}
        for router_family in router_families:
            family_plan = ROUTER_FAMILY_ANALYSIS_PLANS.get(router_family)
            if family_plan is None:
                coverage[router_family] = "UNSUPPORTED"
                continue
            families.update(family_plan["families"])
            analyzers.update(family_plan["analyzers"])
            generic_queries.update(family_plan["generic_queries"])
            knowledge_guidance.update(family_plan["knowledge_guidance"])
            coverage[router_family] = family_plan["coverage"]

        return AnalysisPlan(
            tuple(ordered_cwes),
            frozenset(families),
            tuple(sorted(analyzers)),
            tuple(router_families),
            tuple(sorted(generic_queries)),
            tuple(sorted(knowledge_guidance)),
            tuple(sorted(coverage.items())),
        )
