from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable


AVAILABLE_ANALYSIS_METHODS = (
    "sensitive_call",
    "call_roles",
    "backward_slice",
    "dominance",
    "control_dependency",
    "buffer_capacity",
    "path_constraint",
    "bounds_property",
    "lifetime_events",
    "path_order",
)


def _evidence_id(value: dict[str, Any]) -> str:
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "EV-" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:12]


def _item(
    *,
    method: str,
    family: str,
    function: str,
    analysis_mode: str,
    state: str,
    hypothesis: str,
    subject: dict[str, Any],
    raw_facts: dict[str, Any],
    supporting: list[str] | None = None,
    counter: list[str] | None = None,
    unknowns: list[str] | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    base = {
        "schema_version": 1,
        "analysis_method": method,
        "candidate_family": family,
        "function": function,
        "analysis_mode": analysis_mode,
        "state": state,
        "hypothesis": hypothesis,
        "subject": subject,
        "supporting_evidence": supporting or [],
        "counter_evidence": counter or [],
        "unknowns": unknowns or [],
        "limitations": limitations or [],
        "confidence": (
            0.2 if state == "UNKNOWN" and analysis_mode == "precise_c"
            else 0.1 if state == "UNKNOWN"
            else 0.95 if analysis_mode == "precise_c"
            else 0.45
        ),
        "raw_facts": raw_facts,
    }
    return {"evidence_id": _evidence_id(base), **base}


def normalize_program_evidence(
    raw_evidence: Iterable[dict[str, Any]],
    method: str | None = None,
) -> list[dict[str, Any]]:
    """Flatten heterogeneous analyzer facts into a stable LLM-facing envelope."""
    if method is not None and method not in AVAILABLE_ANALYSIS_METHODS:
        raise ValueError(f"unsupported analysis method: {method}")
    output: list[dict[str, Any]] = []
    for function_evidence in raw_evidence:
        function = function_evidence.get("function", "unknown")
        analysis_mode = function_evidence.get("analysis_mode", "unknown")
        common_limitations = list(function_evidence.get("limitations", []))

        for operation in function_evidence.get("sensitive_operations", []):
            family = operation.get("family", "unknown")
            if method in (None, "sensitive_call"):
                output.append(_item(
                    method="sensitive_call", family=family, function=function,
                    analysis_mode=analysis_mode, state="ESTABLISHED",
                    hypothesis="A security-relevant operation is present.",
                    subject={"api": operation.get("api"), "line": operation.get("line")},
                    raw_facts=operation,
                    supporting=[f"Recognized {operation.get('api')} as {operation.get('kind')}."],
                    limitations=common_limitations,
                ))
            if method in (None, "call_roles"):
                roles = operation.get("roles", {})
                output.append(_item(
                    method="call_roles", family=family, function=function,
                    analysis_mode=analysis_mode,
                    state="ESTABLISHED" if roles else "UNKNOWN",
                    hypothesis="Security-relevant call arguments have semantic roles.",
                    subject={"api": operation.get("api"), "line": operation.get("line")},
                    raw_facts={"arguments": operation.get("arguments", []), "roles": roles, "result": operation.get("result")},
                    supporting=[f"Mapped roles: {sorted(roles)}."] if roles else [],
                    unknowns=[] if roles else ["No argument-role specification is available."],
                    limitations=common_limitations,
                ))

        for security_slice in function_evidence.get("security_slices", []):
            sink = security_slice.get("sink", {})
            family = sink.get("family", "unknown")
            slice_limitations = common_limitations + list(security_slice.get("limitations", []))
            backward = security_slice.get("backward_slice", {})
            if method in (None, "backward_slice"):
                output.append(_item(
                    method="backward_slice", family=family, function=function,
                    analysis_mode=analysis_mode,
                    state="ESTABLISHED" if backward.get("node_ids") else "UNKNOWN",
                    hypothesis="Definitions or parameters reach a security-sensitive sink.",
                    subject={"api": sink.get("api"), "line": sink.get("line")},
                    raw_facts={"slice": backward, "source_parameters": security_slice.get("source_parameters", [])},
                    supporting=[f"Backward slice contains {len(backward.get('node_ids', []))} nodes."] if backward.get("node_ids") else [],
                    unknowns=[] if backward.get("node_ids") else ["No DFG slice reached the sink."],
                    limitations=slice_limitations,
                ))
            guards = security_slice.get("guards", [])
            if method in (None, "dominance"):
                output.append(_item(
                    method="dominance", family=family, function=function,
                    analysis_mode=analysis_mode,
                    state="ESTABLISHED" if guards else "UNKNOWN",
                    hypothesis="A guard dominates the security-sensitive sink.",
                    subject={"api": sink.get("api"), "line": sink.get("line")},
                    raw_facts={"guards": guards},
                    supporting=[f"{len(guards)} dominating guard(s) were found."] if guards else [],
                    unknowns=[] if guards else ["No dominating guard was established."],
                    limitations=slice_limitations,
                ))
            if method in (None, "path_constraint"):
                constraints = [guard.get("constraint") for guard in guards if guard.get("constraint")]
                output.append(_item(
                    method="path_constraint", family=family, function=function,
                    analysis_mode=analysis_mode,
                    state="ESTABLISHED" if constraints else "UNKNOWN",
                    hypothesis="A structured path constraint applies when execution reaches the sink.",
                    subject={"api": sink.get("api"), "line": sink.get("line")},
                    raw_facts={"constraints": constraints},
                    supporting=[f"Extracted {len(constraints)} path constraint(s)."] if constraints else [],
                    unknowns=[] if constraints else ["No supported simple path constraint was extracted."],
                    limitations=slice_limitations,
                ))
            if method in (None, "bounds_property"):
                for security_property in security_slice.get("security_properties", []):
                    state = security_property.get("state", "UNKNOWN")
                    output.append(_item(
                        method="bounds_property", family=family, function=function,
                        analysis_mode=analysis_mode, state=state,
                        hypothesis="The copy length is within the destination capacity.",
                        subject={"api": sink.get("api"), "line": sink.get("line")},
                        raw_facts=security_property,
                        supporting=[security_property.get("reason", "")] if state == "ESTABLISHED" else [],
                        counter=[security_property.get("reason", "")] if state == "NOT_ESTABLISHED" else [],
                        unknowns=[security_property.get("reason", "")] if state == "UNKNOWN" else [],
                        limitations=slice_limitations,
                    ))

        if method in (None, "control_dependency"):
            dependencies = function_evidence.get("control_dependencies", [])
            output.append(_item(
                method="control_dependency", family="generic", function=function,
                analysis_mode=analysis_mode,
                state="ESTABLISHED" if dependencies else "UNKNOWN",
                hypothesis="A branch controls execution of a security-relevant operation.",
                subject={"function": function}, raw_facts={"dependencies": dependencies},
                supporting=[f"Found {len(dependencies)} relevant control dependence edge(s)."] if dependencies else [],
                unknowns=[] if dependencies else ["No relevant control dependence edge was established."],
                limitations=common_limitations,
            ))

        if method in (None, "buffer_capacity"):
            capacities = function_evidence.get("buffer_capacities", [])
            for capacity in capacities:
                output.append(_item(
                    method="buffer_capacity", family="bounds_numeric", function=function,
                    analysis_mode=analysis_mode, state="ESTABLISHED",
                    hypothesis="A destination object's static capacity is known.",
                    subject={"object": capacity.get("object"), "line": capacity.get("line")},
                    raw_facts=capacity,
                    supporting=[f"Capacity is {capacity.get('capacity')} {capacity.get('unit')}."],
                    limitations=common_limitations,
                ))

        if method in (None, "lifetime_events"):
            for event in function_evidence.get("lifetime_events", []):
                output.append(_item(
                    method="lifetime_events", family=event.get("family", "pointer_lifetime"), function=function,
                    analysis_mode=analysis_mode, state="ESTABLISHED",
                    hypothesis="A resource lifecycle event is present.",
                    subject={"api": event.get("api"), "line": event.get("line")},
                    raw_facts=event,
                    supporting=[f"Observed lifecycle event {event.get('kind')}."],
                    limitations=common_limitations,
                ))
        if method in (None, "path_order"):
            for prop in function_evidence.get("lifetime_properties", []):
                state = prop.get("state", "UNKNOWN")
                output.append(_item(
                    method="path_order", family="pointer_lifetime", function=function,
                    analysis_mode=analysis_mode, state=state,
                    hypothesis="Resource lifecycle events occur in a security-relevant reachable order.",
                    subject={"object": prop.get("object")}, raw_facts=prop,
                    supporting=[prop.get("reason", "")] if state == "ESTABLISHED" else [],
                    unknowns=[prop.get("reason", "")] if state == "UNKNOWN" else [],
                    limitations=common_limitations,
                ))

    deduplicated: dict[str, dict[str, Any]] = {}
    for item in output:
        deduplicated[item["evidence_id"]] = item
    return list(deduplicated.values())


def unknown_method_evidence(method: str, analysis_mode: str, reason: str) -> dict[str, Any]:
    return _item(
        method=method, family="unknown", function="unknown", analysis_mode=analysis_mode,
        state="UNKNOWN", hypothesis="The requested analysis method yields evidence.",
        subject={}, raw_facts={}, unknowns=[reason], limitations=[],
    )
