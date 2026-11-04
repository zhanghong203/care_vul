from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any, Iterable


PARAMETER_PREFIX_RE = re.compile(r"^param:\s*", re.IGNORECASE)
SPACE_RE = re.compile(r"\s+")


def _normalized_text(value: Any) -> str:
    return SPACE_RE.sub(" ", str(value or "").strip())


def _parameter_name(value: Any) -> str:
    return PARAMETER_PREFIX_RE.sub("", _normalized_text(value))


def _feature_key(feature: dict[str, Any]) -> str:
    return json.dumps(feature, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _feature_multiset(evidence: Iterable[dict[str, Any]]) -> Counter[str]:
    features: Counter[str] = Counter()
    for function in evidence:
        for operation in function.get("sensitive_operations", []):
            feature = {
                "feature": "sensitive_operation",
                "family": operation.get("family", "unknown"),
                "kind": operation.get("kind", "unknown"),
                "api": operation.get("api", "unknown"),
                "argument_roles": sorted(operation.get("roles", {})),
            }
            features[_feature_key(feature)] += 1

        for security_slice in function.get("security_slices", []):
            sink = security_slice.get("sink", {})
            sink_api = sink.get("api", "unknown")
            family = sink.get("family", "unknown")
            roles = sink.get("roles", {})
            for source in security_slice.get("source_parameters", []):
                source_name = _parameter_name(source.get("label", ""))
                semantic_roles = sorted(
                    role for role, expression in roles.items()
                    if _normalized_text(expression) == source_name
                )
                feature = {
                    "feature": "parameter_to_sink",
                    "family": family,
                    "source_roles": semantic_roles or ["unmapped_parameter"],
                    "sink_api": sink_api,
                }
                features[_feature_key(feature)] += 1

            for guard in security_slice.get("guards", []):
                constraint = guard.get("constraint") or {}
                feature = {
                    "feature": "guard_for_sink",
                    "family": family,
                    "sink_api": sink_api,
                    "dominates_sink": bool(guard.get("dominates_sink")),
                    "controls_sink": bool(guard.get("controls_sink")),
                    "constraint_relevant": bool(constraint.get("relevant")),
                    "path_operators": sorted({
                        item.get("operator", "") for item in constraint.get("path_constraints", [])
                    }),
                }
                features[_feature_key(feature)] += 1

            variables = security_slice.get("backward_slice", {}).get("variables", [])
            if variables:
                variable_set = {_normalized_text(variable) for variable in variables}
                feature = {
                    "feature": "slice_roles",
                    "family": family,
                    "sink_api": sink_api,
                    "roles": sorted({
                        role for role, expression in roles.items()
                        if _normalized_text(expression) in variable_set
                    }),
                }
                features[_feature_key(feature)] += 1

            for security_property in security_slice.get("security_properties", []):
                feature = {
                    "feature": "security_property",
                    "family": family,
                    "sink_api": sink_api,
                    "name": security_property.get("name", "unknown"),
                    "state": security_property.get("state", "UNKNOWN"),
                    "guard_effectiveness": security_property.get("guard_effectiveness", "UNKNOWN"),
                }
                features[_feature_key(feature)] += 1

        for ordinal, event in enumerate(function.get("lifetime_events", []), 1):
            feature = {
                "feature": "lifecycle_event",
                "family": event.get("family", "unknown"),
                "kind": event.get("kind", "unknown"),
                "api": event.get("api", "unknown"),
                "ordinal": ordinal,
            }
            features[_feature_key(feature)] += 1
        for lifetime_property in function.get("lifetime_properties", []):
            feature = {
                "feature": "lifetime_property",
                "name": lifetime_property.get("name", "unknown"),
                "state": lifetime_property.get("state", "UNKNOWN"),
            }
            features[_feature_key(feature)] += 1
    return features


def _expand(features: Counter[str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for serialized in sorted(features):
        feature = json.loads(serialized)
        count = features[serialized]
        if count > 1:
            feature["count"] = count
        output.append(feature)
    return output


def compare_security_evidence(
    evidence_a: Iterable[dict[str, Any]],
    evidence_b: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Compare two evidence packages without assigning a security label or direction."""
    features_a = _feature_multiset(evidence_a)
    features_b = _feature_multiset(evidence_b)
    shared = features_a & features_b
    return {
        "schema_version": 1,
        "orientation": "symmetric_code_a_code_b",
        "verdict_free": True,
        "shared": _expand(shared),
        "only_in_a": _expand(features_a - shared),
        "only_in_b": _expand(features_b - shared),
    }


def swap_comparison(comparison: dict[str, Any]) -> dict[str, Any]:
    """Return the expected comparison when Code-A and Code-B are swapped."""
    return {
        **comparison,
        "only_in_a": comparison.get("only_in_b", []),
        "only_in_b": comparison.get("only_in_a", []),
    }
