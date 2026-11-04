from __future__ import annotations

from typing import Any

from .control import ControlPathAdapter
from .evidence_schema import (
    AVAILABLE_ANALYSIS_METHODS,
    normalize_program_evidence,
    unknown_method_evidence,
)


def inspect_analysis(
    code: str,
    method: str,
    adapter: ControlPathAdapter | None = None,
) -> dict[str, Any]:
    """Run one analysis method and return both its raw and normalized evidence."""
    if method not in AVAILABLE_ANALYSIS_METHODS:
        raise ValueError(f"unsupported analysis method: {method}")
    adapter = adapter or ControlPathAdapter()
    facts = adapter.extract(code)
    normalized = normalize_program_evidence(facts.security_evidence, method)
    if not normalized:
        normalized = [unknown_method_evidence(
            method,
            str(facts.metadata.get("analysis_mode", "unknown")),
            "The analyzer produced no fact for this method on the supplied code.",
        )]
    return {
        "schema_version": 1,
        "requested_method": method,
        "available_methods": list(AVAILABLE_ANALYSIS_METHODS),
        "extraction_metadata": facts.metadata,
        "normalized_evidence": normalized,
        "raw_program_analysis": facts.security_evidence,
    }
