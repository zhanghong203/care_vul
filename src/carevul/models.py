from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class EvidenceState(str, Enum):
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class ProgramFacts:
    ast_facts: list[dict[str, Any]] = field(default_factory=list)
    cfg_facts: list[dict[str, Any]] = field(default_factory=list)
    dfg_facts: list[dict[str, Any]] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    sinks: list[dict[str, Any]] = field(default_factory=list)
    flows: list[dict[str, Any]] = field(default_factory=list)
    guards: list[dict[str, Any]] = field(default_factory=list)
    security_evidence: list[dict[str, Any]] = field(default_factory=list)
    normalized_security_evidence: list[dict[str, Any]] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    verbalized_context: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProgramFacts":
        return cls(
            ast_facts=value.get("ast_facts", []),
            cfg_facts=value.get("cfg_facts", []),
            dfg_facts=value.get("dfg_facts", []),
            sources=value.get("sources", []),
            sinks=value.get("sinks", []),
            flows=value.get("flows", []),
            guards=value.get("guards", []),
            security_evidence=value.get("security_evidence", []),
            normalized_security_evidence=value.get("normalized_security_evidence", []),
            operations=value.get("operations", []),
            metadata=value.get("metadata", {}),
            verbalized_context=value.get("verbalized_context", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Candidate:
    cwe: str
    score: float
    sources: list[str] = field(default_factory=list)
    components: dict[str, float] = field(default_factory=dict)


@dataclass(slots=True)
class AlignedCondition:
    condition: str
    state: EvidenceState
    evidence: str
    weight: float
    trust: float


@dataclass(slots=True)
class Alignment:
    cwe: str
    score: float
    observability: float
    conditions: list[AlignedCondition]

