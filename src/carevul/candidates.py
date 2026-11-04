from __future__ import annotations

from collections import defaultdict

from .models import Candidate, ProgramFacts
from .mulvul import MulVulCandidate
from .retrieval import KnowledgeItem
from .templates import API_TO_CWE, TEMPLATES


class CorrectiveCandidateGenerator:
    def __init__(self, max_candidates: int = 8, min_coverage: float = 0.6):
        self.max_candidates = max_candidates
        self.min_coverage = min_coverage

    def generate(
        self,
        facts: ProgramFacts,
        retrieved: list[tuple[KnowledgeItem, float]],
        mulvul: list[MulVulCandidate] | None = None,
    ) -> list[Candidate]:
        components: dict[str, dict[str, float]] = defaultdict(dict)
        provenance: dict[str, set[str]] = defaultdict(set)

        for candidate in mulvul or []:
            components[candidate.cwe]["mulvul"] = max(
                components[candidate.cwe].get("mulvul", 0.0), candidate.score
            )
            provenance[candidate.cwe].add("mulvul")

        for item, similarity in retrieved:
            if item.cwe and item.label == 1:
                components[item.cwe]["retrieval"] = max(
                    components[item.cwe].get("retrieval", 0.0), 0.6 * similarity
                )
                provenance[item.cwe].add("retrieval")

        # Static facts are an independent recovery channel when retrieval misses the true class.
        for operation in facts.operations:
            for cwe in API_TO_CWE.get(operation, ()):
                components[cwe]["static"] = max(components[cwe].get("static", 0.0), 0.85)
                provenance[cwe].add(f"static:{operation}")

        scores = {cwe: self._fuse(parts.values()) for cwe, parts in components.items()}
        initial = sorted(scores, key=scores.get, reverse=True)
        for cwe in initial[:3]:
            template = TEMPLATES.get(cwe)
            if template:
                for related in template.related:
                    if related in TEMPLATES:
                        components[related]["taxonomy"] = max(components[related].get("taxonomy", 0.0), 0.15)
                        provenance[related].add(f"taxonomy:{cwe}")

        scores = {cwe: self._fuse(parts.values()) for cwe, parts in components.items()}

        if not scores:
            # Open-set fallback: retain known templates without pretending confidence.
            for cwe in TEMPLATES:
                scores[cwe] = 0.01
                components[cwe]["fallback"] = 0.01
                provenance[cwe].add("fallback")

        ranked = sorted(scores.items(), key=lambda pair: pair[1], reverse=True)[: self.max_candidates]
        return [
            Candidate(cwe, round(score, 6), sorted(provenance[cwe]), {
                name: round(value, 6) for name, value in sorted(components[cwe].items())
            })
            for cwe, score in ranked
        ]

    @staticmethod
    def _fuse(values) -> float:
        # Bounded noisy-OR: independent recovery channels can raise confidence
        # without allowing many retrieved examples to overwhelm other signals.
        remainder = 1.0
        for value in values:
            remainder *= 1.0 - min(1.0, max(0.0, float(value)))
        return 1.0 - remainder

