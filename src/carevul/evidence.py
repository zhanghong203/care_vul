from __future__ import annotations

from dataclasses import asdict, dataclass

from .models import Alignment, EvidenceState


@dataclass(slots=True)
class EvidenceItem:
    cwe: str
    condition: str
    state: str
    text: str
    score: float
    token_estimate: int


class EvidenceSelector:
    def __init__(self, token_budget: int = 1200):
        self.token_budget = token_budget

    def select(self, alignments: list[Alignment]) -> list[dict]:
        items: list[EvidenceItem] = []
        for alignment in alignments:
            for condition in alignment.conditions:
                token_estimate = max(1, len(condition.evidence.split()))
                relevance = condition.weight
                state_bonus = 1.0 if condition.state != EvidenceState.UNKNOWN else 0.45
                value = relevance * condition.trust * state_bonus / (1.0 + token_estimate / 100.0)
                items.append(EvidenceItem(
                    alignment.cwe,
                    condition.condition,
                    condition.state.value,
                    condition.evidence,
                    round(value, 6),
                    token_estimate,
                ))

        # Preserve both support and counter-evidence before filling by value.
        chosen: list[EvidenceItem] = []
        for state in (EvidenceState.SUPPORTED.value, EvidenceState.CONTRADICTED.value):
            candidates = sorted((item for item in items if item.state == state), key=lambda x: x.score, reverse=True)
            if candidates:
                chosen.append(candidates[0])
        for item in sorted(items, key=lambda x: x.score, reverse=True):
            if item not in chosen:
                chosen.append(item)

        output: list[EvidenceItem] = []
        used = 0
        seen: set[tuple[str, str, str]] = set()
        for item in chosen:
            fingerprint = (item.cwe, item.condition, item.text)
            if fingerprint in seen or used + item.token_estimate > self.token_budget:
                continue
            seen.add(fingerprint)
            output.append(item)
            used += item.token_estimate
        return [asdict(item) for item in output]

