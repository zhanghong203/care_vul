from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

import torch
from torch.utils.data import Dataset


@dataclass(frozen=True)
class RouterExample:
    """One function-level router example derived from a PrimeVul pair."""

    sample_id: str
    pair_id: str
    version: str
    code: str
    labels: tuple[float, ...]
    pair_consistency_eligible: bool


def _validate_member(member: dict, pair_id: str, version: str, num_labels: int) -> RouterExample:
    code = member.get("func")
    vector = member.get("family_label_vector")
    if not isinstance(code, str) or not code.strip():
        raise ValueError(f"{pair_id}/{version}: missing non-empty func")
    if not isinstance(vector, list) or len(vector) != num_labels:
        raise ValueError(f"{pair_id}/{version}: expected {num_labels}-dimensional label vector")
    if any(value not in (0, 1, 0.0, 1.0) for value in vector):
        raise ValueError(f"{pair_id}/{version}: labels must be binary")
    if not any(vector):
        raise ValueError(f"{pair_id}/{version}: at least one family label is required")
    return RouterExample(
        sample_id=f"{pair_id}:{version}",
        pair_id=pair_id,
        version=version,
        code=code,
        labels=tuple(float(value) for value in vector),
        pair_consistency_eligible=False,
    )


def load_pair_examples(
    path: str | Path,
    num_labels: int,
    max_pairs: int | None = None,
) -> list[RouterExample]:
    """Load paired JSONL while exposing only source code as model input."""

    examples: list[RouterExample] = []
    seen_pairs: set[str] = set()
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            pair_id = str(record.get("pair_id", "")).strip()
            if not pair_id:
                raise ValueError(f"{path}:{line_number}: missing pair_id")
            if pair_id in seen_pairs:
                raise ValueError(f"{path}:{line_number}: duplicate pair_id {pair_id}")
            seen_pairs.add(pair_id)
            eligible = bool(record.get("pair_consistency_eligible", False))
            pair_examples = []
            for version in ("vulnerable", "fixed"):
                if not isinstance(record.get(version), dict):
                    raise ValueError(f"{path}:{line_number}: missing {version} member")
                item = _validate_member(record[version], pair_id, version, num_labels)
                pair_examples.append(
                    RouterExample(
                        sample_id=item.sample_id,
                        pair_id=item.pair_id,
                        version=item.version,
                        code=item.code,
                        labels=item.labels,
                        pair_consistency_eligible=eligible,
                    )
                )
            examples.extend(pair_examples)
            if max_pairs is not None and len(seen_pairs) >= max_pairs:
                break
    if not examples:
        raise ValueError(f"No router examples found in {path}")
    return examples


class PairJsonlDataset(Dataset):
    def __init__(self, examples: Sequence[RouterExample]):
        self.examples = list(examples)

    def __len__(self) -> int:
        return len(self.examples)

    def __getitem__(self, index: int) -> RouterExample:
        return self.examples[index]


class RouterCollator:
    def __init__(self, tokenizer, max_length: int):
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __call__(self, examples: Sequence[RouterExample]) -> dict:
        encoded = self.tokenizer(
            [example.code for example in examples],
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )
        encoded["labels"] = torch.tensor([example.labels for example in examples], dtype=torch.float32)
        encoded["sample_ids"] = [example.sample_id for example in examples]
        encoded["pair_ids"] = [example.pair_id for example in examples]
        encoded["versions"] = [example.version for example in examples]
        encoded["pair_consistency_eligible"] = [example.pair_consistency_eligible for example in examples]
        return encoded


def compute_pos_weight(examples: Iterable[RouterExample], allow_missing: bool = False) -> torch.Tensor:
    labels = torch.tensor([example.labels for example in examples], dtype=torch.float32)
    positives = labels.sum(dim=0)
    if torch.any(positives == 0) and not allow_missing:
        missing = torch.where(positives == 0)[0].tolist()
        raise ValueError(f"Cannot compute pos_weight: labels with no positives: {missing}")
    negatives = labels.shape[0] - positives
    weights = torch.ones_like(positives)
    present = positives > 0
    weights[present] = negatives[present] / positives[present]
    return weights
