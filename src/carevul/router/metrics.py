from __future__ import annotations

from collections import defaultdict
from typing import Sequence

import numpy as np

from .data import RouterExample


def _topk_mask(scores: np.ndarray, k: int) -> np.ndarray:
    k = min(k, scores.shape[1])
    indices = np.argpartition(-scores, kth=k - 1, axis=1)[:, :k]
    mask = np.zeros_like(scores, dtype=bool)
    np.put_along_axis(mask, indices, True, axis=1)
    return mask


def _mean_recall(targets: np.ndarray, predictions: np.ndarray) -> float:
    denominator = targets.sum(axis=1)
    return float(((targets & predictions).sum(axis=1) / denominator).mean())


def compute_router_metrics(
    probabilities: np.ndarray,
    examples: Sequence[RouterExample],
    label_names: Sequence[str],
    ks: Sequence[int] = (1, 3, 5),
) -> dict:
    """Compute candidate-recall metrics without selecting a threshold on test data."""

    probabilities = np.asarray(probabilities, dtype=np.float64)
    targets = np.asarray([example.labels for example in examples], dtype=bool)
    if probabilities.shape != targets.shape:
        raise ValueError(f"Probability shape {probabilities.shape} != target shape {targets.shape}")
    if targets.shape[1] != len(label_names):
        raise ValueError("label_names length does not match targets")

    versions = np.asarray([example.version for example in examples])
    result: dict[str, object] = {"samples": len(examples), "pairs": len({e.pair_id for e in examples})}

    for k in ks:
        selected = _topk_mask(probabilities, k)
        result[f"recall@{k}"] = _mean_recall(targets, selected)
        result[f"hit_rate@{k}"] = float(np.any(targets & selected, axis=1).mean())
        for version in ("vulnerable", "fixed"):
            subset = versions == version
            result[f"{version}_recall@{k}"] = _mean_recall(targets[subset], selected[subset])

        family_recall = {}
        for index, name in enumerate(label_names):
            positive = targets[:, index]
            family_recall[name] = float(selected[positive, index].mean()) if positive.any() else None
        present = [value for value in family_recall.values() if value is not None]
        result[f"macro_family_recall@{k}"] = float(np.mean(present))
        result[f"family_recall@{k}"] = family_recall

        grouped: dict[str, list[int]] = defaultdict(list)
        for index, example in enumerate(examples):
            grouped[example.pair_id].append(index)
        union_recalls = []
        both_version_hits = []
        eligible_both_hits = []
        for indices in grouped.values():
            pair_target = np.any(targets[indices], axis=0)
            pair_candidates = np.any(selected[indices], axis=0)
            union_recalls.append(float((pair_target & pair_candidates).sum() / pair_target.sum()))
            version_hits = [bool(np.any(targets[index] & selected[index])) for index in indices]
            both_hit = len(indices) == 2 and all(version_hits)
            both_version_hits.append(float(both_hit))
            if all(examples[index].pair_consistency_eligible for index in indices):
                eligible_both_hits.append(float(both_hit))
        result[f"pair_union_recall@{k}"] = float(np.mean(union_recalls))
        result[f"pair_both_versions_hit@{k}"] = float(np.mean(both_version_hits))
        result[f"eligible_pair_both_versions_hit@{k}"] = float(np.mean(eligible_both_hits))

    result["average_candidate_size"] = {str(k): float(min(k, len(label_names))) for k in ks}
    return result
