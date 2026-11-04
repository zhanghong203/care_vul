from __future__ import annotations

from collections.abc import Sequence

import torch
from torch import nn
from torch.nn import functional as F

from .data import RouterExample, compute_pos_weight


CE_OBJECTIVES = {"weighted_ce", "focal_ce"}
SUPPORTED_OBJECTIVES = {"weighted_bce", *CE_OBJECTIVES}


def _single_label_targets(labels: torch.Tensor) -> torch.Tensor:
    if labels.ndim != 2 or not torch.all(labels.sum(dim=1) == 1):
        raise ValueError("Cross-entropy Router objectives require exactly one positive label per sample")
    return labels.argmax(dim=1)


def compute_class_weights(
    examples: Sequence[RouterExample],
    mode: str = "sqrt_inverse",
    allow_missing: bool = False,
) -> torch.Tensor:
    labels = torch.tensor([example.labels for example in examples], dtype=torch.float32)
    _single_label_targets(labels)
    counts = labels.sum(dim=0)
    if torch.any(counts == 0) and not allow_missing:
        missing = torch.where(counts == 0)[0].tolist()
        raise ValueError(f"Cannot compute class weights: labels with no positives: {missing}")
    safe_counts = torch.where(counts > 0, counts, torch.ones_like(counts))
    if mode == "none":
        weights = torch.ones_like(counts)
    elif mode == "inverse":
        weights = labels.shape[0] / safe_counts
    elif mode == "sqrt_inverse":
        weights = torch.sqrt(labels.shape[0] / safe_counts)
    else:
        raise ValueError(f"unsupported class-weight mode: {mode}")
    weights = torch.where(counts > 0, weights, torch.ones_like(weights))
    return weights / weights.mean()


class FocalCrossEntropy(nn.Module):
    def __init__(
        self,
        class_weights: torch.Tensor,
        gamma: float = 2.0,
        label_smoothing: float = 0.0,
    ):
        super().__init__()
        self.register_buffer("class_weights", class_weights)
        self.gamma = gamma
        self.label_smoothing = label_smoothing

    def forward(self, logits: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        targets = _single_label_targets(labels)
        ce = F.cross_entropy(
            logits,
            targets,
            weight=self.class_weights,
            label_smoothing=self.label_smoothing,
            reduction="none",
        )
        true_probabilities = torch.softmax(logits, dim=-1).gather(1, targets.unsqueeze(1)).squeeze(1)
        return (((1.0 - true_probabilities) ** self.gamma) * ce).mean()


def build_training_loss(
    objective: str,
    examples: Sequence[RouterExample],
    device: torch.device,
    class_weight_mode: str = "sqrt_inverse",
    label_smoothing: float = 0.05,
    focal_gamma: float = 2.0,
    allow_missing: bool = False,
) -> tuple[nn.Module, dict]:
    if objective not in SUPPORTED_OBJECTIVES:
        raise ValueError(f"unsupported Router objective: {objective}")
    if objective == "weighted_bce":
        weights = compute_pos_weight(examples, allow_missing=allow_missing).to(device)
        return nn.BCEWithLogitsLoss(pos_weight=weights), {
            "objective": objective,
            "prediction_activation": "sigmoid",
            "pos_weight": weights.detach().cpu().tolist(),
        }

    weights = compute_class_weights(examples, class_weight_mode, allow_missing).to(device)
    metadata = {
        "objective": objective,
        "prediction_activation": "softmax",
        "class_weight_mode": class_weight_mode,
        "class_weights": weights.detach().cpu().tolist(),
        "label_smoothing": label_smoothing,
    }
    if objective == "weighted_ce":
        return nn.CrossEntropyLoss(weight=weights, label_smoothing=label_smoothing), metadata
    metadata["focal_gamma"] = focal_gamma
    return FocalCrossEntropy(weights, focal_gamma, label_smoothing), metadata


def objective_loss(
    objective: str,
    loss_fn: nn.Module,
    logits: torch.Tensor,
    labels: torch.Tensor,
) -> torch.Tensor:
    if objective in CE_OBJECTIVES and not isinstance(loss_fn, FocalCrossEntropy):
        return loss_fn(logits, _single_label_targets(labels))
    return loss_fn(logits, labels)


def evaluation_loss(objective: str, logits: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
    if objective in CE_OBJECTIVES:
        return F.cross_entropy(logits, _single_label_targets(labels))
    return F.binary_cross_entropy_with_logits(logits, labels)


def probabilities_from_logits(objective: str, logits: torch.Tensor) -> torch.Tensor:
    if objective in CE_OBJECTIVES:
        return torch.softmax(logits, dim=-1)
    return torch.sigmoid(logits)
