from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

import torch
from transformers import AutoTokenizer

from .model import CodeBertRouter


@dataclass(frozen=True, slots=True)
class RouterPrediction:
    family: str
    score: float
    rank: int

    def to_dict(self) -> dict[str, str | float | int]:
        return asdict(self)


class RouterProvider(Protocol):
    def predict(self, code: str, top_k: int = 3) -> list[RouterPrediction]:
        """Return ranked coarse vulnerability-family predictions for source code."""


class RouterPredictor:
    """Online inference adapter for a trained CodeBERT Router checkpoint."""

    def __init__(
        self,
        checkpoint_dir: str | Path,
        label_index: str | Path,
        device: str = "auto",
        max_length: int = 512,
    ):
        if device == "cuda" and not torch.cuda.is_available():
            raise RuntimeError("CUDA was requested for Router inference but is not available")
        resolved_device = "cuda" if device == "auto" and torch.cuda.is_available() else "cpu" if device == "auto" else device
        self.device = torch.device(resolved_device)
        mapping = json.loads(Path(label_index).read_text(encoding="utf-8"))
        indices = sorted(mapping.values())
        if indices != list(range(len(mapping))):
            raise ValueError("Router label indices must be contiguous and start at zero")
        self.label_names = [name for name, _ in sorted(mapping.items(), key=lambda item: item[1])]
        self.model = CodeBertRouter.load_checkpoint(checkpoint_dir, device=self.device)
        if self.model.num_labels != len(self.label_names):
            raise ValueError("Router checkpoint label count does not match label-index file")
        self.tokenizer = AutoTokenizer.from_pretrained(self.model.model_dir, local_files_only=True)
        self.max_length = max_length
        self.model.eval()

    @torch.no_grad()
    def predict(self, code: str, top_k: int = 3) -> list[RouterPrediction]:
        if not code.strip():
            raise ValueError("Router input code must not be empty")
        if top_k <= 0:
            raise ValueError("top_k must be positive")
        encoded = self.tokenizer(
            [code],
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )
        encoded = {name: value.to(self.device) for name, value in encoded.items()}
        probabilities = torch.sigmoid(self.model(**encoded))[0].float().cpu()
        count = min(top_k, len(self.label_names))
        scores, indices = torch.topk(probabilities, k=count)
        return [
            RouterPrediction(self.label_names[int(index)], float(score), rank)
            for rank, (index, score) in enumerate(zip(indices, scores), start=1)
        ]
