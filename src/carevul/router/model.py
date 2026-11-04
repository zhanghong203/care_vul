from __future__ import annotations

import json
import os
from pathlib import Path

import torch
from torch import nn
from transformers import AutoModel


class CodeBertRouter(nn.Module):
    """CodeBERT encoder with a ten-family multi-label classification head."""

    def __init__(
        self,
        model_dir: str | Path,
        num_labels: int,
        dropout: float = 0.1,
        local_files_only: bool = True,
    ):
        super().__init__()
        self.model_dir = str(Path(model_dir).resolve())
        self.num_labels = num_labels
        self.dropout_probability = dropout
        self.encoder = AutoModel.from_pretrained(self.model_dir, local_files_only=local_files_only)
        hidden_size = int(self.encoder.config.hidden_size)
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Linear(hidden_size, num_labels)

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor, **kwargs) -> torch.Tensor:
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask, **kwargs)
        cls_embedding = outputs.last_hidden_state[:, 0]
        return self.classifier(self.dropout(cls_embedding))

    def freeze_encoder(self) -> None:
        for parameter in self.encoder.parameters():
            parameter.requires_grad = False

    def save_checkpoint(self, directory: str | Path, metadata: dict | None = None) -> Path:
        destination = Path(directory)
        destination.mkdir(parents=True, exist_ok=True)
        checkpoint = destination / "router_state.pt"
        torch.save(self.state_dict(), checkpoint)
        try:
            relative_model_dir = os.path.relpath(self.model_dir, start=destination.resolve())
        except ValueError:
            # Windows cannot construct relative paths between different drives.
            relative_model_dir = None
        config = {
            "model_dir": self.model_dir,
            "model_dir_relative_to_checkpoint": relative_model_dir,
            "num_labels": self.num_labels,
            "dropout": self.dropout_probability,
            "metadata": metadata or {},
        }
        (destination / "router_config.json").write_text(
            json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return checkpoint

    @classmethod
    def load_checkpoint(cls, directory: str | Path, device: torch.device | str = "cpu") -> "CodeBertRouter":
        source = Path(directory)
        config = json.loads((source / "router_config.json").read_text(encoding="utf-8"))
        relative_value = config.get("model_dir_relative_to_checkpoint")
        relative_model_dir = source.resolve() / relative_value if relative_value else None
        model_dir = (
            relative_model_dir.resolve()
            if relative_model_dir is not None and relative_model_dir.exists()
            else Path(config["model_dir"])
        )
        model = cls(
            model_dir=model_dir,
            num_labels=int(config["num_labels"]),
            dropout=float(config["dropout"]),
            local_files_only=True,
        )
        state = torch.load(source / "router_state.pt", map_location=device, weights_only=True)
        model.load_state_dict(state)
        return model.to(device)
