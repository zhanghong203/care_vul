"""CodeBERT-based coarse vulnerability-family router.

Data and metric helpers remain importable without the optional training stack.
"""

from .data import PairJsonlDataset, RouterExample, compute_pos_weight, load_pair_examples
from .metrics import compute_router_metrics

__all__ = [
    "CodeBertRouter",
    "PairJsonlDataset",
    "RouterExample",
    "compute_pos_weight",
    "compute_router_metrics",
    "load_pair_examples",
    "RouterPrediction",
    "RouterPredictor",
]


def __getattr__(name: str):
    if name == "CodeBertRouter":
        from .model import CodeBertRouter

        return CodeBertRouter
    if name in {"RouterPrediction", "RouterPredictor"}:
        from .predictor import RouterPrediction, RouterPredictor

        return {"RouterPrediction": RouterPrediction, "RouterPredictor": RouterPredictor}[name]
    raise AttributeError(name)
