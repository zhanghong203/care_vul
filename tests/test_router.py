import json

import numpy as np
import pytest
import torch

from carevul.router.data import RouterExample, compute_pos_weight, load_pair_examples
from carevul.router.metrics import compute_router_metrics
from carevul.router.objectives import (
    build_training_loss,
    compute_class_weights,
    objective_loss,
    probabilities_from_logits,
)


def _example(pair_id, version, labels, eligible=True):
    return RouterExample(
        sample_id=f"{pair_id}:{version}",
        pair_id=pair_id,
        version=version,
        code="int f(void) { return 0; }",
        labels=tuple(labels),
        pair_consistency_eligible=eligible,
    )


def test_pair_loader_emits_two_function_examples_without_metadata_input(tmp_path):
    record = {
        "pair_id": "train_1",
        "pair_consistency_eligible": True,
        "vulnerable": {"func": "void f(){bad();}", "family_label_vector": [1, 0]},
        "fixed": {"func": "void f(){good();}", "family_label_vector": [1, 0]},
        "group_metadata": {"cve": "must-not-be-model-input"},
    }
    path = tmp_path / "pairs.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    examples = load_pair_examples(path, num_labels=2)

    assert [example.version for example in examples] == ["vulnerable", "fixed"]
    assert [example.code for example in examples] == ["void f(){bad();}", "void f(){good();}"]
    assert all("must-not-be-model-input" not in example.code for example in examples)


def test_pos_weight_is_computed_from_training_examples_only():
    examples = [
        _example("p1", "vulnerable", [1, 0]),
        _example("p1", "fixed", [1, 0]),
        _example("p2", "vulnerable", [0, 1]),
        _example("p2", "fixed", [0, 1]),
    ]
    assert compute_pos_weight(examples).tolist() == pytest.approx([1.0, 1.0])


def test_metrics_distinguish_union_recall_from_both_version_hit():
    examples = [
        _example("p1", "vulnerable", [1, 0]),
        _example("p1", "fixed", [1, 0]),
    ]
    probabilities = np.asarray([[0.9, 0.1], [0.1, 0.9]])

    metrics = compute_router_metrics(probabilities, examples, ["memory", "logic"], ks=(1,))

    assert metrics["pair_union_recall@1"] == 1.0
    assert metrics["pair_both_versions_hit@1"] == 0.0
    assert metrics["vulnerable_recall@1"] == 1.0
    assert metrics["fixed_recall@1"] == 0.0


def test_sqrt_inverse_class_weights_raise_long_tail_without_full_inverse():
    examples = [
        _example("p1", "vulnerable", [1, 0]),
        _example("p1", "fixed", [1, 0]),
        _example("p2", "vulnerable", [1, 0]),
        _example("p2", "fixed", [0, 1]),
    ]
    sqrt_weights = compute_class_weights(examples, "sqrt_inverse")
    inverse_weights = compute_class_weights(examples, "inverse")

    assert sqrt_weights.mean().item() == pytest.approx(1.0)
    assert sqrt_weights[1] > sqrt_weights[0]
    assert (sqrt_weights[1] / sqrt_weights[0]) < (inverse_weights[1] / inverse_weights[0])


def test_weighted_ce_uses_softmax_and_rejects_multilabel_targets():
    examples = [
        _example("p1", "vulnerable", [1, 0]),
        _example("p2", "vulnerable", [0, 1]),
    ]
    loss_fn, metadata = build_training_loss(
        "weighted_ce", examples, torch.device("cpu"), label_smoothing=0.05
    )
    logits = torch.tensor([[2.0, -1.0], [-1.0, 2.0]])
    labels = torch.tensor([[1.0, 0.0], [0.0, 1.0]])

    assert objective_loss("weighted_ce", loss_fn, logits, labels).item() > 0.0
    probabilities = probabilities_from_logits("weighted_ce", logits)
    assert probabilities.sum(dim=1).tolist() == pytest.approx([1.0, 1.0])
    assert metadata["prediction_activation"] == "softmax"

    with pytest.raises(ValueError, match="exactly one positive"):
        objective_loss("weighted_ce", loss_fn, logits[:1], torch.tensor([[1.0, 1.0]]))
