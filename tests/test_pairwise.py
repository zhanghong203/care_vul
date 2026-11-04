from pathlib import Path

import pytest

from carevul.pairwise import compare_security_evidence, swap_comparison
from carevul.pipeline import CareVulPipeline
from carevul.retrieval import KnowledgeItem, LocalKnowledgeBase


requires_vultriage = pytest.mark.skipif(
    not (Path(__file__).resolve().parents[1] / "third_party" / "VulTriage").exists(),
    reason="requires an external VulTriage checkout",
)


UNGUARDED = r'''void copy(char *src, int len) {
    char dst[8];
    memcpy(dst, src, len);
}'''

GUARDED = r'''void copy(char *src, int len) {
    char dst[8];
    if (len <= 8)
        memcpy(dst, src, len);
}'''


def _evidence(with_guard: bool):
    guards = []
    if with_guard:
        guards.append({
            "node_id": "unstable-node-id",
            "expression": "if (len <= 8)",
            "line": 99,
            "dominates_sink": True,
            "controls_sink": True,
            "constraint": {"relevant": True},
        })
    return [{
        "function": "copy",
        "sensitive_operations": [{
            "node_id": "another-unstable-id",
            "api": "memcpy",
            "family": "bounds_numeric",
            "kind": "memory_write",
            "line": 100,
        }],
        "security_slices": [{
            "sink": {"api": "memcpy", "family": "bounds_numeric"},
            "source_parameters": [{"label": "param: len", "line": 1}],
            "backward_slice": {"variables": ["len"]},
            "guards": guards,
        }],
        "lifetime_events": [],
    }]


def test_pair_comparison_is_verdict_free_and_swap_symmetric():
    left, right = _evidence(False), _evidence(True)
    forward = compare_security_evidence(left, right)
    backward = compare_security_evidence(right, left)

    assert forward["verdict_free"] is True
    assert backward == swap_comparison(forward)
    assert not forward["only_in_a"]
    assert any(feature["feature"] == "guard_for_sink" for feature in forward["only_in_b"])
    serialized = str(forward)
    assert "unstable-node-id" not in serialized
    assert "line" not in serialized


@requires_vultriage
def test_prepare_pair_uses_predicted_union_and_is_order_invariant():
    pipeline = CareVulPipeline()
    forward = pipeline.prepare_pair(UNGUARDED, GUARDED)
    backward = pipeline.prepare_pair(GUARDED, UNGUARDED)

    assert forward["pair_contract"]["ground_truth_used_for_routing"] is False
    assert forward["pair_contract"]["assumes_exactly_one_vulnerable"] is False
    assert forward["pair_candidates"] == backward["pair_candidates"]
    assert backward["pairwise_security_comparison"] == swap_comparison(
        forward["pairwise_security_comparison"]
    )
    assert "vulnerable_version" not in forward["user_prompt"]
    assert "fixed_version" not in forward["user_prompt"]
    assert '"valid_binary_label_combinations"' in forward["user_prompt"]
    assert any(
        feature["feature"] == "guard_for_sink"
        for feature in forward["pairwise_security_comparison"]["only_in_b"]
    )


def test_pair_excludes_exact_pair_from_retrieved_security_deltas():
    knowledge = LocalKnowledgeBase([KnowledgeItem(
        item_id="same-pair",
        code=UNGUARDED,
        cwe="CWE-787",
        label=1,
        fixed_code=GUARDED,
    )])
    result = CareVulPipeline(knowledge_base=knowledge).prepare_pair(UNGUARDED, GUARDED)

    assert result["code_a"]["retrieved_security_deltas"] == []
    assert result["code_b"]["retrieved_security_deltas"] == []


def test_pair_dry_run_does_not_require_api_key():
    result = CareVulPipeline().analyze_pair(UNGUARDED, GUARDED, model="unused", dry_run=True)
    assert "prediction" not in result
    assert result["pairwise_security_comparison"]["verdict_free"] is True
