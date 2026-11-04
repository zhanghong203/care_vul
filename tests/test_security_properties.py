from pathlib import Path

import pytest

from carevul.analysis_planner import AnalysisPlanner
from carevul.pipeline import CareVulPipeline


requires_vultriage = pytest.mark.skipif(
    not (Path(__file__).resolve().parents[1] / "third_party" / "VulTriage").exists(),
    reason="requires an external VulTriage checkout",
)


def _bounds_property(code: str):
    result = CareVulPipeline().prepare(code)
    evidence = result["facts"]["security_evidence"]
    security_slice = next(
        security_slice
        for function in evidence
        for security_slice in function["security_slices"]
        if security_slice["sink"]["api"] == "memcpy"
    )
    return result, security_slice, security_slice["security_properties"][0]


@requires_vultriage
def test_call_roles_capacity_and_effective_guard_are_extracted():
    code = r'''void copy(char *src, int len) {
        char dst[8];
        if (len <= sizeof(dst))
            memcpy(dst, src, len);
    }'''
    result, security_slice, security_property = _bounds_property(code)

    assert security_slice["sink"]["roles"] == {
        "destination": "dst", "source": "src", "size": "len"
    }
    assert security_property["destination_capacity"]["capacity"] == 8
    assert security_property["destination_capacity"]["unit"] == "bytes"
    assert security_property["state"] == "ESTABLISHED"
    assert security_property["guard_effectiveness"] == "EFFECTIVE"
    assert result["facts"]["metadata"]["analysis_plan"]["families"] == ["bounds_numeric"]


@requires_vultriage
def test_log_only_guard_is_not_treated_as_effective():
    code = r'''void copy(char *src, int len) {
        char dst[8];
        if (len > 8)
            puts("oversized");
        memcpy(dst, src, len);
    }'''
    _, security_slice, security_property = _bounds_property(code)

    assert security_property["state"] == "NOT_ESTABLISHED"
    assert security_property["guard_effectiveness"] == "INEFFECTIVE"
    assert security_slice["guards"][0]["controls_sink"] is False


@requires_vultriage
def test_early_return_inverts_path_constraint_and_proves_bound():
    code = r'''void copy(char *src, int len) {
        char dst[8];
        if (len > 8)
            return;
        memcpy(dst, src, len);
    }'''
    _, security_slice, security_property = _bounds_property(code)
    constraint = security_slice["guards"][0]["constraint"]

    assert security_slice["guards"][0]["branch_to_sink"] == "False"
    assert constraint["path_constraints"] == [{"left": "len", "operator": "<=", "right": "8"}]
    assert security_property["state"] == "ESTABLISHED"


def test_analysis_planner_unions_candidate_capabilities():
    plan = AnalysisPlanner().create_plan([{"cwe": "CWE-78"}, {"cwe": "CWE-416"}])

    assert plan.families == frozenset({"taint_injection", "pointer_lifetime"})
    assert "backward_slice" in plan.analyzers
    assert "lifetime_events" in plan.analyzers


@requires_vultriage
def test_pointer_lifetime_detects_repeated_release_of_same_expression():
    code = r'''void release_twice(void) {
        char *ptr = malloc(8);
        free(ptr);
        free(ptr);
    }'''
    result = CareVulPipeline().prepare(code)
    evidence = result["facts"]["security_evidence"]
    properties = [item for function in evidence for item in function["lifetime_properties"]]

    assert result["facts"]["metadata"]["analysis_plan"]["families"] == ["pointer_lifetime"]
    assert any(
        item["name"] == "object_released_more_than_once" and item["state"] == "ESTABLISHED"
        for item in properties
    )


@requires_vultriage
def test_pointer_lifetime_does_not_merge_mutually_exclusive_releases():
    code = r'''void release_on_one_branch(char *ptr, int flag) {
        if (flag)
            free(ptr);
        else
            free(ptr);
    }'''
    result = CareVulPipeline().prepare(code)
    properties = [
        item
        for function in result["facts"]["security_evidence"]
        for item in function["lifetime_properties"]
    ]

    assert not any(item["name"] == "object_released_more_than_once" for item in properties)


@requires_vultriage
def test_pair_semantic_features_tolerate_local_variable_renaming():
    code_a = r'''void a(char *src, int len) {
        char dst[8];
        if (len <= 8) memcpy(dst, src, len);
    }'''
    code_b = r'''void b(char *input, int size) {
        char buffer[8];
        if (size <= 8) memcpy(buffer, input, size);
    }'''
    comparison = CareVulPipeline().prepare_pair(code_a, code_b)["pairwise_security_comparison"]

    assert comparison["only_in_a"] == []
    assert comparison["only_in_b"] == []
    assert any(
        item["feature"] == "security_property" and item["state"] == "ESTABLISHED"
        for item in comparison["shared"]
    )
