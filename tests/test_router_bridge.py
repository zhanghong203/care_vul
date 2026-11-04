from __future__ import annotations

from carevul.analysis_planner import AnalysisPlanner
from carevul.pipeline import CareVulPipeline
from carevul.router import RouterPrediction


class FakeRouter:
    def __init__(self, predictions_by_code=None):
        self.predictions_by_code = predictions_by_code or {}
        self.calls = []

    def predict(self, code: str, top_k: int = 3):
        self.calls.append((code, top_k))
        return self.predictions_by_code.get(
            code,
            [
                RouterPrediction("memory", 0.9, 1),
                RouterPrediction("crypto", 0.4, 2),
            ],
        )[:top_k]


def test_router_families_map_directly_to_analysis_capabilities():
    plan = AnalysisPlanner().create_plan([], [
        {"family": "memory", "score": 0.9},
        {"family": "crypto", "score": 0.4},
    ])

    assert plan.families == frozenset({"bounds_numeric", "pointer_lifetime"})
    assert "bounds_property" in plan.analyzers
    assert "lifetime_events" in plan.analyzers
    assert "crypto_api_query" in plan.generic_queries
    assert dict(plan.coverage) == {"crypto": "GENERIC_ONLY", "memory": "SPECIALIZED"}
    assert any("hard-coded" in item for item in plan.knowledge_guidance)


def test_unknown_router_family_is_explicitly_unsupported():
    plan = AnalysisPlanner().create_plan([], [{"family": "future_family", "score": 1.0}])
    assert dict(plan.coverage) == {"future_family": "UNSUPPORTED"}
    assert plan.families == frozenset()


def test_pipeline_routes_online_predictions_into_planner_and_prompt():
    router = FakeRouter()
    code = "void f(char *p) { free(p); }"
    result = CareVulPipeline(router_provider=router, router_top_k=2).prepare(code)

    assert router.calls == [(code, 2)]
    assert result["router_predictions"][0]["family"] == "memory"
    plan = result["facts"]["metadata"]["analysis_plan"]
    assert plan["router_families"] == ["crypto", "memory"]
    assert plan["coverage"]["crypto"] == "GENERIC_ONLY"
    assert "pointer_lifetime" in plan["families"]
    assert '"router_predictions"' in result["user_prompt"]


def test_pair_pipeline_unions_router_predictions_without_label_information():
    code_a = "void a(char *p) { free(p); }"
    code_b = "void b(const char *cmd) { system(cmd); }"
    router = FakeRouter({
        code_a: [RouterPrediction("memory", 0.8, 1)],
        code_b: [RouterPrediction("injection", 0.9, 1)],
    })
    result = CareVulPipeline(router_provider=router, router_top_k=1).prepare_pair(code_a, code_b)

    assert {item["family"] for item in result["pair_router_predictions"]} == {"memory", "injection"}
    assert set(result["analysis_plan"]["families"]) >= {"bounds_numeric", "pointer_lifetime", "taint_injection"}
