import json
from pathlib import Path

import pytest

from carevul.models import EvidenceState
from carevul.mulvul import FileMulVulCandidateProvider
from carevul.pipeline import CareVulPipeline


requires_vultriage = pytest.mark.skipif(
    not (Path(__file__).resolve().parents[1] / "third_party" / "VulTriage").exists(),
    reason="requires an external VulTriage checkout",
)


COMMAND_INJECTION = r'''#include <stdlib.h>
void ping_host(const char *host) {
    char command[256];
    if (host == NULL) return;
    snprintf(command, sizeof(command), "ping -c 1 %s", host);
    system(command);
}
'''


def test_static_recovery_adds_command_injection_candidate():
    result = CareVulPipeline().prepare(COMMAND_INJECTION)
    cwes = [candidate["cwe"] for candidate in result["candidates"]]
    assert "CWE-78" in cwes
    command_flow = next(flow for flow in result["facts"]["flows"] if flow["sink"] == "system")
    assert command_flow["path"] == ["host", "snprintf", "system"]


def test_alignment_is_three_state_and_prompt_is_open_set():
    result = CareVulPipeline().prepare(COMMAND_INJECTION)
    cwe78 = next(item for item in result["alignments"] if item["cwe"] == "CWE-78")
    states = {condition["state"] for condition in cwe78["conditions"]}
    assert states <= {state.value for state in EvidenceState}
    assert "not a closed label set" in result["system_prompt"]
    assert "OUTSIDE_CANDIDATES" in result["user_prompt"]


def test_dry_run_does_not_require_api_key():
    result = CareVulPipeline(use_vultriage=False).analyze(COMMAND_INJECTION, model="unused", dry_run=True)
    assert "prediction" not in result
    assert result["selected_evidence"]


@requires_vultriage
def test_vultriage_control_path_is_used_when_available():
    result = CareVulPipeline().prepare(COMMAND_INJECTION)
    assert result["facts"]["metadata"]["provider"] == "vultriage"
    assert result["facts"]["metadata"]["analysis_mode"] == "precise_c"
    assert result["facts"]["metadata"]["preprocessor"] in {"gcc", "clang", "cpp", "pcpp"}
    assert result["facts"]["metadata"]["detail_level"] == "B"
    assert "【AST】" in result["facts"]["verbalized_context"]
    assert '"control_path_context"' in result["user_prompt"]
    assert "【AST】" in result["user_prompt"]
    assert "【CFG】" in result["user_prompt"]
    assert "【DFG】" in result["user_prompt"]
    assert result["facts"]["metadata"]["program_analysis_available"] is True
    assert result["facts"]["security_evidence"]
    assert '"program_analysis_evidence"' in result["user_prompt"]


@requires_vultriage
def test_precise_cfg_accepts_nested_and_single_statement_for_bodies():
    code = r'''void loops(int n) {
        int i, j;
        for (i = 0; i < n; i++)
            for (j = 0; j < n; j++)
                i = i + 1;
        for (i = 0; i < n; i++)
            j++;
    }'''
    result = CareVulPipeline().prepare(code)
    assert result["facts"]["metadata"]["analysis_mode"] == "precise_c"


@requires_vultriage
def test_precise_dfg_slices_single_statement_if_body():
    code = r'''void copy(char *src, int len) {
        char dst[8];
        if (len <= 8)
            memcpy(dst, src, len);
    }'''
    result = CareVulPipeline().prepare(code)
    function = result["facts"]["security_evidence"][0]
    security_slice = next(item for item in function["security_slices"] if item["sink"]["api"] == "memcpy")

    assert {source["label"] for source in security_slice["source_parameters"]} >= {"param: src", "param: len"}
    assert security_slice["limitations"] == []
    assert security_slice["guards"][0]["constraint"]["relevant"] is True


def test_mulvul_candidates_are_preserved_and_static_channel_recovers_a_miss(tmp_path):
    predictions = tmp_path / "mulvul.json"
    predictions.write_text(json.dumps({
        "candidates": [{"cwe": "CWE-416", "score": 0.95}]
    }), encoding="utf-8")
    provider = FileMulVulCandidateProvider(predictions)

    result = CareVulPipeline(mulvul_provider=provider).prepare(COMMAND_INJECTION)
    by_cwe = {candidate["cwe"]: candidate for candidate in result["candidates"]}

    assert result["mulvul_candidates"] == [{"cwe": "CWE-416", "score": 0.95}]
    assert by_cwe["CWE-416"]["components"]["mulvul"] == 0.95
    assert by_cwe["CWE-78"]["components"]["static"] == 0.85
    assert "static:system" in by_cwe["CWE-78"]["sources"]


def test_mulvul_jsonl_can_be_selected_by_sample_id(tmp_path):
    predictions = tmp_path / "mulvul.jsonl"
    predictions.write_text(
        json.dumps({"sample_id": "sample-7", "predicted_cwes": ["CWE_78"]}) + "\n",
        encoding="utf-8",
    )
    provider = FileMulVulCandidateProvider(predictions)
    result = CareVulPipeline(mulvul_provider=provider).prepare(COMMAND_INJECTION, sample_id="sample-7")
    assert result["mulvul_candidates"][0]["cwe"] == "CWE-78"

