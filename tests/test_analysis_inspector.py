from __future__ import annotations

import json
from pathlib import Path

from carevul.analysis_inspector import inspect_analysis
from carevul.control import ControlPathAdapter
from carevul.evidence_schema import AVAILABLE_ANALYSIS_METHODS, normalize_program_evidence


ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "examples" / "analysis_cases"
REQUIRED_FIELDS = {
    "evidence_id",
    "schema_version",
    "analysis_method",
    "candidate_family",
    "function",
    "analysis_mode",
    "state",
    "hypothesis",
    "subject",
    "supporting_evidence",
    "counter_evidence",
    "unknowns",
    "limitations",
    "confidence",
    "raw_facts",
}


def test_every_analysis_method_has_a_runnable_case():
    manifest = json.loads((CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert {item["method"] for item in manifest} == set(AVAILABLE_ANALYSIS_METHODS)
    assert all((CASE_DIR / item["file"]).is_file() for item in manifest)


def test_normalized_evidence_uses_one_fixed_envelope():
    raw = [{
        "function": "f",
        "analysis_mode": "precise_c",
        "sensitive_operations": [{
            "api": "memcpy",
            "line": 3,
            "kind": "memory_write",
            "family": "bounds_numeric",
            "arguments": ["dst", "src", "len"],
            "roles": {"destination": "dst", "source": "src", "length": "len"},
        }],
        "security_slices": [],
        "control_dependencies": [],
        "buffer_capacities": [],
        "lifetime_events": [],
        "lifetime_properties": [],
        "limitations": [],
    }]
    result = normalize_program_evidence(raw)
    assert result
    assert all(REQUIRED_FIELDS == set(item) for item in result)


def test_inspector_returns_requested_method_even_when_no_fact_exists():
    adapter = ControlPathAdapter(use_vultriage=False)
    result = inspect_analysis("int f(void) { return 0; }", "path_order", adapter)
    assert result["requested_method"] == "path_order"
    assert result["normalized_evidence"][0]["analysis_method"] == "path_order"
    assert result["normalized_evidence"][0]["state"] == "UNKNOWN"
