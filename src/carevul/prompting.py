from __future__ import annotations

import json
from typing import Any


SYSTEM_PROMPT = """You are a software vulnerability analyst. Return only valid JSON. Candidate CWEs are suggestions, not a closed label set. Independently verify all supplied evidence against the source code. Do not infer that a security-sensitive API alone proves a vulnerability. Missing static evidence means UNKNOWN, not absence. You may return a CWE outside the candidate set, BENIGN, or UNKNOWN."""

PAIR_SYSTEM_PROMPT = """You are a software vulnerability analyst comparing two unordered code inputs. Return only valid JSON. Code-A and Code-B have no vulnerable/fixed, before/after, or label-implied ordering. Evaluate each code input independently before using their symmetric evidence comparison. All four binary outcomes (benign/benign, vulnerable/benign, benign/vulnerable, vulnerable/vulnerable) are valid. Candidate CWEs are predictions, not labels or a closed set. Missing evidence means UNKNOWN, not absence."""


def build_prompt(
    code: str,
    candidates: list[dict],
    alignments: list[dict],
    evidence: list[dict],
    deltas: list[dict],
    control_path: str = "",
    extraction_metadata: dict | None = None,
    program_analysis: list[dict] | None = None,
    router_predictions: list[dict] | None = None,
) -> str:
    payload = {
        "source_code": code,
        "control_path_context": control_path,
        "extraction_metadata": extraction_metadata or {},
        "program_analysis_evidence": program_analysis or [],
        "router_predictions": router_predictions or [],
        "candidate_cwes": candidates,
        "alignment_summary": alignments,
        "selected_evidence": evidence,
        "retrieved_security_deltas": deltas,
    }
    return f"""Analyze the following evidence package.

Rules:
1. Verify sources, sinks, data/control-flow relationships, and guards.
2. Evaluate both supporting and contradicting evidence.
3. Reject candidate CWEs whose necessary conditions are contradicted.
4. A retrieved example is a reference, not proof.
5. If a candidate-external CWE better explains the code, output it and set candidate_status to OUTSIDE_CANDIDATES.
6. If evidence is insufficient, return UNKNOWN rather than inventing facts.

Evidence package:
{json.dumps(payload, ensure_ascii=False, indent=2)}

Return exactly this JSON shape:
{{
  "is_vulnerable": true | false | null,
  "cwe": "CWE-NNN" | null,
  "candidate_status": "IN_CANDIDATES" | "OUTSIDE_CANDIDATES" | "BENIGN" | "UNKNOWN",
  "vulnerable_locations": [{{"line": 0, "statement": ""}}],
  "satisfied_conditions": [{{"condition": "", "evidence": ""}}],
  "counter_evidence": [{{"evidence": "", "effect": ""}}],
  "rejected_candidates": [{{"cwe": "CWE-NNN", "reason": ""}}],
  "confidence": 0.0,
  "reasoning": ""
}}"""


def build_pair_prompt(
    code_a: str,
    code_b: str,
    pair_candidates: list[dict],
    side_a: dict[str, Any],
    side_b: dict[str, Any],
    comparison: dict[str, Any],
) -> str:
    payload = {
        "pair_contract": {
            "orientation": "unordered_code_a_code_b",
            "ground_truth_used_for_routing": False,
            "assumes_exactly_one_vulnerable": False,
            "valid_binary_label_combinations": [[False, False], [True, False], [False, True], [True, True]],
        },
        "pair_candidate_cwes": pair_candidates,
        "code_a": {"source_code": code_a, **side_a},
        "code_b": {"source_code": code_b, **side_b},
        "symmetric_security_evidence_comparison": comparison,
    }
    return f"""Analyze the following unordered pair evidence package.

Rules:
1. First determine Code-A and Code-B independently; do not assume that exactly one is vulnerable.
2. The pair candidates are the union of predictions from both sides, not ground-truth labels.
3. The comparison is verdict-free: only_in_a and only_in_b report structural evidence differences, not fixes or vulnerabilities.
4. Verify every source, sink, flow, guard, and constraint against the corresponding source code.
5. A guard is not necessarily effective unless its control relationship and constraint support that conclusion.
6. A retrieved example is reference knowledge, never proof about either side.
7. Return UNKNOWN for a side when evidence is insufficient.

Evidence package:
{json.dumps(payload, ensure_ascii=False, indent=2)}

Return exactly this JSON shape:
{{
  "code_a": {{
    "is_vulnerable": true | false | null,
    "cwe": "CWE-NNN" | null,
    "candidate_status": "IN_CANDIDATES" | "OUTSIDE_CANDIDATES" | "BENIGN" | "UNKNOWN",
    "evidence": [{{"fact": "", "effect": ""}}],
    "confidence": 0.0
  }},
  "code_b": {{
    "is_vulnerable": true | false | null,
    "cwe": "CWE-NNN" | null,
    "candidate_status": "IN_CANDIDATES" | "OUTSIDE_CANDIDATES" | "BENIGN" | "UNKNOWN",
    "evidence": [{{"fact": "", "effect": ""}}],
    "confidence": 0.0
  }},
  "comparison_used": [{{"feature": "", "interpretation": ""}}],
  "reasoning": ""
}}"""

