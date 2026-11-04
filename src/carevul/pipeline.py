from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Any

from .alignment import EvidenceAligner
from .analysis_planner import AnalysisPlanner
from .candidates import CorrectiveCandidateGenerator
from .control import ControlPathAdapter
from .evidence import EvidenceSelector
from .evidence_schema import normalize_program_evidence
from .models import Candidate
from .pairwise import compare_security_evidence
from .prompting import PAIR_SYSTEM_PROMPT, SYSTEM_PROMPT, build_pair_prompt, build_prompt
from .retrieval import LocalKnowledgeBase, cosine_bow
from .mulvul import MulVulCandidateProvider
from .templates import TEMPLATES


class CareVulPipeline:
    def __init__(
        self,
        knowledge_base: LocalKnowledgeBase | None = None,
        control_cache: str | None = None,
        token_budget: int = 1200,
        vultriage_root: str | None = None,
        control_detail: str = "B",
        use_vultriage: bool = True,
        mulvul_provider: MulVulCandidateProvider | None = None,
        router_provider: Any | None = None,
        router_top_k: int = 3,
    ):
        self.knowledge_base = knowledge_base or LocalKnowledgeBase()
        self.control = ControlPathAdapter(control_cache, vultriage_root, control_detail, use_vultriage)
        self.candidates = CorrectiveCandidateGenerator()
        self.aligner = EvidenceAligner()
        self.planner = AnalysisPlanner()
        self.selector = EvidenceSelector(token_budget)
        self.mulvul_provider = mulvul_provider
        self.router_provider = router_provider
        self.router_top_k = router_top_k

    @staticmethod
    def _router_payload(predictions: list[Any]) -> list[dict[str, Any]]:
        output = []
        for prediction in predictions:
            if hasattr(prediction, "to_dict"):
                output.append(prediction.to_dict())
            elif isinstance(prediction, dict):
                output.append(dict(prediction))
            else:
                output.append({
                    "family": str(prediction.family),
                    "score": float(prediction.score),
                    "rank": int(getattr(prediction, "rank", len(output) + 1)),
                })
        return output

    def _predict_router(self, code: str) -> list[dict[str, Any]]:
        if self.router_provider is None:
            return []
        return self._router_payload(self.router_provider.predict(code, top_k=self.router_top_k))

    def prepare(self, code: str, sample_id: str | None = None) -> dict[str, Any]:
        facts = self.control.extract(code, analysis_families=set())
        router_predictions = self._predict_router(code)
        retrieved = self.knowledge_base.search(code, limit=20)
        mulvul_candidates = self.mulvul_provider.predict(code, sample_id) if self.mulvul_provider else []
        candidates = self.candidates.generate(facts, retrieved, mulvul_candidates)
        plan = self.planner.create_plan(candidates, router_predictions)
        facts.security_evidence = self.control.run_program_analysis(code, set(plan.families))
        facts.normalized_security_evidence = normalize_program_evidence(facts.security_evidence)
        facts.metadata["analysis_plan"] = plan.to_dict()
        facts.metadata["program_analysis_available"] = bool(facts.security_evidence)
        alignments = [self.aligner.align(TEMPLATES[c.cwe], facts) for c in candidates if c.cwe in TEMPLATES]
        alignments.sort(key=lambda item: item.score, reverse=True)
        selected = self.selector.select(alignments)
        deltas = self._security_deltas(code, retrieved, {candidate.cwe for candidate in candidates})
        candidate_payload = [asdict(candidate) for candidate in candidates]
        alignment_payload = [asdict(alignment) for alignment in alignments]
        prompt = build_prompt(
            code,
            candidate_payload,
            alignment_payload,
            selected,
            deltas,
            control_path=facts.verbalized_context,
            extraction_metadata=facts.metadata,
            program_analysis=facts.normalized_security_evidence,
            router_predictions=router_predictions,
        )
        return {
            "facts": facts.to_dict(),
            "mulvul_candidates": [asdict(candidate) for candidate in mulvul_candidates],
            "router_predictions": router_predictions,
            "candidates": candidate_payload,
            "alignments": alignment_payload,
            "selected_evidence": selected,
            "security_deltas": deltas,
            "system_prompt": SYSTEM_PROMPT,
            "user_prompt": prompt,
        }

    @staticmethod
    def _merge_pair_candidates(left: list[Candidate], right: list[Candidate]) -> list[Candidate]:
        """Create an order-independent union without consulting ground-truth labels."""
        merged: dict[str, Candidate] = {}
        for candidate in [*left, *right]:
            current = merged.get(candidate.cwe)
            if current is None:
                merged[candidate.cwe] = Candidate(
                    candidate.cwe,
                    candidate.score,
                    list(candidate.sources),
                    dict(candidate.components),
                )
                continue
            current.score = max(current.score, candidate.score)
            current.sources = sorted(set(current.sources) | set(candidate.sources))
            for name, value in candidate.components.items():
                current.components[name] = max(current.components.get(name, 0.0), value)
        return sorted(merged.values(), key=lambda candidate: (-candidate.score, candidate.cwe))

    def prepare_pair(
        self,
        code_a: str,
        code_b: str,
        sample_id_a: str | None = None,
        sample_id_b: str | None = None,
    ) -> dict[str, Any]:
        """Prepare a symmetric pair without assuming either side's security label."""
        facts_a = self.control.extract(code_a, analysis_families=set())
        facts_b = self.control.extract(code_b, analysis_families=set())
        router_a = self._predict_router(code_a)
        router_b = self._predict_router(code_b)
        retrieved_a = self.knowledge_base.search(code_a, limit=20)
        retrieved_b = self.knowledge_base.search(code_b, limit=20)
        mulvul_a = self.mulvul_provider.predict(code_a, sample_id_a) if self.mulvul_provider else []
        mulvul_b = self.mulvul_provider.predict(code_b, sample_id_b) if self.mulvul_provider else []
        candidates_a = self.candidates.generate(facts_a, retrieved_a, mulvul_a)
        candidates_b = self.candidates.generate(facts_b, retrieved_b, mulvul_b)
        pair_candidates = self._merge_pair_candidates(candidates_a, candidates_b)
        merged_router: dict[str, dict[str, Any]] = {}
        for prediction in [*router_a, *router_b]:
            family = str(prediction.get("family", ""))
            if not family:
                continue
            current = merged_router.get(family)
            if current is None or float(prediction.get("score", 0.0)) > float(current.get("score", 0.0)):
                merged_router[family] = prediction
        pair_router_predictions = sorted(
            merged_router.values(), key=lambda item: (-float(item.get("score", 0.0)), str(item.get("family", "")))
        )
        plan = self.planner.create_plan(pair_candidates, pair_router_predictions)
        shared_families = set(plan.families)
        facts_a.security_evidence = self.control.run_program_analysis(code_a, shared_families)
        facts_b.security_evidence = self.control.run_program_analysis(code_b, shared_families)
        facts_a.normalized_security_evidence = normalize_program_evidence(facts_a.security_evidence)
        facts_b.normalized_security_evidence = normalize_program_evidence(facts_b.security_evidence)
        facts_a.metadata["analysis_plan"] = plan.to_dict()
        facts_b.metadata["analysis_plan"] = plan.to_dict()
        facts_a.metadata["program_analysis_available"] = bool(facts_a.security_evidence)
        facts_b.metadata["program_analysis_available"] = bool(facts_b.security_evidence)

        alignments_a = [
            self.aligner.align(TEMPLATES[candidate.cwe], facts_a)
            for candidate in pair_candidates if candidate.cwe in TEMPLATES
        ]
        alignments_b = [
            self.aligner.align(TEMPLATES[candidate.cwe], facts_b)
            for candidate in pair_candidates if candidate.cwe in TEMPLATES
        ]
        alignments_a.sort(key=lambda item: item.score, reverse=True)
        alignments_b.sort(key=lambda item: item.score, reverse=True)
        selected_a = self.selector.select(alignments_a)
        selected_b = self.selector.select(alignments_b)
        candidate_payload = [asdict(candidate) for candidate in pair_candidates]
        excluded_codes = {code_a.strip(), code_b.strip()}
        deltas_a = self._security_deltas(
            code_a, retrieved_a, {candidate.cwe for candidate in pair_candidates}, excluded_codes
        )
        deltas_b = self._security_deltas(
            code_b, retrieved_b, {candidate.cwe for candidate in pair_candidates}, excluded_codes
        )
        comparison = compare_security_evidence(facts_a.security_evidence, facts_b.security_evidence)

        side_a = {
            "router_predictions": router_a,
            "control_path_context": facts_a.verbalized_context,
            "extraction_metadata": facts_a.metadata,
            "program_analysis_evidence": facts_a.normalized_security_evidence,
            "alignment_summary": [asdict(item) for item in alignments_a],
            "selected_evidence": selected_a,
            "retrieved_security_deltas": deltas_a,
        }
        side_b = {
            "router_predictions": router_b,
            "control_path_context": facts_b.verbalized_context,
            "extraction_metadata": facts_b.metadata,
            "program_analysis_evidence": facts_b.normalized_security_evidence,
            "alignment_summary": [asdict(item) for item in alignments_b],
            "selected_evidence": selected_b,
            "retrieved_security_deltas": deltas_b,
        }
        prompt = build_pair_prompt(code_a, code_b, candidate_payload, side_a, side_b, comparison)
        return {
            "pair_contract": {
                "orientation": "unordered_code_a_code_b",
                "candidate_source": "predicted_union",
                "ground_truth_used_for_routing": False,
                "assumes_exactly_one_vulnerable": False,
            },
            "code_a": {
                "facts": facts_a.to_dict(),
                "mulvul_candidates": [asdict(candidate) for candidate in mulvul_a],
                "independent_candidates": [asdict(candidate) for candidate in candidates_a],
                **side_a,
            },
            "code_b": {
                "facts": facts_b.to_dict(),
                "mulvul_candidates": [asdict(candidate) for candidate in mulvul_b],
                "independent_candidates": [asdict(candidate) for candidate in candidates_b],
                **side_b,
            },
            "pair_candidates": candidate_payload,
            "analysis_plan": plan.to_dict(),
            "pair_router_predictions": pair_router_predictions,
            "pairwise_security_comparison": comparison,
            "system_prompt": PAIR_SYSTEM_PROMPT,
            "user_prompt": prompt,
        }

    @staticmethod
    def _security_deltas(
        code: str,
        retrieved: list,
        candidate_cwes: set[str],
        excluded_codes: set[str] | None = None,
    ) -> list[dict]:
        output = []
        excluded_codes = excluded_codes or set()
        for item, similarity in retrieved:
            if item.cwe not in candidate_cwes or not item.fixed_code:
                continue
            if item.code.strip() in excluded_codes or item.fixed_code.strip() in excluded_codes:
                continue
            output.append({
                "source_id": item.item_id,
                "cwe": item.cwe,
                "similarity": round(similarity, 6),
                "vulnerable_similarity": round(cosine_bow(code, item.code), 6),
                "fixed_similarity": round(cosine_bow(code, item.fixed_code), 6),
                "note": "Compare the target with this vulnerable/fixed pair; similarity is not proof.",
            })
            if len(output) == 2:
                break
        return output

    def analyze(self, code: str, model: str, dry_run: bool = False, base_url: str | None = None, sample_id: str | None = None) -> dict[str, Any]:
        prepared = self.prepare(code, sample_id)
        if dry_run:
            return prepared
        from openai import OpenAI

        client = OpenAI(api_key=os.environ["OPENAI_API_KEY"], base_url=base_url)
        response = client.chat.completions.create(
            model=model,
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": prepared["system_prompt"]},
                {"role": "user", "content": prepared["user_prompt"]},
            ],
        )
        content = response.choices[0].message.content or "{}"
        prepared["prediction"] = json.loads(content)
        return prepared

    def analyze_pair(
        self,
        code_a: str,
        code_b: str,
        model: str,
        dry_run: bool = False,
        base_url: str | None = None,
        sample_id_a: str | None = None,
        sample_id_b: str | None = None,
    ) -> dict[str, Any]:
        prepared = self.prepare_pair(code_a, code_b, sample_id_a, sample_id_b)
        if dry_run:
            return prepared
        from openai import OpenAI

        client = OpenAI(api_key=os.environ["OPENAI_API_KEY"], base_url=base_url)
        response = client.chat.completions.create(
            model=model,
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": prepared["system_prompt"]},
                {"role": "user", "content": prepared["user_prompt"]},
            ],
        )
        content = response.choices[0].message.content or "{}"
        prepared["prediction"] = json.loads(content)
        return prepared

