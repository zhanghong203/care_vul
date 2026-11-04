from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analysis_inspector import inspect_analysis
from .control import ControlPathAdapter
from .evidence_schema import AVAILABLE_ANALYSIS_METHODS
from .pipeline import CareVulPipeline
from .retrieval import LocalKnowledgeBase
from .mulvul import FileMulVulCandidateProvider


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="CARE-Vul one-shot vulnerability detection")
    sub = result.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze")
    analyze.add_argument("code_file")
    analyze.add_argument("--knowledge-base")
    analyze.add_argument("--mulvul-candidates", help="Offline MulVul predictions in JSON or JSONL format")
    analyze.add_argument("--sample-id", help="Record key when --mulvul-candidates is a dataset file")
    analyze.add_argument("--control-cache")
    analyze.add_argument("--vultriage-root", default="third_party/VulTriage")
    analyze.add_argument("--control-detail", choices=["A", "B", "C"], default="B")
    analyze.add_argument("--no-vultriage", action="store_true", help="Use the built-in smoke-test extractor")
    analyze.add_argument("--model", default="gpt-4o-mini")
    analyze.add_argument("--base-url")
    analyze.add_argument("--token-budget", type=int, default=1200)
    analyze.add_argument("--dry-run", action="store_true")
    analyze.add_argument("--output")
    analyze.add_argument("--router-checkpoint", help="Trained CodeBERT Router checkpoint directory")
    analyze.add_argument("--router-label-index", default="data/router/family_label_index.json")
    analyze.add_argument("--router-top-k", type=int, default=3)
    analyze.add_argument("--router-max-length", type=int, default=512)
    analyze.add_argument("--router-device", choices=["auto", "cpu", "cuda"], default="auto")
    pair = sub.add_parser("analyze-pair", help="Analyze an unordered pair without assuming one-positive/one-negative labels")
    pair.add_argument("code_file_a")
    pair.add_argument("code_file_b")
    pair.add_argument("--knowledge-base")
    pair.add_argument("--mulvul-candidates", help="Offline MulVul predictions in JSON or JSONL format")
    pair.add_argument("--sample-id-a")
    pair.add_argument("--sample-id-b")
    pair.add_argument("--control-cache")
    pair.add_argument("--vultriage-root", default="third_party/VulTriage")
    pair.add_argument("--control-detail", choices=["A", "B", "C"], default="B")
    pair.add_argument("--no-vultriage", action="store_true")
    pair.add_argument("--model", default="gpt-4o-mini")
    pair.add_argument("--base-url")
    pair.add_argument("--token-budget", type=int, default=1200)
    pair.add_argument("--dry-run", action="store_true")
    pair.add_argument("--output")
    pair.add_argument("--router-checkpoint", help="Trained CodeBERT Router checkpoint directory")
    pair.add_argument("--router-label-index", default="data/router/family_label_index.json")
    pair.add_argument("--router-top-k", type=int, default=3)
    pair.add_argument("--router-max-length", type=int, default=512)
    pair.add_argument("--router-device", choices=["auto", "cpu", "cuda"], default="auto")
    inspect = sub.add_parser("inspect-analysis", help="Run one program-analysis method and print its evidence")
    inspect.add_argument("code_file")
    inspect.add_argument("--method", required=True, choices=AVAILABLE_ANALYSIS_METHODS)
    inspect.add_argument("--vultriage-root", default="third_party/VulTriage")
    inspect.add_argument("--control-detail", choices=["A", "B", "C"], default="C")
    inspect.add_argument("--no-vultriage", action="store_true")
    inspect.add_argument("--output")
    return result


def main() -> None:
    args = parser().parse_args()
    if args.command == "inspect-analysis":
        code = Path(args.code_file).read_text(encoding="utf-8")
        adapter = ControlPathAdapter(
            vultriage_root=args.vultriage_root,
            detail_level=args.control_detail,
            use_vultriage=not args.no_vultriage,
        )
        result = inspect_analysis(code, args.method, adapter)
        rendered = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        else:
            print(rendered)
        return
    kb = LocalKnowledgeBase.from_jsonl(args.knowledge_base)
    mulvul_provider = FileMulVulCandidateProvider(args.mulvul_candidates) if args.mulvul_candidates else None
    router_provider = None
    if args.router_checkpoint:
        from .router import RouterPredictor

        router_provider = RouterPredictor(
            args.router_checkpoint,
            args.router_label_index,
            args.router_device,
            args.router_max_length,
        )
    pipeline = CareVulPipeline(
        knowledge_base=kb,
        control_cache=args.control_cache,
        token_budget=args.token_budget,
        vultriage_root=args.vultriage_root,
        control_detail=args.control_detail,
        use_vultriage=not args.no_vultriage,
        mulvul_provider=mulvul_provider,
        router_provider=router_provider,
        router_top_k=args.router_top_k,
    )
    if args.command == "analyze-pair":
        code_a = Path(args.code_file_a).read_text(encoding="utf-8")
        code_b = Path(args.code_file_b).read_text(encoding="utf-8")
        result = pipeline.analyze_pair(
            code_a,
            code_b,
            args.model,
            args.dry_run,
            args.base_url,
            args.sample_id_a,
            args.sample_id_b,
        )
    else:
        code = Path(args.code_file).read_text(encoding="utf-8")
        result = pipeline.analyze(code, args.model, args.dry_run, args.base_url, args.sample_id)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()

