from __future__ import annotations

import hashlib
import importlib
import json
import re
import sys
from pathlib import Path

from .models import ProgramFacts
from .program_analysis import ProgramAnalyzer


CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*;")
PARAM_RE = re.compile(r"\w[\w\s\*]*\b([A-Za-z_]\w*)\s*\([^)]*\b([A-Za-z_]\w*)\s*\)")
BUFFER_RE = re.compile(r"\b(?:char|unsigned\s+char)\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]")
IF_RE = re.compile(r"\bif\s*\((.*?)\)", re.DOTALL)


class ControlPathAdapter:
    """Reads cached VulTriage facts, with a small C/C++ fallback for smoke tests."""

    def __init__(
        self,
        cache_path: str | Path | None = None,
        vultriage_root: str | Path | None = None,
        detail_level: str = "B",
        use_vultriage: bool = True,
    ):
        self.cache_path = Path(cache_path) if cache_path else None
        default_root = Path(__file__).resolve().parents[2] / "third_party" / "VulTriage"
        self.vultriage_root = Path(vultriage_root) if vultriage_root else default_root
        self.detail_level = detail_level.upper()
        self.use_vultriage = use_vultriage
        self._cache: dict[str, dict] = {}
        self._analysis_graph_cache: dict[str, dict] = {}
        if self.cache_path and self.cache_path.exists():
            self._cache = json.loads(self.cache_path.read_text(encoding="utf-8"))

    @staticmethod
    def code_hash(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    def extract(self, code: str, analysis_families: set[str] | None = None) -> ProgramFacts:
        cached = self._cache.get(self.code_hash(code))
        if cached is not None:
            facts = ProgramFacts.from_dict(cached)
            facts.metadata.setdefault("provider", "cache")
            return facts
        if self.use_vultriage and self.vultriage_root.exists():
            return self._extract_vultriage(code, analysis_families)
        return self._heuristic_extract(code)

    def _extract_vultriage(self, code: str, analysis_families: set[str] | None = None) -> ProgramFacts:
        root = self.vultriage_root.resolve()
        module_dir = root / "control_flow" / "control_flow"
        for entry in (str(module_dir), str(root)):
            if entry not in sys.path:
                sys.path.insert(0, entry)
        module = importlib.import_module("control_flow.control_flow.vuln_flow_analyzer")
        result = module.analyze_code_str(code, detail_level=self.detail_level, source_name="code.c")
        level_result = result["results"][self.detail_level]
        graph = level_result["graph_out"]
        baseline = self._heuristic_extract(code)

        ast = graph.get("filtered_ast", {})
        cfg = graph.get("filtered_cfg", {})
        dfg = graph.get("filtered_dfg", {})
        raw_cfg = graph.get("analysis_cfg", {})
        raw_dfg = graph.get("analysis_dfg", {})
        raw_ast = graph.get("analysis_ast", {})
        self._analysis_graph_cache[self.code_hash(code)] = {
            "cfg": raw_cfg,
            "dfg": raw_dfg,
            "ast": raw_ast,
            "mode": result.get("mode", "unknown"),
        }
        security_evidence = ProgramAnalyzer().analyze(
            raw_cfg,
            raw_dfg,
            result.get("mode", "unknown"),
            ast_graph=raw_ast,
            families=analysis_families,
        )
        ast_facts: list[dict] = []
        cfg_facts: list[dict] = []
        dfg_facts: list[dict] = []
        operations: list[str] = []
        guards: list[dict] = []

        for function in ast.get("functions", []):
            ast_facts.append({"kind": "function_summary", **function})
            operations.extend(function.get("calls_uniq", function.get("calls", [])))
            for condition in function.get("conditions", []):
                guard = {"expression": condition, "kind": self._guard_kind(condition), "line": function.get("line", -1)}
                guards.append(guard)

        for function, info in cfg.items():
            for branch in info.get("branches", []):
                cfg_facts.append({"kind": "branch", "function": function, **branch})
            for path in info.get("paths", []):
                cfg_facts.append({"kind": "path", "function": function, "path": path})

        for function, info in dfg.items():
            labels = info.get("node_labels", {})
            for edge in info.get("edges", []):
                dfg_facts.append({"kind": "edge", "function": function, **edge})
            for chain in info.get("chains", []):
                rendered = [labels.get(node, node) for node in chain]
                dfg_facts.append({"kind": "chain", "function": function, "path": rendered})

        # The shipped VulTriage analyzer can fall back to heuristic_c and expose no
        # DFG edges. Preserve that fact and use explicitly low-trust lexical flows
        # only so the rest of the pipeline remains executable.
        facts = ProgramFacts(
            ast_facts=ast_facts or baseline.ast_facts,
            cfg_facts=cfg_facts or baseline.cfg_facts,
            dfg_facts=dfg_facts or baseline.dfg_facts,
            sources=baseline.sources,
            sinks=baseline.sinks,
            flows=baseline.flows if not dfg_facts else self._flows_from_dfg(dfg_facts, baseline.flows),
            guards=guards or baseline.guards,
            security_evidence=security_evidence,
            operations=list(dict.fromkeys(operations or baseline.operations)),
            metadata={
                "provider": "vultriage",
                "analysis_mode": result.get("mode"),
                "preprocessor": result.get("preprocessor"),
                "language": result.get("language"),
                "detail_level": self.detail_level,
                "lexical_flow_fallback": not bool(dfg_facts),
                "lexical_flow_augmentation": bool(dfg_facts and baseline.flows),
                "program_analysis_available": bool(security_evidence),
            },
            verbalized_context=level_result.get("prompt_text", ""),
        )
        return facts

    def run_program_analysis(self, code: str, families: set[str]) -> list[dict]:
        cached = self._analysis_graph_cache.get(self.code_hash(code))
        if not cached:
            return []
        return ProgramAnalyzer().analyze(
            cached["cfg"],
            cached["dfg"],
            cached["mode"],
            ast_graph=cached["ast"],
            families=families,
        )

    @staticmethod
    def _guard_kind(expression: str) -> str:
        lowered = expression.lower()
        if "null" in lowered or "nullptr" in lowered:
            return "null_check"
        if any(token in lowered for token in ("sizeof", "length", "len", "size", "<", ">")):
            return "bounds_check"
        return "condition"

    @staticmethod
    def _flows_from_dfg(dfg_facts: list[dict], fallback: list[dict]) -> list[dict]:
        flows: list[dict] = []
        for fact in dfg_facts:
            if fact.get("kind") != "chain" or not fact.get("path"):
                continue
            path = []
            for node in fact["path"]:
                # VulTriage renders semantic labels such as ``param: host`` and
                # ``call system``. Normalize them for CWE templates while
                # retaining the original graph in dfg_facts.
                normalized = re.sub(r"^(?:param:\s*|call\s+|decl\s+)", "", str(node)).strip()
                path.append(normalized or str(node))
            flows.append({"source": path[0], "sink": path[-1], "path": path, "trust": 0.9})

        # The precise VulTriage DFG currently models argument-use edges but may
        # stop at a buffer-writing call (for example host -> snprintf) instead
        # of connecting the written buffer to a later sink (system(command)).
        # Keep those precise chains and add only missing source/sink pairs from
        # the explicitly low-trust lexical reconstruction.
        covered = {(flow["source"], flow["sink"]) for flow in flows}
        for candidate in fallback:
            key = (candidate.get("source"), candidate.get("sink"))
            if key not in covered:
                flows.append(candidate)
                covered.add(key)
        return flows

    @staticmethod
    def _heuristic_extract(code: str) -> ProgramFacts:
        facts = ProgramFacts()
        facts.metadata = {"provider": "builtin_fallback", "analysis_mode": "lexical", "lexical_flow_fallback": True}
        lines = code.splitlines()

        # Parameters are intentionally treated as source candidates, not proven untrusted inputs.
        header = code.split("{", 1)[0]
        if "(" in header and ")" in header:
            params_text = header.rsplit("(", 1)[1].split(")", 1)[0]
            for raw in params_text.split(","):
                names = re.findall(r"[A-Za-z_]\w*", raw)
                if names and raw.strip() != "void":
                    facts.sources.append({"name": names[-1], "kind": "parameter", "line": 1})

        for lineno, line in enumerate(lines, 1):
            for match in BUFFER_RE.finditer(line):
                facts.ast_facts.append({"kind": "fixed_buffer", "name": match.group(1), "size": int(match.group(2)), "line": lineno})
            for match in IF_RE.finditer(line):
                expression = match.group(1).strip()
                kind = "null_check" if "NULL" in expression or "nullptr" in expression else "condition"
                if any(token in expression for token in ("sizeof", "length", "len", "size", "<", ">")):
                    kind = "bounds_check"
                facts.guards.append({"expression": expression, "kind": kind, "line": lineno})
                facts.cfg_facts.append({"kind": "branch", "expression": expression, "line": lineno})
            for match in CALL_RE.finditer(line):
                name, args = match.group(1), match.group(2)
                facts.operations.append(name)
                call = {"kind": "call", "name": name, "arguments": args, "line": lineno}
                facts.ast_facts.append(call)
                if name in {"system", "popen", "execl", "execv", "ShellExecute", "CreateProcess"}:
                    facts.sinks.append({"name": name, "kind": "command", "argument": args, "line": lineno})
                elif name in {"strcpy", "strcat", "memcpy", "sprintf", "snprintf"}:
                    facts.sinks.append({"name": name, "kind": "memory_write", "argument": args, "line": lineno})

        # Conservative lexical flow approximation for smoke tests only.
        for source in facts.sources:
            source_name = source["name"]
            for sink in facts.sinks:
                if source_name in code and sink["argument"]:
                    preceding_calls = [
                        fact["name"]
                        for fact in facts.ast_facts
                        if fact.get("kind") == "call"
                        and fact.get("line", 0) <= sink.get("line", 0)
                        and fact.get("name") != sink["name"]
                    ]
                    intermediates = list(dict.fromkeys(preceding_calls))
                    path = [source_name, *intermediates, sink["name"]]
                    facts.flows.append({"source": source_name, "sink": sink["name"], "path": path, "trust": 0.45})
                    facts.dfg_facts.append({"kind": "candidate_flow", "source": source_name, "sink": sink["name"], "path": path})
        return facts

