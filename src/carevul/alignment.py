from __future__ import annotations

from collections.abc import Callable

from .models import AlignedCondition, Alignment, EvidenceState, ProgramFacts
from .templates import CweTemplate


Predicate = Callable[[ProgramFacts], tuple[EvidenceState, str, float]]


def _supported(message: str, trust: float = 0.9):
    return EvidenceState.SUPPORTED, message, trust


def _contradicted(message: str, trust: float = 0.9):
    return EvidenceState.CONTRADICTED, message, trust


def _unknown(message: str):
    return EvidenceState.UNKNOWN, message, 0.4


def has_external_source(f: ProgramFacts):
    return _supported(f"Source candidates: {[s.get('name') for s in f.sources]}", 0.7) if f.sources else _unknown("No source candidate was extracted")


def has_command_sink(f: ProgramFacts):
    sinks = [s for s in f.sinks if s.get("kind") == "command"]
    return _supported(f"Command sinks: {[s.get('name') for s in sinks]}") if sinks else _contradicted("No command-execution sink was extracted", 0.7)


def source_reaches_command_sink(f: ProgramFacts):
    paths = [p for p in f.flows if p.get("sink") in {"system", "popen", "execl", "execv", "ShellExecute", "CreateProcess"}]
    if paths:
        trust = max(float(path.get("trust", 0.9)) for path in paths)
        return _supported(f"Data-flow paths: {[p.get('path') for p in paths]}", trust)
    return _unknown("No source-to-command-sink path was established")


def no_command_sanitizer(f: ProgramFacts):
    sanitizer_terms = ("allow", "escape", "sanitize", "valid_host", "valid_domain", "valid_ipv4")
    sanitizers = [g for g in f.guards if any(term in g.get("expression", "").lower() for term in sanitizer_terms)]
    if sanitizers:
        return _contradicted(f"Potential command sanitizer/allowlist: {[g.get('expression') for g in sanitizers]}", 0.7)
    if f.guards:
        return _unknown(f"Guards exist but their command-neutralization effect is unknown: {[g.get('expression') for g in f.guards]}")
    return _unknown("No sanitizer was extracted; absence is not proven")


def has_fixed_buffer(f: ProgramFacts):
    buffers = [a for a in f.ast_facts if a.get("kind") == "fixed_buffer"]
    return _supported(f"Fixed buffers: {buffers}") if buffers else _contradicted("No fixed-size buffer was extracted", 0.8)


def has_memory_write(f: ProgramFacts):
    sinks = [s for s in f.sinks if s.get("kind") == "memory_write"]
    return _supported(f"Memory writes: {[s.get('name') for s in sinks]}") if sinks else _contradicted("No memory-write operation was extracted", 0.8)


def external_data_reaches_memory_write(f: ProgramFacts):
    names = {"strcpy", "strcat", "memcpy", "sprintf", "snprintf"}
    paths = [p for p in f.flows if p.get("sink") in names]
    return _supported(f"Candidate source-to-write paths: {[p.get('path') for p in paths]}", 0.6) if paths else _unknown("No source-to-memory-write path was established")


def has_unbounded_copy(f: ProgramFacts):
    dangerous = [op for op in f.operations if op in {"strcpy", "strcat", "sprintf", "gets"}]
    bounded = [op for op in f.operations if op in {"snprintf", "strncpy", "strncat"}]
    if dangerous:
        return _supported(f"Potentially unbounded operations: {dangerous}", 0.8)
    if bounded:
        return _contradicted(f"Only bounded string operations were extracted: {bounded}", 0.75)
    return _unknown("No recognized copy operation was extracted")


def no_bounds_guard(f: ProgramFacts):
    guards = [g for g in f.guards if g.get("kind") == "bounds_check"]
    if guards:
        return _contradicted(f"Potential bounds guards: {[g.get('expression') for g in guards]}", 0.65)
    return _unknown("No bounds guard was extracted; absence is not proven")


def has_reachable_memory_write(f: ProgramFacts):
    return has_memory_write(f)


def has_free(f: ProgramFacts):
    return _supported("free() is present", 0.9) if "free" in f.operations else _contradicted("free() was not extracted", 0.8)


def has_post_free_access(f: ProgramFacts):
    return _unknown("Precise post-free access requires ordered DFG/CFG facts")


def same_released_object(f: ProgramFacts):
    return _unknown("Object identity after free requires alias-aware facts")


def post_free_path_reachable(f: ProgramFacts):
    return _unknown("Post-free reachability requires ordered CFG facts")


PREDICATES: dict[str, Predicate] = {name: value for name, value in globals().copy().items() if callable(value) and name in {
    "has_external_source", "has_command_sink", "source_reaches_command_sink", "no_command_sanitizer",
    "has_fixed_buffer", "external_data_reaches_memory_write", "has_unbounded_copy", "no_bounds_guard",
    "has_memory_write", "has_reachable_memory_write", "has_free", "has_post_free_access",
    "same_released_object", "post_free_path_reachable",
}}


class EvidenceAligner:
    def align(self, template: CweTemplate, facts: ProgramFacts) -> Alignment:
        aligned: list[AlignedCondition] = []
        weighted_state = 0.0
        observed_weight = 0.0
        total_weight = sum(spec.weight for spec in template.conditions) or 1.0

        for spec in template.conditions:
            predicate = PREDICATES[spec.predicate]
            state, evidence, trust = predicate(facts)
            aligned.append(AlignedCondition(spec.name, state, evidence, spec.weight, trust))
            if state != EvidenceState.UNKNOWN:
                observed_weight += spec.weight
                numeric = 1.0 if state == EvidenceState.SUPPORTED else -1.0
                weighted_state += spec.weight * numeric * trust

        observability = observed_weight / total_weight
        signed = weighted_state / total_weight
        score = ((signed + 1.0) / 2.0) * observability
        return Alignment(template.cwe, round(score, 6), round(observability, 6), aligned)

