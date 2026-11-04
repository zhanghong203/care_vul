from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConditionSpec:
    name: str
    predicate: str
    weight: float


@dataclass(frozen=True, slots=True)
class CweTemplate:
    cwe: str
    title: str
    coarse: str
    conditions: tuple[ConditionSpec, ...]
    related: tuple[str, ...] = ()


TEMPLATES: dict[str, CweTemplate] = {
    "CWE-78": CweTemplate(
        "CWE-78", "OS Command Injection", "Injection",
        (
            ConditionSpec("untrusted source", "has_external_source", 0.20),
            ConditionSpec("command execution sink", "has_command_sink", 0.25),
            ConditionSpec("source-to-sink flow", "source_reaches_command_sink", 0.30),
            ConditionSpec("insufficient neutralization", "no_command_sanitizer", 0.25),
        ),
        ("CWE-77", "CWE-20"),
    ),
    "CWE-120": CweTemplate(
        "CWE-120", "Classic Buffer Overflow", "Memory Safety",
        (
            ConditionSpec("fixed-size destination", "has_fixed_buffer", 0.20),
            ConditionSpec("externally influenced write", "external_data_reaches_memory_write", 0.25),
            ConditionSpec("unbounded copy", "has_unbounded_copy", 0.35),
            ConditionSpec("missing bounds guard", "no_bounds_guard", 0.20),
        ),
        ("CWE-119", "CWE-125", "CWE-787"),
    ),
    "CWE-787": CweTemplate(
        "CWE-787", "Out-of-bounds Write", "Memory Safety",
        (
            ConditionSpec("memory write", "has_memory_write", 0.25),
            ConditionSpec("externally influenced size or index", "external_data_reaches_memory_write", 0.25),
            ConditionSpec("insufficient bound", "no_bounds_guard", 0.30),
            ConditionSpec("reachable write", "has_reachable_memory_write", 0.20),
        ),
        ("CWE-119", "CWE-120", "CWE-125"),
    ),
    "CWE-416": CweTemplate(
        "CWE-416", "Use After Free", "Resource Management",
        (
            ConditionSpec("resource release", "has_free", 0.25),
            ConditionSpec("post-release access", "has_post_free_access", 0.35),
            ConditionSpec("same object", "same_released_object", 0.25),
            ConditionSpec("reachable order", "post_free_path_reachable", 0.15),
        ),
        ("CWE-415", "CWE-401"),
    ),
}


API_TO_CWE: dict[str, tuple[str, ...]] = {
    "system": ("CWE-78",),
    "popen": ("CWE-78",),
    "execl": ("CWE-78",),
    "execv": ("CWE-78",),
    "strcpy": ("CWE-120", "CWE-787"),
    "strcat": ("CWE-120", "CWE-787"),
    "memcpy": ("CWE-787", "CWE-120"),
    "free": ("CWE-416",),
}

