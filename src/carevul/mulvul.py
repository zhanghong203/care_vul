from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


CWE_RE = re.compile(r"^CWE[-_ ]?(\d+)$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class MulVulCandidate:
    cwe: str
    score: float


class MulVulCandidateProvider(Protocol):
    def predict(self, code: str, sample_id: str | None = None) -> list[MulVulCandidate]:
        """Return MulVul's ranked CWE candidates without calling an LLM."""


def normalize_cwe(value: Any) -> str:
    match = CWE_RE.match(str(value).strip())
    if not match:
        raise ValueError(f"invalid CWE identifier: {value!r}")
    return f"CWE-{int(match.group(1))}"


def _candidate_list(value: Any) -> list[MulVulCandidate]:
    if isinstance(value, dict):
        value = value.get("candidates", value.get("predictions", value.get("predicted_cwes", [])))
    if not isinstance(value, list):
        raise ValueError("MulVul candidates must be a JSON list")

    output: dict[str, float] = {}
    default_score = 1.0 / max(1, len(value))
    for rank, item in enumerate(value, 1):
        if isinstance(item, str):
            cwe, score = normalize_cwe(item), default_score
        elif isinstance(item, dict):
            raw_cwe = item.get("cwe", item.get("cwe_id", item.get("label")))
            cwe = normalize_cwe(raw_cwe)
            raw_score = item.get("score", item.get("confidence", item.get("probability")))
            score = float(raw_score) if raw_score is not None else 1.0 / rank
        else:
            raise ValueError(f"unsupported MulVul candidate entry: {item!r}")
        if not 0.0 <= score <= 1.0:
            raise ValueError(f"MulVul score for {cwe} must be in [0, 1]")
        output[cwe] = max(output.get(cwe, 0.0), score)
    return [MulVulCandidate(cwe, score) for cwe, score in sorted(output.items(), key=lambda x: x[1], reverse=True)]


class FileMulVulCandidateProvider:
    """Read offline MulVul predictions from JSON or JSONL.

    A direct candidate list applies to one CLI invocation. Dataset files may
    key rows by ``id``/``sample_id`` or by the SHA-256 hash of source code.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.direct: list[MulVulCandidate] | None = None
        self.records: dict[str, list[MulVulCandidate]] = {}
        self._load()

    @staticmethod
    def code_hash(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    def _load(self) -> None:
        text = self.path.read_text(encoding="utf-8")
        if self.path.suffix.lower() == ".jsonl":
            values = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            parsed = json.loads(text)
            values = parsed if isinstance(parsed, list) and parsed and all(isinstance(x, dict) and any(k in x for k in ("id", "sample_id", "code_sha256")) for x in parsed) else None
            if values is None:
                self.direct = _candidate_list(parsed)
                return

        for index, row in enumerate(values, 1):
            key = row.get("sample_id", row.get("id", row.get("code_sha256")))
            if key is None:
                raise ValueError(f"MulVul prediction row {index} has no id, sample_id, or code_sha256")
            self.records[str(key)] = _candidate_list(row)

    def predict(self, code: str, sample_id: str | None = None) -> list[MulVulCandidate]:
        if self.direct is not None:
            return list(self.direct)
        keys = [sample_id, self.code_hash(code)]
        for key in keys:
            if key is not None and str(key) in self.records:
                return list(self.records[str(key)])
        return []
