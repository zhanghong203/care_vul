from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


TOKEN_RE = re.compile(r"[A-Za-z_]\w*|==|!=|<=|>=|->|&&|\|\||[^\s]")


def tokens(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def cosine_bow(left: str, right: str) -> float:
    a, b = Counter(tokens(left)), Counter(tokens(right))
    dot = sum(value * b.get(key, 0) for key, value in a.items())
    na = math.sqrt(sum(value * value for value in a.values()))
    nb = math.sqrt(sum(value * value for value in b.values()))
    return dot / (na * nb) if na and nb else 0.0


@dataclass(slots=True)
class KnowledgeItem:
    item_id: str
    code: str
    cwe: str | None
    label: int
    fixed_code: str | None = None


class LocalKnowledgeBase:
    def __init__(self, items: list[KnowledgeItem] | None = None):
        self.items = items or []

    @classmethod
    def from_jsonl(cls, path: str | Path | None) -> "LocalKnowledgeBase":
        if path is None:
            return cls([])
        items: list[KnowledgeItem] = []
        with Path(path).open(encoding="utf-8") as handle:
            for row_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                items.append(KnowledgeItem(
                    item_id=str(row.get("id", row.get("idx", row_number))),
                    code=row.get("code", row.get("func", "")),
                    cwe=row.get("cwe") or row.get("cwe_id"),
                    label=int(row.get("label", row.get("target", 0))),
                    fixed_code=row.get("fixed_code"),
                ))
        return cls(items)

    def search(self, code: str, limit: int = 20) -> list[tuple[KnowledgeItem, float]]:
        ranked = [(item, cosine_bow(code, item.code)) for item in self.items]
        ranked.sort(key=lambda pair: pair[1], reverse=True)
        return ranked[:limit]

