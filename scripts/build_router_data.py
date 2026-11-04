#!/usr/bin/env python3
"""Build reproducible PrimeVul pair datasets for the coarse-family router.

Source JSONL files are read-only. The builder creates an official protocol
with audit flags and a code-decontaminated protocol with pair-atomic removal.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


FAMILY_ORDER = [
    "memory",
    "injection",
    "input",
    "numeric",
    "resource",
    "concurrency",
    "access",
    "crypto",
    "information",
    "logic",
]

# These entries are absent from the reconstructed mapping but occur in the
# supplied validation set. Assignments are mechanism-based and documented.
MAPPING_ADDITIONS = {
    "CWE-459": {
        "cwe": "CWE-459",
        "name": "Incomplete Cleanup",
        "category": "resource",
        "confidence": "high",
        "method": "documented-extension",
        "evidence": ["cleanup/release lifecycle mechanism"],
    },
    "CWE-565": {
        "cwe": "CWE-565",
        "name": "Reliance on Cookies without Validation and Integrity Checking",
        "category": "input",
        "confidence": "medium",
        "method": "documented-extension",
        "evidence": ["untrusted cookie validation mechanism"],
    },
    "CWE-611": {
        "cwe": "CWE-611",
        "name": "Improper Restriction of XML External Entity Reference",
        "category": "injection",
        "confidence": "high",
        "method": "documented-extension",
        "evidence": ["untrusted XML changes interpreted external entity structure"],
    },
    "CWE-662": {
        "cwe": "CWE-662",
        "name": "Improper Synchronization",
        "category": "concurrency",
        "confidence": "high",
        "method": "documented-extension",
        "evidence": ["synchronization and shared-state mechanism"],
    },
    "CWE-706": {
        "cwe": "CWE-706",
        "name": "Use of Incorrectly-Resolved Name or Reference",
        "category": "logic",
        "confidence": "medium",
        "method": "documented-extension",
        "evidence": ["security-relevant name/reference resolution logic"],
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            row["_source_line"] = line_number
            rows.append(row)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def load_mapping(path: Path) -> tuple[dict[str, str], dict[str, Any]]:
    source = json.loads(path.read_text(encoding="utf-8"))
    entries = dict(source["mapping"])
    entries.update(MAPPING_ADDITIONS)
    mapping = {cwe: item["category"] for cwe, item in entries.items()}
    snapshot = {
        "schema_version": 1,
        "source_mapping": str(path.resolve()),
        "source_mapping_sha256": sha256_file(path),
        "families": FAMILY_ORDER,
        "benign_is_router_family": False,
        "unknown_policy": "Keep in official data with empty family labels; exclude from code-clean training pairs.",
        "mapping": entries,
        "documented_additions": MAPPING_ADDITIONS,
        "limitations": [
            "The source mapping is an independent reconstruction, not MulVul's unpublished official table.",
            "The source mapping was originally generated over observed PrimeVul train/test CWE identifiers.",
            "Medium-confidence cross-cutting assignments require an ablation or sensitivity analysis.",
        ],
    }
    return mapping, snapshot


def cwe_list(row: dict[str, Any]) -> list[str]:
    value = row.get("cwe") or []
    if isinstance(value, str):
        value = [value]
    return sorted({str(item).strip() for item in value if str(item).strip()})


def family_labels(row: dict[str, Any], mapping: dict[str, str]) -> tuple[list[str], list[str]]:
    cwes = cwe_list(row)
    families = sorted({mapping[cwe] for cwe in cwes if cwe in mapping}, key=FAMILY_ORDER.index)
    unknown = sorted(cwe for cwe in cwes if cwe not in mapping)
    return families, unknown


def compact_function(row: dict[str, Any], mapping: dict[str, str]) -> dict[str, Any]:
    families, unknown = family_labels(row, mapping)
    return {
        "idx": row.get("idx"),
        "func": row.get("func") or "",
        "binary_target": row.get("target"),
        "leaf_cwes": cwe_list(row),
        "family_labels": families,
        "family_label_vector": [1 if family in families else 0 for family in FAMILY_ORDER],
        "unmapped_cwes": unknown,
        "func_hash": str(row.get("func_hash") or ""),
        "source_line": row["_source_line"],
    }


def metadata_matches(left: dict[str, Any], right: dict[str, Any]) -> dict[str, bool]:
    return {
        "same_project": left.get("project") == right.get("project"),
        "same_commit": left.get("commit_id") == right.get("commit_id"),
        "same_cve": left.get("cve") == right.get("cve"),
        "same_cwe": cwe_list(left) == cwe_list(right),
    }


def build_pairs(split: str, rows: list[dict[str, Any]], mapping: dict[str, str]) -> list[dict[str, Any]]:
    if len(rows) % 2:
        raise ValueError(f"{split} has an odd row count: {len(rows)}")
    output: list[dict[str, Any]] = []
    for offset in range(0, len(rows), 2):
        left, right = rows[offset], rows[offset + 1]
        checks = metadata_matches(left, right)
        vuln = compact_function(left, mapping)
        fixed = compact_function(right, mapping)
        target_order_valid = left.get("target") == 1 and right.get("target") == 0
        shared_families = [family for family in vuln["family_labels"] if family in fixed["family_labels"]]
        metadata_valid = all(checks.values())
        pair_consistency_eligible = bool(
            target_order_valid and metadata_valid and shared_families
            and not vuln["unmapped_cwes"] and not fixed["unmapped_cwes"]
        )
        reasons: list[str] = []
        if not target_order_valid:
            reasons.append("target_order")
        reasons.extend(key for key, passed in checks.items() if not passed)
        if not shared_families:
            reasons.append("no_shared_family")
        if vuln["unmapped_cwes"] or fixed["unmapped_cwes"]:
            reasons.append("unmapped_cwe")
        output.append({
            "schema_version": 1,
            "pair_id": f"{split}_{offset // 2 + 1:06d}",
            "split": split,
            "pair_number": offset // 2 + 1,
            "vulnerable": vuln,
            "fixed": fixed,
            "shared_family_labels": shared_families,
            "pair_consistency_eligible": pair_consistency_eligible,
            "pair_status": "verified" if pair_consistency_eligible else "excluded_from_pair_loss",
            "pair_status_reasons": reasons,
            "pair_metadata": checks,
            "group_metadata": {
                "project": left.get("project"),
                "commit_id": left.get("commit_id"),
                "cve": left.get("cve"),
            },
            "audit": {
                "code_near_duplicate_cross_split": False,
                "removed_in_code_clean_protocol": False,
            },
        })
    return output


def load_audit_exclusions(
    audit_dir: Path,
) -> tuple[dict[str, set[int]], dict[str, dict[int, list[str]]], dict[str, set[int]]]:
    excluded: dict[str, set[int]] = {"train": set(), "valid": set(), "test": set()}
    flagged: dict[str, set[int]] = {"train": set(), "valid": set(), "test": set()}
    reasons: dict[str, dict[int, list[str]]] = {
        split: {} for split in excluded
    }
    near_path = audit_dir / "near_duplicate_cross_split.csv"
    with near_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            left_split, right_split = row["split_left"], row["split_right"]
            left_pair = (int(row["line_left"]) + 1) // 2
            right_pair = (int(row["line_right"]) + 1) // 2
            flagged[left_split].add(left_pair)
            flagged[right_split].add(right_pair)
            # Keep the final test set fixed. Remove earlier-split pairs atomically.
            if left_split == "train":
                split, line = "train", int(row["line_left"])
            elif left_split == "valid" and right_split == "test":
                split, line = "valid", int(row["line_left"])
            else:
                continue
            pair_number = (line + 1) // 2
            excluded[split].add(pair_number)
            reasons[split].setdefault(pair_number, []).append(
                f"near_duplicate_to_{right_split}:jaccard={row['shingle_jaccard']}"
            )
    pair_path = audit_dir / "pair_integrity_violations.csv"
    with pair_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            split = row["split"]
            pair_number = int(row["pair_number"])
            excluded[split].add(pair_number)
            reasons[split].setdefault(pair_number, []).append(
                f"pair_integrity:{row['violations']}"
            )
    return excluded, reasons, flagged


def apply_audit_flags(
    pairs_by_split: dict[str, list[dict[str, Any]]], flagged: dict[str, set[int]]
) -> None:
    for split, pairs in pairs_by_split.items():
        for pair in pairs:
            pair["audit"]["code_near_duplicate_cross_split"] = (
                pair["pair_number"] in flagged[split]
            )


def clean_protocol(
    pairs_by_split: dict[str, list[dict[str, Any]]],
    exclusions: dict[str, set[int]],
    exclusion_reasons: dict[str, dict[int, list[str]]],
    flagged: dict[str, set[int]],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    clean: dict[str, list[dict[str, Any]]] = {}
    excluded_rows: list[dict[str, Any]] = []
    for split, pairs in pairs_by_split.items():
        kept: list[dict[str, Any]] = []
        for pair in pairs:
            pair_number = pair["pair_number"]
            reasons = list(exclusion_reasons[split].get(pair_number, []))
            if not pair["pair_consistency_eligible"]:
                reasons.extend(pair["pair_status_reasons"])
            reasons = sorted(set(reasons))
            remove = split != "test" and bool(reasons)
            if remove:
                excluded_rows.append({
                    "pair_id": pair["pair_id"],
                    "split": split,
                    "pair_number": pair_number,
                    "reasons": reasons,
                })
                continue
            copied = json.loads(json.dumps(pair, ensure_ascii=False))
            copied["audit"]["code_near_duplicate_cross_split"] = pair_number in flagged[split]
            copied["audit"]["removed_in_code_clean_protocol"] = False
            kept.append(copied)
        clean[split] = kept
    return clean, excluded_rows


def summarize(pairs_by_split: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for split, pairs in pairs_by_split.items():
        family_counts: Counter[str] = Counter()
        unmapped: Counter[str] = Counter()
        for pair in pairs:
            for side in ("vulnerable", "fixed"):
                family_counts.update(pair[side]["family_labels"])
                unmapped.update(pair[side]["unmapped_cwes"])
        result[split] = {
            "pairs": len(pairs),
            "functions": 2 * len(pairs),
            "pair_consistency_eligible": sum(p["pair_consistency_eligible"] for p in pairs),
            "pair_consistency_ineligible": sum(not p["pair_consistency_eligible"] for p in pairs),
            "family_label_counts": {family: family_counts[family] for family in FAMILY_ORDER},
            "unmapped_cwes": dict(sorted(unmapped.items())),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--audit-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    mapping, mapping_snapshot = load_mapping(args.mapping)
    source_files = {
        split: args.data_dir / f"primevul_{split}_paired.jsonl"
        for split in ("train", "valid", "test")
    }
    pairs_by_split = {
        split: build_pairs(split, load_jsonl(path), mapping)
        for split, path in source_files.items()
    }
    exclusions, exclusion_reasons, flagged = load_audit_exclusions(args.audit_dir)
    apply_audit_flags(pairs_by_split, flagged)
    clean_pairs, excluded_rows = clean_protocol(
        pairs_by_split, exclusions, exclusion_reasons, flagged
    )

    for protocol, datasets in (("official", pairs_by_split), ("code_clean", clean_pairs)):
        for split, pairs in datasets.items():
            write_jsonl(args.output_dir / protocol / f"{split}_pairs.jsonl", pairs)
    write_jsonl(args.output_dir / "code_clean" / "excluded_pairs.jsonl", excluded_rows)

    label_index = {family: index for index, family in enumerate(FAMILY_ORDER)}
    (args.output_dir / "family_label_index.json").write_text(
        json.dumps(label_index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "family_mapping_snapshot.json").write_text(
        json.dumps(mapping_snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    statistics = {
        "official": summarize(pairs_by_split),
        "code_clean": summarize(clean_pairs),
        "excluded_pairs": len(excluded_rows),
        "excluded_by_split": dict(Counter(row["split"] for row in excluded_rows)),
    }
    (args.output_dir / "dataset_statistics.json").write_text(
        json.dumps(statistics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    manifest = {
        "schema_version": 1,
        "task": "coarse vulnerability mechanism candidate routing",
        "model_input_fields": ["vulnerable.func", "fixed.func"],
        "supervision_fields": [
            "vulnerable.family_label_vector", "fixed.family_label_vector",
            "shared_family_labels", "pair_consistency_eligible",
        ],
        "forbidden_model_input_fields": [
            "binary_target", "leaf_cwes", "project", "commit_id", "cve",
            "func_hash", "source_line",
        ],
        "families": FAMILY_ORDER,
        "source_files": {
            split: {"path": str(path.resolve()), "sha256": sha256_file(path)}
            for split, path in source_files.items()
        },
        "mapping_sha256": sha256_file(args.output_dir / "family_mapping_snapshot.json"),
        "audit_summary_sha256": sha256_file(args.audit_dir / "audit_summary.json"),
        "protocols": {
            "official": "Official PrimeVul row order retained; invalid pairs are flagged and excluded from pair loss.",
            "code_clean": "Train/valid pairs with audit anomalies or cross-split lexical near-duplicates are removed atomically; test remains unchanged and flagged.",
        },
    }
    (args.output_dir / "protocol_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(statistics, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
