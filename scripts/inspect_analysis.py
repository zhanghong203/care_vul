from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CARE_VUL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CARE_VUL_ROOT / "src"))

from carevul.analysis_inspector import inspect_analysis
from carevul.control import ControlPathAdapter
from carevul.evidence_schema import AVAILABLE_ANALYSIS_METHODS


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect one CARE-Vul program-analysis method.")
    parser.add_argument("code_file", type=Path)
    parser.add_argument("--method", required=True, choices=AVAILABLE_ANALYSIS_METHODS)
    parser.add_argument("--vultriage-root", type=Path, default=CARE_VUL_ROOT / "third_party" / "VulTriage")
    parser.add_argument("--control-detail", choices=["A", "B", "C"], default="C")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    adapter = ControlPathAdapter(
        vultriage_root=args.vultriage_root,
        detail_level=args.control_detail,
    )
    result = inspect_analysis(args.code_file.read_text(encoding="utf-8"), args.method, adapter)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
