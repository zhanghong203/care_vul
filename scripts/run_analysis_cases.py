from __future__ import annotations

import json
import sys
from pathlib import Path

CARE_VUL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CARE_VUL_ROOT / "src"))

from carevul.analysis_inspector import inspect_analysis
from carevul.control import ControlPathAdapter


def main() -> None:
    case_dir = CARE_VUL_ROOT / "examples" / "analysis_cases"
    output_dir = CARE_VUL_ROOT / "outputs" / "analysis_cases"
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
    adapter = ControlPathAdapter(
        vultriage_root=CARE_VUL_ROOT / "third_party" / "VulTriage",
        detail_level="C",
    )
    summary = []
    for case in manifest:
        code_path = case_dir / case["file"]
        result = inspect_analysis(code_path.read_text(encoding="utf-8"), case["method"], adapter)
        output_path = output_dir / f"{case['method']}.json"
        output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        states = sorted({item["state"] for item in result["normalized_evidence"]})
        summary.append({"method": case["method"], "states": states, "output": str(output_path)})
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
