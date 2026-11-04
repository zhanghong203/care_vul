from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CARE_VUL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CARE_VUL_ROOT / "src"))

from carevul.router import RouterPredictor


def main() -> None:
    parser = argparse.ArgumentParser(description="Predict coarse vulnerability families for one source file.")
    parser.add_argument("code_file", type=Path)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--label-index", type=Path, default=CARE_VUL_ROOT / "data" / "router" / "family_label_index.json")
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    args = parser.parse_args()

    predictor = RouterPredictor(args.checkpoint, args.label_index, args.device, args.max_length)
    predictions = predictor.predict(args.code_file.read_text(encoding="utf-8"), args.top_k)
    print(json.dumps([item.to_dict() for item in predictions], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
