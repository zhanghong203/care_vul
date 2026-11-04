# CARE-Vul server training

This package contains the CARE-Vul source code, router datasets, the local
CodeBERT checkpoint, tests, examples, and the VulTriage control-flow analyzer.
Large BGE-M3 retrieval weights and duplicated upstream PrimeVul files are not
included because they are not used by CodeBERT router training.

## 1. Create the environment

Python 3.11 or newer is recommended. From the extracted `care_vul` directory:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[router]'
```

Install the PyTorch build that matches the server CUDA version first if the
default PyPI build is unsuitable for the server.

## 2. Verify the package

```bash
python -m pytest -q
python scripts/run_analysis_cases.py
```

The local test baseline at packaging time is `29 passed`.

## 3. Train the CodeBERT router

```bash
python scripts/train_router.py \
  --device cuda \
  --progress \
  --loss weighted_ce \
  --class-weight-mode sqrt_inverse \
  --label-smoothing 0.05 \
  --early-stopping-patience 2 \
  --epochs 5 \
  --batch-size 1 \
  --eval-batch-size 2 \
  --gradient-accumulation-steps 8 \
  --max-length 256 \
  --output-dir outputs/router/codebert_baseline
```

The packaged defaults point to:

- model: `models/codebert-base`
- labels: `data/router/family_label_index.json`
- train: `data/router/code_clean/train_pairs.jsonl`
- validation: `data/router/code_clean/valid_pairs.jsonl`
- test: `data/router/official/test_pairs.jsonl`

Training writes checkpoints, metrics, thresholds, and test predictions beneath
the selected output directory.

## 4. Inspect one program-analysis method

```bash
python scripts/inspect_analysis.py \
  examples/analysis_cases/08_bounds_property.c \
  --method bounds_property
```
