# Model and data preparation

This repository contains training and inference code, not third-party model
weights or derived dataset samples.

## Router labels

The ten coarse families are defined in
`data/router/family_label_index.json`: memory, injection, input, numeric,
resource, concurrency, access, crypto, information, and logic.

## Build router data

Run the builder against an authorized local dataset and inspect its help for
the required source arguments:

```bash
python scripts/build_router_data.py --help
```

Expected generated paths are:

```text
data/router/code_clean/train_pairs.jsonl
data/router/code_clean/valid_pairs.jsonl
data/router/official/test_pairs.jsonl
```

The official test split must remain evaluation-only.

## Prepare CodeBERT

Place a compatible checkpoint beneath `models/codebert-base`, containing at
least its configuration, tokenizer files, and model weights. CARE-Vul uses
offline loading and does not silently download a replacement checkpoint.

## Train

```bash
python scripts/train_router.py \
  --device cuda \
  --mixed-precision fp16 \
  --epochs 10 \
  --batch-size 2 \
  --gradient-accumulation-steps 8 \
  --gradient-checkpointing \
  --max-length 512 \
  --output-dir outputs/router/codebert_router
```

The script selects the checkpoint with the best validation Recall@3 and then
reports the held-out test metrics. Do not use test metrics for hyperparameter
selection.

