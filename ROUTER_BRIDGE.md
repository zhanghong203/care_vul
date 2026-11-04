# Router to Analysis Planner bridge

## Predict one file

```bash
python scripts/predict_router.py target.c \
  --checkpoint outputs/router/codebert_lowmem_fp16_seed42 \
  --top-k 3 \
  --device cuda
```

## Run the connected dry-run pipeline

```bash
care-vul analyze target.c \
  --router-checkpoint outputs/router/codebert_lowmem_fp16_seed42 \
  --router-top-k 3 \
  --router-max-length 512 \
  --router-device cuda \
  --dry-run \
  --output target.evidence.json
```

The output contains `router_predictions` and
`facts.metadata.analysis_plan`. The plan records selected program-analysis
families, concrete analyzers, generic graph queries, family-specific knowledge
guidance, and a per-family coverage status.

Coverage values are:

- `SPECIALIZED`: dedicated analysis capabilities are available.
- `PARTIAL`: dedicated capabilities exist but do not cover the full Router family.
- `GENERIC_ONLY`: AST/CFG/DFG evidence and knowledge-guided queries are used.
- `UNSUPPORTED`: no mapping is registered; this is explicit rather than silently ignored.

Knowledge guidance describes what to check. It is never treated as proof; final
claims must be supported by facts extracted from the target code.
