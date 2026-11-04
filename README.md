# CARE-Vul

CARE-Vul is a research prototype for **router-guided adaptive program analysis
and evidence-grounded vulnerability reasoning**. Its end-to-end path is:

```text
source code
  -> CodeBERT Top-K coarse families
  -> coverage-aware Analysis Planner
  -> specialized analyzers + generic AST/CFG/DFG queries
  -> normalized evidence
  -> LLM or downstream detector
```

It combines:

- a ten-family CodeBERT router with Recall@K and pair-aware evaluation;
- direct coarse-family-to-analysis-capability planning;
- a VulTriage-compatible control-path adapter for AST/CFG/DFG facts;
- dense/sparse-style example retrieval without model training;
- static-signal and CWE-taxonomy candidate correction;
- normalized supporting, counter, unknown, and limitation evidence;
- three-state (`SUPPORTED`, `CONTRADICTED`, `UNKNOWN`) CWE evidence alignment;
- budgeted support/counter-evidence selection;
- one final LLM call.

The source repository intentionally excludes third-party model weights,
derived PrimeVul JSONL files, generated outputs, and the upstream VulTriage
checkout. See [MODEL_DATA.md](MODEL_DATA.md) and
[THIRD_PARTY.md](THIRD_PARTY.md) before running training or precise static
analysis.

The repository expects the upstream VulTriage checkout at `third_party/VulTriage` and directly calls its `analyze_code_str` Control Path. The analyzer is run once per uncached function; its filtered graph representation and verbalized context are then reused for every CWE candidate.

On Linux/macOS, precise C extraction uses an available `gcc`, `clang`, or `cpp` preprocessor. On Windows, where those commands are often absent, it automatically uses the lightweight pure-Python `pcpp` dependency. The selected backend is recorded in `facts.metadata.preprocessor`; reported experiments should also verify that `facts.metadata.analysis_mode` is `precise_c` rather than `heuristic_c`.

The interfaces remain replaceable: existing MulVul predictions, a trained
CodeBERT Router, and VulTriage control-path output can be connected without
rewriting the evidence pipeline.

## Environment

```powershell
conda env create -f environment.yml
conda activate care-vul
pip install -e .
pytest -q
```

## Quick start without an API call

```powershell
care-vul analyze examples/cwe78.c --dry-run --output result.json
```

This writes the generated candidate set, aligned evidence and final one-shot prompt. To call an OpenAI-compatible endpoint:

```powershell
$env:OPENAI_API_KEY = "..."
care-vul analyze examples/cwe78.c --model gpt-4o-mini --output result.json
```

## Supplying MulVul candidates

CARE-Vul treats MulVul as a replaceable candidate provider. Export a single
prediction as JSON:

```json
{
  "candidates": [
    {"cwe": "CWE-78", "score": 0.83},
    {"cwe": "CWE-120", "score": 0.17}
  ]
}
```

Then run the complete one-shot preparation flow:

```powershell
care-vul analyze examples/cwe78.c `
  --mulvul-candidates examples/mulvul_candidates.json `
  --dry-run --output result.json
```

For dataset experiments, use JSONL with one record per sample. Records are
selected by `sample_id` (or `id`), with the source-code SHA-256 accepted as a
fallback key:

```json
{"sample_id":"primevul-7","candidates":[{"cwe":"CWE-78","score":0.83}]}
```

Pass `--sample-id primevul-7` when analyzing that sample. Candidate output
contains `components` for the independent `mulvul`, `retrieval`, `static`, and
`taxonomy` channels. Scores are combined with bounded noisy-OR; the static
channel can therefore recover a missed CWE without erasing MulVul's original
prediction. The supplied file is an offline interface, not a claim that this
repository contains the original MulVul model weights.

## Supplying VulTriage evidence

For repeatable experiments, precompute VulTriage control-path output and save one JSON object per function, keyed by the SHA-256 hash of the source code:

```json
{
  "<sha256>": {
    "ast_facts": [],
    "cfg_facts": [],
    "dfg_facts": [],
    "sources": [{"name": "host", "kind": "parameter", "line": 3}],
    "sinks": [{"name": "system", "kind": "command", "line": 10, "argument": "command"}],
    "flows": [{"source": "host", "sink": "system", "path": ["host", "command", "system"]}],
    "guards": [{"expression": "host != NULL", "kind": "null_check", "line": 5}],
    "operations": ["snprintf", "system"]
  }
}
```

Then run:

```powershell
care-vul analyze sample.c --control-cache vultriage_facts.json --dry-run
```

When no cache is supplied, CARE-Vul calls the checked-in VulTriage Control Path. Use `--no-vultriage` only for plumbing tests; that option activates the lightweight C/C++ fallback and must not be used for reported experiments.

VulTriage's precise DFG can stop at a buffer-writing call instead of propagating the written value to a later sink. CARE-Vul retains those precise chains and adds only missing source/sink pairs from its low-trust lexical reconstruction. This is exposed as `facts.metadata.lexical_flow_augmentation`; augmented paths keep their lower trust score and should be evaluated separately in ablations.

## Knowledge-base JSONL format

```json
{"id":"sample-1","code":"...","cwe":"CWE-78","label":1,"fixed_code":"..."}
```

Pass it with `--knowledge-base train.jsonl`. Never build the index from the test split.

## Reproducibility boundaries

- Graph extraction is performed once and cached; it is never rerun per CWE candidate.
- Candidate CWEs are suggestions, not a closed output space.
- Missing static evidence is `UNKNOWN`, not proof of absence.
- The paired PrimeVul test set must remain evaluation-only.

## CodeBERT family-router baseline

The first-stage router is a ten-label CodeBERT classifier trained only from
function source code. It uses the code-clean train/validation splits and keeps
the official 435-pair test split evaluation-only. Run the offline smoke test in
the existing PyTorch 2.6 environment before starting a full experiment:

```powershell
conda run -n pytorch-2.6-gpu python scripts/train_router.py --smoke-test
```

The original baseline optimizes weighted binary cross-entropy. The current
single-label protocol defaults to square-root class-weighted cross entropy with
label smoothing and early stopping; `weighted_bce` and `focal_ce` are retained
as explicit ablations. Pair-consistency training is intentionally excluded so
that it can be evaluated later as a separate method contribution. The script
reports Recall@1/3/5, per-family recall,
vulnerable/fixed recall, pair-union recall, and the stricter rate for which both
versions of a pair retrieve a correct family.

Defaults are sized for the local 4 GiB RTX 3050 Laptop GPU: sequence length 256,
batch size 1, eight-step gradient accumulation, FP16, and gradient checkpointing.
These settings still fine-tune the complete encoder; `--freeze-encoder` is an
explicit cheaper ablation rather than the default method.

After training, inspect one file directly:

```bash
python scripts/predict_router.py target.c \
  --checkpoint outputs/router/codebert_baseline \
  --top-k 3
```

Connect the trained Router to the Planner and evidence pipeline:

```bash
care-vul analyze target.c \
  --router-checkpoint outputs/router/codebert_baseline \
  --router-top-k 3 \
  --dry-run \
  --output target.evidence.json
```

The result exposes `router_predictions` and
`facts.metadata.analysis_plan`, including per-family coverage (`SPECIALIZED`,
`PARTIAL`, `GENERIC_ONLY`, or `UNSUPPORTED`), selected analyzers, generic graph
queries, and knowledge guidance. Knowledge describes what to inspect; it is
never treated as proof without target-code evidence.

