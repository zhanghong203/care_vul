# Third-party components

CARE-Vul integrates with external projects but does not redistribute their
repositories, datasets, or model weights in this source repository.

## VulTriage

The control-path adapter expects a compatible VulTriage checkout at
`third_party/VulTriage` by default. Upstream repository:

<https://github.com/vinsontang1/VulTriage>

```bash
mkdir -p third_party
git clone https://github.com/vinsontang1/VulTriage.git third_party/VulTriage
```

The CARE-Vul integration calls
`control_flow.control_flow.vuln_flow_analyzer.analyze_code_str`. Precise
experiments should verify that the returned metadata reports
`analysis_mode=precise_c`. If a compatible analyzer is unavailable, use
`--no-vultriage` only for plumbing tests; that fallback is not equivalent to
the reported static-analysis path.

VulTriage is kept out of this repository because its upstream checkout does
not currently expose a clear root license file. Users are responsible for
reviewing upstream terms before redistribution.

## CodeBERT

Router training and inference expect a Hugging Face-compatible CodeBERT model
directory, normally `models/codebert-base`. Model weights are intentionally not
tracked by Git. Review and comply with the license of the selected checkpoint.

## PrimeVul-derived router data

Generated router JSONL splits are intentionally ignored. Use
`scripts/build_router_data.py` with an authorized local copy of the source
dataset. Only small protocol metadata, label mappings, and statistics are
tracked.

