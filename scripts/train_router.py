from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
from pathlib import Path

CARE_VUL_ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("HF_HOME", str(CARE_VUL_ROOT / ".cache" / "huggingface"))
sys.path.insert(0, str(CARE_VUL_ROOT / "src"))

import numpy as np
import torch
from torch import nn
from torch.optim import AdamW
from torch.utils.data import DataLoader
from tqdm.auto import tqdm
from transformers import AutoTokenizer, get_linear_schedule_with_warmup

from carevul.router import CodeBertRouter, PairJsonlDataset, compute_router_metrics, load_pair_examples
from carevul.router.data import RouterCollator
from carevul.router.objectives import (
    SUPPORTED_OBJECTIVES,
    build_training_loss,
    evaluation_loss,
    objective_loss,
    probabilities_from_logits,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the CodeBERT coarse-family router baseline.")
    parser.add_argument("--model-dir", type=Path, default=CARE_VUL_ROOT / "models" / "codebert-base")
    parser.add_argument("--label-index", type=Path, default=CARE_VUL_ROOT / "data" / "router" / "family_label_index.json")
    parser.add_argument("--train-file", type=Path, default=CARE_VUL_ROOT / "data" / "router" / "code_clean" / "train_pairs.jsonl")
    parser.add_argument("--valid-file", type=Path, default=CARE_VUL_ROOT / "data" / "router" / "code_clean" / "valid_pairs.jsonl")
    parser.add_argument("--test-file", type=Path, default=CARE_VUL_ROOT / "data" / "router" / "official" / "test_pairs.jsonl")
    parser.add_argument("--output-dir", type=Path, default=CARE_VUL_ROOT / "outputs" / "router" / "codebert_baseline")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--eval-batch-size", type=int, default=2)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--warmup-ratio", type=float, default=0.1)
    parser.add_argument("--dropout", type=float, default=0.1)
    parser.add_argument("--loss", choices=sorted(SUPPORTED_OBJECTIVES), default="weighted_ce")
    parser.add_argument("--class-weight-mode", choices=("none", "inverse", "sqrt_inverse"), default="sqrt_inverse")
    parser.add_argument("--label-smoothing", type=float, default=0.05)
    parser.add_argument("--focal-gamma", type=float, default=2.0)
    parser.add_argument(
        "--early-stopping-patience",
        type=int,
        default=2,
        help="Stop after this many epochs without validation Recall@3 improvement; 0 disables early stopping.",
    )
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--num-workers", type=int, default=0)
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    parser.add_argument("--freeze-encoder", action="store_true")
    parser.add_argument(
        "--gradient-checkpointing",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Trade compute for lower activation memory during encoder fine-tuning.",
    )
    parser.add_argument("--mixed-precision", choices=("auto", "none", "fp16", "bf16"), default="auto")
    parser.add_argument("--max-train-pairs", type=int)
    parser.add_argument("--max-valid-pairs", type=int)
    parser.add_argument("--max-test-pairs", type=int)
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument(
        "--progress",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Show training, validation, and test progress bars (default: enabled).",
    )
    return parser.parse_args()


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def ordered_labels(path: Path) -> list[str]:
    mapping = json.loads(path.read_text(encoding="utf-8"))
    indices = sorted(mapping.values())
    if indices != list(range(len(mapping))):
        raise ValueError("Label indices must be contiguous and start at zero")
    return [name for name, _ in sorted(mapping.items(), key=lambda item: item[1])]


def select_device(requested: str) -> torch.device:
    if requested == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA was requested but is not available")
    if requested == "auto":
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    return torch.device(requested)


def model_batch(batch: dict, device: torch.device) -> dict[str, torch.Tensor]:
    excluded = {"labels", "sample_ids", "pair_ids", "versions", "pair_consistency_eligible"}
    return {key: value.to(device) for key, value in batch.items() if key not in excluded}


def amp_dtype(requested: str, device: torch.device) -> torch.dtype | None:
    if device.type != "cuda" or requested == "none":
        return None
    if requested == "bf16":
        if not torch.cuda.is_bf16_supported():
            raise RuntimeError("bfloat16 was requested but is not supported by this GPU")
        return torch.bfloat16
    if requested in {"auto", "fp16"}:
        return torch.float16
    return None


@torch.no_grad()
def evaluate(
    model,
    loader,
    examples,
    label_names,
    device,
    mixed_dtype=None,
    objective="weighted_bce",
    description="Evaluate",
    show_progress=True,
) -> tuple[float, dict, np.ndarray]:
    model.eval()
    losses = []
    all_probabilities = []
    batches = tqdm(
        loader,
        desc=description,
        leave=False,
        dynamic_ncols=True,
        disable=not show_progress,
    )
    for batch in batches:
        labels = batch["labels"].to(device)
        with torch.autocast(device_type=device.type, dtype=mixed_dtype, enabled=mixed_dtype is not None):
            logits = model(**model_batch(batch, device))
        losses.append(float(evaluation_loss(objective, logits, labels).item()))
        # NumPy has no native torch.bfloat16 dtype. Keep mixed precision for
        # model execution, then export FP32 probabilities for metric code.
        all_probabilities.append(probabilities_from_logits(objective, logits).float().cpu().numpy())
    probabilities = np.concatenate(all_probabilities, axis=0)
    metrics = compute_router_metrics(probabilities, examples, label_names)
    return float(np.mean(losses)), metrics, probabilities


def save_json(path: Path, value: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def serializable_config(args: argparse.Namespace) -> dict:
    return {
        key: str(value.resolve()) if isinstance(value, Path) else value
        for key, value in vars(args).items()
    }


def run(args: argparse.Namespace) -> dict:
    set_seed(args.seed)
    label_names = ordered_labels(args.label_index)
    if not 0.0 <= args.label_smoothing < 1.0:
        raise ValueError("label_smoothing must be in [0, 1)")
    if args.focal_gamma < 0.0:
        raise ValueError("focal_gamma must be non-negative")
    if args.early_stopping_patience < 0:
        raise ValueError("early_stopping_patience must be non-negative")

    if args.smoke_test:
        args.epochs = 1
        args.batch_size = 2
        args.eval_batch_size = 2
        args.gradient_accumulation_steps = 1
        args.max_length = min(args.max_length, 128)
        args.max_train_pairs = args.max_train_pairs or 2
        args.max_valid_pairs = args.max_valid_pairs or 2
        args.max_test_pairs = args.max_test_pairs or 2

    train_examples = load_pair_examples(args.train_file, len(label_names), args.max_train_pairs)
    valid_examples = load_pair_examples(args.valid_file, len(label_names), args.max_valid_pairs)
    test_examples = load_pair_examples(args.test_file, len(label_names), args.max_test_pairs)
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir, local_files_only=True)
    collator = RouterCollator(tokenizer, args.max_length)
    generator = torch.Generator().manual_seed(args.seed)
    train_loader = DataLoader(
        PairJsonlDataset(train_examples), batch_size=args.batch_size, shuffle=True,
        collate_fn=collator, num_workers=args.num_workers, generator=generator,
    )
    valid_loader = DataLoader(
        PairJsonlDataset(valid_examples), batch_size=args.eval_batch_size, shuffle=False,
        collate_fn=collator, num_workers=args.num_workers,
    )
    test_loader = DataLoader(
        PairJsonlDataset(test_examples), batch_size=args.eval_batch_size, shuffle=False,
        collate_fn=collator, num_workers=args.num_workers,
    )

    device = select_device(args.device)
    model = CodeBertRouter(args.model_dir, len(label_names), args.dropout, local_files_only=True).to(device)
    if args.freeze_encoder:
        model.freeze_encoder()
    elif args.gradient_checkpointing:
        if hasattr(model.encoder.config, "use_cache"):
            model.encoder.config.use_cache = False
        model.encoder.gradient_checkpointing_enable()
    mixed_dtype = amp_dtype(args.mixed_precision, device)
    scaler = torch.amp.GradScaler("cuda", enabled=mixed_dtype == torch.float16)
    parameters = [parameter for parameter in model.parameters() if parameter.requires_grad]
    optimizer = AdamW(parameters, lr=args.learning_rate, weight_decay=args.weight_decay)
    updates_per_epoch = max(1, (len(train_loader) + args.gradient_accumulation_steps - 1) // args.gradient_accumulation_steps)
    total_updates = updates_per_epoch * args.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(total_updates * args.warmup_ratio),
        num_training_steps=total_updates,
    )
    loss_fn, objective_metadata = build_training_loss(
        args.loss,
        train_examples,
        device,
        class_weight_mode=args.class_weight_mode,
        label_smoothing=args.label_smoothing,
        focal_gamma=args.focal_gamma,
        allow_missing=args.smoke_test,
    )

    history = []
    best_recall = -1.0
    best_state = None
    best_epoch = None
    epochs_without_improvement = 0
    optimizer.zero_grad(set_to_none=True)
    for epoch in range(1, args.epochs + 1):
        model.train()
        train_losses = []
        train_batches = tqdm(
            train_loader,
            desc=f"Train {epoch}/{args.epochs}",
            dynamic_ncols=True,
            disable=not args.progress,
        )
        for step, batch in enumerate(train_batches, start=1):
            labels = batch["labels"].to(device)
            with torch.autocast(device_type=device.type, dtype=mixed_dtype, enabled=mixed_dtype is not None):
                logits = model(**model_batch(batch, device))
                loss = objective_loss(args.loss, loss_fn, logits, labels) / args.gradient_accumulation_steps
            scaler.scale(loss).backward()
            train_losses.append(float(loss.item() * args.gradient_accumulation_steps))
            train_batches.set_postfix(
                loss=f"{np.mean(train_losses):.4f}",
                lr=f"{optimizer.param_groups[0]['lr']:.2e}",
                refresh=False,
            )
            if step % args.gradient_accumulation_steps == 0 or step == len(train_loader):
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(parameters, max_norm=1.0)
                scale_before_step = scaler.get_scale()
                scaler.step(optimizer)
                scaler.update()
                # GradScaler skips optimizer.step() when FP16 gradients
                # overflow. Keep the LR schedule aligned with real updates.
                if scaler.get_scale() >= scale_before_step:
                    scheduler.step()
                optimizer.zero_grad(set_to_none=True)

        valid_loss, valid_metrics, _ = evaluate(
            model,
            valid_loader,
            valid_examples,
            label_names,
            device,
            mixed_dtype,
            objective=args.loss,
            description=f"Valid {epoch}/{args.epochs}",
            show_progress=args.progress,
        )
        epoch_result = {
            "epoch": epoch,
            "train_loss": float(np.mean(train_losses)),
            "valid_loss": valid_loss,
            "valid_metrics": valid_metrics,
        }
        history.append(epoch_result)
        score = float(valid_metrics["recall@3"])
        if score > best_recall:
            best_recall = score
            best_epoch = epoch
            epochs_without_improvement = 0
            best_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
        else:
            epochs_without_improvement += 1
        print(json.dumps(epoch_result, ensure_ascii=False))
        if (
            args.early_stopping_patience > 0
            and epochs_without_improvement >= args.early_stopping_patience
        ):
            print(json.dumps({
                "early_stopping": True,
                "best_epoch": best_epoch,
                "best_valid_recall@3": best_recall,
                "patience": args.early_stopping_patience,
            }, ensure_ascii=False))
            break

    if best_state is None:
        raise RuntimeError("Training did not produce a checkpoint")
    model.load_state_dict(best_state)
    model.to(device)
    test_loss, test_metrics, test_probabilities = evaluate(
        model,
        test_loader,
        test_examples,
        label_names,
        device,
        mixed_dtype,
        objective=args.loss,
        description="Test",
        show_progress=args.progress,
    )

    predictions = []
    for example, scores in zip(test_examples, test_probabilities):
        top_indices = np.argsort(-scores)[:5]
        predictions.append({
            "sample_id": example.sample_id,
            "pair_id": example.pair_id,
            "version": example.version,
            "true_families": [label_names[i] for i, value in enumerate(example.labels) if value],
            "top5": [{"family": label_names[i], "score": float(scores[i])} for i in top_indices],
        })

    summary = {
        "baseline": f"codebert_{args.loss}",
        "training_config": serializable_config(args),
        "device": str(device),
        "model_dir": str(args.model_dir.resolve()),
        "labels": label_names,
        "train_pairs": len(train_examples) // 2,
        "valid_pairs": len(valid_examples) // 2,
        "test_pairs": len(test_examples) // 2,
        "objective": objective_metadata,
        "best_epoch": best_epoch,
        "history": history,
        "best_valid_recall@3": best_recall,
        "test_loss": test_loss,
        "test_metrics": test_metrics,
    }

    if args.smoke_test:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="checkpoint-", dir=args.output_dir) as temp_dir:
            model.save_checkpoint(temp_dir, {"smoke_test": True})
            reloaded = CodeBertRouter.load_checkpoint(temp_dir, device=device)
            reload_loss, reload_metrics, _ = evaluate(
                reloaded,
                valid_loader,
                valid_examples,
                label_names,
                device,
                mixed_dtype,
                objective=args.loss,
                description="Reload check",
                show_progress=args.progress,
            )
            summary["checkpoint_reload"] = {
                "successful": True,
                "valid_loss": reload_loss,
                "valid_recall@3": reload_metrics["recall@3"],
            }
    else:
        model.save_checkpoint(args.output_dir, {
            "best_valid_recall@3": best_recall,
            "best_epoch": best_epoch,
            **objective_metadata,
        })

    save_json(args.output_dir / "run_summary.json", summary)
    save_json(args.output_dir / "test_predictions.json", predictions)
    return summary


def main() -> None:
    args = parse_args()
    summary = run(args)
    print(json.dumps({
        "status": "ok",
        "output_dir": str(args.output_dir.resolve()),
        "best_valid_recall@3": summary["best_valid_recall@3"],
        "test_recall@3": summary["test_metrics"]["recall@3"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
