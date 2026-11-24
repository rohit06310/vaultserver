"""Benchmark suite for VaultlessSecrets.

Evaluates precision, recall, F1 score, false-positive rate, and throughput
against the labeled seed dataset.
"""
import json
import sys
import time
from pathlib import Path

# Ensure root directory is on PYTHONPATH when executed directly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.detectors import redact

SEED_FILE = Path(__file__).resolve().parent.parent / "data" / "seed_logs.jsonl"


def run_benchmark(iterations: int = 100) -> dict:
    """Run benchmark against seed logs.

    Returns:
        total_samples: number of evaluated logs
        true_positives (TP): secret present and detected
        false_positives (FP): no secret present but detector reported secret
        false_negatives (FN): secret present but detector missed it
        true_negatives (TN): no secret present and detector reported clean
        precision: TP / (TP + FP)
        recall: TP / (TP + FN)
        f1_score: 2 * (P * R) / (P + R)
        throughput_logs_per_sec: logs processed per second
        avg_latency_ms: average processing latency per log line in milliseconds
    """
    with open(SEED_FILE, encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    tp = 0
    fp = 0
    fn = 0
    tn = 0

    # 1. Evaluate accuracy metrics over seed dataset
    for row in rows:
        clean, findings = redact(row["log"])
        predicted_has_secret = len(findings) > 0
        actual_has_secret = row["has_secret"]

        if predicted_has_secret and actual_has_secret:
            tp += 1
        elif predicted_has_secret and not actual_has_secret:
            fp += 1
        elif not predicted_has_secret and actual_has_secret:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # 2. Benchmark throughput over multiple iterations
    start_time = time.perf_counter()
    total_runs = len(rows) * iterations
    for _ in range(iterations):
        for row in rows:
            redact(row["log"])
    elapsed = time.perf_counter() - start_time

    logs_per_sec = total_runs / elapsed if elapsed > 0 else 0.0
    avg_latency_ms = (elapsed / total_runs) * 1000 if total_runs > 0 else 0.0

    return {
        "dataset_size": len(rows),
        "benchmark_runs": total_runs,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "throughput_logs_per_sec": round(logs_per_sec, 2),
        "avg_latency_ms": round(avg_latency_ms, 4),
    }


if __name__ == "__main__":
    results = run_benchmark(iterations=200)
    print("=" * 45)
    print(" VaultlessSecrets Detection Benchmark")
    print("=" * 45)
    print(f"Dataset Size:           {results['dataset_size']} logs")
    print(f"Precision:              {results['precision'] * 100:.1f}%")
    print(f"Recall:                 {results['recall'] * 100:.1f}%")
    print(f"F1 Score:               {results['f1_score'] * 100:.1f}%")
    print(f"Throughput:             {results['throughput_logs_per_sec']:,} logs/sec")
    print(f"Avg Latency:            {results['avg_latency_ms']} ms/log")
    print("=" * 45)
