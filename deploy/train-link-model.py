#!/usr/bin/env python3
"""Train Cuven's link health classifier on labeled local measurements."""

import argparse
import csv
import json
import math
from pathlib import Path
import random


def features(rtt, minimum, variation, loss):
    base = max(minimum, 1)
    return [
        min(max(rtt / base - 1, 0), 8) / 8,
        min(max(variation / base, 0), 8) / 8,
        loss,
        1,
    ]


def demo_samples(rng):
    """Synthetic healthy and degraded link samples for testing the pipeline."""
    for i in range(2400):
        baseline = rng.uniform(5, 180)
        label = i % 2
        multiplier = rng.uniform(1.0, 1.65) if label == 0 else rng.uniform(1.8, 5.0)
        variation = rng.uniform(0.01, 0.15) if label == 0 else rng.uniform(0.2, 1.8)
        loss = rng.uniform(0, 0.015) if label == 0 else rng.uniform(0.025, 0.45)
        yield features(baseline * multiplier, baseline, baseline * variation, loss), label


def load_samples(path):
    columns = ("rtt_ms", "min_rtt_ms", "variation_ms", "loss_ratio", "degraded")
    with path.open(newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            rtt, minimum, variation, loss, label = map(float, (row[key] for key in columns))
            values = (rtt, minimum, variation, loss)
            if any(not math.isfinite(v) or v < 0 for v in values):
                raise ValueError("measurement values must be finite and nonnegative")
            if minimum <= 0 or rtt < minimum or loss > 1 or label not in (0, 1):
                raise ValueError("invalid minimum RTT, loss ratio or class label")
            yield features(*values), label


def predict(hidden, output, inputs):
    activations = [math.tanh(sum(x * w for x, w in zip(inputs, row))) for row in hidden]
    logit = sum(a * w for a, w in zip(activations, output)) + output[-1]
    return 1 / (1 + math.exp(-max(-50, min(logit, 50)))), activations


def train(samples, rng):
    width = 6
    hidden = [[rng.uniform(-0.2, 0.2) for _ in range(4)] for _ in range(width)]
    output = [rng.uniform(-0.2, 0.2) for _ in range(width + 1)]
    for _ in range(18):
        rng.shuffle(samples)
        for inputs, label in samples:
            probability, activations = predict(hidden, output, inputs)
            delta = (probability - label) * 0.03
            for i, activation in enumerate(activations):
                change = delta * output[i] * (1 - activation * activation)
                for k, input_value in enumerate(inputs):
                    hidden[i][k] -= change * input_value
                output[i] -= delta * activation
            output[-1] -= delta
    return hidden, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--csv", type=Path)
    source.add_argument("--demo", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rng = random.Random(2026)
    samples = list(demo_samples(rng) if args.demo else load_samples(args.csv))
    training, validation = [], []
    for label in (0, 1):
        group = [(x, y) for x, y in samples if y == label]
        if len(group) < 20:
            parser.error("at least 20 labeled samples per class are required")
        rng.shuffle(group)
        cutoff = len(group) * 4 // 5
        training.extend(group[:cutoff])
        validation.extend(group[cutoff:])
    hidden, output = train(training, rng)
    tp = tn = fp = fn = 0
    for inputs, label in validation:
        score, _ = predict(hidden, output, inputs)
        if label:
            tp, fn = (tp + 1, fn) if score >= 0.8 else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if score >= 0.8 else (fp, tn + 1)
    args.output.write_text(json.dumps({"version": 1, "hidden": hidden, "output": output}) + "\n")
    kind = "synthetic demo" if args.demo else "held-out rows"
    print(f"{kind}, threshold 0.8: TP={tp} TN={tn} FP={fp} FN={fn}")


if __name__ == "__main__":
    main()
