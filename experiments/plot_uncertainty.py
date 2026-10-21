"""Export the frozen synthetic uncertainty study; never modifies measurements."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
import numpy as np

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "experiments/uncertainty-study.json")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "experiments/figures")
    args = parser.parse_args()
    report = json.loads(args.input.read_text(encoding="utf-8"))
    summary = report["summary"]
    conditions = list(summary)
    labels = [name.replace("_", "\n").replace("iid", "IID") for name in conditions]
    methods = [("baseline", "Validation baseline", "#727272"), ("marginal_gate", "Marginal conformal gate", "#3873a8"), ("class_conditional_gate", "Class conditional gate", "#c45a13"), ("always_challenge", "Always challenge", "#252525")]
    panels = [("suspicious_detection_rate", "Suspicious verification rate"), ("legitimate_friction_rate", "Legitimate verification burden"), ("suspicious_coverage", "Suspicious label set coverage")]
    plt.rcParams.update({"font.size": 10, "svg.fonttype": "none", "axes.spines.top": False, "axes.spines.right": False})
    figure, axes = plt.subplots(1, 3, figsize=(15, 5), constrained_layout=True)
    for axis, (metric, heading) in zip(axes, panels):
        selected = [item for item in methods if metric in summary[conditions[0]][item[0]]]
        width = .8 / len(selected)
        for index, (method, label, color) in enumerate(selected):
            values = [summary[name][method][metric] for name in conditions]
            positions = np.arange(len(conditions)) + (index - (len(selected) - 1) / 2) * width
            axis.bar(positions, [value["mean"] for value in values], width, color=color, label=label, yerr=[value["sample_std"] for value in values], capsize=2, error_kw={"linewidth": .8})
        if metric == "suspicious_coverage":
            axis.axhline(1 - report["alpha"], color="#a32929", linestyle="--", linewidth=1, label="Class-conditional IID target")
            axis.set_xlabel("Marginal sets have no class-specific coverage target.", fontsize=8)
        axis.set(title=heading, xticks=np.arange(len(conditions)), xticklabels=labels, ylim=(0, 1.06))
        axis.yaxis.set_major_formatter(PercentFormatter(1))
        axis.grid(axis="y", alpha=.18)
        axis.set_axisbelow(True)
        axis.legend(loc="lower left", fontsize=7, framealpha=.95)
    figure.suptitle(f"Synthetic IAM uncertainty stress study · {len(report['seeds'])} fresh fits\nBars: seed means; error bars: sample SD. Distribution shift has no general coverage guarantee.", fontsize=12)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for suffix in ("svg", "png"):
        figure.savefig(args.output_dir / f"uncertainty-study.{suffix}", dpi=180, metadata={"Description": "Synthetic measurements from uncertainty-study.json; not deployment outcomes."})
    plt.close(figure)
    print("Exported uncertainty-study.svg and uncertainty-study.png from the measured report.")


if __name__ == "__main__":
    main()
