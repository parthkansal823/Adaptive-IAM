"""Generate shareable scientific figures from the saved measured evidence."""
from pathlib import Path
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
report = json.loads((ROOT / "experiments/results.json").read_text(encoding="utf-8"))
robustness = json.loads((ROOT / "experiments/robustness.json").read_text(encoding="utf-8"))
out = ROOT / "experiments/figures"
out.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False, "savefig.dpi": 220})
fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.2), layout="constrained")
keys = ["accuracy", "precision", "recall", "f1", "roc_auc"]
x = np.arange(len(keys))
axes[0].bar(x-.18, [report["baseline"][k] for k in keys], .36, label="Raw paper blend", color="#737373")
axes[0].bar(x+.18, [report["improved"][k] for k in keys], .36, label="Calibrated candidate", color="#c2410c")
axes[0].set(xticks=x, xticklabels=["Accuracy", "Precision", "Recall", "F1", "ROC AUC"], ylim=(0, 1), ylabel="Score", title="Held-out classification (n = 2,000)")
axes[0].legend(fontsize=8)
policy_keys = ["suspicious_challenge_or_block_recall", "legitimate_friction_rate", "blocked_legitimate_rate"]
px = np.arange(len(policy_keys))
axes[1].bar(px-.18, [report["baseline"][k] for k in policy_keys], .36, color="#737373")
axes[1].bar(px+.18, [report["improved"][k] for k in policy_keys], .36, color="#c2410c")
axes[1].set(xticks=px, xticklabels=["Attack challenge\nor block", "Benign MFA\nor block", "Benign\nblock"], ylim=(0, 1), ylabel="Rate", title="Authentication policy trade-off")
fig.suptitle("Adaptive IAM: synthetic evidence, not deployment performance", fontsize=12)
fig.savefig(out / "risk-comparison.png")
fig.savefig(out / "risk-comparison.svg")
plt.close(fig)

pair = robustness["paired_comparison"]
fig, ax = plt.subplots(figsize=(8, 3.5), layout="constrained")
labels = ["F1 score", "Brier error", "Policy detection", "Benign friction"]
keys = ["f1", "brier_score", "policy_detection_recall", "legitimate_friction_rate"]
values = np.array([pair[k]["difference_candidate_minus_baseline"] for k in keys])
low = np.array([pair[k]["ci95"][0] for k in keys])
high = np.array([pair[k]["ci95"][1] for k in keys])
ax.errorbar(values, np.arange(4), xerr=np.vstack([values-low, high-values]), fmt="o", color="#c2410c", capsize=5)
ax.axvline(0, color="#777", linewidth=1, linestyle="--")
ax.set(yticks=np.arange(4), yticklabels=labels, xlabel="Candidate minus baseline (lower favors Brier and friction)", title="Paired stratified bootstrap: 95% percentile intervals")
fig.savefig(out / "paired-uncertainty.png")
fig.savefig(out / "paired-uncertainty.svg")
plt.close(fig)
print(f"Figures saved in {out}")
