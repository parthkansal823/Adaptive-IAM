"""Export fixed-bin reliability, repeated-policy and multilingual evidence figures."""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent


def pooled_bins(runs, key):
    result = []
    for index in range(10):
        rows = [run[key]["reliability"]["bins"][index] for run in runs]
        total = sum(row["count"] for row in rows)
        if total:
            result.append((sum(row["mean_probability"]*row["count"] for row in rows if row["count"])/total,
                           sum(row["observed_positive_rate"]*row["count"] for row in rows if row["count"])/total))
    return np.asarray(result)


def main():
    risk = json.loads((ROOT/"risk-protocol.json").read_text())
    text = json.loads((ROOT/"multilingual-results.json").read_text())
    plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
                         "svg.fonttype": "none", "figure.facecolor": "white"})
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.2), layout="constrained")
    for key, label, color in [("paper_baseline", "Raw", "#171717"), ("calibrated_validation_matched", "Calibrated", "#ee7415")]:
        points = pooled_bins(risk["runs"], key)
        axes[0].plot(points[:, 0], points[:, 1], "o-", label=label, color=color)
    axes[0].plot([0, 1], [0, 1], "--", color="#888888", linewidth=1)
    axes[0].set(title="A  Pooled fixed-bin reliability", xlabel="Mean predicted probability", ylabel="Observed synthetic positive rate", xlim=(0, 1), ylim=(0, 1))
    axes[0].legend(frameon=False)
    models = ["paper_baseline", "raw_validation_matched", "calibrated_validation_matched", "calibrated_80percent_policy"]
    fields = [("suspicious_challenge_or_block_recall", "Detection", "#171717"), ("legitimate_friction_rate", "Legitimate friction", "#ee7415")]
    positions = np.arange(4)
    for i, (field, label, color) in enumerate(fields):
        means = [risk["summary"][model][field]["mean"]*100 for model in models]
        spread = [risk["summary"][model][field]["sample_std"]*100 for model in models]
        axes[1].bar(positions+(i-.5)*.36, means, .36, yerr=spread, capsize=3, label=label, color=color)
    axes[1].set(title="B  Full retraining, five seeds", ylabel="Rate (%) · bars mean ± sample SD", ylim=(0, 100))
    axes[1].set_xticks(positions, ["Paper\ncutoffs", "Raw\nmatched", "Calibrated\nmatched", "80% val.\ntarget"], fontsize=8)
    axes[1].legend(frameon=False, fontsize=8)
    languages = ["en", "hi", "hinglish"]
    for i, (field, label, color) in enumerate([("suspicious_flag_rate", "Suspicious flagged / 3", "#171717"), ("legitimate_flag_rate", "Benign flagged / 3", "#ee7415"), ("abstentions", "Abstained / 6", "#b8b8b8")]):
        values = [text["by_language"][lang]["runtime_advisory"][field]*(100/6 if field == "abstentions" else 100) for lang in languages]
        axes[2].bar(np.arange(3)+(i-1)*.24, values, .24, label=label, color=color)
    axes[2].set(title="C  Author language diagnostics", ylabel="Rate (%) · six translated items/language", ylim=(0, 132))
    axes[2].set_yticks([0, 25, 50, 75, 100])
    axes[2].set_xticks(np.arange(3), ["English", "Hindi", "Hinglish"])
    axes[2].legend(frameon=False, fontsize=7, loc="upper left")
    fig.suptitle("Adaptive IAM: probability calibration does not establish stronger detection", fontsize=12)
    target = ROOT/"figures"
    target.mkdir(exist_ok=True)
    for extension in ["svg", "png"]:
        fig.savefig(target/f"validation-controls.{extension}", dpi=180)
    print("Wrote experiments/figures/validation-controls.svg and .png")


if __name__ == "__main__":
    main()
