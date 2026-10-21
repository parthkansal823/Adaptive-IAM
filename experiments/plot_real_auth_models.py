"""Export measured real-log model comparisons without treating unknown labels as benign."""
from pathlib import Path
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter


ROOT = Path(__file__).resolve().parents[1]
METHODS = ("lifetime_user_computer", "hierarchical_static", "hierarchical_decay")
LABELS = ("Lifetime\ncontrol", "Global\nbackoff", "Backoff\n+ decay")
COLORS = ("#697782", "#287ca3", "#d17b26")


def main():
    report = json.loads((ROOT / "experiments/real-auth-model-study.json").read_text(encoding="utf-8"))
    if report.get("schema_version") != "real-auth-model-study-v1" or report.get("status") != "measured":
        raise ValueError("Generate the measured real-auth model report first")
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    figure, axes = plt.subplots(1, 3, figsize=(14, 4.6), constrained_layout=True)
    for axis, key, title in zip(axes[:2], ("lanl2015_retrospective", "lanl2014_unlabeled"),
                                ("2015 release: retrospective", "2014 release: no attack labels")):
        dataset = report["datasets"][key]
        denominator = dataset["partitions"]["test"]["unlabeled_events"]
        values = [dataset["methods"][name]["alert_fraction_over_unlabeled"] for name in METHODS]
        if not denominator or any(value is None for value in values):
            raise ValueError("A plotted unlabeled denominator is unavailable")
        axis.bar(LABELS, values, color=COLORS, width=.65)
        axis.axhline(report["protocol"]["validation_alert_budget"], color="#9b3a40", linestyle="--", linewidth=1,
                     label="Validation budget; no test guarantee")
        axis.set(title=title, ylabel="Alerts / unlabeled test events", ylim=(0, max(.012, max(values) * 1.3)))
        axis.yaxis.set_major_formatter(PercentFormatter(1))
        axis.set_axisbelow(True)
        axis.grid(axis="y", alpha=.18)
        for index, name in enumerate(METHODS):
            count = dataset["methods"][name]["unlabeled_alerts"]
            axis.annotate(f"{count:,} / {denominator:,}\n{values[index]:.3%}", (index, values[index]),
                          xytext=(0, 5), textcoords="offset points", ha="center", fontsize=8,
                          bbox={"facecolor": "white", "edgecolor": "none", "alpha": .95, "pad": 1})
        axis.legend(loc="upper right", fontsize=7)
    labelled = report["datasets"]["lanl2015_retrospective"]
    denominator = labelled["partitions"]["test"]["known_redteam_unique_tuples"]
    if not labelled["labels"]["detection_metrics_eligible"] or not denominator:
        raise ValueError("Exercise tuple recall is unavailable")
    recalled = [labelled["methods"][name]["known_redteam_recalled_unique_tuples"] for name in METHODS]
    axes[2].bar(LABELS, recalled, color=COLORS, width=.65)
    axes[2].set(title="2015 listed exercise tuples", ylabel="Distinct known tuples flagged", ylim=(0, denominator * 1.1),
                xlabel="Clustered exercise events; retrospective sample")
    axes[2].set_yticks(range(0, denominator + 1, max(1, denominator // 5)))
    axes[2].set_axisbelow(True)
    axes[2].grid(axis="y", alpha=.18)
    for index, value in enumerate(recalled):
        axes[2].annotate(f"{value} / {denominator}", (index, value), xytext=(0, 5), textcoords="offset points", ha="center")
    figure.suptitle("Fixed novelty models on two real LANL releases\nUnlabeled alert burden is not false-positive rate; no production accuracy claim", fontsize=13)
    output = ROOT / "experiments/figures"
    output.mkdir(parents=True, exist_ok=True)
    for extension in ("svg", "png"):
        figure.savefig(output / f"real-auth-models.{extension}", dpi=180)
    plt.close(figure)
    print("Exported real-auth-models.svg and real-auth-models.png from the measured report.")


if __name__ == "__main__":
    main()
