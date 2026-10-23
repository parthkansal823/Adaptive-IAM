"""Export the measured real-log training comparison; never infer negative labels."""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

ROOT = Path(__file__).resolve().parents[1]
METHODS = ("lifetime_user_computer", "hierarchical_static", "hierarchical_decay", "isolation_forest", "isolation_forest_tuned")
LABELS = ("Lifetime", "Backoff", "Decay", "IF fixed", "IF selected")
COLORS = ("#697782", "#287ca3", "#d17b26", "#8064aa", "#238778")
SOURCES = (("lanl2015_retrospective", "2015: retrospective exercise sample"),
           ("lanl2014_month00", "2014 first slice: no attack labels"),
           ("lanl2014_month01", "2014 later slice: no attack labels"))


def main():
    report = json.loads((ROOT / "experiments/real-auth-training.json").read_text(encoding="utf-8"))
    if report.get("schema_version") != "real-auth-training-v1" or report.get("status") != "measured":
        raise ValueError("Generate the measured training report first")
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    figure, axes = plt.subplots(2, 2, figsize=(13, 8), constrained_layout=True)
    for axis, (key, title) in zip(axes.flat, SOURCES):
        dataset = report["datasets"][key]
        denominator = dataset["partitions"]["test"]["unlabeled_events"]
        values = [dataset["methods"][name]["alert_fraction_over_unlabeled"] for name in METHODS]
        if not denominator or any(value is None for value in values):
            raise ValueError("A plotted denominator is unavailable")
        axis.bar(LABELS, values, color=COLORS)
        axis.set(title=title, ylabel="Alerts / unlabeled test events", ylim=(0, max(.012, max(values) * 1.35)))
        axis.yaxis.set_major_formatter(PercentFormatter(1))
        axis.set_axisbelow(True); axis.grid(axis="y", alpha=.18)
        axis.axhline(.01, color="#9b3a40", linestyle="--", linewidth=1, label="Validation budget; no test guarantee")
        for index, name in enumerate(METHODS):
            count = dataset["methods"][name]["unlabeled_alerts"]
            axis.annotate(f"{count:,}\n{values[index]:.3%}", (index, values[index]), xytext=(0, 4),
                          textcoords="offset points", ha="center", fontsize=8,
                          bbox={"facecolor": "white", "edgecolor": "none", "alpha": .95, "pad": 1})
        axis.set_xlabel(f"{denominator:,} unlabeled test events; individual panel scale")
        axis.legend(loc="upper right", fontsize=7)
    dataset = report["datasets"]["lanl2015_retrospective"]
    denominator = dataset["partitions"]["test"]["known_redteam_unique_tuples"]
    if not dataset["labels"]["detection_metrics_eligible"] or not denominator:
        raise ValueError("Exercise tuple recall is unavailable")
    recalled = [dataset["methods"][name]["known_redteam_recalled_unique_tuples"] for name in METHODS]
    axis = axes[1, 1]
    axis.bar(LABELS, recalled, color=COLORS)
    axis.set(title="2015 known exercise tuples", ylabel="Distinct tuples flagged", ylim=(0, denominator * 1.1),
             xlabel="Ten clustered exercise tuples; retrospective comparison")
    axis.set_yticks(range(0, denominator + 1, max(1, denominator // 5)))
    axis.set_axisbelow(True); axis.grid(axis="y", alpha=.18)
    for index, count in enumerate(recalled):
        axis.annotate(f"{count} / {denominator}", (index, count), xytext=(0, 4), textcoords="offset points", ha="center")
    figure.suptitle("Actual warmup training and chronological validation search on real logs\nSelected IF optimizes validation budget stability; alert burden is not false-positive rate", fontsize=13)
    output = ROOT / "experiments/figures"
    output.mkdir(parents=True, exist_ok=True)
    for extension in ("svg", "png"):
        figure.savefig(output / f"real-auth-training.{extension}", dpi=180)
    plt.close(figure)
    print("Exported real-auth-training.svg and real-auth-training.png from the measured report.")


if __name__ == "__main__":
    main()
