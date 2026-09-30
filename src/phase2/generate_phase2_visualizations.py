"""Publication-Quality Figure Generator for Phase 2 Multi-Agent Investigation Architecture.

Generates 8 professional, high-resolution figures saved to results/figures/phase2/:
1. fig1_baseline_vs_multiagent.png: Precision, Recall, F1 comparison
2. fig2_agent_ablation.png: Progressive metrics across ablation configurations
3. fig3_correlation_window.png: Impact of 5m, 10m, 30m windows on incidents and precision
4. fig4_confusion_matrix_baseline.png: Heatmap of Phase 1 Baseline confusion matrix
5. fig5_confusion_matrix_multiagent.png: Heatmap of Phase 2 Multi-Agent confusion matrix
6. fig6_incident_severity_distribution.png: Breakdown of incident severity levels
7. fig7_agent_contributions.png: Number of findings and telemetry volume per specialist agent
8. fig8_incident_timeline_lifecycle.png: Multi-stage timeline of an attack incident through the agent pipeline
"""

import sys
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
FIGURES_DIR = PROJECT_ROOT / "results" / "figures" / "phase2"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

# Set high-DPI modern publication aesthetics
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 12,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "figure.autolayout": True,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linestyle": "--"
})

DARK_BG = "#0f172a"
PANEL_BG = "#1e293b"
TEXT_COLOR = "#f8fafc"
ACCENT_BLUE = "#38bdf8"
ACCENT_PURPLE = "#a855f7"
ACCENT_RED = "#f43f5e"
ACCENT_GREEN = "#10b981"
ACCENT_AMBER = "#f59e0b"


def set_dark_theme(fig, ax):
    fig.patch.set_facecolor(DARK_BG)
    if isinstance(ax, np.ndarray):
        for a in ax.flat:
            a.set_facecolor(PANEL_BG)
            a.tick_params(colors=TEXT_COLOR)
            a.xaxis.label.set_color(TEXT_COLOR)
            a.yaxis.label.set_color(TEXT_COLOR)
            a.title.set_color(TEXT_COLOR)
            for spine in a.spines.values():
                spine.set_color("#475569")
    else:
        ax.set_facecolor(PANEL_BG)
        ax.tick_params(colors=TEXT_COLOR)
        ax.xaxis.label.set_color(TEXT_COLOR)
        ax.yaxis.label.set_color(TEXT_COLOR)
        ax.title.set_color(TEXT_COLOR)
        for spine in ax.spines.values():
            spine.set_color("#475569")


def plot_fig1_baseline_vs_multiagent():
    """Fig 1: Baseline vs Multi-Agent (Precision, Recall, F1)."""
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    set_dark_theme(fig, ax)

    categories = ["Precision (%)", "Recall (%)", "F1-Score (%)", "Specificity (%)"]
    baseline_vals = [0.84, 100.0, 1.66, 54.70]
    multiagent_vals = [0.89, 100.0, 1.76, 57.30]

    x = np.arange(len(categories))
    width = 0.35

    rects1 = ax.bar(x - width/2, baseline_vals, width, label="Phase 1 Baseline", color="#64748b", edgecolor="#94a3b8")
    rects2 = ax.bar(x + width/2, multiagent_vals, width, label="Phase 2 Multi-Agent (Prioritized)", color=ACCENT_BLUE, edgecolor="#7dd3fc")

    ax.set_ylabel("Metric Percentage (%)")
    ax.set_title("Detection Performance: Phase 1 Baseline vs. Phase 2 Multi-Agent")
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend(facecolor=PANEL_BG, edgecolor="#475569", labelcolor=TEXT_COLOR)
    ax.set_ylim(0, 115)

    for rect in rects1:
        h = rect.get_height()
        ax.annotate(f"{h:.2f}%", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", color=TEXT_COLOR, fontsize=9)
    for rect in rects2:
        h = rect.get_height()
        ax.annotate(f"{h:.2f}%", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", color=ACCENT_BLUE, fontweight="bold", fontsize=9)

    out_file = FIGURES_DIR / "fig1_baseline_vs_multiagent.png"
    plt.savefig(out_file, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"Saved {out_file}")


def plot_fig2_agent_ablation():
    """Fig 2: Progressive performance across ablation configurations."""
    fig, ax1 = plt.subplots(figsize=(10, 5), dpi=300)
    set_dark_theme(fig, ax1)

    configs = [
        "A: Baseline",
        "B: AuthAgent",
        "C: Auth+Proc",
        "D: All Specialists",
        "E: +Correlation",
        "F: Full Pipeline"
    ]
    recall = [100.0, 0.0, 0.0, 100.0, 100.0, 100.0]
    precision = [0.84, 0.00, 0.00, 0.86, 0.86, 0.89]
    incidents = [1105, 0, 0, 0, 1075, 1075]

    x = np.arange(len(configs))

    color = ACCENT_BLUE
    ax1.set_xlabel("Agent Architecture Configuration")
    ax1.set_ylabel("Recall / Specificity (%)", color=color)
    line1 = ax1.plot(x, recall, marker="o", color=ACCENT_GREEN, linewidth=2.5, label="Recall (%)")
    ax1.tick_params(axis="y", labelcolor=ACCENT_GREEN)
    ax1.set_ylim(-5, 115)

    ax2 = ax1.twinx()
    ax2.set_facecolor(PANEL_BG)
    line2 = ax2.plot(x, precision, marker="s", color=ACCENT_PURPLE, linewidth=2.5, linestyle="--", label="Precision (%)")
    ax2.set_ylabel("Precision (%)", color=ACCENT_PURPLE)
    ax2.tick_params(axis="y", labelcolor=ACCENT_PURPLE)
    ax2.spines["right"].set_color(ACCENT_PURPLE)
    ax2.spines["left"].set_color(ACCENT_GREEN)
    ax2.set_ylim(-0.1, 1.2)

    ax1.set_xticks(x)
    ax1.set_xticklabels(configs, rotation=15, ha="right")
    ax1.set_title("Agent Ablation Study: Progressive Marginal Contributions")

    # Combine legends
    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="center left", facecolor=PANEL_BG, edgecolor="#475569", labelcolor=TEXT_COLOR)

    out_file = FIGURES_DIR / "fig2_agent_ablation.png"
    plt.savefig(out_file, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"Saved {out_file}")


def plot_fig3_correlation_window():
    """Fig 3: Correlation Window Sensitivity (5m, 10m, 30m)."""
    fig, ax1 = plt.subplots(figsize=(8, 5), dpi=300)
    set_dark_theme(fig, ax1)

    windows = ["5 Minutes\n(300s)", "10 Minutes\n(600s - Baseline)", "30 Minutes\n(1800s)"]
    incidents = [1554, 1075, 652]
    rt_incidents = [75, 38, 7]

    x = np.arange(len(windows))
    width = 0.35

    rects1 = ax1.bar(x - width/2, incidents, width, label="Total Incidents Formed", color=ACCENT_BLUE, edgecolor="#7dd3fc")
    rects2 = ax1.bar(x + width/2, rt_incidents, width, label="Red-Team Attack Incidents", color=ACCENT_AMBER, edgecolor="#fcd34d")

    ax1.set_ylabel("Incident Count")
    ax1.set_title("Impact of Correlation Sliding Window on Incident Clustering")
    ax1.set_xticks(x)
    ax1.set_xticklabels(windows)
    ax1.legend(facecolor=PANEL_BG, edgecolor="#475569", labelcolor=TEXT_COLOR)
    ax1.set_ylim(0, 1800)

    for rect in rects1:
        h = rect.get_height()
        ax1.annotate(f"{h:,}", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3),
                     textcoords="offset points", ha="center", va="bottom", color=TEXT_COLOR, fontsize=9)
    for rect in rects2:
        h = rect.get_height()
        ax1.annotate(f"{h:,}", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3),
                     textcoords="offset points", ha="center", va="bottom", color=ACCENT_AMBER, fontweight="bold", fontsize=9)

    out_file = FIGURES_DIR / "fig3_correlation_window.png"
    plt.savefig(out_file, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"Saved {out_file}")


def plot_fig4_confusion_matrix_baseline():
    """Fig 4: Confusion Matrix for Phase 1 Baseline."""
    fig, ax = plt.subplots(figsize=(6, 5), dpi=300)
    set_dark_theme(fig, ax)

    cm = np.array([[497, 0], [58885, 71115]])
    im = ax.imshow(cm, interpolation="nearest", cmap="Blues")

    ax.set_title("Phase 1 Baseline Confusion Matrix")
    tick_marks = np.arange(2)
    ax.set_xticks(tick_marks)
    ax.set_yticks(tick_marks)
    ax.set_xticklabels(["Predicted Attack", "Predicted Benign"])
    ax.set_yticklabels(["Actual Attack", "Actual Benign"])

    thresh = cm.max() / 2.
    labels = [["TP: 497\n(100.0%)", "FN: 0\n(0.0%)"],
              ["FP: 58,885\n(45.3%)", "TN: 71,115\n(54.7%)"]]

    for i in range(2):
        for j in range(2):
            val_str = labels[i][j]
            ax.text(j, i, val_str, ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "#0f172a",
                    fontweight="bold", fontsize=11)

    ax.set_ylabel("Ground Truth")
    ax.set_xlabel("Baseline Classification")

    out_file = FIGURES_DIR / "fig4_confusion_matrix_baseline.png"
    plt.savefig(out_file, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"Saved {out_file}")


def plot_fig5_confusion_matrix_multiagent():
    """Fig 5: Confusion Matrix for Phase 2 Multi-Agent."""
    fig, ax = plt.subplots(figsize=(6, 5), dpi=300)
    set_dark_theme(fig, ax)

    cm = np.array([[497, 0], [55505, 74495]])
    im = ax.imshow(cm, interpolation="nearest", cmap="Purples")

    ax.set_title("Phase 2 Multi-Agent Confusion Matrix (Prioritized)")
    tick_marks = np.arange(2)
    ax.set_xticks(tick_marks)
    ax.set_yticks(tick_marks)
    ax.set_xticklabels(["Predicted Attack", "Predicted Benign"])
    ax.set_yticklabels(["Actual Attack", "Actual Benign"])

    thresh = cm.max() / 2.
    labels = [["TP: 497\n(100.0%)", "FN: 0\n(0.0%)"],
              ["FP: 55,505\n(-3,380 FPs)", "TN: 74,495\n(+3,380 TNs)"]]

    for i in range(2):
        for j in range(2):
            val_str = labels[i][j]
            ax.text(j, i, val_str, ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "#0f172a",
                    fontweight="bold", fontsize=11)

    ax.set_ylabel("Ground Truth")
    ax.set_xlabel("Multi-Agent Classification")

    out_file = FIGURES_DIR / "fig5_confusion_matrix_multiagent.png"
    plt.savefig(out_file, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"Saved {out_file}")


def plot_fig6_severity_distribution():
    """Fig 6: Correlated Incident Severity Distribution."""
    fig, ax = plt.subplots(figsize=(7, 5), dpi=300)
    set_dark_theme(fig, ax)

    severities = ["Critical\n(Risk >= 75)", "High\n(Risk 50-74)", "Medium\n(Risk 25-49)", "Low\n(Risk < 25)"]
    counts = [55, 142, 874, 4]
    colors = [ACCENT_RED, ACCENT_AMBER, ACCENT_BLUE, "#64748b"]

    bars = ax.bar(severities, counts, color=colors, edgecolor=TEXT_COLOR, width=0.55)
    ax.set_ylabel("Number of Reconstructed Incidents")
    ax.set_title("Phase 2 Multi-Agent: Incident Severity Distribution (N=1,075)")
    ax.set_ylim(0, 1000)

    for bar in bars:
        h = bar.get_height()
        ax.annotate(f"{h:,}", xy=(bar.get_x() + bar.get_width()/2, h), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", color=TEXT_COLOR, fontweight="bold", fontsize=10)

    out_file = FIGURES_DIR / "fig6_incident_severity_distribution.png"
    plt.savefig(out_file, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"Saved {out_file}")


def plot_fig7_agent_contributions():
    """Fig 7: Number of findings and telemetry volume per specialist agent."""
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    set_dark_theme(fig, ax)

    agents = ["AuthenticationAgent\n(AUTH)", "ProcessAgent\n(PROCESS)", "NetworkAgent\n(FLOW/DNS)", "RedTeamTele\n(Ground Truth)"]
    telemetry_analyzed = [55000, 25000, 50000, 497]
    findings_flagged = [52277, 4984, 278, 497]

    x = np.arange(len(agents))
    width = 0.35

    rects1 = ax.bar(x - width/2, telemetry_analyzed, width, label="Raw Telemetry Ingested", color="#475569", edgecolor="#94a3b8")
    rects2 = ax.bar(x + width/2, findings_flagged, width, label="Specialist Findings Flagged", color=ACCENT_PURPLE, edgecolor="#d8b4fe")

    ax.set_ylabel("Event Count (Log Scale)")
    ax.set_yscale("log")
    ax.set_title("Specialist Agent Workload and Suspicious Telemetry Yield")
    ax.set_xticks(x)
    ax.set_xticklabels(agents)
    ax.legend(facecolor=PANEL_BG, edgecolor="#475569", labelcolor=TEXT_COLOR)

    for rect in rects2:
        h = rect.get_height()
        ax.annotate(f"{h:,}", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", color=ACCENT_PURPLE, fontweight="bold", fontsize=9)

    out_file = FIGURES_DIR / "fig7_agent_contributions.png"
    plt.savefig(out_file, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"Saved {out_file}")


def plot_fig8_incident_timeline_lifecycle():
    """Fig 8: Multi-stage timeline of an attack incident through the agent pipeline."""
    fig, ax = plt.subplots(figsize=(10, 4.5), dpi=300)
    set_dark_theme(fig, ax)

    stages = [
        "1. Ingestion\n& Dispatch",
        "2. Specialist\nAgents",
        "3. Correlation\nAgent",
        "4. Analysis\nAgent",
        "5. Response\nAgent",
        "6. Human\nSOC Review"
    ]
    x_pos = np.arange(len(stages))
    y_pos = np.ones(len(stages))

    # Connect nodes with gradient flow line
    ax.plot(x_pos, y_pos, color=ACCENT_BLUE, linewidth=3, zorder=1)

    node_colors = [ACCENT_BLUE, ACCENT_PURPLE, ACCENT_AMBER, ACCENT_RED, ACCENT_GREEN, "#e2e8f0"]
    descriptions = [
        "130,497 raw events\npartitioned by domain",
        "Auth (52k), Proc (5k)\nNet (278) findings",
        "±10 min sliding window\n1,075 incidents formed",
        "Transparent Risk (91)\n& Confidence (62)",
        "P1 Isolation playbook\n(No destructive auto)",
        "Analyst Approval\nMandatory Sign-off"
    ]

    for i in range(len(stages)):
        ax.scatter(x_pos[i], y_pos[i], s=550, color=node_colors[i], edgecolors="white", linewidth=2, zorder=2)
        ax.text(x_pos[i], y_pos[i] + 0.12, stages[i], ha="center", va="bottom", color=TEXT_COLOR, fontweight="bold", fontsize=10)
        ax.text(x_pos[i], y_pos[i] - 0.15, descriptions[i], ha="center", va="top", color="#94a3b8", fontsize=8.5)

    ax.set_xlim(-0.6, len(stages) - 0.4)
    ax.set_ylim(0.6, 1.4)
    ax.axis("off")
    ax.set_title("End-to-End Multi-Agent Investigation Architecture Lifecycle", color=TEXT_COLOR, fontsize=13, pad=20)

    out_file = FIGURES_DIR / "fig8_incident_timeline_lifecycle.png"
    plt.savefig(out_file, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"Saved {out_file}")


def main():
    print("Generating all 8 publication-quality figures for Phase 2...")
    plot_fig1_baseline_vs_multiagent()
    plot_fig2_agent_ablation()
    plot_fig3_correlation_window()
    plot_fig4_confusion_matrix_baseline()
    plot_fig5_confusion_matrix_multiagent()
    plot_fig6_severity_distribution()
    plot_fig7_agent_contributions()
    plot_fig8_incident_timeline_lifecycle()
    print("\nAll 8 figures successfully generated in results/figures/phase2/!")


if __name__ == "__main__":
    main()
