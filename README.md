# AI Investigator for Cybersecurity Threat Detection and Response

An explainable, multi-source cybersecurity investigation and threat triage pipeline built using the **Los Alamos National Laboratory (LANL) Comprehensive Multi-Source Cyber-Security Events Dataset**. 

This system ingests multi-source host and network telemetry (Authentication, Process Execution, DNS, and Network Flow), performs explainable rule-based threat triage, correlates related telemetry across entities (users and hosts) into multi-stage incidents, computes calibrated Risk and Confidence scores, supports human analyst review via an interactive dashboard, and rigorously evaluates detection performance against known Red-Team ground truth.

---

## 🔒 Defensive Research Scope
This is an academic, defensive cybersecurity research project. All algorithms, detection logic, and correlation rules operate exclusively on the downloaded, sanitized LANL dataset. No live network scanning, penetration testing, or offensive actions are performed.

---

## 📂 Project Structure

```
mini_proj/
├── data/
│   ├── raw/                       # LANL raw datasets (auth.txt.gz, proc.txt.gz, etc.)
│   ├── subset/                    # Extracted Day 9-13 subsets
│   │   ├── redteam_subset.csv     # 497 validated redteam attacks
│   │   └── multisource_subset.csv # Multi-source telemetry subset (~100k events)
│   └── processed/                 # Cleaned, triaged, and correlated datasets
│       ├── events_processed.csv   # Normalized & chronologically sorted events
│       ├── triaged_events.csv     # Events with risk scores & explainable reasons
│       ├── incidents.csv          # Correlated multi-stage security incidents
│       ├── incident_events.csv    # Event-to-incident mapping table
│       ├── human_review_queue.csv # Tier-1 SOC analyst review queue
│       └── evaluation_results.csv # TP, TN, FP, FN, Precision, Recall, F1
├── results/
│   ├── figures/                   # 8 Publication-grade visualizations (300 DPI)
│   │   ├── redteam_activity_timeline.png
│   │   ├── event_source_distribution.png
│   │   ├── event_type_distribution.png
│   │   ├── risk_score_distribution.png
│   │   ├── suspicious_events_timeline.png
│   │   ├── incident_severity_confidence.png
│   │   ├── detection_performance_metrics.png
│   │   └── incident_attack_timeline.png
│   └── reports/                   # Human-readable evaluation and markdown reports
│       ├── subset_statistics.txt
│       ├── preprocessing_summary.txt
│       ├── incident_summaries.md
│       ├── investigation_dashboard.html
│       ├── evaluation_report.txt
│       └── final_investigation_report.md
├── src/                           # Python pipeline scripts (Day 1 through Day 10)
│   ├── day1_explore_redteam.py
│   ├── day2_build_subset.py
│   ├── day2_build_multisource_subset.py
│   ├── day2_inspect_data.py
│   ├── day3_check_auth_format.py
│   ├── day3_inspect_auth.py
│   ├── day4_preprocess.py
│   ├── day5_triage.py
│   ├── day6_correlation.py
│   ├── day7_incident_analysis.py
│   ├── day8_risk_confidence.py
│   ├── day9_human_review.py
│   ├── day10_evaluation.py
│   └── generate_visualizations.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## ⚙️ Requirements & Installation

- Python 3.10+ (tested on Python 3.14 on Windows)
- Dependencies: `pandas`, `numpy`, `matplotlib`

Install required dependencies:
```bash
pip install -r requirements.txt
```

---

## ⏱️ Investigation Window & Reconciliation

A rolling 5-day window analysis of `redteam.txt` identified **Day 9 to Day 13** as the peak adversary campaign window across the entire LANL dataset:
- In LANL dataset convention, Day 1 begins at $t = 0$.
- With 1-based day indexing (`day = timestamp // 86400 + 1`):
  - **Day 9:** $[8 \times 86400, 9 \times 86400) = [691200, 777600)$ (273 redteam attacks)
  - **Day 10:** $[9 \times 86400, 10 \times 86400) = [777600, 864000)$ (15 redteam attacks)
  - **Day 11:** $[10 \times 86400, 11 \times 86400) = [864000, 950400)$ (0 attacks)
  - **Day 12:** $[11 \times 86400, 12 \times 86400) = [950400, 1036800)$ (0 attacks)
  - **Day 13:** $[12 \times 86400, 13 \times 86400) = [1036800, 1123200)$ (209 redteam attacks)
  - **Total:** **497 redteam attacks** across 71 attack users and 240 attack hosts.

> **Discrepancy Note:** An earlier experimental script used $[777600, 1209600)$, which corresponded to Day 10–Day 14 (305 attacks). The reconciled window $[691200, 1123200)$ accurately captures the true Day 9–13 window containing all 497 attacks.

---

## 🚀 Execution Pipeline

Run each phase sequentially from the project root directory:

```bash
# Day 1: Explore red-team activity & find best attack windows
python src/day1_explore_redteam.py

# Day 2: Build reconciled red-team and multi-source subset
python src/day2_build_subset.py
python src/day2_build_multisource_subset.py

# Day 3: Verify authentication schema & Day 9-13 auth distribution
python src/day3_check_auth_format.py
python src/day3_inspect_auth.py

# Day 4: Preprocessing, normalization, and temporal feature extraction
python src/day4_preprocess.py

# Day 5: Explainable rule-based threat triage & risk scoring
python src/day5_triage.py

# Day 6: Cross-source temporal event correlation & incident clustering
python src/day6_correlation.py

# Day 7: Incident narrative analysis & explainable indicator mapping
python src/day7_incident_analysis.py

# Day 8: Calibrated Risk & Confidence scoring engine
python src/day8_risk_confidence.py

# Day 9: Human-in-the-loop review queue & interactive HTML dashboard
python src/day9_human_review.py

# Day 10: Ground-truth evaluation (Confusion Matrix, Precision, Recall, F1)
python src/day10_evaluation.py

# Phase 9: Generate publication-grade figures
python src/generate_visualizations.py
```

---

## 🖥️ Human-in-the-Loop Investigation Dashboard

The system generates an interactive HTML dashboard:
```
results/reports/investigation_dashboard.html
```
Open this file in any web browser to:
- Filter incidents by Review Status, Risk Level, or Telemetry Type
- Inspect incident details (User pivots, Host pivots, event sequences)
- Review explainable triage indicators justifying each alert
- Examine analyst recommendations for containment and further queries

---

## 🔬 System Architecture

```
                    LANL MULTI-SOURCE RAW LOGS
        (auth.txt.gz, proc.txt.gz, dns.txt.gz, flows.txt.gz, redteam.txt)
                                  │
                                  ▼
                     RECONCILED WINDOW FILTERING
                   Day 9 to Day 13: [691200, 1123200)
                                  │
                                  ▼
                     MULTI-SOURCE DATA SUBSET
                 (~100,000 events: Relevant + Normal)
                                  │
                                  ▼
                   PREPROCESSING & NORMALIZATION
                (Schema hygiene, timestamps, sorting)
                                  │
                                  ▼
                     EXPLAINABLE THREAT TRIAGE
               (10 Transparent Heuristic Rules + Risk Score)
                                  │
                                  ▼
                   CROSS-SOURCE EVENT CORRELATION
               (±10 min window: AUTH → PROC → DNS → FLOW)
                                  │
                                  ▼
                    INCIDENT NARRATIVE ANALYSIS
                 (Explainable indicators & Attack chains)
                                  │
                                  ▼
                     RISK & CONFIDENCE SCORING
                     (Dual mathematical models)
                                  │
                                  ▼
                    HUMAN-IN-THE-LOOP REVIEW
               (Interactive SOC Dashboard & Review Queue)
                                  │
                                  ▼
                     GROUND-TRUTH EVALUATION
                (Confusion Matrix, Precision, Recall, F1)
                                  │
                                  ▼
                     REPORTS & VISUALIZATIONS
```

---

## 🔮 Proposed Future Work (AI / Agentic Extensions)

The current implementation provides a fully explainable, mathematically transparent investigation pipeline. The following features are proposed as extensions:
1. **LLM-Powered SOC Assistant**: Ingestion of structured incident evidence into an LLM via LangChain/LangGraph to generate human-readable incident summaries and remediation playbooks.
2. **RAG Knowledge Base**: Integration with MITRE ATT&CK enterprise techniques to map observed LANL tactics automatically.
3. **Automated Response Orchestration**: Automated IP/host isolation recommendations based on confidence thresholds.
#   A I - I n v e s t i g a t o r - C y b e r s e c u r i t y - T h r e a t - D e t e c t i o n  
 