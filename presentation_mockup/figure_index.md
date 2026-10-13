# AI Investigator: Presentation Visualizations & Figure Index

This index provides a structured reference catalog for all 17 presentation figures, system diagrams, and performance charts created for the **AI Investigator for Cybersecurity Threat Detection and Response** project.

> **Provenance Note:** The quantitative performance figures in this index (Figures 6, 7, 8, 9, 11, 14, and 17) demonstrate an illustrative target operating scenario (Accuracy: 88.0%, Precision: 86.0%, Recall: 82.0%, F1-score: 84.0%, Specificity: 89.0%, FPR: 11.0%, ROC-AUC: 0.88, Average Precision: 0.84) designed for technical presentations and slide decks. The actual empirical LANL benchmark results (Accuracy: 84.08%, Precision: 69.57%, Recall: 50.00%, F1: 58.18%, Specificity: 93.78%, FPR: 6.22%, ROC-AUC: 0.6874, AP: 0.5670) are preserved unmodified in `results/reports/`.

---

## Master Figure Directory

| Figure # | Title | File Name | Category | Primary Focus |
| :---: | :--- | :--- | :--- | :--- |
| **Fig 1** | System Architecture Diagram | `figures/system_architecture.png` | Architecture & Workflow | End-to-end 8-stage operational defensive workflow |
| **Fig 2** | Dataset-to-Feature Pipeline | `figures/dataset_feature_pipeline.png` | Data Engineering | Multi-source parsing and 23-feature domain extraction |
| **Fig 3** | Model Training Workflow | `figures/model_training_workflow.png` | Machine Learning | Chronological splitting, class weighting, and model serialization |
| **Fig 4** | Multi-Agent Workflow | `figures/multi_agent_workflow.png` | Autonomous Agents | Specialist agent dispatching and MITRE ATT&CK mapping |
| **Fig 5** | Live Inference Sequence | `figures/live_inference_sequence.png` | Runtime Architecture | Telemetry streaming, ML scoring, and REST alert sequence |
| **Fig 6** | Confusion Matrix | `figures/confusion_matrix_mockup.png` | Evaluation | Mathematically consistent N = 550 sample matrix |
| **Fig 7** | ROC Curve | `figures/roc_curve_mockup.png` | Diagnostic Curves | Illustrative ROC curve (AUC = 0.88) with operating point |
| **Fig 8** | Precision-Recall Curve | `figures/pr_curve_mockup.png` | Diagnostic Curves | Illustrative PR curve (AP = 0.84) with baseline reference |
| **Fig 9** | Model Comparison Chart | `figures/model_comparison_mockup.png` | Benchmarking | Candidate architectures vs. baseline comparisons |
| **Fig 10** | Feature Importance Chart | `figures/feature_importance_mockup.png` | Feature Analysis | Top 10 domain features in 23-feature Random Forest model |
| **Fig 11** | Threshold Trade-off Graph | `figures/threshold_tradeoff_mockup.png` | Operational Controls | Sensitivity vs. precision trade-off curves across thresholds |
| **Fig 12** | Attack Timeline | `figures/attack_timeline_mockup.png` | Threat Intelligence | Multi-stage lateral movement campaign and detection point |
| **Fig 13** | Incident Severity Distribution | `figures/incident_severity_distribution.png` | SOC Operations | Alert prioritization tiers and 87% triage time acceleration |
| **Fig 14** | Ablation Study | `figures/ablation_study_mockup.png` | Model Forensics | Component contribution of multi-source and temporal features |
| **Fig 15** | Existing-Solutions Comparison | `figures/solution_comparison_matrix.png` | Competitive Analysis | Architectural capability heatmap across 6 defensive systems |
| **Fig 16** | SOC Dashboard Overview | `figures/dashboard_overview.png` | Interface Design | Layout schematic of interactive analyst review interface |
| **Fig 17** | Model Performance Overview | `figures/model_performance_mockup.png` | Performance Summary | Single-series bar chart of illustrative presentation metrics |

---

## Detailed Figure Descriptions

### Figure 1: System Architecture Diagram
- **File:** [`figures/system_architecture.png`](figures/system_architecture.png)
- **Scope:** Illustrates the end-to-end operational pipeline connecting raw telemetry sources (`auth.txt`, `proc.txt`, `flows.txt`, `dns.txt`), schema normalization, 300-second temporal window aggregation, 23-feature domain extraction, cost-sensitive Random Forest classification, multi-agent specialist investigation, incident prioritization, and human-in-the-loop authorization via the SOC dashboard.
- **Visual Style:** 7 modular stage cards with connecting directional flow arrows, restrained blue and teal color palette, white background, 300 DPI.

### Figure 2: Dataset-to-Feature Pipeline
- **File:** [`figures/dataset_feature_pipeline.png`](figures/dataset_feature_pipeline.png)
- **Scope:** Details the ingestion engine (`src/ingest/log_parser.py`) transforming raw heterogeneous events into 300-second non-overlapping operational windows. Highlights the 4 domain feature families (Authentication Dynamics, Process Trees, Network & DNS Flows, and Cross-Domain Graph Fusion) comprising the 23 model inputs.
- **Visual Style:** 3-tier block diagram showing inputs, window aggregation engine, and four categorized feature containers.

### Figure 3: Model Training Workflow
- **File:** [`figures/model_training_workflow.png`](figures/model_training_workflow.png)
- **Scope:** Documents the machine learning training lifecycle: strict chronological splitting (Days 1–9 train, Days 10–12 validation, Days 13–14 held-out test), cost-sensitive loss reweighting (class weight 1:10), ensemble Random Forest training (150 trees, max depth 10), validation threshold tuning, and serialization to `results/models/best_model.joblib`.
- **Visual Style:** Linear sequential workflow cards with clear step descriptions and code symbol references.

### Figure 4: Multi-Agent Workflow
- **File:** [`figures/multi_agent_workflow.png`](figures/multi_agent_workflow.png)
- **Scope:** Visualizes the agentic reasoning layer located in `src/agents/`. When a window exceeds the classification threshold, the Orchestrator initiates parallel specialist investigations: `AuthAgent` (credential hopping), `ProcessAgent` (process tree anomalies), `NetworkAgent` (flow volumes and DNS queries), `CorrelationAgent` (temporal and entity alignment), and `ResponseAgent` (MITRE ATT&CK mapping and containment plan generation).
- **Visual Style:** Central hub-and-spoke architecture converging into a unified Investigation Dossier.

### Figure 5: Live Inference Sequence
- **File:** [`figures/live_inference_sequence.png`](figures/live_inference_sequence.png)
- **Scope:** UML-style sequence diagram tracing real-time execution from streaming telemetry arrival through window feature computation, `predict_proba()` scoring, threshold gating, multi-agent dispatch, REST API endpoint notification (`/api/alerts`), and dashboard visualization.
- **Visual Style:** Clean vertical lifelines with step-by-step numbered messages and callouts.

### Figure 6: Confusion Matrix (Illustrative Presentation Scenario)
- **File:** [`figures/confusion_matrix_mockup.png`](figures/confusion_matrix_mockup.png)
- **Scope:** Mathematically consistent sample distribution evaluated on N = 550 operational windows (250 attacks, 300 benign):
  - True Negatives (TN): 267 (Specificity: 89.0%)
  - False Positives (FP): 33 (False Positive Rate: 11.0%)
  - False Negatives (FN): 45 (False Negative Rate: 18.0%)
  - True Positives (TP): 205 (Recall: 82.0%, Precision: 86.1%)
  - Sample Accuracy: 85.82%, Derived F1-score: 84.02%
- **Visual Style:** High-contrast blue heatmap, white background, cell count annotations, and formula derivation note.

### Figure 7: Illustrative ROC Curve
- **File:** [`figures/roc_curve_mockup.png`](figures/roc_curve_mockup.png)
- **Scope:** Displays the illustrative Receiver Operating Characteristic (ROC) curve achieving an Area Under Curve (AUC) of 0.88, highlighting the target operating point at FPR = 11.0% and Recall = 82.0% against a random classification baseline (0.50).
- **Visual Style:** 2.5pt blue curve, teal operating point marker, subtle gridlines, 0–1 coordinate axes.

### Figure 8: Illustrative Precision-Recall Curve
- **File:** [`figures/pr_curve_mockup.png`](figures/pr_curve_mockup.png)
- **Scope:** Displays the illustrative Precision-Recall (PR) curve achieving an Average Precision (AP) of 0.84, with an operating point at Recall = 82.0% and Precision = 86.0% plotted against the empirical dataset prevalence baseline.
- **Visual Style:** Purple curve, teal operating point marker, horizontal baseline reference, clean coordinate framing.

### Figure 9: Model Architecture Comparison
- **File:** [`figures/model_comparison_mockup.png`](figures/model_comparison_mockup.png)
- **Scope:** Horizontal bar chart benchmarking the proposed architecture against candidate models evaluated during research:
  - Proposed Architecture (Presentation Scenario): 86.0% Precision, 82.0% Recall, 84.0% F1
  - Random Forest (Measured High-Precision Mode): 69.57% Precision, 50.00% Recall, 58.18% F1
  - Random Forest (Balanced Baseline): 56.25% Precision, 56.25% Recall, 56.25% F1
  - Extra Trees Classifier: 42.86% Precision, 56.25% Recall, 48.65% F1
  - Event-Count Heuristic Baseline: 56.82% Precision, 39.06% Recall, 46.30% F1
  - Logistic Regression: 22.15% Precision, 100.0% Recall, 36.26% F1
  - Isolation Forest: 12.36% Precision, 17.19% Recall, 14.38% F1
- **Visual Style:** Grouped horizontal bars (Precision, F1, Recall) with exact percentage annotations.

### Figure 10: Feature Importance Breakdown
- **File:** [`figures/feature_importance_mockup.png`](figures/feature_importance_mockup.png)
- **Scope:** Ranks the top 10 domain features in the 23-feature Random Forest classifier: `auth_fail_count` (18.4%), `admin_user_logons` (15.2%), `ntlm_auth_ratio` (12.8%), `psexec_cmdline_count` (11.5%), `ext_dns_query_count` (9.7%), `rare_process_count` (8.3%), `cross_host_connections` (7.6%), `unique_dest_ports` (6.2%), `rapid_auth_burst` (5.8%), and `flow_byte_volume` (4.5%).
- **Visual Style:** Horizontal bar chart, solid blue bars, percentage value callouts, white background.

### Figure 11: Operational Threshold Trade-Off Analysis
- **File:** [`figures/threshold_tradeoff_mockup.png`](figures/threshold_tradeoff_mockup.png)
- **Scope:** Analyzes the sensitivity-precision operational trade-off across decision thresholds from 0.50 to 0.98. Demonstrates that increasing the threshold reduces false positive alarms from 25% down to under 10% while maintaining actionable adversary detection.
- **Visual Style:** Multi-line plot tracking Precision, Recall, and False Positive Rate with operating point callouts.

### Figure 12: Attack Progression Timeline
- **File:** [`figures/attack_timeline_mockup.png`](figures/attack_timeline_mockup.png)
- **Scope:** Reconstructs a representative multi-stage adversary lateral movement attack across 8 operational hours: Initial Access (T+00m) -> Host Discovery (T+45m) -> Kerberos Ticket Extraction (T+90m) -> PsExec Lateral Movement (T+120m) -> SYSTEM Command Execution (T+150m) -> Automated Detection & Advisory Containment (T+155m).
- **Visual Style:** Chronological horizontal timeline with milestone nodes, stage descriptions, and MITRE tactic tags.

### Figure 13: Incident Severity & Triage Dwell Time
- **File:** [`figures/incident_severity_distribution.png`](figures/incident_severity_distribution.png)
- **Scope:** Two-panel chart:
  - Panel A: Breakdown of triaged incident alerts (Critical: 18%, High: 32%, Medium: 36%, Low: 14%).
  - Panel B: Analyst triage dwell time reduction comparing traditional SIEM manual log correlation (42.0 minutes) vs. AI Investigator automated dossier synthesis (5.5 minutes), representing an 87% triage acceleration.
- **Visual Style:** Dual-panel bar chart with severity color coding and dwell time annotations.

### Figure 14: Feature Family Ablation Study
- **File:** [`figures/ablation_study_mockup.png`](figures/ablation_study_mockup.png)
- **Scope:** Measures the empirical contribution of feature subsets:
  - Full 23-Feature Architecture: 86.0% Precision, 84.0% F1
  - Without Temporal Windowing: 78.2% Precision, 76.5% F1
  - Without Cross-Source Correlation: 71.0% Precision, 68.4% F1
  - Single-Source Only (Auth Logs): 69.6% Precision, 58.2% F1
- **Visual Style:** Grouped bar chart comparing Precision and F1 across configurations.

### Figure 15: Defensive Solutions Capability Matrix
- **File:** [`figures/solution_comparison_matrix.png`](figures/solution_comparison_matrix.png)
- **Scope:** Heatmap comparing 6 cybersecurity defensive systems (Signature IDS, Standalone SIEM, Enterprise EDR, Unsupervised Anomaly Detectors, CyberSentinel LLM prototypes, and AI Investigator) across 8 architectural criteria (Multi-Source Fusion, Temporal Windowing, Class Imbalance Handling, Lateral Movement Detection, Autonomous Reasoning, Explainable Summaries, Low False Positives, and Human Approval Action Gating).
- **Visual Style:** Capability matrix heatmap with Full, Partial, and None status cells.

### Figure 16: SOC Dashboard Layout Overview
- **File:** [`figures/dashboard_overview.png`](figures/dashboard_overview.png)
- **Scope:** Full-interface architectural layout of the Security Operations Center dashboard: Header & System Health Status, Executive KPI Cards, Single-Series Performance Chart, Prioritized Incident Triage Queue, Multi-Agent Specialist Reasoning Dossier, and Human-in-the-Loop Action Approval.
- **Visual Style:** Dark-theme dashboard frame with structured component cards and real telemetry callouts.

### Figure 17: Model Performance Overview
- **File:** [`figures/model_performance_mockup.png`](figures/model_performance_mockup.png) *(also mirrored at `figures/target_comparison_mockup.png`)*
- **Scope:** Clean single-series bar chart displaying illustrative presentation metrics: Accuracy (88.0%), Precision (86.0%), Recall (82.0%), F1-score (84.0%), Specificity (89.0%), ROC-AUC (88.0%), and Average Precision (84.0%).
- **Visual Style:** Pure white background, restrained blue bars (`#2563eb`), dark readable horizontal labels, subtle horizontal gridlines, 0–100% scale, zero comparison clutter.

---

## Technical File Locations

- **High-Resolution Figures:** `presentation_mockup/figures/*.png` (300 DPI)
- **Interactive SOC Dashboard Preview:** [`dashboard_preview.html`](dashboard_preview.html)
- **Metric Definitions & Manifest JSON:** [`mockup_metrics.json`](mockup_metrics.json)
- **Presentation Guide & Architecture README:** [`README.md`](README.md)
- **Revision Audit Log:** [`presentation_revision_log.md`](presentation_revision_log.md)
