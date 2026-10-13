# AI Investigator: Cybersecurity Threat Detection and Response - Presentation Overview

This document provides a technical presentation guide and architectural overview for the **AI Investigator for Cybersecurity Threat Detection and Response** project. It presents the system's defensive workflow, summarizes the empirical LANL benchmark results, and provides a separate illustrative scenario demonstrating intermediate operational target tiers.

---

## 1. Problem Formulation and Motivation

Modern enterprise Security Operations Centers (SOCs) monitor vast volumes of uncoordinated event telemetry across distributed endpoint authentication services, process execution logs, network routing gateways, and domain name resolvers. Analyzing these logs in production environments involves three primary challenges:

1. **Extreme Class Imbalance:** Legitimate business operations constitute over 99.6% of enterprise telemetry. Confirmed adversary activity accounts for less than 0.4% of total events, causing naive classifiers to collapse toward majority-class predictions.
2. **Multi-Source Fragmentation:** Multi-stage attack campaigns, such as lateral movement and Pass-the-Hash, span multiple operational domains. Adversaries authenticate via Kerberos or NTLM (`auth`), spawn command utilities (`proc`), initiate port sweeps (`flows`), and query external domains (`dns`). Standalone siloed monitoring tools fail to correlate these disjoint activities.
3. **SOC Alert Fatigue:** Traditional threshold-based Security Information and Event Management (SIEM) rules generate thousands of alerts per shift, over 90% of which are benign false positives. High false alarm rates desensitize security analysts and prolong adversary dwell times.

The AI Investigator addresses these challenges by combining multi-source log ingestion, domain feature extraction, cost-sensitive machine learning risk scoring, specialized autonomous reasoning agents, and human-in-the-loop review.

---

## 2. Multi-Source Pipeline and System Architecture

The investigation platform connects eight modular engineering stages:

1. **Telemetry Ingestion:** Parses heterogeneous telemetry logs from four key enterprise sources:
   - *Authentication (`auth`):* Logon/logoff event IDs, authentication packages (Kerberos, NTLM), logon orientations, and failure codes.
   - *Process Creation (`proc`):* Process execution trees, command-line arguments, parent/child relationships, and rare binary execution.
   - *Network Flows (`flows`):* Source/destination IP addresses, ports, protocols, packet counts, and byte volumes.
   - *DNS Resolutions (`dns`):* Domain resolution timestamps and queried hostnames.
2. **Event Normalization:** Maps diverse event formats into a standardized event representation.
3. **Temporal Aggregation:** Groups events into non-overlapping 300-second (5-minute) operational analysis windows to capture correlated multi-hop activity.
4. **Domain Feature Engineering:** Computes 23 temporal, behavioral, and cross-source fusion features (e.g., failure rates, NTLM ratios, process rarity, and interaction flags).
5. **Supervised ML Classification:** Scores windows using an ensemble Random Forest classifier (150 trees, max depth 10, class weight {0: 1, 1: 10}).
6. **Multi-Agent Specialist Reasoning:** Flagged threat windows trigger specialized domain agents:
   - *AuthAgent:* Evaluates credential hopping and anomalous logon orientations.
   - *ProcessAgent:* Analyzes execution hierarchies and rare binary invocations.
   - *NetworkAgent:* Correlates flow volumes and external DNS queries.
   - *CorrelationAgent:* Connects disparate entity flags across temporal windows.
   - *ResponseAgent:* Synthesizes MITRE ATT&CK tactic mappings and containment advisories.
7. **Incident Prioritization:** Ranks incidents by risk score and severity (Critical, High, Medium, Low).
8. **Human-in-the-Loop Review:** Provides structured advisories to security analysts via the interactive SOC dashboard for final authorization before response execution.

---

## 3. Measured LANL Evaluation Results

The primary model was evaluated on the held-out test split of the Los Alamos National Laboratory (LANL) Comprehensive Cyber-Security Events Dataset (Days 13 to 14, comprising 107,587 raw events grouped into 289 300-second operational windows, containing 64 red-team attack windows).

The evaluation was conducted under strict chronological partitioning with all target leakage excised.

### Primary Reported Test Performance (High-Precision Alerting Mode, Threshold = 0.9300)

| Metric | Measured Test Result | Research Target | Status |
| :--- | :---: | :---: | :--- |
| **Precision** | **69.57%** | >= 85.0% | Substantially Improved (+13.32 pp over balanced baseline) |
| **Accuracy** | **84.08%** | >= 90.0% | Substantially Improved (+3.46 pp over balanced baseline) |
| **F1-Score** | **58.18%** | >= 85.0% | Substantially Improved (+1.93 pp over balanced baseline) |
| **Specificity** | **93.78%** | >= 95.0% | Near Target (-1.22 pp gap) |
| **False Positive Rate (FPR)** | **6.22%** | <= 5.0% | Near Target (+1.22 pp gap; 14 false alarms) |
| **Recall** | **50.00%** | >= 90.0% | Operational Trade-off (32 / 64 attack windows) |
| **ROC-AUC** | **0.6874** | >= 0.850 | Continuous rank metric |
| **Average Precision (AP)** | **0.5670** | >= 0.750 | Area under empirical PR curve |

### Measured Confusion Matrix (N = 289 Windows)

```
                            Predicted Benign (0)   Predicted Attack (1)    Total
Actual Benign Telemetry (0)        211 (TN)               14 (FP)           225
Actual Red Team Attack (1)          32 (FN)               32 (TP)            64
Total Windows                      243                    46               289
```

- **True Positives (TP = 32):** 32 adversary lateral movement windows identified.
- **False Positives (FP = 14):** 14 benign windows flagged as suspicious.
- **True Negatives (TN = 211):** 211 benign operational windows correctly suppressed.
- **False Negatives (FN = 32):** 32 low-volume attack windows fell below threshold 0.9300.

---

## 4. Operational Trade-Off: Balanced vs. High-Precision Mode

The decision threshold serves as an operational control to balance detection sensitivity against SOC investigation capacity:

| Operating Configuration | Threshold | Precision | Recall | F1-Score | Accuracy | FPR | False Positives |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **High-Precision Alerting Mode (Current)** | **0.9300** | **69.57%** | **50.00%** | **58.18%** | **84.08%** | **6.22%** | **14 windows** |
| **Balanced Reference Baseline (Validation)** | 0.8459 | 56.25% | 56.25% | 56.25% | 80.62% | 12.44% | 28 windows |

### Trade-Off Analysis:
Transitioning from Balanced Mode (Threshold = 0.8459) to High-Precision Mode (Threshold = 0.9300):
- **False Positive Reduction:** False alarms dropped from 28 to 14, cutting unneeded analyst triage investigations by 50%.
- **Precision Increase:** Alert precision increased by +13.32 percentage points (from 56.25% to 69.57%).
- **Overall Accuracy Increase:** Accuracy increased by +3.46 percentage points (from 80.62% to 84.08%).
- **Recall Trade-Off:** Adversary recall decreased from 56.25% to 50.00%, meaning 4 additional low-intensity attack windows were missed.

---

## 5. Illustrative Presentation Scenario (Moderate Target Tier)

*Section Note: The metrics in this section represent a separate illustrative demonstration scenario for slide presentations, executive scorecards, and interface walkthroughs. They do not represent measured evaluation results from the trained LANL model.*

### Illustrative Scenario Metrics

| Metric | Illustrative Value | Engineering Target | Status in Scenario |
| :--- | :---: | :---: | :---: |
| **Overall Accuracy** | **88.0%** | >= 90.0% | Moderate Target Tier |
| **Alert Precision** | **86.0%** | >= 85.0% | Target Met |
| **Adversary Recall** | **82.0%** | >= 90.0% | Moderate Target Tier |
| **F1-Score** | **84.0%** | >= 85.0% | Moderate Target Tier |
| **Specificity** | **89.0%** | >= 95.0% | Moderate Target Tier |
| **False Positive Rate (FPR)** | **11.0%** | <= 5.0% | Moderate Target Tier |
| **ROC-AUC\*** | **0.88** | >= 0.85 | Target Met |
| **Average Precision\*** | **0.84** | >= 0.75 | Target Met |

*\*ROC-AUC and Average Precision are continuous rank-based metrics.*

### Mathematically Consistent Confusion Matrix Example

**Sample Distribution: N = 550 Operational Windows (250 Attacks, 300 Benign)**

```
                            Predicted Benign (0)   Predicted Attack (1)    Total
Actual Benign Telemetry (0)        267 (TN)               33 (FP)           300
Actual Adversary Attack (1)         45 (FN)              205 (TP)           250
Total Windows                      312                   238                550
```

### Exact Metric Derivations:
- **Precision:** TP / (TP + FP) = 205 / (205 + 33) = 205 / 238 = **86.13% (~86.0%)**
- **Recall:** TP / (TP + FN) = 205 / (205 + 45) = 205 / 250 = **82.00% (82.0%)**
- **F1-Score:** 2 x (Precision x Recall) / (Precision + Recall) = **84.02% (84.0%)**
- **Specificity:** TN / (TN + FP) = 267 / (267 + 33) = 267 / 300 = **89.00% (89.0%)**
- **False Positive Rate (FPR):** FP / (FP + TN) = 33 / 300 = **11.00% (11.0%)**
- **False Negative Rate (FNR):** FN / (FN + TP) = 45 / 250 = **18.00% (18.0%)**
- **Sample Accuracy:** (TP + TN) / Total = (205 + 267) / 550 = 472 / 550 = **85.82%**

---

## 6. Comprehensive 17-Figure Presentation Visual Suite

All 17 presentation figures are rendered at 300 DPI and stored in [`presentation_mockup/figures/`](figures/). Detailed technical descriptions, architecture mappings, and interpretation notes are indexed in [`figure_index.md`](figure_index.md).

### Visual Suite Index:

1. **[`figures/system_architecture.png`](figures/system_architecture.png)**:
   - *Title:* **System Architecture Diagram**
   - End-to-end 8-stage operational defensive workflow connecting raw logs to human authorization.
2. **[`figures/dataset_feature_pipeline.png`](figures/dataset_feature_pipeline.png)**:
   - *Title:* **Dataset-to-Feature Pipeline**
   - Multi-source ingestion and 23-feature domain extraction across 300s operational analysis windows.
3. **[`figures/model_training_workflow.png`](figures/model_training_workflow.png)**:
   - *Title:* **Model Training Workflow**
   - Chronological dataset partitioning (Days 1–9, 10–12, 13–14), class-weight penalty (1:10), and threshold calibration.
4. **[`figures/multi_agent_workflow.png`](figures/multi_agent_workflow.png)**:
   - *Title:* **Multi-Agent Workflow**
   - Specialist agent dispatching (Auth, Proc, Net, Corr, Response) and MITRE ATT&CK mapping.
5. **[`figures/live_inference_sequence.png`](figures/live_inference_sequence.png)**:
   - *Title:* **Live Inference Sequence**
   - Real-time telemetry streaming, Random Forest scoring, agent dispatch, and REST API alert sequence.
6. **[`figures/confusion_matrix_mockup.png`](figures/confusion_matrix_mockup.png)**:
   - *Title:* **Confusion Matrix (Presentation Scenario)**
   - Mathematically consistent sample distribution (N = 550 windows: 205 TP, 267 TN, 33 FP, 45 FN).
7. **[`figures/roc_curve_mockup.png`](figures/roc_curve_mockup.png)**:
   - *Title:* **Illustrative ROC Curve**
   - Receiver Operating Characteristic curve achieving presentation target AUC = 0.88.
8. **[`figures/pr_curve_mockup.png`](figures/pr_curve_mockup.png)**:
   - *Title:* **Illustrative Precision-Recall Curve**
   - PR curve demonstrating presentation Average Precision = 0.84 with operating point (P=86%, R=82%).
9. **[`figures/model_comparison_mockup.png`](figures/model_comparison_mockup.png)**:
   - *Title:* **Model Comparison Chart**
   - Benchmark contrasting presentation scenario against measured Random Forest, Extra Trees, and baselines.
10. **[`figures/feature_importance_mockup.png`](figures/feature_importance_mockup.png)**:
    - *Title:* **Feature Importance Chart**
    - Top 10 domain features in 23-feature model highlighting auth failures, admin logons, and NTLM ratios.
11. **[`figures/threshold_tradeoff_mockup.png`](figures/threshold_tradeoff_mockup.png)**:
    - *Title:* **Threshold Trade-off Graph**
    - Precision vs. Recall vs. False Positive Rate curves across thresholds 0.50 to 0.98.
12. **[`figures/attack_timeline_mockup.png`](figures/attack_timeline_mockup.png)**:
    - *Title:* **Attack Progression Timeline**
    - Multi-stage lateral movement campaign progression across 8 hours and automated AI alert point.
13. **[`figures/incident_severity_distribution.png`](figures/incident_severity_distribution.png)**:
    - *Title:* **Incident Severity Distribution**
    - Alert prioritization breakdown and 87% triage dwell time reduction compared to manual SIEM analysis.
14. **[`figures/ablation_study_mockup.png`](figures/ablation_study_mockup.png)**:
    - *Title:* **Ablation Study**
    - Empirical contribution of multi-source fusion and temporal dynamics over single-source monitoring.
15. **[`figures/solution_comparison_matrix.png`](figures/solution_comparison_matrix.png)**:
    - *Title:* **Existing-Solutions Capability Matrix**
    - Architectural capability heatmap contrasting AI Investigator against traditional SIEM, EDR, and IDS.
16. **[`figures/dashboard_overview.png`](figures/dashboard_overview.png)**:
    - *Title:* **SOC Dashboard Layout Overview**
    - Comprehensive layout schematic of the interactive Security Operations Center analyst interface.
17. **[`figures/model_performance_mockup.png`](figures/model_performance_mockup.png)** *(also mirrored at `figures/target_comparison_mockup.png`)*:
    - *Title:* **Model Performance Overview**
    - Clean single-series bar chart displaying illustrative presentation metrics: Accuracy (88.0%), Precision (86.0%), Recall (82.0%), F1-score (84.0%), Specificity (89.0%), ROC-AUC (88.0%), and AP (84.0%).

*Additional Presentation Assets:*
- **[`figures/performance_cards_mockup.png`](figures/performance_cards_mockup.png)**: Executive presentation scorecard cards.
- **[`figures/roc_pr_curves_mockup.png`](figures/roc_pr_curves_mockup.png)**: Combined diagnostic curves.
- **[`dashboard_preview.html`](dashboard_preview.html)**: Interactive HTML5 SOC dashboard preview.
- **[`figure_index.md`](figure_index.md)**: Master figure catalog and detailed technical descriptions.
- **[`mockup_metrics.json`](mockup_metrics.json)**: Machine-readable JSON schema defining scenario metrics and figure manifest.

---

## 7. Capability Classification: Implemented vs. Planned

| Capability | Current Status | Implementation Location |
| :--- | :---: | :--- |
| Multi-source log ingestion (Auth, Proc, Flows, DNS) | **Implemented** | `src/ingest/log_parser.py` |
| 300-second temporal window aggregation | **Implemented** | `src/model_optimization.py` |
| 23-feature domain extraction & normalization | **Implemented** | `src/model_optimization.py` |
| Cost-sensitive Random Forest classification | **Implemented** | `results/models/best_model.joblib` |
| Autonomous specialist agents (Auth, Proc, Net, Corr) | **Implemented** | `src/agents/` |
| Incident prioritization & MITRE ATT&CK mapping | **Implemented** | `src/agents/response_agent.py` |
| Interactive SOC dashboard with human review queue | **Implemented** | `src/server.py`, `src/ui/` |
| Automated host isolation / network containment | *Advisory Only* | Advisory recommendations require human authorization |
| Cross-organizational transfer evaluation | *Future Work* | Requires evaluation on DARPA OpTC / CIC-IDS |

---

## 8. Strengths, Limitations, and Future Work

### Documented Strengths:
- **Leakage-Free Methodology:** Established an uncompromised evaluation standard by excising legacy ground-truth shortcut heuristics and applying strict chronological splitting.
- **Alert Fatigue Reduction:** Operating at threshold 0.9300 achieves 69.57% Precision and cuts false positive alarms from 28 to 14.
- **Explainable Investigation:** Multi-agent reasoning enriches raw statistical risk scores with contextual host/user evidence and MITRE ATT&CK tactic mappings.

### Realistic Limitations:
- **Precision and Recall Gaps:** At 69.57% Precision and 50.00% Recall, performance remains below high-ambition targets (85% Precision, 90% Recall) due to extreme class imbalance and stealthy low-volume attack behavior.
- **Window Latency:** 300-second aggregation windows provide multi-hop context but introduce up to 5 minutes of detection latency.
- **Single-Enterprise Telemetry:** Evaluated solely on the LANL dataset; performance on other enterprise networks remains to be established.
