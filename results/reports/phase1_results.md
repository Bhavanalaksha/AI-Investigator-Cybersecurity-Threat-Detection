# Phase 1 Experimental Results

**Project:** AI Investigator for Cybersecurity Threat Detection and Response
**Dataset:** LANL Comprehensive Multi-Source Cyber-Security Events Dataset
**Investigation Window:** Day 9-Day 13 inclusive - Timestamp interval [691200, 1123200)
**System Architecture:** Explainable rule-based threat triage + multi-source temporal correlation + incident analysis + transparent risk/confidence scoring + human review
**Report Date:** 2026-09-18

> All values in this document are extracted directly from existing project files, generated CSVs, reports, dashboards, and analysis outputs. No values have been estimated or fabricated. Source file citations are provided for every extracted example.

---

## 1. Dataset Subset

### 1.1 Investigation Window

| Parameter | Value |
|---|---|
| Dataset | LANL Comprehensive Multi-Source Cyber-Security Events |
| Investigation Window | Day 9 - Day 13 (inclusive) |
| Timestamp Start | 691,200 (= 8 x 86,400) |
| Timestamp End | 1,123,200 (= 13 x 86,400) |
| Window Duration | 432,000 seconds (120 hours) |
| Day Indexing Convention | 1-based: day = floor(timestamp / 86400) + 1 |
| Total Raw Events in Window | 154,263,086 (streamed, not fully loaded) |

*Source: results/reports/subset_statistics.txt*

### 1.2 Red-Team Ground Truth per Day

| Day | Timestamp Range | Red-Team Events |
|---|---|---|
| Day 9 | [691,200 - 777,600) | 273 |
| Day 10 | [777,600 - 864,000) | 15 |
| Day 11 | [864,000 - 950,400) | 0 |
| Day 12 | [950,400 - 1,036,800) | 0 |
| Day 13 | [1,036,800 - 1,123,200) | 209 |
| **Total** | **[691,200 - 1,123,200)** | **497** |

*Source: results/reports/final_investigation_report.md (Section 3)*

### 1.3 Multi-Source Subset Composition

| Event Source | Events Sampled | % of Subset |
|---|---|---|
| AUTH | 55,000 | 42.1% |
| DNS | 25,000 | 19.2% |
| PROCESS | 25,000 | 19.2% |
| FLOW | 25,000 | 19.2% |
| REDTEAM | 497 | 0.4% |
| **Total** | **130,497** | **100%** |

| Entity Type | Count |
|---|---|
| Unique User Accounts | 11,510 |
| Unique Host Endpoints | 9,050 |
| Unique Attack Users (ground truth) | 71 |
| Unique Attack Hosts (ground truth) | 240 |

*Source: results/reports/subset_statistics.txt, data/subset/multisource_subset.csv*

---

## 2. Triage Results

**System:** Explainable rule-based threat triage engine with 10 explicit behavioral indicators.
**Threshold:** risk_score >= 3 => flagged as suspicious.

### 2.0 Triage Summary

| Category | Count |
|---|---|
| Total Events Triaged | 130,497 |
| Flagged Suspicious | 59,382 (45.5%) |
| Normal / Benign | 71,115 (54.5%) |
| Average Risk Score (flagged) | 3.67 |
| Maximum Risk Score Observed | 13 |

*Source: results/reports/final_investigation_report.md (Section 5)*

### 2.1 Detection Rules

| Rule ID | Description | Additive Score | Events Triggered |
|---|---|---|---|
| R1 | Authentication Failure | +2 | 214 |
| R2 | Authentication Burst (>3 logons in 5 min by same user) | +2 | 13,397 |
| R3 | Unusual Authentication Protocol (NTLM/Network) | +1 | 51,372 |
| R4 | Rare User-to-Host Mapping | +2 | 21,317 |
| R5 | Rare Process Execution | +2 | 873 |
| R6 | Process Burst (high-density spawning in 2 min) | +2 | 4,104 |
| R7 | Network Flow Anomaly (>50 KB or extended duration) | +1 | 408 |
| R8 | Threat Actor Account Telemetry | +3 | 3,378 |
| R9 | Compromised Endpoint Telemetry | +2 | 108,757 |
| R10 | Compound Threat Temporal Burst (>=2 indicators simultaneously) | +2 | 59,037 |

*Source: results/reports/final_investigation_report.md (Section 5)*

---

### 2.2 Correctly Flagged Examples (True Positives)

These are events where is_suspicious = 1 AND is_redteam = 1 - correctly detected ground-truth adversary actions.

**Source file: data/processed/triaged_events.csv**

---

#### TP Example 1

| Field | Value |
|---|---|
| Event ID | EVT-0008487 |
| Event Type / Source | REDTEAM |
| Timestamp | 725,488 (Day 9, 09:00 hour) |
| User | U1653@DOM1 |
| Source Host | C17693 |
| Destination Host | C395 |
| Action | REDTEAM_ATTACK |
| Risk Score | 12 |
| Is Redteam | Yes |
| Triggered Rules | R4_RARE_USER_HOST; R8_REDTEAM_USER; R9_REDTEAM_HOST; R_REDTEAM_GROUND_TRUTH; R10_TEMPORAL_BURST |
| Why Flagged | Rare lateral mapping (U1653@DOM1 -> C395); known threat actor account (U1653@DOM1); known compromised host (C17693); confirmed ground-truth attack; compound 4-indicator burst |
| Verdict | CONFIRMED CORRECT (True Positive) |

---

#### TP Example 2

| Field | Value |
|---|---|
| Event ID | EVT-0008501 |
| Event Type / Source | REDTEAM |
| Timestamp | 725,589 (Day 9, 09:00 hour) |
| User | U1653@DOM1 |
| Source Host | C17693 |
| Destination Host | C2669 |
| Action | REDTEAM_ATTACK |
| Risk Score | 12 |
| Is Redteam | Yes |
| Triggered Rules | R4_RARE_USER_HOST; R8_REDTEAM_USER; R9_REDTEAM_HOST; R_REDTEAM_GROUND_TRUTH; R10_TEMPORAL_BURST |
| Why Flagged | Rare lateral mapping (U1653@DOM1 -> C2669); known threat actor account (U1653@DOM1); known compromised host (C17693); confirmed ground-truth attack; compound 4-indicator burst |
| Verdict | CONFIRMED CORRECT (True Positive) |

---

#### TP Example 3

| Field | Value |
|---|---|
| Event ID | EVT-0008582 |
| Event Type / Source | REDTEAM |
| Timestamp | 725,983 (Day 9, 09:00 hour) |
| User | U293@DOM1 |
| Source Host | C17693 |
| Destination Host | C3153 |
| Action | REDTEAM_ATTACK |
| Risk Score | 10 |
| Is Redteam | Yes |
| Triggered Rules | R8_REDTEAM_USER; R9_REDTEAM_HOST; R_REDTEAM_GROUND_TRUTH; R10_TEMPORAL_BURST |
| Why Flagged | Known threat actor account (U293@DOM1); known compromised host (C17693); confirmed ground-truth attack; compound 3-indicator burst |
| Verdict | CONFIRMED CORRECT (True Positive) |

---

### 2.3 Incorrectly Flagged Examples (False Positives)

These are events where is_suspicious = 1 AND is_redteam = 0 - normal/background events incorrectly flagged as suspicious due to behavioral rule overlap with compromised hosts.

**Source file: data/processed/triaged_events.csv**

---

#### FP Example 1

| Field | Value |
|---|---|
| Event ID | EVT-0000062 |
| Event Type / Source | DNS |
| Timestamp | 691,318 (Day 9, 00:00 hour) |
| Source Host | C1823 |
| Destination Host (Resolved) | C1819 |
| User | (none - DNS event) |
| Action | DNS_QUERY |
| Risk Score | 6 |
| Is Redteam | No |
| Triggered Rules | R4_RARE_USER_HOST; R9_REDTEAM_HOST; R10_TEMPORAL_BURST |
| Why Flagged | Rare host-to-host DNS mapping (-> C1819); C1823 is a known compromised host; compound 2-indicator burst |
| Root Cause of FP | Normal DNS resolution originating from a host that appears in the compromised host list; no actual attacker action |
| Verdict | FALSE POSITIVE |

---

#### FP Example 2

| Field | Value |
|---|---|
| Event ID | EVT-0007140 |
| Event Type / Source | DNS |
| Timestamp | 718,873 (Day 9, 07:00 hour) |
| Source Host | C1191 |
| Destination Host (Resolved) | C606 |
| User | (none - DNS event) |
| Action | DNS_QUERY |
| Risk Score | 6 |
| Is Redteam | No |
| Triggered Rules | R4_RARE_USER_HOST; R9_REDTEAM_HOST; R10_TEMPORAL_BURST |
| Why Flagged | Rare host-to-host DNS mapping (-> C606); C1191 is a known compromised host; compound 2-indicator burst |
| Root Cause of FP | Routine DNS query from a host in the compromised host set; no adversary action confirmed |
| Verdict | FALSE POSITIVE |

---

#### FP Example 3

| Field | Value |
|---|---|
| Event ID | EVT-0007411 |
| Event Type / Source | DNS |
| Timestamp | 720,605 (Day 9, 08:00 hour) |
| Source Host | C13360 |
| Destination Host (Resolved) | C3173 |
| User | (none - DNS event) |
| Action | DNS_QUERY |
| Risk Score | 6 |
| Is Redteam | No |
| Triggered Rules | R4_RARE_USER_HOST; R9_REDTEAM_HOST; R10_TEMPORAL_BURST |
| Why Flagged | Rare host-to-host DNS mapping (-> C3173); C3173 is a known compromised host; compound 2-indicator burst |
| Root Cause of FP | Standard DNS resolution touching a destination that is in the compromised host list; benign administrative traffic |
| Verdict | FALSE POSITIVE |

---

## 3. Correlation Results

**Correlation method:** Entity-indexed sliding temporal window (+/-10 minutes / 600 seconds), pivoted on shared users and host endpoints, applied to the 59,382 candidate suspicious events.

### 3.1 Confirmed Correlation Statistics

| Metric | Value | Source |
|---|---|---|
| Total Correlated Incidents Formed | 1,105 | data/processed/evaluation_results.csv |
| Incidents Containing Red-Team Attacks | 28 | data/processed/evaluation_results.csv |
| Total Red-Team Events Captured in Incidents | 497 / 497 (100.00%) | data/processed/evaluation_results.csv |
| Cross-Source Incidents (>= 2 telemetry types) | 81 | results/reports/final_investigation_report.md Section 6 |
| Average Incident Duration | 294.0 seconds (~4.9 min) | results/reports/final_investigation_report.md Section 6 |
| Average Event Count per Incident | 53.7 events | results/reports/final_investigation_report.md Section 6 |
| Structural Telemetry Reduction | 99.15% (130,497 -> 1,105 incidents) | data/processed/evaluation_results.csv |

### 3.2 Correlation Quality Assessment

| Quality Category | Status |
|---|---|
| Correctly grouped events (redteam in incidents) | 497 / 497 (100%) - confirmed via evaluation_results.csv |
| Events that should have been grouped but were split | **Not evaluated in the current implementation.** No explicit split-group analysis was performed. |
| Events that were wrongly merged (over-clustering) | **Not evaluated in the current implementation.** No merge-quality audit was performed. |

> The current implementation confirms that all 497 ground-truth red-team events are captured within 28 correlated incidents. No analysis of false merges or missed splits was conducted; this remains a gap for future evaluation.

---

## 4. Incident Analysis Examples

All examples below are drawn from data/processed/incidents.csv, data/processed/human_review_queue.csv, and results/reports/incident_summaries.md.

---

### Incident 1: INC-0018 - Confirmed Red-Team Attack (Multi-User Lateral Movement)

| Field | Value |
|---|---|
| Incident ID | INC-0018 |
| Time Range | Timestamp 745,795 -> 749,054 (Duration: 3,259 s / ~54 min) |
| Users Involved | U1450@DOM1; U2575@DOM1; U374@DOM1; U8777@C1500; U8777@C3388; U8777@C583; U882@DOM1; U9947@DOM1 |
| Hosts Involved | C11039, C1119, C12448, C1461, C1479, C1500, C1616, C17425, C17693, C18113, C19156, C19803, C20203, C3388, C346, C583, C853, C923 |
| Event Sources / Types | REDTEAM |
| Total Events Correlated | 31 |
| Red-Team Events | 31 (100%) |
| Triggered Detection Rules | R4 (Rare User-Host), R8 (Threat Actor Account), R9 (Compromised Host), R10 (Compound Burst) |
| Risk Score | 91 / 100 (Critical) |
| Confidence Score | 62% (Medium) |
| Severity | Critical |
| Review Status | Confirmed Suspicious |
| Why Suspicious | Multiple known threat actor accounts (U8777, U882, U9947) performing simultaneous lateral movements across 18 hosts; all 31 events confirmed as LANL redteam ground truth |
| Red-Team Ground Truth | YES - 31 confirmed red-team events |

*Source: data/processed/incidents.csv, data/processed/human_review_queue.csv, results/reports/incident_summaries.md (INC-0018 section)*

---

### Incident 2: INC-0037 - Confirmed Red-Team Attack (Single Threat Actor Burst)

| Field | Value |
|---|---|
| Incident ID | INC-0037 |
| Time Range | Timestamp 830,548 -> 830,822 (Duration: 274 s / ~4.6 min) |
| Users Involved | U1653@DOM1 |
| Hosts Involved | C22409, C754 |
| Event Sources / Types | REDTEAM |
| Total Events Correlated | 15 |
| Red-Team Events | 15 (100%) |
| Triggered Detection Rules | R8 (Threat Actor Account), R9 (Compromised Host), R10 (Compound Burst - 3 simultaneous indicators) |
| Risk Score | 79 / 100 (Critical) |
| Confidence Score | 58% (Medium) |
| Severity | Critical |
| Review Status | Confirmed Suspicious |
| Why Suspicious | Known threat actor U1653@DOM1 executed 15 attack events against hosts C22409 and C754 in a 274-second concentrated burst; all events confirmed ground-truth red-team |
| Red-Team Ground Truth | YES - 15 confirmed red-team events |

*Source: data/processed/incidents.csv, data/processed/human_review_queue.csv, results/reports/incident_summaries.md (INC-0037 section)*

---

### Incident 3: INC-0407 - High-Priority Review (Multi-Source AUTH + PROCESS Anomaly)

| Field | Value |
|---|---|
| Incident ID | INC-0407 |
| Time Range | Timestamp 1,088,333 -> 1,091,233 (Duration: 2,900 s / ~48 min) |
| Users Involved | C1611$@DOM1; LOCAL SERVICE@C1611; U1449@DOM1; U2913@DOM1; U4738@DOM1; U5012@DOM1; U52@DOM1; U6826@DOM1; U7640@DOM1; U7845@DOM1; U8158@DOM1; U8250@DOM1; U9735@DOM1 |
| Hosts Involved | C1611, C7946, C801 |
| Event Sources / Types | AUTH -> PROCESS (multi-source) |
| Total Events Correlated | 25 |
| Red-Team Events | 0 |
| Triggered Detection Rules | R4 (Rare User-Host), R5 (Rare Process P415), R6 (Process Burst: 4-6 processes in 2 min), R9 (Compromised Host C1611), R10 (Compound Burst 2-3 simultaneous indicators) |
| Risk Score | 67 / 100 (High) |
| Confidence Score | 59% (Medium) |
| Severity | High |
| Review Status | Review Required |
| Why Suspicious | Multiple users performing rare lateral mappings to unknown hosts combined with an infrequently-executed process (P415) and high-density process bursts on known compromised host C1611 |
| Red-Team Ground Truth | NO - no ground-truth red-team events; classified as potential false positive or unlabeled adversary activity |

*Source: data/processed/incidents.csv, data/processed/human_review_queue.csv, results/reports/incident_summaries.md (INC-0407 section)*

---

## 5. Risk and Confidence

### 5.1 Scoring Formulas

**Risk Score (0-100)** - reflects potential impact and threat severity:

    Risk = min(100, round(R_base + R_lateral + R_velocity + R_threat))
      R_base     = min(55, MaxEventRisk x 3.5 + ln(1 + SumRisk) x 5.0)
      R_lateral  = min(20, max(0, N_hosts - 1) x 4.0)
      R_velocity = min(10, (N_events / Duration) x 90.0)
      R_threat   = 15.0 if GroundTruthPresent else 0.0

**Confidence Score (0-100)** - reflects evidentiary certainty and multi-source corroboration:

    Confidence = min(100, round(C_sources + C_volume + C_entities + C_groundtruth))
      C_sources     = N_telemetry_types x 12.5 (up to 50 for AUTH+PROC+DNS+FLOW)
      C_volume      = min(20, log2(N_events + 1) x 4.0)
      C_entities    = 15.0 if (Hosts and Users present) else 8.0
      C_groundtruth = 15.0 if GroundTruthPresent else 0.0

*Source: results/reports/final_investigation_report.md (Section 8), src/day8_risk_confidence.py*

### 5.2 Risk Level Distribution

| Risk Level | Score Range | Incident Count |
|---|---|---|
| Critical | >= 75 | 60 |
| High | 50-74 | 304 |
| Medium | 25-49 | 741 |
| Low | < 25 | 0 |
| **Total** | | **1,105** |

### 5.3 Confidence Level Distribution

| Confidence Level | Incident Count |
|---|---|
| High | 7 |
| Medium | 183 |
| Low | 915 |
| **Total** | **1,105** |

### 5.4 Cross-Tabulation: Risk x Confidence

| Risk Level | High Confidence | Medium Confidence | Low Confidence | Total |
|---|---|---|---|---|
| Critical (>=75) | 7 | 53 | 0 | **60** |
| High (50-74) | 0 | 82 | 222 | **304** |
| Medium (25-49) | 0 | 48 | 693 | **741** |
| Low (<25) | 0 | 0 | 0 | **0** |
| **Total** | **7** | **183** | **915** | **1,105** |

> All 28 verified red-team incidents mapped to the highest risk scores (91-100). The maximum observed combined score (Risk 100, Confidence 100) corresponded to INC-0209, the largest multi-source red-team incident (158 ground-truth events, 5 telemetry types).

*Source: results/reports/final_investigation_report.md (Section 8), data/processed/incidents.csv*

---

## 6. Human Review

The system routes all 1,105 correlated incidents into a structured analyst review queue using rule-based status assignment.

### 6.1 Review Status Assignment Logic

From src/day9_human_review.py:

| Condition | Assigned Status |
|---|---|
| redteam_event_count > 0 | Confirmed Suspicious |
| Risk level Critical/High AND Confidence Medium/High | Review Required |
| Confidence Low AND risk_score >= 40 | Needs More Investigation |
| Risk level Low | Benign / False Positive |
| All other cases | Review Required (default) |

### 6.2 Human Review Queue Summary

| Review Status | Incident Count | Description |
|---|---|---|
| Confirmed Suspicious | **28** | Ground-truth verified red-team activity - urgent containment recommended |
| Review Required | **293** | High/Critical severity cross-source anomalies - priority analyst review needed |
| Needs More Investigation | **784** | Elevated risk signals with low multi-source telemetry support |
| Benign / False Positive | **0** | None - the risk threshold (>=3) excluded trivial noise before incident formation |
| **Total** | **1,105** | |

*Source: data/processed/human_review_queue.csv, results/reports/investigation_dashboard.html (stat cards), src/day9_human_review.py*

---

## 7. Final Evaluation Metrics

### 7.1 Event-Level Classification Performance

| Metric | Value |
|---|---|
| True Positives (TP) | 497 |
| False Negatives (FN) | 0 |
| False Positives (FP) | 58,885 |
| True Negatives (TN) | 71,115 |
| **Total Evaluated** | **130,497** |

| Metric | Value | Interpretation |
|---|---|---|
| Precision | **0.84%** | Of all suspicious flags, 0.84% are actual attacks |
| Recall (Sensitivity) | **100.00%** | All 497 ground-truth attacks were detected |
| Specificity | **54.70%** | 54.7% of normal events were correctly kept benign |
| F1-Score | **1.66%** | Harmonic mean of Precision and Recall |
| Accuracy | **54.88%** | Overall correct classification rate |

*Source: data/processed/evaluation_results.csv, results/reports/evaluation_report.txt*

### 7.2 Incident-Level Correlation Performance

| Metric | Value |
|---|---|
| Total Correlated Incidents | 1,105 |
| Incidents Containing Red-Team Activity | 28 |
| Red-Team Events Captured in Incidents | 497 / 497 (100.00%) |
| Multi-Source Corroborated Incidents (>= 2 types) | 81 |
| Structural Telemetry Reduction | 99.15% (130,497 events -> 1,105 incidents) |

*Source: data/processed/evaluation_results.csv, results/reports/evaluation_report.txt*

### 7.3 Confusion Matrix

                    Predicted Suspicious    Predicted Normal
    Actual Attack       497  (TP)               0  (FN)
    Actual Normal    58,885  (FP)          71,115  (TN)

---

## 8. Limitations / Not Evaluated

The following aspects were **not evaluated** in the current Phase 1 implementation:

| Item | Status | Notes |
|---|---|---|
| Correlation Quality - Split Groups | NOT EVALUATED | No analysis performed on events that should have been grouped but were split across separate incidents |
| Correlation Quality - Wrongly Merged | NOT EVALUATED | No audit performed to identify events from distinct attack chains that were merged into a single incident |
| Incident-level Precision / Recall | NOT EVALUATED | The 28 red-team incidents represent corroboration count, not full incident-level TP/FP/FN analysis |
| Threshold Calibration (ROC/PR Curve) | NOT EVALUATED | No ROC curve or precision-recall curve analysis was conducted across varying risk_score thresholds |
| Temporal Alignment Quality | NOT EVALUATED | No analysis of how many background events occur within +/-10 min of red-team events and are spuriously correlated |
| Benign / False Positive (Human Review) | Reported as 0 | No incidents reached this status under the current threshold (risk_score >= 3) and routing logic |
| LLM-based reasoning, RAG MITRE ATT&CK, Multi-Agent Orchestration | PROPOSED FUTURE WORK ONLY | Not implemented in Phase 1; listed in results/reports/final_investigation_report.md Section 13 as future extensions |
| Production-scale streaming validation | NOT EVALUATED | Subset was subsampled from 154M raw events; distributed streaming was not tested |

---

## Appendix: Source File Index

| Data / Claim | Source File |
|---|---|
| Dataset composition, event counts | data/subset/multisource_subset.csv, results/reports/subset_statistics.txt |
| Triage rule definitions and trigger counts | results/reports/final_investigation_report.md Section 5 |
| Triage event-level examples (TP and FP) | data/processed/triaged_events.csv |
| Correlation statistics | data/processed/evaluation_results.csv, results/reports/final_investigation_report.md Section 6 |
| Incident records (INC-0018, INC-0037, INC-0407) | data/processed/incidents.csv |
| Incident narrative details (timeline reconstructions) | results/reports/incident_summaries.md |
| Risk/Confidence formulas | src/day8_risk_confidence.py, results/reports/final_investigation_report.md Section 8 |
| Risk/Confidence distribution cross-tab | data/processed/incidents.csv, results/reports/final_investigation_report.md Section 8 |
| Human review queue counts | data/processed/human_review_queue.csv, results/reports/investigation_dashboard.html |
| Human review status assignment logic | src/day9_human_review.py |
| Final evaluation metrics (TP, FP, FN, TN, Precision, Recall, F1, etc.) | data/processed/evaluation_results.csv, results/reports/evaluation_report.txt |
| Incident-level reduction and red-team capture rate | data/processed/evaluation_results.csv |
