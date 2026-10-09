# Research Question & Hypothesis: Phase 2 Multi-Agent Investigation

**Project:** AI Investigator for Cybersecurity Threat Detection and Response  
**Investigation Framework:** Multi-Agent Architecture vs. Rule-Based SOC Baseline  
**Dataset:** Los Alamos National Laboratory (LANL) Comprehensive Multi-Source Cyber-Security Events  
**Document Created:** 2026-09-24  

---

## 1. Research Question

> **"Does multi-agent cybersecurity investigation improve detection and incident analysis compared with the existing rule-based investigation baseline on the LANL Comprehensive Multi-Source Cyber-Security Events Dataset?"**

### 1.1 Context and Problem Formulation
In modern Security Operations Centers (SOCs), rule-based Security Information and Event Management (SIEM) systems generate overwhelming volumes of alerts (alert fatigue). In Phase 1 of this research, our explainable rule-based baseline on 130,497 multi-source LANL events achieved 100% recall on the 497 ground-truth red-team attacks, but at the cost of 58,885 false positives (precision: 97.26%, F1-score: 98.61%).

Phase 2 investigates whether decomposing the investigation into specialized, autonomous, and collaborative agents—each focusing on a specific telemetry domain (Authentication, Process Execution, Network/DNS) and coordinating via an Orchestrator, Correlation, Analysis, and Response agent—can significantly suppress false positives, enhance contextual incident reconstruction, and improve operational triage efficiency.

---

## 2. Hypotheses

### Hypothesis 1 (Alternative Hypothesis — H_1)
H_1: \text{Performance}_{\text{Multi-Agent}} > \text{Performance}_{\text{Rule-Based Baseline}}

A modular, multi-agent cybersecurity investigation architecture provides superior incident analysis, higher detection precision, improved F1-score, and reduced false-positive rates compared with the existing rule-based investigation baseline, while preserving high recall on ground-truth red-team attacks.

### Hypothesis 0 (Null Hypothesis — H_0)
H_0: \text{Performance}_{\text{Multi-Agent}} \le \text{Performance}_{\text{Rule-Based Baseline}}

The multi-agent architecture does not provide a statistically significant or operational improvement in the selected detection and incident analysis evaluation metrics (Precision, Recall, F1-Score, Specificity, Accuracy, and Alert Reduction) compared with the existing rule-based baseline.

---

## 3. Evaluation Criteria & Metrics

To evaluate H_1 vs. H_0 objectively and without prior assumption:

1. **Event-Level Detection Performance:**
   - **Precision (P):** \frac{TP}{TP + FP} (Primary objective: suppress false positives)
   - **Recall / Sensitivity (R):** \frac{TP}{TP + FN} (Must remain at or near 100% ground-truth coverage)
   - **F1-Score (F_1):** 2 \times \frac{P \times R}{P + R} (Harmonic balance of precision and recall)
   - **Specificity (S):** \frac{TN}{TN + FP} (Ability to correctly identify normal background activity)
   - **Accuracy (A):** \frac{TP + TN}{\text{Total Events}}

2. **Incident-Level Analysis Quality:**
   - **Correlated Incident Count:** Structural alert reduction rate
   - **Multi-Source Corroboration:** Rate of incidents combining cross-domain telemetry
   - **Explainability & Narrative Detail:** Structured provenance, rule attribution, and uncertainty reporting
   - **Actionability:** Prioritized defensive guidance generated with mandatory human approval

3. **Generalization Across Temporal Windows:**
   - Testing across multiple LANL windows (Window 1: Days 9–13, Window 2: Days 13–15, Window 3: Days 2–6) to ensure findings are not an artifact of a single timeframe.

---

## 4. Experimental Discipline

All experiments are conducted with strict scientific integrity:
- Both the baseline and multi-agent systems are evaluated on identical datasets, identical feature sets, and identical ground-truth annotations.
- H_1 is not presumed to be true; empirical results from ablation studies, temporal window variations, and error analysis will decide the validity of the hypothesis.
- Results and metrics are derived strictly from deterministic script executions without fabrication.
