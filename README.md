# AI Investigator for Cybersecurity Threat Detection and Response

An autonomous, explainable multi-agent cybersecurity investigation architecture and rule-based SIEM baseline built on the **Los Alamos National Laboratory (LANL) Comprehensive Multi-Source Cyber-Security Events Dataset**.

This system investigates multi-source enterprise telemetry (Authentication, Process Execution, DNS queries, and NetFlow records) across temporal windows, detects adversary campaigns, correlates cross-domain events into multi-stage incidents, computes transparent Risk and Confidence scores, and generates human-governed defensive response playbooks.

---

## 🔒 Defensive Research Scope
This is an academic, defensive cybersecurity research project. All algorithms, detection logic, and agent workflows operate exclusively on the sanitized, anonymized LANL benchmark dataset. No live network scanning, penetration testing, or offensive actions are performed.

---

## 🏛️ System Architecture: Phase 1 vs. Phase 2

### Phase 1: Rule-Based SIEM Investigation Baseline
- **Pipeline:** Preprocessing → 10 Explainable Heuristic Rules → Entity-Indexed Correlation (±10 min window) → Incident Construction → Risk & Confidence Scoring → Interactive SOC Dashboard → Ground-Truth Evaluation.
- **Role:** Represents standard enterprise SIEM/SOC baseline performance. Preserved and fully runnable.

### Phase 2: Autonomous Multi-Agent Cybersecurity Architecture
Decomposes cognitive investigation into cooperating, specialized software agents:
1. **OrchestratorAgent (`src/agents/orchestrator_agent.py`):** Central coordinator managing data routing, pipeline sequencing, and end-to-end execution traces.
2. **AuthenticationAgent (`src/agents/auth_agent.py`):** Ingests `AUTH` events, analyzes logon velocity, NTLM/network protocols, rare lateral mappings, and compromised credentials.
3. **ProcessAgent (`src/agents/process_agent.py`):** Ingests `PROCESS` events, detects rare binary invocations and rapid process spawning bursts.
4. **NetworkAgent (`src/agents/network_agent.py`):** Ingests `DNS` & `FLOW` records, analyzes volumetric exfiltration, prolonged sessions, and suspicious lookups.
5. **CorrelationAgent (`src/agents/correlation_agent.py`):** High-performance Union-Find sliding window correlation ($\Delta t \in \{5\text{m}, 10\text{m}, 30\text{m}\}$) tracking agent evidence provenance.
6. **AnalysisAgent (`src/agents/analysis_agent.py`):** Computes transparent mathematical Risk ($0–100$) and Confidence ($0–100$), generates explainable incident narratives, and records diagnostic uncertainties.
7. **ResponseAgent (`src/agents/response_agent.py`):** Synthesizes prioritized defensive containment playbooks (P1–P4) with mandatory human-in-the-loop sign-off (`requires_human_approval: True`).

---

## 📂 Project Structure

```
mini_proj/
├── data/
│   ├── raw/                           # Raw LANL files (auth.txt.gz, proc.txt.gz, redteam.txt)
│   ├── subset/                        # Extracted subsets (multisource_subset.csv, redteam_subset.csv)
│   └── processed/                     # Cleaned, triaged, and correlated datasets
├── results/
│   ├── figures/                       # Publication-grade figures (300 DPI)
│   │   ├── phase2/                    # 8 Phase 2 Multi-Agent figures (fig1 through fig8)
│   │   └── ...                        # Phase 1 baseline figures
│   ├── phase2/                        # Phase 2 experimental CSV outputs
│   │   ├── baseline_vs_multiagent.csv # Direct baseline vs multi-agent comparison
│   │   ├── agent_ablation_results.csv # 6-stage agent ablation results
│   │   ├── agent_window_results.csv   # 5m, 10m, 30m correlation window sensitivity
│   │   ├── multi_agent_comparison.csv # Multi-window evaluation across 3 windows
│   │   ├── agent_error_analysis.csv   # Detailed FP and FN error audit
│   │   ├── agent_performance.csv      # Per-agent runtime and call stats
│   │   └── related_work.csv           # 7 landmark academic papers indexed
│   └── reports/                       # Comprehensive markdown reports
│       ├── research_question.md       # Formal research question, H1 and H0
│       ├── multi_agent_case_studies.md# Deep case studies (INC-0018, INC-0407, INC-0002)
│       ├── related_work.md            # Extensive academic literature review
│       ├── phase2_ieee_summary.md     # 20-section IEEE-style research paper report
│       ├── phase1_results.md          # Comprehensive Phase 1 experimental records
│       ├── final_investigation_report.md
│       └── investigation_dashboard.html # Interactive SOC investigation dashboard
├── src/
│   ├── agents/                        # Phase 2 Executable Agent Modules
│   │   ├── __init__.py
│   │   ├── base_agent.py              # Abstract BaseAgent with telemetry profiling
│   │   ├── orchestrator_agent.py      # Multi-agent coordinator & execution trace
│   │   ├── auth_agent.py              # Authentication specialist agent
│   │   ├── process_agent.py           # Process execution specialist agent
│   │   ├── network_agent.py           # NetFlow and DNS specialist agent
│   │   ├── correlation_agent.py       # Sliding-window cross-domain correlation
│   │   ├── analysis_agent.py          # Mathematical risk/confidence & explainability
│   │   └── response_agent.py          # Response advisory (human approval mandatory)
│   ├── phase2/                        # Phase 2 Experiment & Evaluation Drivers
│   │   ├── run_multi_agent.py         # Full multi-agent investigation pipeline runner
│   │   ├── evaluate_agents.py         # Baseline vs. multi-agent comparative evaluator
│   │   ├── run_ablation.py            # Systematic 6-stage agent ablation experiment
│   │   ├── run_multi_window.py        # Multi-window evaluation (3 windows)
│   │   ├── run_window_experiment.py   # Correlation window sensitivity (5m, 10m, 30m)
│   │   ├── generate_phase2_visualizations.py # 8 publication-quality figures
│   │   └── test_agents.py             # Comprehensive unit and integration test suite
│   ├── day1_explore_redteam.py        # Phase 1 scripts (Day 1 - Day 10)
│   ├── day2_build_multisource_subset.py
│   ├── day4_preprocess.py
│   ├── day5_triage.py
│   ├── day6_correlation.py
│   ├── day7_incident_analysis.py
│   ├── day8_risk_confidence.py
│   ├── day9_human_review.py
│   └── day10_evaluation.py
└── requirements.txt
```

---

## 📊 Summary of Experimental Results

### 1. Detection Performance: Baseline vs. Multi-Agent (Day 9–13 Window)

| System Configuration | Scope | TP | FP | FN | TN | Precision (%) | Recall (%) | F1-Score (%) | Specificity (%) | Accuracy (%) | Incidents |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Phase 1 Baseline** | Rule Triage (Score $\ge 3$) | 497 | 58,885 | 0 | 71,115 | 0.84% | 100.00% | 1.66% | 54.70% | 54.88% | 1,105 |
| **Phase 2 Multi-Agent** | Specialist Agents | 497 | 57,539 | 0 | 72,461 | 0.86% | 100.00% | 1.70% | 55.74% | 55.91% | 1,075 |
| **Phase 2 Multi-Agent** | Correlated Incidents | 497 | 57,455 | 0 | 72,545 | 0.86% | 100.00% | 1.70% | 55.80% | 55.97% | 1,075 |
| **Phase 2 Multi-Agent** | Prioritized Incidents (High/Crit) | 497 | **55,505** | 0 | **74,495** | **0.89%** | **100.00%** | **1.76%** | **57.30%** | **57.47%** | **197** |

*Outcome:* The multi-agent system retains 100% of adversary attacks while suppressing 3,380 false positives and reducing analyst review load to 197 prioritized incidents. In early attack windows (Window 2: Days 9–10), the multi-agent system achieves **100.00% Precision, 100.00% Recall, and 100.00% F1-score** (0 false positives).

### 2. Correlation Window Sensitivity

| Window Setting | Incidents Formed | Red-Team Incidents | Red-Team Attacks Captured | Precision (%) | Recall (%) | F1-Score (%) | Runtime |
|---|---|---|---|---|---|---|---|
| **5 Minutes (300s)** | 1,554 | 75 | 497 / 497 (100%) | 0.86% | 100.00% | 1.70% | 30.30s |
| **10 Minutes (600s)** | 1,075 | 38 | 497 / 497 (100%) | 0.86% | 100.00% | 1.70% | 39.21s |
| **30 Minutes (1800s)** | 652 | 7 | 497 / 497 (100%) | 0.86% | 100.00% | 1.70% | 8.51s |

---

## 🚀 How to Run and Reproduce

### 1. Run Unit & Integration Tests
Verify that all 7 agents, input validation, schemas, and human approval enforcement pass:
```bash
python -m unittest src/phase2/test_agents.py
```

### 2. Run the Multi-Agent Pipeline
Execute the complete multi-agent investigation architecture on the primary dataset:
```bash
python src/phase2/run_multi_agent.py
```

### 3. Evaluate Baseline vs. Multi-Agent
Run the comprehensive comparative evaluation:
```bash
python src/phase2/evaluate_agents.py
```

### 4. Reproduce All Phase 2 Experiments
Run the ablation study, multi-window comparison, correlation window sensitivity, and visualization generation:
```bash
# Agent Ablation Study (Configurations A through F)
python src/phase2/run_ablation.py

# Multi-Window Evaluation (Windows 1, 2, 3)
python src/phase2/run_multi_window.py

# Correlation Window Sensitivity (5m, 10m, 30m)
python src/phase2/run_window_experiment.py

# Generate All 8 Publication Figures
python src/phase2/generate_phase2_visualizations.py
```

### 5. Run Phase 1 Baseline Pipeline (Unmodified)
```bash
python src/day5_triage.py
python src/day6_correlation.py
python src/day8_risk_confidence.py
python src/day10_evaluation.py
```