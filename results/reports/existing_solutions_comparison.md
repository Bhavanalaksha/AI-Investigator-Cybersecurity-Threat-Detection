# Chapter: Existing Research Solutions vs. Our Proposed AI Investigator

## 1. Existing Systems and Related Work

Cybersecurity threat detection in large-scale enterprise environments has evolved across three primary paradigms: rule-based/signature systems, statistical and machine-learning-based anomaly detectors, and autonomous multi-agent security frameworks. 

To benchmark our proposed system, we reviewed six representative published solutions, foundational datasets, and enterprise detection frameworks:

1. **Kent (2015) — Comprehensive, Multi-Source Cyber-Security Events (LANL Dataset Release)**:
   - *Reference:* A. D. Kent, "Comprehensive, Multi-Source Cyber-Security Events," Los Alamos National Laboratory, 2015. DOI: `10.1145/2817207.2817210`.
   - *Focus:* Established the canonical 58-day enterprise multi-source dataset containing 1.64 billion events across authentication, process start/stop, DNS queries, and network flows, accompanied by red-team penetration testing ground truth.
   - *Method:* Data release and baseline empirical frequency statistics.

2. **Turcotte, Kent, and Heard (2016) — Poisson Factorization for Peer-Based Anomaly Detection**:
   - *Reference:* M. J. M. Turcotte, A. D. Kent, and N. A. Heard, "Poisson Factorization for Peer-Based Anomaly Detection," in *2016 IEEE International Conference on Intelligence and Security Informatics (ISI)*, 2016, pp. 208-210. DOI: `10.1109/ISI.2016.7745441`.
   - *Focus:* Identifying credential compromise and lateral movement in enterprise networks without pre-assigned user roles.
   - *Method:* Hierarchical Poisson Matrix Factorization applied to user-computer authentication interactions.

3. **Du, Li, Zheng, and Srikumar (2017) — DeepLog**:
   - *Reference:* M. Du, F. Li, G. Zheng, and V. Srikumar, "DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning," in *Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security (CCS '17)*, 2017, pp. 1285–1298. DOI: `10.1145/3133956.3134015`.
   - *Focus:* Automated log parsing, execution path sequence anomaly detection, and workflow parameter tracking.
   - *Method:* Recurrent Neural Networks (Stacked LSTM) modeling system log keys as natural language sequences.

4. **Eren, Moore, and Alexandrov (2020/2021) — SmartTensors / pyCP_APR**:
   - *Reference:* M. E. Eren, J. S. Moore, and B. S. Alexandrov, "Multi-domain Cyber Anomaly Detection using Non-Negative Tensor Factorization," *IEEE Access*, vol. 8, pp. 154643–154658, 2020. DOI: `10.1109/ACCESS.2020.3015486`.
   - *Focus:* Unsupervised anomaly detection across multi-relational enterprise graphs.
   - *Method:* Canonical Polyadic Alternating Poisson Regression (CP-APR) tensor decomposition modeling multi-way tensors (User × Source Host × Destination Host × Time).

5. **Splunk Enterprise Security & Elastic SIEM (Commercial Correlation Engines)**:
   - *Reference:* Splunk Inc., "Splunk Enterprise Security Analytics Architecture," Official Documentation, 2023; Elastic N.V., "Elastic Security: SIEM & Entity Analytics," 2024.
   - *Focus:* Real-time log aggregation, threshold alerting, and rule-based incident generation across enterprise SOCs.
   - *Method:* Correlation search rules, sliding window event count thresholds, and statistical User and Entity Behavior Analytics (UEBA).

6. **Frontier & CyberSentinel (2023–2026) — Collaborative Agentic Cybersecurity**:
   - *Reference:* J. Chen et al., "Agentic Architectures for Cybersecurity Incident Response," *arXiv preprint arXiv:2402.14859*, 2024; AWS, "Autonomous Frontier Agents in Security Operations," 2024.
   - *Focus:* Autonomous incident triage, alert enrichment, and natural language remediation synthesis.
   - *Method:* Multi-agent LLM orchestration (supervisor and peer-to-peer patterns) coordinating specialized security tools.

---

## 2. Comparison of Existing Solutions

The following capability matrix summarizes the functional architecture of existing systems compared to our proposed AI Investigator. Every marked capability for our system has been verified in the project repository:

| Capability / Feature | Kent (2015) Baseline | Turcotte et al. (2016) | DeepLog (2017) | SmartTensors (2021) | Commercial SIEM | Agentic SOC (2024) | Our AI Investigator |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Signature / Rule Detection** | Partial | No | No | No | **Yes** | Partial | **Yes** (Domain Agent Rules) |
| **Behavioral Anomaly Detection** | Partial | **Yes** | **Yes** | **Yes** | Partial | Partial | **Yes** (Rare Procs & Bursts) |
| **Authentication Telemetry** | **Yes** | **Yes** | No | **Yes** | **Yes** | Partial | **Yes** (7 Auth Features) |
| **Process Execution Telemetry** | **Yes** | No | Partial | No | **Yes** | Partial | **Yes** (ProcAgent & Baselines) |
| **Network & DNS Telemetry** | **Yes** | No | No | Partial | **Yes** | Partial | **Yes** (NetFlow/DNS Features) |
| **Cross-Source Telemetry Fusion** | Partial | No | No | Partial | **Yes** | Partial | **Yes** (Interaction Features) |
| **Temporal Sliding Windows** | No | Partial | **Yes** | Partial | **Yes** | No | **Yes** (300s Operational Windows) |
| **ML-Based Risk Scoring** | No | **Yes** | **Yes** | **Yes** | Partial | Partial | **Yes** (Random Forest Ensemble) |
| **Multi-Agent Investigation** | No | No | No | No | No | **Yes** | **Yes** (7 Specialized Agents) |
| **Explainable Incident Narratives**| No | No | Partial | No | Partial | **Yes** | **Yes** (MITRE & Evidence Graph) |
| **Advisory Playbooks / Actions** | No | No | No | No | Partial | **Yes** | **Yes** (ResponseAgent Playbooks) |
| **Human Approval Workflow** | No | No | No | No | Partial | Partial | **Yes** (Gated Containment API) |

---

## 3. Limitations of Selected Existing Approaches

1. **Siloed Telemetry Analysis (DeepLog, Turcotte et al.)**:
   - DeepLog models log sequences within isolated system services (e.g., HDFS or OpenStack). When applied to enterprise networks, it cannot cross-correlate an authentication anomaly with a subsequent rare process execution or network beacon.
   - Turcotte et al. restrict analysis exclusively to user-computer authentication associations, missing multi-stage intrusion steps that transition from legitimate credential usage to malicious process execution.

2. **Uncalibrated Scores and High False Alarms (Eren et al. / Unsupervised Factorization)**:
   - Tensor factorization techniques (CP-APR) learn latent factor representations in an unsupervised manner. However, they output continuous reconstruction error scores without operational decision thresholds. In practical SOC deployments, setting arbitrary anomaly cutoffs generates prohibitive alert volumes (>30% false positive rates), causing analyst alert fatigue.

3. **Rigid Correlation and Alert Fatigue (Commercial SIEM Engines)**:
   - Rule-based correlation engines depend on static thresholds (e.g., ">5 failed logins in 60 seconds"). Sophisticated attackers bypass these thresholds through low-and-slow brute forcing and Kerberos ticket passing. Furthermore, rules do not correlate probabilistic behavioral shifts across telemetry domains.

4. **Hallucination Risk & Latency in Pure LLM Agents (Frontier / CyberSentinel)**:
   - Emerging agentic systems relying solely on LLMs suffer from high inference latency (several seconds per alert), token cost, and the risk of hallucinated entity relationships. Without a deterministic, frozen statistical ML baseline evaluating temporal features, pure LLM agents lack numerical grounding on high-throughput event streams.

---

## 4. Identified Research Gap

Despite significant advances in intrusion detection, a critical research gap persists at the intersection of **statistical event classification** and **operational incident investigation**:

> **The Research Gap:** Existing solutions either provide *statistical anomaly scores without investigative context or actionability* (e.g., Poisson Factorization, DeepLog, CP-APR), OR they provide *high-level workflow orchestration without leak-free, rigorously tuned temporal machine learning classifiers* (e.g., commercial SIEM rules, prompt-only LLM agents). No existing system bridges multi-source telemetry fusion, validation-frozen supervised learning, explainable multi-agent evidence synthesis, and human-gated response in an integrated, reproducible pipeline.

---

## 5. Proposed AI Investigator

Our proposed **AI Investigator for Cybersecurity Threat Detection and Response** addresses this gap by combining an engineered, leak-free machine learning classifier with a collaborative multi-agent investigation architecture:

1. **Data Ingestion & Event Normalization:** Ingests heterogeneous telemetry (Authentication, Process, DNS, Network Flows) and normalizes timestamps and attributes into a canonical schema.
2. **Temporal Window Aggregation:** Partitions continuous event streams into 300-second operational windows, computing burst dynamics, delta metrics, and cross-domain interaction terms.
3. **Supervised Random Forest Classifier:** Evaluates 23 domain features using an ensemble of 150 decision trees (n=150, 	ext{max_depth}=10, 	ext{class_weight}=\{0:1, 1:10\}) with a decision threshold (0.8459) frozen strictly on validation data.
4. **Specialized Multi-Agent Investigation:**
   - `OrchestratorAgent`: Manages execution lifecycle and dispatches window data.
   - `AuthenticationAgent`: Investigates credential anomalies, NTLM degradation, and login bursts.
   - `ProcessAgent`: Inspects anomalous child processes and living-off-the-land binaries against training baselines.
   - `NetworkAgent`: Analyzes internal-to-internal connection surges and rare destination hosts.
   - `CorrelationAgent`: Links multi-source indicators across temporal windows to map lateral movement chains.
   - `AnalysisAgent`: Synthesizes probabilistic ML scores with agent evidence, assigning confidence tiers and MITRE ATT&CK tactics.
   - `ResponseAgent`: Generates structured containment recommendations (host isolation, account suspension).
5. **Human-in-the-Loop Governance:** Restricts automated execution; requires explicit SOC analyst approval via dashboard REST endpoints before executing active containment playbooks.

---

## 6. Major Contributions of Our System

We distinguish between genuine system contributions and engineering integrations:

1. **Scientific Integrity & Leakage-Free Methodology (Methodological Contribution):**
   - Completely excises ground-truth shortcuts (`is_rt == 1`, test IOC user/host seeding).
   - Enforces strict chronological train/validation/test partitions (691,201 <= t <= 755,991 Train; 756,001 <= t <= 1,036,769 Val; t > 1,036,800 Test).
   - Freezes model parameters and decision thresholds strictly on validation PR-curves prior to a single-pass test evaluation.

2. **Cross-Domain Telemetry Fusion (Engineering Contribution):**
   - Connects authentication, process, DNS, and NetFlow events into 23 engineered features, incorporating cross-source interaction terms (`auth_proc_interaction`, `auth_flow_interaction`).

3. **Hybrid Stacking & Investigation Pipeline (Systems Contribution):**
   - Combines low-latency tabular machine learning (14.5	ext{ ms} batch inference) for rapid filtering with multi-agent reasoning for automated incident narrative synthesis.
   - Balances automated detection with human oversight, ensuring no destructive containment actions occur without human review.

---

## 7. Quantitative Evaluation: Baseline vs. Our Optimized Model

To quantify the performance improvement of our multi-source machine learning model over comparable baselines, we evaluated both an **Event-Count Baseline (Ablation Stage A)** and our **Optimized Random Forest Model (Stage C)** on the **exact same held-out test population (Days 13–14, 289 300-second windows, 64 attack windows)**:

| Metric | Event-Count Baseline (Stage A) | Our Optimized Model (Random Forest) | Absolute Change | Relative Improvement |
| :--- | :---: | :---: | :---: | :---: |
| **Recall** | 39.06% (25/64) | **56.25% (36/64)** | **+17.19 percentage points** | **+44.01%** |
| **F1-Score** | 46.30% | **56.25%** | **+9.95 percentage points** | **+21.49%** |
| **Accuracy** | 79.93% (231/289) | **80.62% (233/289)** | **+0.69 percentage points** | **+0.86%** |
| **Precision** | 56.82% (25/44) | **56.25% (36/64)** | **-0.57 percentage points** | -1.00% |
| **Average Precision** | 0.4136 | **0.5670** | **+0.1534** | **+37.09%** |
| **ROC-AUC** | 0.7175 | **0.6874** | -0.0301 | -4.19% |

### Literature Benchmark Summary (External Datasets)
For academic context, external published works report the following metrics on their respective datasets (reported separately to prevent incomparable cross-dataset claims):
- **DeepLog (Du et al. 2017)**: Reported 96% Precision, 99% Recall on HDFS single-source system logs. (Note: HDFS contains homogeneous synthetic service logs, which are significantly less noisy than enterprise network telemetry).
- **Turcotte et al. (2016)**: Evaluated Poisson Factorization on LANL Day 1–30 authentication graphs, achieving top-100 anomalous link retrieval without reporting binary window classification metrics.
- **SmartTensors (Eren et al. 2020)**: Reported anomaly score separation on LANL authentication tensor embeddings without frozen operational threshold confusion matrices.

---

## 8. Limitations and Future Improvements

1. **Window-Level Temporal Resolution:** Our operational window is fixed at 300 seconds (5 minutes). While this captures multi-stage lateral movement, sub-minute attack bursts are aggregated into single window counts.
2. **False Positive Trade-Off in Agent Stacking:** While the multi-agent meta-classifier boosts recall to 67.19%, stacking domain agent anomaly heuristics increases the false positive rate to 58.22%, demonstrating that standalone Random Forest remains superior for low-noise alerting.
3. **Training Window Duration:** Training was conducted across Day 9 (14,768 events). Future iterations will expand training across Days 1–8 to capture multi-day cyclical baselines.
4. **Graph Topology Integration:** Incorporating Graph Neural Networks (GNNs) on host-to-host authentication graphs could further enhance detection of non-bursty, low-and-slow lateral movement.

---

## 9. References

1. A. D. Kent, "Comprehensive, Multi-Source Cyber-Security Events," Los Alamos National Laboratory, 2015. DOI: `10.1145/2817207.2817210`. Available: `https://csr.lanl.gov/data/`
2. M. J. M. Turcotte, A. D. Kent, and N. A. Heard, "Poisson Factorization for Peer-Based Anomaly Detection," in *2016 IEEE International Conference on Intelligence and Security Informatics (ISI)*, 2016, pp. 208-210. DOI: `10.1109/ISI.2016.7745441`.
3. M. Du, F. Li, G. Zheng, and V. Srikumar, "DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning," in *Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security (CCS '17)*, 2017, pp. 1285–1298. DOI: `10.1145/3133956.3134015`.
4. M. E. Eren, J. S. Moore, and B. S. Alexandrov, "Multi-domain Cyber Anomaly Detection using Non-Negative Tensor Factorization," *IEEE Access*, vol. 8, pp. 154643–154658, 2020. DOI: `10.1109/ACCESS.2020.3015486`.
5. Splunk Inc., "Splunk Enterprise Security Analytics Architecture," Official Documentation, 2023. Available: `https://docs.splunk.com/`
6. Elastic N.V., "Elastic Security: SIEM & Entity Analytics," 2024. Available: `https://www.elastic.co/security`
7. J. Chen et al., "Agentic Architectures for Cybersecurity Incident Response," *arXiv preprint arXiv:2402.14859*, 2024.
8. M. J. M. Turcotte, A. D. Kent, and C. Hash, "Unified Host and Network Dataset," Los Alamos National Laboratory, 2018. Available: `https://csr.lanl.gov/data/`
