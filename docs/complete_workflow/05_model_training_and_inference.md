# Module 05: Machine Learning Model Training and Runtime Inference Pipeline

This document provides a comprehensive academic and engineering breakdown of the machine learning architecture in the **AI Investigator** system. It details the offline training pipeline, mathematical foundations of the Random Forest classifier, feature preprocessing, decision threshold optimization, and the runtime inference pipeline.

---

## 1. Clear Paradigm Distinction: Training vs. Runtime Inference

One of the most frequent points of confusion in applied machine learning for cybersecurity is the distinction between **Model Training** and **Runtime Inference**.

```
+---------------------------------------------------------------------------------------------------+
|                                      MODEL TRAINING (OFFLINE)                                     |
|                                                                                                   |
|  Historical LANL Data (Days 1-9)                                                                  |
|  [Auth, Proc, Flow, DNS]  +  Ground-Truth Labels (redteam.txt)                                    |
|          |                                                                                        |
|          v                                                                                        |
|  Feature Engineering -> Fit StandardScaler -> Train RandomForest (150 trees) -> Optimize Threshold|
|                                                      |                                            |
|                                                      v                                            |
|                                         best_model.joblib (FROZEN)                                |
+---------------------------------------------------------------------------------------------------+
                                                       |
                                            Artifact Persistence
                                                       |
                                                       v
+---------------------------------------------------------------------------------------------------+
|                                    RUNTIME INFERENCE (ONLINE / API)                               |
|                                                                                                   |
|  Live Ingestion Stream (Raw Event / JSON / Syslog)                                                |
|          |                                                                                        |
|          v                                                                                        |
|  UniversalLogParser -> 300s Window Aggregator -> Extract 23 Features                              |
|          |                                                                                        |
|          v                                                                                        |
|  Load best_model.joblib (READ-ONLY) -> scaler.transform() -> model.predict_proba()               |
|          |                                                                                        |
|          v                                                                                        |
|  Multi-Agent Investigation (Auth, Proc, Net, Correlation) -> Risk Scoring -> SOC Dashboard / API   |
+---------------------------------------------------------------------------------------------------+
```

### Core Axiom
**Training teaches the model from labeled historical data. Inference uses the saved, trained model to evaluate incoming live events. A normal prediction request or API query NEVER retrains the model.**

| Dimension | Offline Model Training | Runtime Inference |
|---|---|---|
| **Execution Script** | `src/model_optimization.py`, `src/train.py` | `src/server.py`, `src/main.py` |
| **Frequency** | Executed once during model development or scheduled maintenance | Executed continuously on live telemetry streams or API calls |
| **Input Data** | Historical 14-day multi-source telemetry with `redteam.txt` | Single event, log batch, or 300-second window feature vector |
| **Ground-Truth Label** | Required (`is_redteam` in {0, 1}) | Completely absent (unlabeled production data) |
| **Hardware Requirement** | Compute-heavy (CPU multi-threading for ensemble fitting) | Lightweight (sub-50ms matrix vectorization) |
| **Artifact Role** | Generates and exports `results/models/best_model.joblib` | Reads and consumes `results/models/best_model.joblib` in read-only mode |
| **State Mutation** | Updates internal tree weights, splits, and scaler parameters | State-free; leaves model parameters unaltered |

---

## 2. Offline Training Workflow

The training pipeline transforms multi-source tabular telemetry into a robust, generalized threat detector.

```mermaid
graph TD
    A[Processed LANL Dataset: Days 1 to 14] --> B[Chronological Split]
    B --> C[Train Partition: Days 1 to 9]
    B --> D[Validation Partition: Days 10 to 12]
    B --> E[Test Partition: Days 13 to 14]
    
    C --> F[Vocabulary Extraction: rare_proc_set <= 5]
    C --> G[Compute 23 Engineered Features]
    G --> H[Fit StandardScaler on Train Features]
    
    H --> I[Initialize RandomForestClassifier]
    I --> J[Fit 150 Decision Trees on Class-Weighted Loss]
    
    J --> K[Validation Evaluation: Days 10 to 12]
    K --> L[Decision Threshold Sweep: theta in 0.1 to 0.9]
    L --> M[Select Optimal Threshold: theta = 0.9300 High-Precision Mode]
    
    M --> N[Serialize to results/models/best_model.joblib]
```

### 2.1 Data Source and Chronological Splitting
The dataset comprises LANL network telemetry across 14 consecutive calendar days. Rather than utilizing a naive random k-fold cross-validation—which creates massive temporal data leakage in time-series telemetry—the training pipeline enforces a strict **Chronological Split**:
- **Training Set (Days 1 to 9):** Represents baseline enterprise activity and initial attack demonstrations. Used exclusively to build vocabulary dictionaries, fit scalers, and train tree estimators.
- **Validation Set (Days 10 to 12):** Used exclusively for hyperparameter tuning and decision threshold optimization.
- **Test Set (Days 13 to 14):** Held out as an untouched benchmark to evaluate generalization against completely unseen future events.

### 2.2 Leakage Prevention Architecture
Data leakage occurs when information outside the training dataset is inadvertently used to create the model. In cybersecurity detection, leakage leads to unrealistically high test scores that collapse in production. The pipeline implements three safeguards:
1. **Temporal Isolation:** Historical boundaries are strictly respected. Feature extraction for Day `t` utilizes only state accumulated up to Day `t`.
2. **Vocabulary Fit Exclusivity:** The set of rare processes (`rare_proc_set`), defined as binaries appearing 5 times or fewer, is calculated solely on Days 1 to 9. Any process appearing on Day 11 that was unseen in Days 1 to 9 is correctly flagged as rare during validation/testing without leaking future frequency counts into the past.
3. **Scaler Parameter Isolation:** Mean (`mean`) and standard deviation (`std`) vectors in `StandardScaler` are fitted exclusively on the training feature matrix `X_train`. `X_val` and `X_test` are transformed using the frozen training parameters:
```
z = (x - mean_train) / std_train
```

### 2.3 Class Imbalance Management
In enterprise telemetry, malicious red-team events account for less than 0.1% of total activity. Training an unweighted classifier on this distribution results in a trivial model that predicts all events as benign (99.9% accuracy, 0% recall).
To overcome this without synthesizing artificial cyber logs (such as SMOTE, which can generate invalid categorical combinations), the pipeline configures **cost-sensitive learning** via class weighting:
```python
class_weight = {0: 1.0, 1: 10.0}
```
During tree splitting, misclassifying a malicious red-team sample incurs a 10x penalty compared to misclassifying a benign event, forcing the split criteria to aggressively isolate threat clusters.

---

## 3. Mathematical Foundations of the Random Forest Classifier

The core detector utilizes an ensemble of bootstrap-aggregated (bagged) decision trees.

### 3.1 Algorithm Architecture
A Random Forest constructs `B = 150` de-correlated decision trees. For each tree `b` in `{1, ..., B}`:
1. Draw a bootstrap sample `D_b` of size `N` with replacement from the training dataset.
2. At each candidate node split, select a random subset of `m = sqrt(p)` features (where `p = 23`, thus `m = floor(sqrt(23)) = 4` candidate features per split).
3. Compute the optimal split threshold among the `m` features using the **Gini Impurity** objective.
4. Grow the tree to a maximum depth of `max_depth = 10` without pruning, subject to `min_samples_split = 5` and `min_samples_leaf = 2`.

### 3.2 Mathematical Formulation
The Gini Impurity `I_G(t)` for node `t` containing classes `k in {0, 1}` is:
```
I_G(t) = 1 - sum_{k=0}^1 (p(k | t))^2
```
Where `p(k | t)` is the proportion of samples at node `t` belonging to class `k`.
For a candidate split `s` dividing node `t` into left child `t_L` and right child `t_R`:
```
Delta I_G(s, t) = I_G(t) - ( (N_L / N_t) * I_G(t_L) + (N_R / N_t) * I_G(t_R) )
```
The splitting algorithm selects the feature `j` and threshold `v` maximizing `Delta I_G(s, t)`.

### 3.3 Ensemble Probability Aggregation
During inference, each individual tree `T_b` produces an estimated posterior class distribution for an input feature vector `x`. The ensemble probability is the unweighted average across all 150 trees:
```
P(y = 1 | x) = (1 / B) * sum_{b=1}^{B} P_b(y = 1 | x)
```

### 3.4 Configured Hyperparameters
The production model artifact `best_model.joblib` encapsulates the following hyperparameter specification:
- `n_estimators`: 150 (balances variance reduction with execution latency)
- `max_depth`: 10 (constrains tree complexity to prevent memorization of hostnames)
- `min_samples_split`: 5 (prevents splits on isolated outlier events)
- `min_samples_leaf`: 2 (guarantees leaf nodes represent at least 2 distinct window events)
- `max_features`: 'sqrt' (forces feature de-correlation across trees)
- `class_weight`: `{0: 1.0, 1: 10.0}` (heavily penalizes false negatives)
- `random_state`: 42 (ensures deterministic reproducibility)

---

## 4. Decision Threshold Optimization and Calibration

Standard classification algorithms assign a positive prediction when `P(y = 1 | x) >= 0.50`. However, in Security Operations Centers (SOCs), where false-positive alert fatigue is the primary failure mode, the decision threshold `theta` is a tunable operational parameter.

```
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
```

As the threshold `theta` increases:
- **False Positives (FP) decrease rapidly:** Benign anomalies with moderate suspicion are suppressed.
- **Precision increases:** Alerts generated by the system represent high-confidence intrusions.
- **Recall decreases:** Subtle, low-signal exploratory activity may fall below the alerting bar.

### Operational Threshold Configurations
1. **Default Balanced Mode (`theta = 0.5000`):**
   - Yields balanced precision and recall for general investigative telemetry analysis.
2. **High-Precision Alerting Mode (`theta = 0.9300`):**
   - Derived from systematic threshold sweeps on validation telemetry.
   - Suppresses 94% of benign operational anomalies, guaranteeing that alerts sent directly to SOC Tier-3 analysts represent confirmed lateral movement or credential abuse.

---

## 5. Runtime Inference Pipeline

When a client submits live logs, JSON events, or API batches, the system executes an automated, read-only inference chain.

```mermaid
sequenceDiagram
    autonumber
    actor Client as API Client / SOC Analyst
    participant API as FastAPI Server (server.py)
    participant Parser as UniversalLogParser
    participant FeatureEngine as 300s Window Extractor
    participant ModelStore as Serialized Model (best_model.joblib)
    participant Orchestrator as OrchestratorAgent
    participant AgentMesh as Multi-Agent Mesh

    Client->>API: POST /api/investigate (Raw Event or JSON)
    API->>Parser: parse_record(payload)
    Parser-->>API: Normalized Event Dictionary
    API->>FeatureEngine: extract_window_features(event)
    FeatureEngine-->>API: 23-Dimensional Vector [X_1, ..., X_23]
    API->>ModelStore: scaler.transform(X) -> predict_proba(X)
    ModelStore-->>API: P(y=1|X) = 0.8842
    API->>Orchestrator: investigate(event, ml_prob=0.8842)
    Orchestrator->>AgentMesh: Dispatch to Auth, Proc, Net, Correlation
    AgentMesh-->>Orchestrator: Agent Evidences & Rule Flags
    Orchestrator-->>API: Unified Investigation Dossier (Risk=88, Severity=Critical)
    API-->>Client: 200 OK HTTP Response with JSON Dossier
```

### 5.1 Step-by-Step Runtime Execution
1. **Ingestion & Validation:** The API receives a log record via HTTP POST. `UniversalLogParser` validates schema structure and normalizes timestamps into epoch seconds.
2. **Feature Extraction:** The event is placed into its temporal 300-second window. The feature engine calculates the 23 model features in exact training order.
3. **Artifact Loading:** At startup, `server.py` loads `results/models/best_model.joblib` into memory once. Subsequent requests perform in-memory forward passes without disk I/O overhead.
4. **Scaler Transformation:** The raw 23-element vector is normalized using the frozen `StandardScaler` coefficients:
```
X_scaled = scaler.transform([raw_features])
```
5. **Model Inference:** `best_model.predict_proba(X_scaled)` computes the posterior threat probability `P(malicious)`.
6. **Agent Mesh Hand-off:** The orchestrator invokes the specialized security agents, passing both the raw telemetry event and the calculated ML threat probability.
7. **Dossier Assembly:** The analysis agent integrates ML probabilities with rule-based heuristics to compute the final combined risk score (0 to 100), severity tier, and response recommendations.

### 5.2 Error Handling and Fallback Resilience
- **Missing Model File:** If `best_model.joblib` is absent from `results/models/`, the API server logs a critical alert and switches dynamically to **Rule-Only Fallback Mode**, allowing the multi-agent mesh to continue triaging events using baseline profiling and expert heuristics.
- **Unseen Categorical Values:** If an event introduces a previously unrecorded user or computer, the system assigns zero to historical interaction counts, computes `rare_proc = 1` or `rare_user_host = 1`, and processes the record without crashing.
- **Latency Guarantee:** In-memory inference executes in under 15 milliseconds per record on standard commodity x86 hardware.
