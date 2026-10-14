# AI Investigator: Dataset and Column Dictionary

This document provides a complete, column-by-column breakdown of all raw, subset, processed, and evaluation data files utilized across the project.

---

## 1. Primary Dataset: Los Alamos National Laboratory (LANL) Benchmark

The project uses the **LANL Comprehensive Cyber-Security Events Dataset** (Unified Host and Network Dataset). This dataset represents 58 consecutive days of operational enterprise telemetry captured within Los Alamos National Laboratory's corporate network. 

The dataset contains over 1.6 billion events, within which the LANL Red Team performed verified adversary attacks (lateral movement, credential dumping, and administrative privilege misuse).

### Raw Telemetry Files in `data/raw/`:

| File Name | File Size | Description | Native Format |
| :--- | :---: | :--- | :--- |
| `auth.txt.gz` | 7.62 GB | Authentication and logon/logoff events across Active Directory domain controllers. | Comma-delimited text |
| `proc.txt.gz` | 2.35 GB | Process creation and termination events on corporate workstations and servers. | Comma-delimited text |
| `flows.txt.gz` | 1.08 GB | IP network flow summary records collected from central enterprise routing switches. | Comma-delimited text |
| `dns.txt.gz` | 185 MB | Domain Name System (DNS) host resolution request records. | Comma-delimited text |
| `redteam.txt` | 22.9 KB | Ground-truth log of verified adversary lateral movement events conducted by LANL Red Team. | Comma-delimited text |

---

## 2. Raw Dataset Column Specifications

### A. Authentication Logs (`auth.txt.gz`)
The raw LANL authentication log records Active Directory logon and ticket requests.

| Column Name | Data Type | Meaning | Example Value | Used By Stage | Feature or Metadata? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `time` | Integer | Epoch time in seconds from start of collection (Day 1 = 1 to 86,400). | `150885` | Window Aggregator, AuthAgent | Metadata & Temporal Feature |
| `source_user` | String | User identity originating the authentication request. | `U620@DOM1` | AuthAgent, BaselineProfiler | Entity Identifier |
| `destination_user` | String | Target user identity being authenticated against. | `U620@DOM1` | AuthAgent | Entity Identifier |
| `source_computer` | String | Host identity from which authentication was initiated. | `C17693` | AuthAgent, Feature Engine | Entity Identifier |
| `destination_computer` | String | Target host identity receiving authentication request. | `C1003` | AuthAgent, Feature Engine | Entity Identifier |
| `authentication_type` | String | Authentication protocol/package used (Kerberos, NTLM, Negotiate, etc.). | `Kerberos` | AuthAgent, Feature Engine | Feature (`auth_ntlm`) |
| `logon_type` | String | Windows logon orientation (Interactive, Network, Unlock, Batch, Service). | `Network` | AuthAgent | Feature & Context |
| `authentication_orientation` | String | Directional orientation (LogOn, LogOff, TGS, TGT). | `LogOn` | AuthAgent | Feature & Context |
| `status` | String | Outcome status: `Success` or `Fail`. | `Success` | AuthAgent, Feature Engine | Feature (`auth_fail`) |

### B. Process Execution Logs (`proc.txt.gz`)
The raw process log captures process creation events across enterprise endpoints.

| Column Name | Data Type | Meaning | Example Value | Used By Stage | Feature or Metadata? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `time` | Integer | Epoch time in seconds from start of collection. | `151020` | Window Aggregator, ProcessAgent | Metadata & Temporal Feature |
| `user` | String | User identity executing the process binary. | `U620@DOM1` | ProcessAgent, Feature Engine | Entity Identifier |
| `computer` | String | Host identity where process execution occurred. | `C17693` | ProcessAgent, Feature Engine | Entity Identifier |
| `process_name` | String | Executable binary identifier (anonymized in LANL, e.g., `P1`, `P4`). | `P1` | ProcessAgent, Feature Engine | Feature (`proc_rare`) |
| `action` | String | Process lifecycle event: `Start` or `End`. | `Start` | ProcessAgent | Feature & Context |

### C. Network Flow Logs (`flows.txt.gz`)
The raw flow log captures network connection summaries between communicating endpoints.

| Column Name | Data Type | Meaning | Example Value | Used By Stage | Feature or Metadata? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `time` | Integer | Epoch time in seconds from start of collection. | `150900` | Window Aggregator, NetworkAgent | Metadata & Temporal Feature |
| `duration` | Integer | Total elapsed duration of network session in seconds. | `45` | NetworkAgent | Feature (`duration`) |
| `source_computer` | String | Initiating host identifier. | `C17693` | NetworkAgent, Feature Engine | Entity Identifier |
| `source_port` | String | Originating TCP/UDP port number (anonymized or explicit). | `Port1024` | NetworkAgent | Feature Context |
| `destination_computer` | String | Destination host identifier. | `C1003` | NetworkAgent, Feature Engine | Entity Identifier |
| `destination_port` | String | Target service port number (e.g., SMB/445, RDP/3389). | `Port445` | NetworkAgent, Feature Engine | Feature Context |
| `protocol` | String | Transport layer protocol (TCP, UDP). | `6` | NetworkAgent | Feature Context |
| `packet_count` | Integer | Number of packets transferred in network flow. | `120` | NetworkAgent | Feature Context |
| `byte_count` | Integer | Total bytes transferred in network flow. | `64500` | NetworkAgent, Feature Engine | Feature (`flow_byte_volume`) |

### D. DNS Resolution Logs (`dns.txt.gz`)
The raw DNS log records name resolution queries executed by corporate hosts.

| Column Name | Data Type | Meaning | Example Value | Used By Stage | Feature or Metadata? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `time` | Integer | Epoch time in seconds from start of collection. | `150920` | Window Aggregator, NetworkAgent | Metadata & Temporal Feature |
| `source_computer` | String | Host identifier querying domain resolver. | `C17693` | NetworkAgent, Feature Engine | Entity Identifier |
| `resolved_computer` | String | Domain name or resolved host identifier. | `C1003` | NetworkAgent, Feature Engine | Feature Context |

### E. Red Team Ground-Truth Labels (`redteam.txt`)
Records confirmed adversary activities conducted by authorized LANL penetration testers.

| Column Name | Data Type | Meaning | Example Value | Used By Stage | Feature or Metadata? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `time` | Integer | Exact epoch second of adversary lateral movement action. | `150885` | Label Generator | Ground Truth Label ONLY |
| `user` | String | Compromised credential used by Red Team during attack. | `U620@DOM1` | Label Generator | Ground Truth Label ONLY |
| `source_computer` | String | Pivot host identity used by Red Team to initiate hop. | `C17693` | Label Generator | Ground Truth Label ONLY |
| `destination_computer` | String | Target host identity compromised or accessed by Red Team. | `C1003` | Label Generator | Ground Truth Label ONLY |

> **Critical Leakage Rule:** The contents of `redteam.txt` are used strictly to assign ground-truth binary labels (y in {0, 1\) during training and post-hoc test evaluation. Red-team columns are **never** used as feature inputs to the machine learning model.

---

## 3. Normalized Internal Schema (`INTERNAL_SCHEMA`)

To decouple the multi-agent system from dataset-specific naming conventions, `src/ingest/log_parser.py` maps all raw inputs into an 11-column standard schema:

| Standard Column | Normalized Meaning | Mapped From LANL Columns | Example |
| :--- | :--- | :--- | :--- |
| `event_type` | Telemetry domain category (`auth`, `process`, `flow`, `dns`). | Inferred or explicit file tag | `auth` |
| `timestamp` | Epoch time in integer seconds. | `time` | `150885` |
| `user` | Primary acting user identity. | `user` or `source_user` | `U620@DOM1` |
| `source_user` | Originating identity in delegation/logon. | `source_user` | `U620@DOM1` |
| `destination_user` | Target identity in delegation/logon. | `destination_user` | `U620@DOM1` |
| `source_host` | Initiating computer/endpoint. | `source_computer` or `computer` | `C17693` |
| `destination_host` | Target computer/endpoint. | `destination_computer` | `C1003` |
| `process` | Executed binary or process name. | `process_name` | `P1` |
| `action` | Action descriptor (`LogOn`, `Start`, `Resolve`). | `action` or `authentication_orientation` | `LogOn` |
| `details` | Structured pipe-delimited metadata string. | Formatted string containing status, packages, ports | `status=success|package=kerberos` |
| `is_redteam` | Evaluation label (`1` = verified attack, `0` = normal). | Left join match with `redteam.txt` | `0` or `1` |

---

## 4. Processed Data Artifacts in `data/processed/`

| Processed File | Primary Key | Key Columns | Purpose in Pipeline |
| :--- | :--- | :--- | :--- |
| `events_processed.csv` | `event_id` | `event_id`, `event_type`, `timestamp`, `user`, `source_host`, `destination_host`, `process`, `action`, `details`, `day`, `time_in_day_sec`, `hour_of_day` | Day 1–14 normalized event subset with added temporal partition columns. |
| `triaged_events.csv` | `event_id` | `event_id`, `risk_score`, `is_suspicious`, `triggered_rules`, `triage_reasons` | Output of initial heuristic triage scoring identifying suspicious raw events. |
| `incidents.csv` | `incident_id` | `incident_id`, `start_time`, `end_time`, `duration_sec`, `users`, `hosts`, `processes`, `event_count`, `risk_score` | Clustered multi-source incidents grouped across 600s correlation windows. |
| `incident_events.csv` | `(incident_id, event_id)` | `incident_id`, `event_id`, `event_type`, `timestamp`, `user`, `source_host`, `destination_host` | Relational join table mapping specific raw events into their parent incident cluster. |
| `human_review_queue.csv` | `incident_id` | `incident_id`, `risk_level`, `confidence_score`, `confidence_level`, `review_status`, `analyst_recommendation` | Incidents requiring analyst review, prioritization, and response sign-off. |

---

## 5. Distinction Between Column Types

Understanding data transformations is essential for viva defense:

```
[ Raw Dataset Columns ]  --> Exact strings as emitted by sensors (e.g., U620@DOM1, C17693, Kerberos, Fail)
         |
         v
[ Parsed Normalized Schema ] --> Standardized names (user, source_host, destination_host, action, details)
         |
         v
[ 300s Aggregated Metrics ] --> Counts & ratios over window (total_events=42, auth_fail=3, proc_rare=1)
         |
         v
[ Engineered Features (23) ] --> Normalization, log-interactions, temporal deltas (auth_fail_rate, delta_procs)
         |
         v
[ Model Input Vector X ] --> StandardScaler transformed floating-point vector fed into best_model.joblib
         |
         v
[ Model Prediction & Prob ] --> Continuous probability P in [0.0, 1.0], binary decision (P >= 0.9300)
         |
         v
[ Incident Risk Score (0-100) ] --> Contextual formula from AnalysisAgent combining ML, host count, velocity
```
