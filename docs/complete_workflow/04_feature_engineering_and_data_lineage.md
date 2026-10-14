# AI Investigator: Feature Engineering and Data Lineage

This document provides a mathematical and implementation-level specification of the 23 domain features used by the machine learning model, followed by a step-by-step trace of how raw records transform into ML feature vectors.

---

## 1. 300-Second Operational Temporal Windows

The core machine learning engine does not classify individual log lines in isolation. Classifying raw log lines independently fails because stealthy lateral movement events appear individually identical to normal administrative logons. 

Instead, the pipeline groups normalized events into **non-overlapping 300-second (5-minute) operational analysis windows**:

```
ext{Window ID = floor( rac{	ext{timestamp - t_{min{300 
ight
floor
```

Where:
- t_{\min is the earliest timestamp in the data partition.
- 300 seconds provides sufficient temporal context to capture multi-stage adversary sequences (e.g., ticket grant o administrative share access o command execution) while maintaining an operational detection latency suitable for SOC response.

---

## 2. Complete 23-Feature Dictionary

Implemented in `src/model_optimization.py` under `build_window_dataset()`.

| Index | Feature Name | Source Fields | Mathematical Formula / Extraction Logic | Security Significance |
| :---: | :--- | :--- | :--- | :--- |
| **1** | `total_events` | All | \sum 1 across 300s window | Baseline telemetry density. Extreme bursts indicate automated scanning or scripted attacks. |
| **2** | `is_auth` | `event_type` | \sum \mathbb{I(	ext{event\_type = 	ext{'auth') | Volume of authentication activity in window. |
| **3** | `auth_fail` | `details`, `action` | \sum \mathbb{I(	ext{is\_auth \land 	ext{'fail' in 	ext{details) | Failed logon attempts; key indicator of credential stuffing or brute-force attempts. |
| **4** | `auth_fail_rate` | Computed | rac{	ext{auth\_fail{	ext{is\_auth + 10^{-5 | Ratio of failed logons to total logons. Normalizes for high-volume enterprise authentication servers. |
| **5** | `auth_ntlm` | `details` | \sum \mathbb{I(	ext{is\_auth \land 	ext{'ntlm' in 	ext{details) | Legacy NTLM authentication volume. NTLM is frequently abused in Pass-the-Hash campaigns. |
| **6** | `auth_ntlm_rate` | Computed | rac{	ext{auth\_ntlm{	ext{is\_auth + 10^{-5 | Proportion of NTLM logons. Elevated ratios indicate protocol downgrade or lateral movement. |
| **7** | `auth_off_hours` | `timestamp` | \sum \mathbb{I(	ext{is\_auth \land (	ext{hour < 6 \lor 	ext{hour >= 20)) | Logons occurring outside normal business operating hours (20:00 to 06:00). |
| **8** | `is_proc` | `event_type` | \sum \mathbb{I(	ext{event\_type = 	ext{'process') | Total process execution count on monitored endpoints. |
| **9** | `proc_rare` | `process` | \sum \mathbb{I(	ext{is\_proc \land 	ext{process in 	ext{rare\_proc\_set) | Execution of rare processes (<= 5 historical training occurrences). Flags custom malware or LOLBins. |
| **10** | `is_dns` | `event_type` | \sum \mathbb{I(	ext{event\_type = 	ext{'dns') | Volume of domain resolution requests. |
| **11** | `is_flow` | `event_type` | \sum \mathbb{I(	ext{event\_type = 	ext{'flow') | Volume of network transport connection flows. |
| **12** | `user` | `user` | ext{CountDistinct(	ext{user) | Number of distinct active usernames in window. |
| **13** | `destination_host` | `destination_host` | ext{CountDistinct(	ext{destination\_host) | Number of distinct destination hosts contacted. Spikes indicate network mapping or lateral fan-out. |
| **14** | `source_host` | `source_host` | ext{CountDistinct(	ext{source\_host) | Number of distinct originating hosts. |
| **15** | `process` | `process` | ext{CountDistinct(	ext{process) | Number of distinct executable binaries spawned. |
| **16** | `user_to_host_ratio` | Computed | rac{	ext{user{	ext{destination\_host + 10^{-5 | Ratio of unique users to unique target hosts. Low ratio with high host count indicates lateral hopping. |
| **17** | `active_sources` | Computed | \mathbb{I(	ext{is\_auth > 0) + \mathbb{I(	ext{is\_proc > 0) + \mathbb{I(	ext{is\_dns > 0) + \mathbb{I(	ext{is\_flow > 0) | Multi-source diversity count (1 to 4). Adversary lateral movement typically activates >= 2 sources. |
| **18** | `multi_source_flag` | Computed | \mathbb{I(	ext{active\_sources >= 2) | Binary indicator identifying cross-domain operational windows. |
| **19** | `auth_proc_interaction` | Computed | \ln(1 + 	ext{is\_auth) 	imes \ln(1 + 	ext{is\_proc) | Non-linear interaction between logons and process executions (e.g., PsExec authentication followed by execution). |
| **20** | `auth_flow_interaction` | Computed | \ln(1 + 	ext{is\_auth) 	imes \ln(1 + 	ext{is\_flow) | Non-linear interaction between authentication and outbound network flow sessions. |
| **21** | `delta_total_events` | `total_events` | ext{total\_events_t - 	ext{total\_events_{t-1 | Temporal velocity: rate of change in overall event activity compared to the preceding 300s window. |
| **22** | `delta_auth_fails` | `auth_fail` | ext{auth\_fail_t - 	ext{auth\_fail_{t-1 | Failure acceleration: sudden onset of authentication failures across window boundaries. |
| **23** | `delta_procs` | `is_proc` | ext{is\_proc_t - 	ext{is\_proc_{t-1 | Process burst acceleration: sudden elevation in process executions compared to prior window. |

---

## 3. Step-by-Step Numerical Example

Consider an operational window W_{14 containing 50 events spanning seconds 4200 to 4499:
- 30 Authentication events (`is_auth = 30`), among which 6 have `status=fail` (`auth_fail = 6`), 9 use NTLM (`auth_ntlm = 9`), and 15 occurred at 02:30 AM (`auth_off_hours = 15`).
- 12 Process events (`is_proc = 12`), of which 3 invoke rare binary `P482` (`proc_rare = 3`).
- 8 Flow events (`is_flow = 8`).
- 0 DNS events (`is_dns = 0`).
- Unique entities: 2 users (`user = 2`), 6 destination hosts (`destination_host = 6`), 1 source host (`source_host = 1`), 4 processes (`process = 4`).
- Previous window W_{13 had `total_events = 20`, `auth_fail = 1`, `is_proc = 2`.

### Calculations:
1. ext{auth\_fail\_rate = rac{6{30 + 10^{-5 = \mathbf{0.2000 (20% failure rate)
2. ext{auth\_ntlm\_rate = rac{9{30 + 10^{-5 = \mathbf{0.3000 (30% NTLM rate)
3. ext{user\_to\_host\_ratio = rac{2{6 + 10^{-5 = \mathbf{0.3333 (1 user per 3 hosts)
4. ext{active\_sources = 1 (	ext{auth) + 1 (	ext{proc) + 0 (	ext{dns) + 1 (	ext{flow) = \mathbf{3
5. ext{multi\_source\_flag = \mathbb{I(3 >= 2) = \mathbf{1
6. ext{auth\_proc\_interaction = \ln(1 + 30) 	imes \ln(1 + 12) = 3.434 	imes 2.565 = \mathbf{8.808
7. ext{auth\_flow\_interaction = \ln(1 + 30) 	imes \ln(1 + 8) = 3.434 	imes 2.197 = \mathbf{7.545
8. ext{delta\_total\_events = 50 - 20 = \mathbf{+30
9. ext{delta\_auth\_fails = 6 - 1 = \mathbf{+5
10. ext{delta\_procs = 12 - 2 = \mathbf{+10

---

## 4. End-to-End Data Lineage Table

Tracing 4 heterogeneous raw log records from sensor arrival to final threat classification:

| Step | Telemetry Domain | Input Sensor Record | Transformation Applied | Resulting Feature Contribution | Consuming Component |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **1** | **Authentication** | `150885,U620@DOM1,C17693,C1003,Kerberos,Network,LogOn,Success` | Mapped via `log_parser.py` into internal schema. Assigned to Window W_{502. | Increments `is_auth` (+1), updates unique user/host sets. | Feature Engine & `AuthenticationAgent` |
| **2** | **Process** | `150910,U620@DOM1,C1003,P1,Start` | Ingested; matches `rare_proc_set` (<= 5 baseline occurrences). | Increments `is_proc` (+1), increments `proc_rare` (+1). | Feature Engine & `ProcessAgent` |
| **3** | **Network Flow** | `150940,45,C17693,Port1024,C1003,Port445,6,120,64500` | Ingested; extracted byte count (64,500 bytes) and port 445 (SMB). | Increments `is_flow` (+1), activates multi-source interaction. | Feature Engine & `NetworkAgent` |
| **4** | **DNS Resolution** | `150950,C17693,C1003` | Ingested; extracted source host and destination resolution. | Increments `is_dns` (+1), sets `active_sources` = 4. | Feature Engine & `NetworkAgent` |
| **5** | **Window Assembly** | Aggregated across all events in seconds 150600–150899 | Vectorized aggregation in `model_optimization.py`. | 23-dimensional numerical row vector constructed. | `StandardScaler` |
| **6** | **Standardization** | Raw 23-feature vector | Z-score scaling: z = rac{x - mean_{	ext{train{std_{	ext{train using frozen parameters. | Normalized feature vector X_{	ext{scaled in \mathbb{R^{23. | `RandomForestClassifier` |
| **7** | **Model Inference** | Scaled vector X_{	ext{scaled | Evaluated across 150 decision trees; averaged voting probability. | Continuous threat probability P = \mathbf{0.942. | Threshold Comparator |
| **8** | **Threshold Gating** | Probability P = 0.942 | Gated against frozen High-Precision threshold (heta = 0.9300). | Binary threat alert triggered (0.942 >= 0.9300). | `OrchestratorAgent` |
