# Multi-Agent Cybersecurity Investigation: Deep Case Studies

**Project:** AI Investigator for Cybersecurity Threat Detection and Response  
**Framework:** Autonomous & Collaborative Multi-Agent SOC Investigation  
**Dataset:** Los Alamos National Laboratory (LANL) Multi-Source Cyber-Security Events  
**Report Date:** 2026-09-24  

---

## Executive Overview
This document presents three deep-dive case studies illustrating the multi-agent investigation lifecycle across heterogeneous real-world scenarios in the LANL cybersecurity dataset:
1. **Case Study 1 (INC-0018):** Confirmed Adversary Red-Team Campaign (High-Velocity Lateral Movement)
2. **Case Study 2 (INC-0407):** Multi-Source Suspicious Cross-Domain Anomaly (Authentication + Process Execution)
3. **Case Study 3 (INC-0002):** False-Positive / Borderline Telemetry Event (Watchlist Entity Association)

Each case study details the chronological progression through specialist agents (`AuthenticationAgent`, `ProcessAgent`, `NetworkAgent`), cross-entity temporal grouping by `CorrelationAgent`, multi-source evidentiary synthesis by `AnalysisAgent`, and human-governed remediation playbooks by `ResponseAgent`.

---

## Case Study 1: Confirmed Adversary Red-Team Campaign (INC-0018)

### 1. Incident Metadata
- **Incident ID:** INC-0018
- **Temporal Boundaries:** Timestamps [745,795 → 749,054] (Duration: 3,259 seconds / ~54 minutes)
- **Investigation Window:** Day 9 (08:43 – 09:37 UTC equivalent)
- **Total Events Correlated:** 31 events
- **Ground-Truth Red-Team Events:** 31 / 31 (100.00% confirmed adversary attack activity)
- **Users Involved (8):** `U1450@DOM1`, `U2575@DOM1`, `U374@DOM1`, `U8777@C1500`, `U8777@C3388`, `U8777@C583`, `U882@DOM1`, `U9947@DOM1`
- **Endpoints Involved (18):** `C11039`, `C1119`, `C12448`, `C1461`, `C1479`, `C1500`, `C1616`, `C17425`, `C17693`, `C18113`, `C19156`, `C19803`, `C20203`, `C3388`, `C346`, `C583`, `C853`, `C923`

### 2. Multi-Agent Detection & Contribution
- **Agents Involved:** `AuthenticationAgent`, `CorrelationAgent`, `AnalysisAgent`, `ResponseAgent`
- **What Happened:**
  An adversary established an initial foothold on staging host `C17693` and methodically executed a multi-account credential-hopping campaign across 18 distinct domain endpoints. Compromised user credentials (`U8777`, `U882`, `U9947`) were successively utilized to authenticate to internal hosts via network logon protocols.
- **Evidence Contributed by Specialist Agents:**
  - `AuthenticationAgent`: Flagged rapid authentication bursts across disparate machines, rare lateral user-to-host pairings, and confirmed usage of threat actor accounts (`U8777`, `U9947`).
  - `NetworkAgent`: Identified concurrent sessions originating from pivot host `C17693`.
- **CorrelationAgent Synthesis:**
  The `CorrelationAgent` utilized an entity-indexed sliding temporal window (±10 minutes / 600s), pivoting upon shared source host `C17693` and hopping user accounts. Rather than emitting 31 disparate, fragmented alerts, the agent consolidated the entire 54-minute intrusion into a single structured incident object.
- **AnalysisAgent Conclusion:**
  - **Risk Score:** 91.0 / 100 (Critical Severity)
  - **Confidence Score:** 62.0 / 100 (Substantial Evidentiary Certainty)
  - **Uncertainty Accounting:** The agent explicitly noted the absence of endpoint process telemetry (`PROCESS` data) in this specific incident cluster, identifying that while lateral credential propagation was verified, command-line execution payloads could not be reconstructed.
- **ResponseAgent Recommendations:**
  - **Action:** Immediate Analyst Escalation & Endpoint Isolation Staging
  - **Priority:** P1 - Critical / Urgent
  - **Containment Playbook:**
    1. Stage emergency network isolation for pivot host `C17693` and targeted endpoints (`C11039`, `C1119`, `C12448`).
    2. Invalidate active Kerberos Ticket-Granting Tickets (TGT) and force immediate password resets for accounts `U8777`, `U882`, and `U9947`.
    3. Export volatile RAM dumps and event logs from `C17693` for forensics.
  - **Human Approval Requirement:** `requires_human_approval: True` (strictly enforced; no automated host shutdown).

---

## Case Study 2: Cross-Source Suspicious Telemetry Anomaly (INC-0407)

### 1. Incident Metadata
- **Incident ID:** INC-0407
- **Temporal Boundaries:** Timestamps [1,088,333 → 1,091,233] (Duration: 2,900 seconds / ~48 minutes)
- **Investigation Window:** Day 13
- **Total Events Correlated:** 25 events
- **Ground-Truth Red-Team Events:** 0 (Unlabeled anomaly / potential novel attack behavior)
- **Users Involved (13):** `C1611$@DOM1`, `LOCAL SERVICE@C1611`, `U1449@DOM1`, `U2913@DOM1`, `U4738@DOM1`, `U5012@DOM1`, `U52@DOM1`, `U6826@DOM1`, `U7640@DOM1`, `U7845@DOM1`, `U8158@DOM1`, `U8250@DOM1`, `U9735@DOM1`
- **Endpoints Involved (3):** `C1611`, `C7946`, `C801`
- **Telemetry Sources:** `AUTH` → `PROCESS` (Cross-domain progression)

### 2. Multi-Agent Detection & Contribution
- **Agents Involved:** `AuthenticationAgent`, `ProcessAgent`, `CorrelationAgent`, `AnalysisAgent`, `ResponseAgent`
- **What Happened:**
  Host `C1611` experienced an influx of 13 distinct domain users authenticating within a 48-minute period. Immediately following the authentication cluster, the host executed an anomalous binary (`P415`) with high process burst density (4–6 executions in under 2 minutes).
- **Evidence Contributed by Specialist Agents:**
  - `AuthenticationAgent`: Flagged rare user-to-host mappings and NTLM network authentications targeting `C1611`.
  - `ProcessAgent`: Flagged execution of process `P415` (global baseline frequency < 15 occurrences across the entire dataset) and rapid process execution bursts on host `C1611`.
- **CorrelationAgent Synthesis:**
  The `CorrelationAgent` linked the authentication sequence to the subsequent process creation events based on shared endpoint `C1611` and temporal proximity (events occurring within 180 seconds of each other).
- **AnalysisAgent Conclusion:**
  - **Risk Score:** 67.0 / 100 (High Severity)
  - **Confidence Score:** 59.0 / 100 (Medium Confidence)
  - **Explainability Narrative:** The agent documented a multi-stage attack pattern: multi-user credential landing followed by rare binary execution on an endpoint on the compromised host list.
  - **Uncertainty Accounting:** The agent flagged that network flow data (`FLOW`) was missing for this cluster, leaving potential external data exfiltration unverified.
- **ResponseAgent Recommendations:**
  - **Action:** Tier-2 SOC Analyst Review & Target Host Monitoring
  - **Priority:** P2 - High Priority
  - **Playbook:**
    1. Inspect parent-child process tree for binary `P415` on host `C1611`.
    2. Audit user privileges for accounts `U1449` and `U2913`.
    3. Enable enhanced telemetry collection on host `C1611`.
  - **Human Approval Requirement:** `requires_human_approval: True`.

---

## Case Study 3: Benign / False-Positive Borderline Telemetry Event (INC-0002)

### 1. Incident Metadata
- **Incident ID:** INC-0002
- **Temporal Boundaries:** Timestamp 691,318 (Instantaneous)
- **Investigation Window:** Day 9
- **Total Events Correlated:** 1 event (`EVT-0000062`)
- **Ground-Truth Red-Team Events:** 0 (Normal background traffic)
- **Users Involved:** None (Machine network resolution)
- **Endpoints Involved (2):** `C1823` → `C1819`
- **Telemetry Source:** `DNS`

### 2. Multi-Agent Detection & Contribution
- **Agents Involved:** `NetworkAgent`, `CorrelationAgent`, `AnalysisAgent`, `ResponseAgent`
- **What Happened:**
  Host `C1823` issued a DNS query resolving destination host `C1819`. Because `C1819` was recorded in the global watchlist of compromised endpoints, static rule evaluation triggered an alert.
- **Evidence Contributed by Specialist Agents:**
  - `NetworkAgent`: Flagged interaction with a watchlist host (`C1819`).
  - `AuthenticationAgent`: Reported zero corroborating anomalous authentication attempts.
  - `ProcessAgent`: Reported zero suspicious binary executions on `C1823`.
- **CorrelationAgent Synthesis:**
  `CorrelationAgent` formed an isolated single-event cluster. Because no follow-up lateral movement or execution occurred within the ±10 minute temporal window, the cluster remained uncorroborated by other specialist agents.
- **AnalysisAgent Conclusion:**
  - **Risk Score:** 35.0 / 100 (Medium Severity)
  - **Confidence Score:** 25.0 / 100 (Low Evidentiary Certainty)
  - **Diagnostic Assessment:** Classified as an isolated watchlist hit with zero cross-domain corroboration. The agent explicitly identified high likelihood of a false positive resulting from benign internal infrastructure resolution.
- **ResponseAgent Recommendations:**
  - **Action:** Automated Telemetry Logging & Baseline Tracking
  - **Priority:** P4 - Low / Informational
  - **Playbook:**
    1. Maintain passive telemetry logging without active endpoint intervention.
    2. Suppress urgent escalation to prevent SOC analyst fatigue.
  - **Human Approval Requirement:** `requires_human_approval: True`.

---

## Summary Comparison Across Case Studies

| Metric / Dimension | Case Study 1 (INC-0018) | Case Study 2 (INC-0407) | Case Study 3 (INC-0002) |
|---|---|---|---|
| **Incident Nature** | Confirmed Red-Team Attack | Multi-Source Anomaly | Benign / False Positive |
| **Ground Truth** | Adversary Lateral Movement | Unlabeled Anomaly | Normal Traffic |
| **Telemetry Progression** | AUTH (Burst + Lateral) | AUTH → PROCESS | DNS (Isolated) |
| **Specialist Agents Corroborating** | AuthAgent + NetworkAgent | AuthAgent + ProcessAgent | NetworkAgent Only |
| **Risk Score** | **91.0 / 100 (Critical)** | **67.0 / 100 (High)** | **35.0 / 100 (Medium)** |
| **Confidence Score** | **62.0 / 100 (High)** | **59.0 / 100 (Medium)** | **25.0 / 100 (Low)** |
| **Assigned Priority** | P1 - Urgent Containment | P2 - Tier-2 SOC Review | P4 - Passive Logging |
| **Human Approval Required** | **YES (Mandatory)** | **YES (Mandatory)** | **YES (Mandatory)** |
