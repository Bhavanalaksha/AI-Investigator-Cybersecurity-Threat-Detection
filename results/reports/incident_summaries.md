# AI Cybersecurity Incident Investigation Summaries

This report provides transparent, explainable investigation summaries for security incidents reconstructed from multi-source LANL telemetry (Day 9–Day 13).

**Total Incidents Analyzed:** 1105
**High-Risk Incidents (Risk >= 60):** 127
**Incidents Corroborating Red-Team Ground Truth:** 28

---

## Incident INC-0407 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1088333 to 1091233 (Duration: 2900s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `25`
- **Users Involved:** C1611@DOM1, LOCAL SERVICE@C1611, U1449@DOM1, U2913@DOM1, U4738@DOM1, U5012@DOM1, U52@DOM1, U6826@DOM1, U7640@DOM1, U7845@DOM1, U8158@DOM1, U8250@DOM1, U9735@DOM1
- **Hosts Involved:** C1611, C7946, C801
- **Processes Involved:** P10, P131, P17, P171, P18, P209, P21, P211, P285, P287, P288, P289, P4, P415, P44, P5, P796
- **Telemetry Progression:** AUTH -> PROCESS

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Infrequently executed process (P415)
- Involves known compromised host (C1611)
- Process burst: 4 processes spawned in 2 minutes
- Process burst: 5 processes spawned in 2 minutes
- Process burst: 6 processes spawned in 2 minutes
- Rare user-to-host lateral mapping (U1449@DOM1 -> nan)
- Rare user-to-host lateral mapping (U6826@DOM1 -> nan)
- Rare user-to-host lateral mapping (U7845@DOM1 -> nan)
- Rare user-to-host lateral mapping (U8158@DOM1 -> nan)

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1088333: Start (process=P285)
1. `PROCESS` at t=1088395: Start (process=P4)
1. `PROCESS` at t=1088589: End (process=P211)
1. `PROCESS` at t=1088961: End (process=P415)
1. `PROCESS` at t=1089167: End (process=P44)
1. `PROCESS` at t=1089167: End (process=P21)
1. `PROCESS` at t=1089637: End (process=P796)
1. `PROCESS` at t=1090095: End (process=P18)
1. `PROCESS` at t=1090095: Start (process=P18)
1. `PROCESS` at t=1090173: End (process=P171)

---

## Incident INC-0037 — CONFIRMED RED-TEAM ATTACK (High Priority)

- **Time Window:** Timestamp 830548 to 830822 (Duration: 274s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `15`
- **Total Events Correlated:** `15`
- **Users Involved:** U1653@DOM1
- **Hosts Involved:** C22409, C754
- **Telemetry Progression:** REDTEAM

### Why This Incident is Suspicious (Explainable Indicators):
- Associated with known threat actor account (U1653@DOM1)
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Confirmed Red-Team ground truth attack event
- Involves known compromised host (C22409)

### Timeline Reconstruction (First 10 Events):
1. `REDTEAM` at t=830548: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=830548: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=830548: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=830548: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=830548: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=830550: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=830578: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=830578: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=830578: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=830578: REDTEAM_ATTACK (Known red-team event)

---

## Incident INC-1072 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1122949 to 1123258 (Duration: 309s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `71`
- **Users Involved:** ANONYMOUS LOGON@C586, C10099@DOM1, C11220@DOM1, C11560@DOM1, C14069@DOM1, C1441@DOM1, C1450@DOM1, C18632@DOM1, C2616@DOM1, C586@DOM1, C7006@DOM1, C821@DOM1, C9030@DOM1, U1269@DOM1, U242@DOM1, U2460@DOM1, U4003@DOM1, U4693@DOM1, U4748@DOM1, U5171@DOM1, U6230@DOM1, U767@DOM1, U8744@DOM1
- **Hosts Involved:** C10099, C11220, C11560, C12402, C12935, C14069, C1441, C1450, C18632, C2616, C3443, C5618, C573, C586, C7006, C9030
- **Telemetry Progression:** AUTH

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Involves known compromised host (C5618)
- Network logon / NTLM authentication protocol observed
- Rapid auth burst: 4 logons in 5 minutes
- Rapid auth burst: 5 logons in 5 minutes
- Rapid auth burst: 6 logons in 5 minutes
- Rapid auth burst: 7 logons in 5 minutes
- Rapid auth burst: 8 logons in 5 minutes

### Timeline Reconstruction (First 10 Events):
1. `AUTH` at t=1122949: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1122951: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1122961: LogOff (?|Network|Success)
1. `AUTH` at t=1122962: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1122962: LogOff (?|Network|Success)
1. `AUTH` at t=1122964: LogOff (?|Network|Success)
1. `AUTH` at t=1122976: LogOff (?|Network|Success)
1. `AUTH` at t=1122981: LogOn (NTLM|Network|Success)
1. `AUTH` at t=1122988: LogOff (?|Network|Success)
1. `AUTH` at t=1122995: LogOff (?|Network|Success)

---

## Incident INC-1015 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1121690 to 1121721 (Duration: 31s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `43`
- **Users Involved:** C10052@DOM1, C11169@DOM1, C11596@DOM1, C11757@DOM1, C12430@DOM1, C13886@DOM1, C14268@DOM1, C1513@DOM1, C1520@DOM1, C170@DOM1, C17443@DOM1, C18414@DOM1, C19217@DOM1, C19883@DOM1, C21758@DOM1, C2248@DOM1, C2363@DOM1, C2900@DOM1, C3261@DOM1, C3377@DOM1, C3465@DOM1, C4664@DOM1, C5107@DOM1, C5121@DOM1, C7503@DOM1, C7672@DOM1, C790@DOM1, C9700@DOM1, C988@DOM1, C9904@DOM1, U2608@DOM1, U3062@DOM1, U3683@DOM1, U5099@DOM1, U50@DOM1, U6@DOM1, U7056@DOM1, U9197@DOM1
- **Hosts Involved:** C10052, C11169, C11596, C11757, C1183, C12430, C13886, C1439, C170, C18414, C19468, C2249, C2363, C457, C586, C7503, C7776, C921
- **Telemetry Progression:** AUTH

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Involves known compromised host (C457)
- Involves known compromised host (C7503)
- Network logon / NTLM authentication protocol observed
- Rapid auth burst: 5 logons in 5 minutes
- Rare user-to-host lateral mapping (C170@DOM1 -> C170)
- Rare user-to-host lateral mapping (C9904@DOM1 -> C457)
- Rare user-to-host lateral mapping (U3683@DOM1 -> C457)

### Timeline Reconstruction (First 10 Events):
1. `AUTH` at t=1121690: LogOff (?|Network|Success)
1. `AUTH` at t=1121691: LogOff (?|Network|Success)
1. `AUTH` at t=1121691: LogOff (?|Network|Success)
1. `AUTH` at t=1121692: LogOff (?|Network|Success)
1. `AUTH` at t=1121692: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1121693: LogOff (?|Network|Success)
1. `AUTH` at t=1121694: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1121695: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1121695: LogOff (?|Network|Success)
1. `AUTH` at t=1121696: LogOn (Kerberos|Network|Success)

---

## Incident INC-0018 — CONFIRMED RED-TEAM ATTACK (High Priority)

- **Time Window:** Timestamp 745795 to 749054 (Duration: 3259s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `31`
- **Total Events Correlated:** `31`
- **Users Involved:** U1450@DOM1, U2575@DOM1, U374@DOM1, U8777@C1500, U8777@C3388, U8777@C583, U882@DOM1, U9947@DOM1
- **Hosts Involved:** C11039, C1119, C12448, C1461, C1479, C1500, C1616, C17425, C17693, C18113, C19156, C19803, C20203, C3388, C346, C583, C853, C923
- **Telemetry Progression:** REDTEAM

### Why This Incident is Suspicious (Explainable Indicators):
- Associated with known threat actor account (U8777@C583)
- Associated with known threat actor account (U882@DOM1)
- Associated with known threat actor account (U9947@DOM1)
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Compound threat: 4 distinct risk indicators triggered simultaneously
- Confirmed Red-Team ground truth attack event
- Involves known compromised host (C17693)
- Rare user-to-host lateral mapping (U8777@C583 -> C583)
- Rare user-to-host lateral mapping (U882@DOM1 -> C11039)
- Rare user-to-host lateral mapping (U882@DOM1 -> C1616)
- Rare user-to-host lateral mapping (U9947@DOM1 -> C20203)
- Rare user-to-host lateral mapping (U9947@DOM1 -> C346)
- Rare user-to-host lateral mapping (U9947@DOM1 -> C923)

### Timeline Reconstruction (First 10 Events):
1. `REDTEAM` at t=745795: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=745961: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=746039: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=746078: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=746151: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=746353: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=746387: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=746595: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=746638: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=746860: REDTEAM_ATTACK (Known red-team event)

---

## Incident INC-1063 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1122821 to 1123126 (Duration: 305s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `26`
- **Users Involved:** C11508@DOM1, C12649@DOM1, C1265@DOM1, C1394@DOM1, C14149@DOM1, C16625@DOM1, C18754@DOM1, C19867@DOM1, C22505@DOM1, C2397@DOM1, C2576@DOM1, C457@DOM1, C559@DOM1, C7769@DOM1, U6@DOM1, U8125@DOM1, U9215@DOM1, U9859@DOM1, U9937@DOM1
- **Hosts Involved:** C1183, C12649, C16625, C18754, C19485, C22506, C457, C516, C559
- **Telemetry Progression:** AUTH

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Involves known compromised host (C457)
- Network logon / NTLM authentication protocol observed
- Rapid auth burst: 5 logons in 5 minutes
- Rare user-to-host lateral mapping (C14149@DOM1 -> C457)
- Rare user-to-host lateral mapping (C19867@DOM1 -> C457)
- Rare user-to-host lateral mapping (C559@DOM1 -> C559)

### Timeline Reconstruction (First 10 Events):
1. `AUTH` at t=1122821: LogOff (?|Network|Success)
1. `AUTH` at t=1122866: LogOff (?|Network|Success)
1. `AUTH` at t=1122868: LogOff (?|Network|Success)
1. `AUTH` at t=1122868: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1122869: LogOff (?|Network|Success)
1. `AUTH` at t=1122869: LogOff (?|Network|Success)
1. `AUTH` at t=1122871: LogOff (?|Network|Success)
1. `AUTH` at t=1122871: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1122872: LogOff (?|Network|Success)
1. `AUTH` at t=1122873: LogOff (?|Network|Success)

---

## Incident INC-0410 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1088505 to 1089721 (Duration: 1216s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `18`
- **Users Involved:** C9692@DOM1, U3718@DOM1
- **Hosts Involved:** C9692
- **Processes Involved:** P130, P16, P2711, P5
- **Telemetry Progression:** PROCESS

### Why This Incident is Suspicious (Explainable Indicators):
- Associated with known threat actor account (U3718@DOM1)
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Compound threat: 4 distinct risk indicators triggered simultaneously
- Infrequently executed process (P2711)
- Involves known compromised host (C9692)
- Process burst: 4 processes spawned in 2 minutes
- Process burst: 5 processes spawned in 2 minutes
- Process burst: 6 processes spawned in 2 minutes
- Process burst: 7 processes spawned in 2 minutes

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1088505: Start (process=P130)
1. `PROCESS` at t=1088855: Start (process=P2711)
1. `PROCESS` at t=1088889: Start (process=P2711)
1. `PROCESS` at t=1089245: Start (process=P2711)
1. `PROCESS` at t=1089249: Start (process=P5)
1. `PROCESS` at t=1089257: Start (process=P2711)
1. `PROCESS` at t=1089323: Start (process=P2711)
1. `PROCESS` at t=1089339: Start (process=P16)
1. `PROCESS` at t=1089347: Start (process=P2711)
1. `PROCESS` at t=1089367: Start (process=P5)

---

## Incident INC-0984 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1120774 to 1123215 (Duration: 2441s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `254`
- **Users Involved:** ANONYMOUS LOGON@C586, C10227@DOM1, C10340@DOM1, C10503@DOM1, C1065@DOM1, C10870@DOM1, C11376@DOM1, C11719@DOM1, C1172@DOM1, C11817@DOM1, C12149@DOM1, C12508@DOM1, C13713@DOM1, C13724@DOM1, C13779@DOM1, C14514@DOM1, C15436@DOM1, C15939@DOM1, C16348@DOM1, C1657@DOM1, C16619@DOM1, C16665@DOM1, C19120@DOM1, C19145@DOM1, C19505@DOM1, C19520@DOM1, C1987@DOM1, C20042@DOM1, C2025@DOM1, C20704@DOM1, C22365@DOM1, C22511@DOM1, C2319@DOM1, C260@DOM1, C3103@DOM1, C3405@DOM1, C3427@DOM1, C3568@DOM1, C3728@DOM1, C467@DOM1, C623@DOM1, C6257@DOM1, C6705@DOM1, C720@DOM1, C743@DOM1, C7546@DOM1, C7842@DOM1, C8062@DOM1, C8637@DOM1, C8651@DOM1, C868@DOM1, C8705@DOM1, C8730@DOM1, C945@DOM1, C9462@DOM1, U1072@DOM1, U1376@DOM1, U1490@DOM1, U1491@DOM1, U2088@DOM1, U242@DOM1, U2735@DOM1, U3231@DOM1, U4006@DOM1, U4067@DOM1, U4356@DOM1, U4599@DOM1, U4839@DOM1, U4866@DOM1, U5254@DOM1, U52@DOM1, U5523@DOM1, U5527@DOM1, U5986@DOM1, U6045@DOM1, U756@DOM1, U7640@DOM1, U8292@DOM1, U9008@DOM1, U9225@DOM1, U9235@DOM1
- **Hosts Involved:** C10227, C10340, C10503, C10901, C11376, C11719, C11817, C12149, C12434, C12508, C13713, C13724, C14514, C15786, C15939, C1657, C16619, C19145, C19424, C19505, C19520, C1987, C20042, C20704, C2320, C3427, C3568, C366, C467, C586, C623, C6257, C7842, C801, C8062, C8637, C8651, C868, C8730, C945, C9462
- **Telemetry Progression:** AUTH -> FLOW

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Involves known compromised host (C467)
- Network logon / NTLM authentication protocol observed
- Rapid auth burst: 16 logons in 5 minutes
- Rapid auth burst: 7 logons in 5 minutes
- Rare user-to-host lateral mapping (C13779@DOM1 -> C467)
- Rare user-to-host lateral mapping (C260@DOM1 -> C467)
- Rare user-to-host lateral mapping (C3728@DOM1 -> C467)
- Rare user-to-host lateral mapping (C623@DOM1 -> C623)
- Rare user-to-host lateral mapping (C8705@DOM1 -> C467)

### Timeline Reconstruction (First 10 Events):
1. `AUTH` at t=1120774: LogOff (?|Network|Success)
1. `AUTH` at t=1120802: LogOff (?|Network|Success)
1. `AUTH` at t=1120803: LogOff (?|Network|Success)
1. `AUTH` at t=1120804: LogOff (?|Network|Success)
1. `AUTH` at t=1120804: TGS (?|?|Success)
1. `AUTH` at t=1120804: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1120806: LogOff (?|Network|Success)
1. `AUTH` at t=1120806: LogOff (?|Network|Success)
1. `AUTH` at t=1120808: LogOff (?|Network|Success)
1. `AUTH` at t=1120808: LogOff (?|Network|Success)

---

## Incident INC-1031 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1122019 to 1123002 (Duration: 983s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `27`
- **Users Involved:** ANONYMOUS LOGON@C457, C119@DOM1, C12531@DOM1, C14667@DOM1, C163@DOM1, C18418@DOM1, C2096@?, C22509@DOM1, C3356@DOM1, C4257@DOM1, C457@DOM1, C523@DOM1, C6513@DOM1, C9099@DOM1, C9384@DOM1, U2637@DOM1, U3680@DOM1, U6@DOM1, U80@DOM1, U8412@DOM1
- **Hosts Involved:** C1183, C14667, C163, C25240, C25554, C3356, C4257, C457, C6513
- **Telemetry Progression:** AUTH

### Why This Incident is Suspicious (Explainable Indicators):
- Authentication attempt failed
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Involves known compromised host (C457)
- Network logon / NTLM authentication protocol observed
- Rapid auth burst: 14 logons in 5 minutes
- Rare user-to-host lateral mapping (C12531@DOM1 -> C457)
- Rare user-to-host lateral mapping (C14667@DOM1 -> C457)
- Rare user-to-host lateral mapping (C2096@? -> C25240)
- Rare user-to-host lateral mapping (C9099@DOM1 -> C457)

### Timeline Reconstruction (First 10 Events):
1. `AUTH` at t=1122019: TGT (?|?|Fail)
1. `AUTH` at t=1122095: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1122097: TGT (?|?|Fail)
1. `AUTH` at t=1122097: LogOff (?|Network|Success)
1. `AUTH` at t=1122372: LogOff (?|Network|Success)
1. `AUTH` at t=1122372: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1122372: LogOff (?|Network|Success)
1. `AUTH` at t=1122373: TGT (?|?|Fail)
1. `AUTH` at t=1122578: LogOff (?|Network|Success)
1. `AUTH` at t=1122579: LogOff (?|Network|Success)

---

## Incident INC-0497 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1093569 to 1095243 (Duration: 1674s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `34`
- **Users Involved:** C1089@DOM1, C1382@DOM1, C1611@DOM1, C6633@DOM1, C8408@DOM1, LOCAL SERVICE@C1382, LOCAL SERVICE@C1611, U3016@DOM1, U4594@DOM1, U5009@DOM1, U8771@DOM1
- **Hosts Involved:** C1089, C1382, C1611, C586, C8408
- **Processes Involved:** P125, P159, P16, P165, P169, P17, P178, P18, P19, P22, P237, P265, P289, P4, P5
- **Telemetry Progression:** AUTH -> PROCESS

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Infrequently executed process (P125)
- Infrequently executed process (P237)
- Involves known compromised host (C1089)
- Involves known compromised host (C1382)
- Involves known compromised host (C1611)
- Involves known compromised host (C586)
- Network logon / NTLM authentication protocol observed
- Process burst: 4 processes spawned in 2 minutes
- Process burst: 5 processes spawned in 2 minutes
- Process burst: 6 processes spawned in 2 minutes
- Rare user-to-host lateral mapping (C8408@DOM1 -> C586)
- Rare user-to-host lateral mapping (U3016@DOM1 -> nan)

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1093569: End (process=P165)
1. `PROCESS` at t=1093827: Start (process=P22)
1. `PROCESS` at t=1093827: Start (process=P5)
1. `PROCESS` at t=1093999: Start (process=P237)
1. `PROCESS` at t=1093999: Start (process=P125)
1. `PROCESS` at t=1094027: End (process=P178)
1. `AUTH` at t=1094037: LogOff (?|Network|Success)
1. `PROCESS` at t=1094045: End (process=P22)
1. `AUTH` at t=1094051: LogOn (Kerberos|Network|Success)
1. `PROCESS` at t=1094057: End (process=P17)

---

## Incident INC-0516 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1094579 to 1098951 (Duration: 4372s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `57`
- **Users Involved:** ANONYMOUS LOGON@C467, C10159@DOM1, C10340@DOM1, C11376@DOM1, C11719@DOM1, C11817@DOM1, C12508@DOM1, C12609@DOM1, C13724@DOM1, C1473@DOM1, C15207@DOM1, C16619@DOM1, C18842@DOM1, C19520@DOM1, C20042@DOM1, C467@DOM1, C650@DOM1, C7014@DOM1, C718@DOM1, C7354@DOM1, C7946@DOM1, C8062@DOM1, C9542@DOM1, C9893@DOM1, U1376@DOM1, U1484@DOM1, U1491@DOM1, U2443@DOM1, U2629@DOM1, U2735@DOM1, U3231@DOM1, U3677@DOM1, U4006@DOM1, U4067@DOM1, U4219@DOM1, U4221@DOM1, U4604@DOM1, U5265@DOM1, U5523@DOM1, U5527@DOM1, U5788@DOM1, U5908@DOM1, U5986@DOM1, U6272@DOM1, U6927@DOM1, U7500@DOM1, U7556@DOM1, U7640@DOM1, U807@DOM1, U9235@DOM1
- **Hosts Involved:** C10227, C10340, C10503, C11376, C12391, C12508, C12596, C12609, C13724, C14262, C1442, C14527, C1473, C15786, C18842, C20042, C467, C650, C7014, C718, C7354, C7398, C801, C8062, C9542, C9893
- **Telemetry Progression:** AUTH -> FLOW

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Involves known compromised host (C801)
- Network logon / NTLM authentication protocol observed
- Rare user-to-host lateral mapping (C12609@DOM1 -> C801)
- Rare user-to-host lateral mapping (C18842@DOM1 -> C801)
- Rare user-to-host lateral mapping (U1484@DOM1 -> C801)

### Timeline Reconstruction (First 10 Events):
1. `AUTH` at t=1094579: LogOff (?|Network|Success)
1. `AUTH` at t=1094712: LogOff (?|Network|Success)
1. `AUTH` at t=1094761: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1094851: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1095041: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1095113: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1095191: LogOff (?|Network|Success)
1. `AUTH` at t=1095261: LogOff (?|Network|Success)
1. `AUTH` at t=1095271: LogOff (?|Network|Success)
1. `AUTH` at t=1095344: LogOff (?|Network|Success)

---

## Incident INC-0772 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1110994 to 1123093 (Duration: 12099s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `265`
- **Users Involved:** ANONYMOUS LOGON@C586, C10407@DOM1, C10521@DOM1, C10927@DOM1, C11017@DOM1, C11155@DOM1, C11253@DOM1, C13277@DOM1, C14042@DOM1, C1432@DOM1, C16852@DOM1, C1794@DOM1, C18092@DOM1, C19139@DOM1, C21579@DOM1, C2493@DOM1, C2782@DOM1, C2850@DOM1, C286@DOM1, C460@DOM1, C6194@DOM1, C6471@DOM1, C743@DOM1, C7893@DOM1, C8331@DOM1, C9046@DOM1, C9820@DOM1, LOCAL SERVICE@C1432, U10630@DOM1, U5542@DOM1
- **Hosts Involved:** C10407, C10927, C11017, C11775, C12741, C13277, C14042, C1432, C19127, C19139, C2782, C586, C6194, C8331, C9820
- **Processes Involved:** P138, P139, P141, P142, P16, P191, P21, P25, P41, P5, P54, P8, P86, P9
- **Telemetry Progression:** AUTH -> PROCESS

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Involves known compromised host (C1432)
- Process burst: 4 processes spawned in 2 minutes
- Process burst: 5 processes spawned in 2 minutes
- Process burst: 6 processes spawned in 2 minutes

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1110994: End (process=P21)
1. `PROCESS` at t=1111026: Start (process=P21)
1. `PROCESS` at t=1111026: Start (process=P86)
1. `PROCESS` at t=1111028: Start (process=P21)
1. `PROCESS` at t=1111252: End (process=P54)
1. `PROCESS` at t=1111464: Start (process=P142)
1. `PROCESS` at t=1111466: End (process=P142)
1. `PROCESS` at t=1111482: End (process=P21)
1. `PROCESS` at t=1111546: Start (process=P21)
1. `PROCESS` at t=1111578: Start (process=P21)

---

## Incident INC-0921 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1118247 to 1123257 (Duration: 5010s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `81`
- **Users Involved:** U2260@DOM1
- **Hosts Involved:** C3388
- **Telemetry Progression:** AUTH

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Involves known compromised host (C3388)
- Network logon / NTLM authentication protocol observed
- Rapid auth burst: 4 logons in 5 minutes
- Rapid auth burst: 5 logons in 5 minutes
- Rapid auth burst: 6 logons in 5 minutes
- Rapid auth burst: 7 logons in 5 minutes

### Timeline Reconstruction (First 10 Events):
1. `AUTH` at t=1118247: LogOn (NTLM|Network|Success)
1. `AUTH` at t=1118437: LogOff (?|Network|Success)
1. `AUTH` at t=1118697: LogOn (NTLM|Network|Success)
1. `AUTH` at t=1118735: LogOff (?|Network|Success)
1. `AUTH` at t=1118737: LogOn (NTLM|Network|Success)
1. `AUTH` at t=1118897: LogOff (?|Network|Success)
1. `AUTH` at t=1118907: LogOn (NTLM|Network|Success)
1. `AUTH` at t=1118917: LogOff (?|Network|Success)
1. `AUTH` at t=1118927: LogOn (NTLM|Network|Success)
1. `AUTH` at t=1119097: LogOn (NTLM|Network|Success)

---

## Incident INC-0891 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1117209 to 1119065 (Duration: 1856s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `49`
- **Users Involved:** C101@DOM1, C12484@DOM1, C12508@DOM1, C1382@DOM1, C15511@DOM1, C16273@DOM1, C17716@DOM1, C19831@DOM1, C19942@DOM1, C2908@DOM1, C3011@DOM1, C3692@DOM1, C3736@DOM1, C5004@DOM1, C6785@DOM1, C692@DOM1, C7564@DOM1, C8515@DOM1, C9402@DOM1, LOCAL SERVICE@C1382, U3184@DOM1, U3351@DOM1, U576@DOM1
- **Hosts Involved:** C101, C12508, C1382, C16273, C17716, C19831, C19942, C3692, C3736, C467, C7564, C9402
- **Processes Involved:** P16, P17, P18, P22, P5
- **Telemetry Progression:** AUTH -> PROCESS

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Involves known compromised host (C1382)
- Involves known compromised host (C467)
- Network logon / NTLM authentication protocol observed
- Process burst: 4 processes spawned in 2 minutes
- Process burst: 5 processes spawned in 2 minutes
- Process burst: 7 processes spawned in 2 minutes
- Process burst: 8 processes spawned in 2 minutes
- Rare user-to-host lateral mapping (C19831@DOM1 -> C467)

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1117209: End (process=P18)
1. `PROCESS` at t=1117251: End (process=P22)
1. `PROCESS` at t=1117269: Start (process=P18)
1. `PROCESS` at t=1117269: End (process=P17)
1. `PROCESS` at t=1117269: Start (process=P5)
1. `PROCESS` at t=1117311: Start (process=P5)
1. `PROCESS` at t=1117329: End (process=P5)
1. `PROCESS` at t=1117329: Start (process=P18)
1. `AUTH` at t=1117660: LogOff (?|Network|Success)
1. `AUTH` at t=1117661: LogOn (Kerberos|Network|Success)

---

## Incident INC-0139 — CONFIRMED RED-TEAM ATTACK (High Priority)

- **Time Window:** Timestamp 1068312 to 1069035 (Duration: 723s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `9`
- **Total Events Correlated:** `10`
- **Users Involved:** C3813@DOM1, U12@DOM1, U66@DOM1
- **Hosts Involved:** C1006, C1191, C17693, C366, C368, C3813, C4610, C626
- **Processes Involved:** P262
- **Telemetry Progression:** PROCESS -> REDTEAM

### Why This Incident is Suspicious (Explainable Indicators):
- Associated with known threat actor account (U12@DOM1)
- Associated with known threat actor account (U66@DOM1)
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Compound threat: 4 distinct risk indicators triggered simultaneously
- Confirmed Red-Team ground truth attack event
- Infrequently executed process (P262)
- Involves known compromised host (C17693)
- Involves known compromised host (C3813)
- Rare user-to-host lateral mapping (U12@DOM1 -> C366)
- Rare user-to-host lateral mapping (U66@DOM1 -> C1006)
- Rare user-to-host lateral mapping (U66@DOM1 -> C1191)
- Rare user-to-host lateral mapping (U66@DOM1 -> C3813)
- Rare user-to-host lateral mapping (U66@DOM1 -> C4610)

### Timeline Reconstruction (First 10 Events):
1. `REDTEAM` at t=1068312: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=1068390: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=1068507: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=1068638: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=1068692: REDTEAM_ATTACK (Known red-team event)
1. `PROCESS` at t=1068702: End (process=P262)
1. `REDTEAM` at t=1068753: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=1068810: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=1068887: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=1069035: REDTEAM_ATTACK (Known red-team event)

---

## Incident INC-0130 — CONFIRMED RED-TEAM ATTACK (High Priority)

- **Time Window:** Timestamp 1067704 to 1070696 (Duration: 2992s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `9`
- **Total Events Correlated:** `22`
- **Users Involved:** C3586@DOM1, U2575@DOM1, U342@DOM1, U3635@DOM1, U4112@DOM1, U4448@DOM1, U5254@DOM1, U66@DOM1
- **Hosts Involved:** C1438, C17693, C1789, C187, C2519, C2721, C3011, C3586, C398, C458
- **Processes Involved:** P207, P21, P27, P472, P5, P640, P648, P653, P657, P865
- **Telemetry Progression:** PROCESS -> REDTEAM

### Why This Incident is Suspicious (Explainable Indicators):
- Associated with known threat actor account (U342@DOM1)
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Infrequently executed process (P472)
- Infrequently executed process (P640)
- Infrequently executed process (P653)
- Infrequently executed process (P865)
- Involves known compromised host (C3586)
- Involves known compromised host (C458)

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1067704: End (process=P648)
1. `PROCESS` at t=1068003: Start (process=P648)
1. `PROCESS` at t=1068182: Start (process=P865)
1. `PROCESS` at t=1068307: Start (process=P653)
1. `PROCESS` at t=1068487: End (process=P27)
1. `PROCESS` at t=1068780: End (process=P472)
1. `PROCESS` at t=1068847: End (process=P640)
1. `PROCESS` at t=1069201: Start (process=P21)
1. `PROCESS` at t=1069202: End (process=P648)
1. `PROCESS` at t=1069574: End (process=P207)

---

## Incident INC-0769 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1110823 to 1111945 (Duration: 1122s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `25`
- **Users Involved:** C1042@DOM1, C13290@DOM1, C14102@DOM1, C15099@DOM1, C1611@DOM1, C1879@DOM1, C195@DOM1, C20815@DOM1, C3064@DOM1, C467@DOM1, LOCAL SERVICE@C1611, U1345@DOM1, U3001@DOM1, U5487@DOM1, U7489@DOM1, U8720@DOM1, U9255@DOM1
- **Hosts Involved:** C1042, C12882, C14102, C1611, C16352, C195, C2899, C3065, C467
- **Processes Involved:** P16, P17, P22, P5
- **Telemetry Progression:** AUTH -> PROCESS

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Involves known compromised host (C1611)
- Involves known compromised host (C467)
- Network logon / NTLM authentication protocol observed
- Process burst: 4 processes spawned in 2 minutes
- Process burst: 5 processes spawned in 2 minutes
- Rare user-to-host lateral mapping (C20815@DOM1 -> C467)
- Rare user-to-host lateral mapping (C3064@DOM1 -> C467)
- Rare user-to-host lateral mapping (U8720@DOM1 -> C467)

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1110823: Start (process=P5)
1. `PROCESS` at t=1110879: Start (process=P5)
1. `PROCESS` at t=1111163: End (process=P22)
1. `PROCESS` at t=1111179: Start (process=P17)
1. `PROCESS` at t=1111703: Start (process=P5)
1. `AUTH` at t=1111867: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1111879: LogOff (?|Network|Success)
1. `AUTH` at t=1111880: LogOff (?|Network|Success)
1. `AUTH` at t=1111885: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1111889: LogOff (?|Network|Success)

---

## Incident INC-0965 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1120128 to 1120599 (Duration: 471s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `53`
- **Users Involved:** ANONYMOUS LOGON@C586, C10743@DOM1, C1105@DOM1, C13095@DOM1, C13275@DOM1, C13428@DOM1, C14066@DOM1, C1420@DOM1, C14868@DOM1, C15047@DOM1, C15675@DOM1, C17231@DOM1, C18442@DOM1, C18642@DOM1, C18664@DOM1, C19396@DOM1, C195@DOM1, C19764@DOM1, C19810@DOM1, C20059@DOM1, C2155@DOM1, C2319@DOM1, C2962@DOM1, C3568@DOM1, C3906@DOM1, C4519@DOM1, C4747@DOM1, C6223@DOM1, C6429@DOM1, C69@DOM1, C7683@DOM1, C7863@DOM1, C8139@DOM1, C8681@DOM1, C9298@DOM1, C9345@DOM1, C9477@DOM1, U432@DOM1, U5217@DOM1, U5694@DOM1, U6009@DOM1, U7867@DOM1, U818@DOM1, U8994@DOM1
- **Hosts Involved:** C13095, C13722, C13948, C14066, C15047, C15675, C17100, C18642, C18664, C195, C2155, C2320, C2658, C3906, C467, C4747, C545, C5491, C586, C6429, C69, C8139, C9298, C9345, C998
- **Processes Involved:** P300
- **Telemetry Progression:** AUTH -> FLOW -> PROCESS

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Infrequently executed process (P300)
- Involves known compromised host (C467)
- Involves known compromised host (C586)
- Network logon / NTLM authentication protocol observed
- Rapid auth burst: 85 logons in 5 minutes
- Rare user-to-host lateral mapping (C1105@DOM1 -> C586)
- Rare user-to-host lateral mapping (C17231@DOM1 -> C467)
- Rare user-to-host lateral mapping (C4747@DOM1 -> nan)
- Rare user-to-host lateral mapping (C8139@DOM1 -> C467)

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1120128: End (process=P300)
1. `AUTH` at t=1120171: LogOff (?|Network|Success)
1. `AUTH` at t=1120171: LogOff (?|Network|Success)
1. `AUTH` at t=1120172: LogOff (?|Network|Success)
1. `AUTH` at t=1120173: TGS (?|?|Success)
1. `AUTH` at t=1120173: LogOff (?|Network|Success)
1. `AUTH` at t=1120173: LogOff (?|Network|Success)
1. `AUTH` at t=1120174: LogOn (NTLM|Network|Success)
1. `AUTH` at t=1120175: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1120175: LogOn (Kerberos|Network|Success)

---

## Incident INC-0893 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1117221 to 1117760 (Duration: 539s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `36`
- **Users Involved:** C10336@DOM1, C11031@DOM1, C11350@DOM1, C1158@DOM1, C1179@DOM1, C14806@DOM1, C159@DOM1, C1704@DOM1, C17269@DOM1, C18526@DOM1, C18812@DOM1, C19206@DOM1, C19572@DOM1, C21634@DOM1, C21841@DOM1, C2246@DOM1, C291@DOM1, C3600@DOM1, C4455@DOM1, C467@DOM1, C4740@DOM1, C5246@DOM1, C6707@DOM1, C7460@DOM1, C7693@DOM1, C8221@DOM1, C8875@DOM1, C9091@DOM1, U4313@DOM1, U608@DOM1, U8090@DOM1, U9576@DOM1, U9757@DOM1, U9896@DOM1
- **Hosts Involved:** C10336, C11031, C11350, C14806, C1628, C1704, C17269, C17472, C18812, C19572, C21633, C2191, C291, C4455, C457, C467, C4740, C7693, C9091
- **Telemetry Progression:** AUTH

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Involves known compromised host (C457)
- Network logon / NTLM authentication protocol observed
- Rare user-to-host lateral mapping (C19206@DOM1 -> C457)
- Rare user-to-host lateral mapping (C21841@DOM1 -> C457)
- Rare user-to-host lateral mapping (C4455@DOM1 -> C457)
- Rare user-to-host lateral mapping (C8221@DOM1 -> C457)
- Rare user-to-host lateral mapping (U4313@DOM1 -> C457)
- Rare user-to-host lateral mapping (U608@DOM1 -> C14806)
- Rare user-to-host lateral mapping (U608@DOM1 -> C1628)

### Timeline Reconstruction (First 10 Events):
1. `AUTH` at t=1117221: LogOn (NTLM|Network|Success)
1. `AUTH` at t=1117699: LogOff (?|Network|Success)
1. `AUTH` at t=1117714: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1117728: LogOff (?|Network|Success)
1. `AUTH` at t=1117733: LogOff (?|Network|Success)
1. `AUTH` at t=1117735: LogOff (?|Network|Success)
1. `AUTH` at t=1117737: LogOff (?|Network|Success)
1. `AUTH` at t=1117737: LogOff (?|Network|Success)
1. `AUTH` at t=1117738: LogOff (?|Network|Success)
1. `AUTH` at t=1117739: LogOn (Kerberos|Network|Success)

---

## Incident INC-0940 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1119056 to 1123004 (Duration: 3948s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `147`
- **Users Involved:** ANONYMOUS LOGON@C457, C10201@DOM1, C10214@DOM1, C10417@DOM1, C1058@DOM1, C11051@DOM1, C11250@DOM1, C1149@DOM1, C11607@DOM1, C11886@DOM1, C12076@DOM1, C12373@DOM1, C12985@DOM1, C13054@DOM1, C13080@DOM1, C13268@DOM1, C133@DOM1, C13764@DOM1, C139@DOM1, C1460@DOM1, C14702@DOM1, C15224@DOM1, C15763@DOM1, C15775@DOM1, C16130@DOM1, C16223@DOM1, C1627@DOM1, C17033@DOM1, C17050@DOM1, C17264@DOM1, C17280@DOM1, C1777@DOM1, C18351@DOM1, C18621@DOM1, C18777@DOM1, C19040@DOM1, C1910@DOM1, C1916@DOM1, C192@DOM1, C1949@DOM1, C20002@DOM1, C20031@DOM1, C20824@DOM1, C21464@DOM1, C21598@DOM1, C21957@DOM1, C22114@DOM1, C2246@DOM1, C2248@DOM1, C22509@DOM1, C2308@DOM1, C2311@DOM1, C2341@DOM1, C2873@DOM1, C357@DOM1, C3724@DOM1, C3725@DOM1, C4046@DOM1, C457@DOM1, C4574@DOM1, C4847@DOM1, C50@DOM1, C5233@DOM1, C538@DOM1, C552@DOM1, C602@DOM1, C641@DOM1, C6469@DOM1, C6623@DOM1, C6647@DOM1, C6981@DOM1, C6988@DOM1, C790@DOM1, C860@DOM1, C8694@DOM1, C879@DOM1, C888@DOM1, C944@DOM1, C988@DOM1, U1161@DOM1, U1253@DOM1, U1368@DOM1, U1606@DOM1, U2435@DOM1, U2652@DOM1, U2983@DOM1, U3173@DOM1, U3403@DOM1, U3413@DOM1, U3443@DOM1, U4563@DOM1, U5015@DOM1, U5638@DOM1, U5992@DOM1, U6051@DOM1, U6319@DOM1, U6676@DOM1, U6@DOM1, U818@DOM1, U938@DOM1, U9488@DOM1, U9548@DOM1
- **Hosts Involved:** C10201, C10417, C11607, C1183, C11886, C12076, C12180, C12373, C13225, C13268, C133, C13358, C13881, C1460, C14702, C15763, C15775, C18351, C18621, C1911, C192, C20002, C20031, C20824, C21464, C2247, C2249, C22510, C2312, C2873, C289, C357, C3724, C3725, C4046, C4315, C457, C4574, C4655, C516, C547, C602, C641, C6469, C6623, C6647, C6967, C7426, C860, C9154, C9526
- **Telemetry Progression:** AUTH

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Involves known compromised host (C457)
- Network logon / NTLM authentication protocol observed
- Rapid auth burst: 4 logons in 5 minutes
- Rare user-to-host lateral mapping (C10417@DOM1 -> C457)
- Rare user-to-host lateral mapping (C17033@DOM1 -> C457)
- Rare user-to-host lateral mapping (C2311@DOM1 -> C2312)
- Rare user-to-host lateral mapping (U1606@DOM1 -> C457)
- Rare user-to-host lateral mapping (U5638@DOM1 -> C457)

### Timeline Reconstruction (First 10 Events):
1. `AUTH` at t=1119056: TGT (?|?|Success)
1. `AUTH` at t=1119582: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1119582: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1119584: LogOn (NTLM|Network|Success)
1. `AUTH` at t=1119588: LogOff (?|Network|Success)
1. `AUTH` at t=1119589: LogOff (?|Network|Success)
1. `AUTH` at t=1119590: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1119590: LogOn (Kerberos|Network|Success)
1. `AUTH` at t=1119590: LogOff (?|Network|Success)
1. `AUTH` at t=1119592: LogOff (?|Network|Success)

---

## Incident INC-0694 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1105814 to 1109368 (Duration: 3554s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `43`
- **Users Involved:** C765@DOM1
- **Hosts Involved:** C765
- **Processes Involved:** P145, P5, P56, P9
- **Telemetry Progression:** PROCESS

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Involves known compromised host (C765)
- Process burst: 4 processes spawned in 2 minutes
- Process burst: 5 processes spawned in 2 minutes
- Process burst: 6 processes spawned in 2 minutes
- Process burst: 7 processes spawned in 2 minutes

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1105814: Start (process=P56)
1. `PROCESS` at t=1106202: Start (process=P56)
1. `PROCESS` at t=1106290: End (process=P56)
1. `PROCESS` at t=1106356: End (process=P5)
1. `PROCESS` at t=1106356: Start (process=P56)
1. `PROCESS` at t=1106364: End (process=P5)
1. `PROCESS` at t=1106430: Start (process=P145)
1. `PROCESS` at t=1106434: Start (process=P5)
1. `PROCESS` at t=1106444: Start (process=P5)
1. `PROCESS` at t=1106514: Start (process=P5)

---

## Incident INC-0684 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1105086 to 1109590 (Duration: 4504s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `54`
- **Users Involved:** C1432@DOM1
- **Hosts Involved:** C1432
- **Processes Involved:** P141, P191, P21, P25, P41, P54, P86, P9
- **Telemetry Progression:** PROCESS

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Involves known compromised host (C1432)
- Process burst: 4 processes spawned in 2 minutes
- Process burst: 5 processes spawned in 2 minutes
- Process burst: 6 processes spawned in 2 minutes

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1105086: Start (process=P86)
1. `PROCESS` at t=1105120: End (process=P86)
1. `PROCESS` at t=1105184: End (process=P86)
1. `PROCESS` at t=1105330: End (process=P25)
1. `PROCESS` at t=1105334: End (process=P41)
1. `PROCESS` at t=1105334: Start (process=P54)
1. `PROCESS` at t=1105542: End (process=P21)
1. `PROCESS` at t=1105542: Start (process=P86)
1. `PROCESS` at t=1106066: Start (process=P9)
1. `PROCESS` at t=1106092: Start (process=P21)

---

## Incident INC-0181 — CONFIRMED RED-TEAM ATTACK (High Priority)

- **Time Window:** Timestamp 1071902 to 1073810 (Duration: 1908s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `19`
- **Total Events Correlated:** `27`
- **Users Involved:** U1289@DOM1, U13@DOM1, U1519@DOM1, U218@DOM1, U2575@DOM1, U3277@C2519, U342@DOM1, U66@DOM1, U7004@C2519, U7375@DOM1, U7761@C2519
- **Hosts Involved:** C1042, C1737, C17693, C2012, C2519, C2721, C3011, C3288, C3586, C458, C5653, C849, C92
- **Processes Involved:** P21, P284, P5, P648, P653, P95
- **Telemetry Progression:** PROCESS -> REDTEAM

### Why This Incident is Suspicious (Explainable Indicators):
- Associated with known threat actor account (U1289@DOM1)
- Associated with known threat actor account (U13@DOM1)
- Associated with known threat actor account (U342@DOM1)
- Associated with known threat actor account (U66@DOM1)
- Associated with known threat actor account (U7375@DOM1)
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Compound threat: 3 distinct risk indicators triggered simultaneously
- Compound threat: 4 distinct risk indicators triggered simultaneously
- Confirmed Red-Team ground truth attack event
- Involves known compromised host (C17693)
- Involves known compromised host (C2519)
- Involves known compromised host (C3586)
- Involves known compromised host (C458)
- Process burst: 4 processes spawned in 2 minutes
- Rare user-to-host lateral mapping (U1289@DOM1 -> C2519)
- Rare user-to-host lateral mapping (U13@DOM1 -> C3288)
- Rare user-to-host lateral mapping (U7375@DOM1 -> nan)

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1071902: End (process=P5)
1. `PROCESS` at t=1072100: End (process=P5)
1. `PROCESS` at t=1072104: End (process=P284)
1. `PROCESS` at t=1072110: End (process=P95)
1. `PROCESS` at t=1072201: Start (process=P648)
1. `PROCESS` at t=1072203: End (process=P21)
1. `REDTEAM` at t=1072230: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=1072237: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=1072316: REDTEAM_ATTACK (Known red-team event)
1. `REDTEAM` at t=1072375: REDTEAM_ATTACK (Known red-team event)

---

## Incident INC-0329 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1082766 to 1088362 (Duration: 5596s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `27`
- **Users Involved:** C22723@DOM1, C5618@DOM1
- **Hosts Involved:** C10874, C109, C1154, C11581, C12885, C13115, C13642, C1441, C14637, C1507, C20386, C20898, C21380, C217, C22583, C22687, C231, C240, C3081, C3407, C5530, C6163, C706, C9204
- **Telemetry Progression:** AUTH -> FLOW

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- High-volume or prolonged network flow (185890 bytes, 20s)
- Involves known compromised host (C231)
- Involves known compromised host (C706)
- Rare user-to-host lateral mapping (nan -> C1154)
- Rare user-to-host lateral mapping (nan -> C11581)
- Rare user-to-host lateral mapping (nan -> C13115)
- Rare user-to-host lateral mapping (nan -> C14637)
- Rare user-to-host lateral mapping (nan -> C240)
- Rare user-to-host lateral mapping (nan -> C3407)
- Rare user-to-host lateral mapping (nan -> C5530)
- Rare user-to-host lateral mapping (nan -> C6163)

### Timeline Reconstruction (First 10 Events):
1. `FLOW` at t=1082766: NETWORK_FLOW (duration=0|src_port=80|dst_port=3632|protocol=6|packets=5|bytes=569)
1. `FLOW` at t=1083110: NETWORK_FLOW (duration=0|src_port=80|dst_port=N14473|protocol=6|packets=10|bytes=4592)
1. `FLOW` at t=1083359: NETWORK_FLOW (duration=0|src_port=80|dst_port=N23335|protocol=6|packets=6|bytes=3917)
1. `FLOW` at t=1083906: NETWORK_FLOW (duration=1|src_port=80|dst_port=N4932|protocol=6|packets=4|bytes=515)
1. `FLOW` at t=1084047: NETWORK_FLOW (duration=0|src_port=80|dst_port=N237|protocol=6|packets=4|bytes=510)
1. `FLOW` at t=1084206: NETWORK_FLOW (duration=0|src_port=80|dst_port=N8678|protocol=6|packets=6|bytes=4075)
1. `FLOW` at t=1084376: NETWORK_FLOW (duration=3|src_port=80|dst_port=N4403|protocol=6|packets=10|bytes=1316)
1. `FLOW` at t=1084804: NETWORK_FLOW (duration=20|src_port=80|dst_port=N18463|protocol=6|packets=199|bytes=185890)
1. `FLOW` at t=1084893: NETWORK_FLOW (duration=0|src_port=80|dst_port=N18740|protocol=6|packets=6|bytes=2226)
1. `FLOW` at t=1085043: NETWORK_FLOW (duration=0|src_port=80|dst_port=N19827|protocol=6|packets=6|bytes=2226)

---

## Incident INC-0519 — CRITICAL - Immediate Analyst Review Required

- **Time Window:** Timestamp 1094793 to 1095079 (Duration: 286s)
- **Risk Score:** `100/100`
- **Ground-Truth Red-Team Events:** `0`
- **Total Events Correlated:** `29`
- **Users Involved:** C3199@DOM1, U1796@DOM1, U4410@DOM5
- **Hosts Involved:** C3199
- **Processes Involved:** P24, P2626, P5
- **Telemetry Progression:** PROCESS

### Why This Incident is Suspicious (Explainable Indicators):
- Compound threat: 2 distinct risk indicators triggered simultaneously
- Involves known compromised host (C3199)
- Process burst: 4 processes spawned in 2 minutes
- Process burst: 5 processes spawned in 2 minutes
- Process burst: 6 processes spawned in 2 minutes
- Process burst: 7 processes spawned in 2 minutes
- Process burst: 8 processes spawned in 2 minutes

### Timeline Reconstruction (First 10 Events):
1. `PROCESS` at t=1094793: Start (process=P2626)
1. `PROCESS` at t=1094805: End (process=P24)
1. `PROCESS` at t=1094889: End (process=P24)
1. `PROCESS` at t=1094893: Start (process=P5)
1. `PROCESS` at t=1094903: Start (process=P5)
1. `PROCESS` at t=1094907: Start (process=P2626)
1. `PROCESS` at t=1094917: End (process=P24)
1. `PROCESS` at t=1094925: Start (process=P2626)
1. `PROCESS` at t=1094929: Start (process=P2626)
1. `PROCESS` at t=1094941: End (process=P2626)

---
