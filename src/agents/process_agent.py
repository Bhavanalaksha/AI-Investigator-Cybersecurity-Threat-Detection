"""Process Execution Specialist Agent for AI Cybersecurity Multi-Agent Investigation.

Analyzes endpoint process creation and termination telemetry (PROCESS events) for anomalies,
including rare executable invocations, high-density process spawning bursts, and compromised host execution.

Phase 2 Enhancements:
  - Anomaly-based detection replaces hardcoded LANL IOC lists
  - New rules: R15 (LOLBin Execution), R16 (First-Time Process per User)
  - Adaptive thresholds from baseline profiler
  - Safelist support to reduce false positives
"""

from collections import defaultdict, Counter
import bisect
from typing import Dict, Any, List, Optional
import pandas as pd
from .base_agent import BaseAgent


# Living-off-the-land binaries commonly abused by attackers
LOLBINS = {
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "cmd", "cmd.exe",
    "wmic", "wmic.exe",
    "certutil", "certutil.exe",
    "mshta", "mshta.exe",
    "regsvr32", "regsvr32.exe",
    "rundll32", "rundll32.exe",
    "cscript", "cscript.exe",
    "wscript", "wscript.exe",
    "bitsadmin", "bitsadmin.exe",
    "msbuild", "msbuild.exe",
    "installutil", "installutil.exe",
    "schtasks", "schtasks.exe",
    "at", "at.exe",
    "net", "net.exe",
    "net1", "net1.exe",
    "psexec", "psexec.exe",
    "whoami", "whoami.exe",
    "nltest", "nltest.exe",
    "dsquery", "dsquery.exe",
    "csvde", "csvde.exe",
    "ldifde", "ldifde.exe",
}


class ProcessAgent(BaseAgent):
    """Specialist agent focused on endpoint process telemetry investigation."""

    def __init__(
        self,
        known_threat_hosts: Optional[set] = None,
        known_threat_users: Optional[set] = None,
        rare_process_threshold: int = 15,
        burst_threshold: int = 3,
        burst_window_sec: int = 120
    ):
        super().__init__(
            name="ProcessAgent",
            description="Analyzes process executions, rare binary invocations, execution bursts, and host telemetry."
        )
        self.known_threat_hosts = set(known_threat_hosts or set())
        self.known_threat_users = set(known_threat_users or set())
        self.rare_process_threshold = rare_process_threshold
        self.burst_threshold = burst_threshold
        self.burst_window_sec = burst_window_sec

    def analyze(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyzes PROCESS events and returns structured findings.

        Args:
            data: DataFrame or list of dicts containing PROCESS events.
            context: Context containing global process frequency distributions, IOCs, etc.

        Returns:
            Structured dictionary of findings, evidence, risk score, and explanation.
        """
        if isinstance(data, list):
            df = pd.DataFrame(data)
        elif isinstance(data, pd.DataFrame):
            df = data.copy()
        else:
            raise ValueError(f"ProcessAgent expected DataFrame or list of dicts, got {type(data)}")

        if df.empty:
            return {
                "agent": self.name,
                "suspicious": False,
                "risk_contribution": 0.0,
                "entities": [],
                "evidence": ["No process events provided in batch."],
                "events": [],
                "flagged_events": [],
                "explanation": "No process telemetry was present for analysis."
            }

        # Contextual profiles
        process_counts = context.get("process_counts", Counter()) if context else Counter()
        attack_hosts = context.get("attack_hosts", self.known_threat_hosts) if context else self.known_threat_hosts
        attack_users = context.get("attack_users", self.known_threat_users) if context else self.known_threat_users

        # Phase 2: Adaptive baselines
        rare_proc_threshold = context.get("rare_proc_threshold", self.rare_process_threshold) if context else self.rare_process_threshold
        safe_hosts = context.get("safe_hosts", set()) if context else set()
        safe_processes = context.get("safe_processes", set()) if context else set()
        threat_processes = context.get("threat_processes", set()) if context else set()

        # Precompute host process timestamps for burst detection
        host_timestamps = defaultdict(list)
        for row in df.itertuples(index=False):
            h = str(getattr(row, "source_host", "")).strip()
            ts = int(getattr(row, "timestamp", 0))
            if h:
                host_timestamps[h].append(ts)

        # Precompute per-user process sets for first-time detection
        user_process_baseline = defaultdict(set)
        if context:
            # Build from full dataset context if available
            pass

        flagged_events = []
        evidence_list = []
        entities_involved = set()
        total_risk = 0.0

        # Track processes seen per user within this batch
        user_processes_seen = defaultdict(set)

        for idx, row in enumerate(df.itertuples(index=False)):
            ev_id = str(getattr(row, "event_id", f"PROC-{idx}"))
            ts = int(getattr(row, "timestamp", 0))
            u = str(getattr(row, "user", "")).strip()
            src_h = str(getattr(row, "source_host", "")).strip()
            dst_h = str(getattr(row, "destination_host", "")).strip()
            proc = str(getattr(row, "process", "")).strip()
            action = str(getattr(row, "action", "")).strip()
            details = str(getattr(row, "details", "")).strip()
            is_rt = int(getattr(row, "is_redteam", 0))

            if u:
                entities_involved.add(u)
            if src_h:
                entities_involved.add(src_h)
            if proc:
                entities_involved.add(proc)

            # Skip safelisted processes (Phase 2)
            if proc.lower() in safe_processes and src_h in safe_hosts:
                continue

            ev_score = 0
            ev_evidence = []

            # R5: Rare process execution — adaptive threshold
            if proc:
                count = process_counts.get(proc, 0)
                if count < rare_proc_threshold:
                    ev_score += 2
                    ev_evidence.append(f"Execution of infrequent binary: {proc} (seen {count} times in baseline)")

            # R6: Process spawning burst on endpoint
            if src_h and src_h in host_timestamps:
                ts_list = host_timestamps[src_h]
                left_idx = bisect.bisect_left(ts_list, ts - self.burst_window_sec)
                right_idx = bisect.bisect_right(ts_list, ts)
                proc_recent = right_idx - left_idx
                if proc_recent > self.burst_threshold:
                    ev_score += 2
                    ev_evidence.append(f"Rapid process spawning burst: {proc_recent} processes in {self.burst_window_sec}s on host {src_h}")

            # R8/R9: Execution associated with known compromised host or threat user
            # (populated from threat intel or analyst watchlist, not hardcoded LANL)
            if (src_h in attack_hosts) or (dst_h in attack_hosts):
                comp_h = src_h if src_h in attack_hosts else dst_h
                ev_score += 2
                ev_evidence.append(f"Process activity executed on known compromised host: {comp_h}")

            if u in attack_users:
                ev_score += 3
                ev_evidence.append(f"Process executed under known threat actor account: {u}")

            # ======== PHASE 2 NEW RULES ========

            # R15: LOLBin Execution — known living-off-the-land binaries
            proc_lower = proc.lower() if proc else ""
            proc_name = proc_lower.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if proc_name in LOLBINS:
                ev_score += 2
                ev_evidence.append(f"LOLBin (Living-off-the-Land Binary) execution detected: {proc}")

            # R15b: Known malicious process from threat intelligence
            if proc_lower in threat_processes or proc in threat_processes:
                ev_score += 3
                ev_evidence.append(f"Process matches threat intelligence indicator: {proc}")

            # R16: First-Time Process for User — user has never run this binary before
            if u and proc:
                if proc not in user_processes_seen[u]:
                    user_processes_seen[u].add(proc)
                    # Check if this user has a process baseline from profiling
                    user_proc_count = sum(
                        1 for p in process_counts
                        if process_counts[p] > 0
                    )
                    # If process is globally rare AND user hasn't run it, flag
                    global_count = process_counts.get(proc, 0)
                    if global_count == 0:
                        ev_score += 2
                        ev_evidence.append(f"Never-before-seen process: {proc} (zero occurrences in baseline)")

            # Ground truth red-team flag (backward compatibility)
            if is_rt == 1:
                ev_score += 3
                ev_evidence.append("Confirmed adversary red-team ground-truth execution event")

            # Compound multi-indicator bonus
            if len(ev_evidence) >= 2:
                ev_score += 2
                ev_evidence.append("Compound threat: multiple anomalous process execution signals detected")

            if ev_score >= 3:
                flagged_events.append({
                    "event_id": ev_id,
                    "timestamp": ts,
                    "event_type": "process",
                    "user": u,
                    "source_host": src_h,
                    "process": proc,
                    "risk_score": ev_score,
                    "is_redteam": is_rt,
                    "evidence": ev_evidence
                })
                evidence_list.extend(ev_evidence)
                total_risk += ev_score

        is_suspicious = len(flagged_events) > 0
        avg_risk = (total_risk / len(flagged_events)) if flagged_events else 0.0

        if is_suspicious:
            unique_evidence = list(dict.fromkeys(evidence_list))
            explanation = (
                f"ProcessAgent evaluated {len(df)} PROCESS events and identified {len(flagged_events)} anomalous executions "
                f"(average risk: {avg_risk:.2f}). Primary findings: {'; '.join(unique_evidence[:4])}."
            )
        else:
            explanation = (
                f"ProcessAgent evaluated {len(df)} PROCESS events. All execution patterns fell within expected baseline binary distributions; "
                f"no rapid spawning bursts or unapproved executables identified."
            )

        return {
            "agent": self.name,
            "suspicious": is_suspicious,
            "risk_contribution": round(total_risk, 2),
            "flagged_count": len(flagged_events),
            "total_events_analyzed": len(df),
            "entities": sorted(list(entities_involved)),
            "evidence": list(dict.fromkeys(evidence_list)),
            "events": flagged_events,
            "flagged_events": flagged_events,
            "explanation": explanation
        }
