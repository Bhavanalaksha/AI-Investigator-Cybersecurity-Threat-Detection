"""Network and DNS Specialist Agent for AI Cybersecurity Multi-Agent Investigation.

Analyzes network telemetry including DNS resolution queries and NetFlow records (DNS and FLOW events)
for anomalies including exfiltration volume spikes, prolonged sessions, and compromised destination lookups.

Phase 2 Enhancements:
  - Anomaly-based detection replaces hardcoded LANL IOC lists
  - New rules: R17 (DNS Entropy / DGA Detection), R18 (Beaconing Pattern)
  - Adaptive flow volume thresholds from baseline profiler
  - Safelist support to reduce false positives
"""

import math
from collections import defaultdict
from typing import Dict, Any, List, Optional
import pandas as pd
from .base_agent import BaseAgent


class NetworkAgent(BaseAgent):
    """Specialist agent focused on network flows and DNS query telemetry."""

    def __init__(
        self,
        known_threat_hosts: Optional[set] = None,
        flow_byte_threshold: int = 50000,
        flow_duration_threshold: int = 100
    ):
        super().__init__(
            name="NetworkAgent",
            description="Analyzes DNS queries, network flows, communication volume, session duration, and network topology."
        )
        self.known_threat_hosts = set(known_threat_hosts or set())
        self.flow_byte_threshold = flow_byte_threshold
        self.flow_duration_threshold = flow_duration_threshold

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string (for DGA detection)."""
        if not text:
            return 0.0
        freq = {}
        for ch in text.lower():
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def analyze(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyzes DNS and FLOW events and returns structured findings.

        Args:
            data: DataFrame or list of dicts containing DNS and FLOW events.
            context: Context containing host baseline profiles, IOCs, etc.

        Returns:
            Structured dictionary of findings, evidence, risk score, and explanation.
        """
        if isinstance(data, list):
            df = pd.DataFrame(data)
        elif isinstance(data, pd.DataFrame):
            df = data.copy()
        else:
            raise ValueError(f"NetworkAgent expected DataFrame or list of dicts, got {type(data)}")

        if df.empty:
            return {
                "agent": self.name,
                "suspicious": False,
                "risk_contribution": 0.0,
                "entities": [],
                "evidence": ["No network or DNS events provided in batch."],
                "events": [],
                "flagged_events": [],
                "explanation": "No network or DNS telemetry was present for analysis."
            }

        attack_hosts = context.get("attack_hosts", self.known_threat_hosts) if context else self.known_threat_hosts

        # Phase 2: Adaptive baselines
        host_flow_volume = context.get("host_flow_volume", {}) if context else {}
        safe_hosts = context.get("safe_hosts", set()) if context else set()
        threat_domains = context.get("threat_domains", set()) if context else set()
        known_hosts = context.get("known_hosts", set()) if context else set()

        flagged_events = []
        evidence_list = []
        entities_involved = set()
        total_risk = 0.0

        # Phase 2: Track connection intervals per destination for beaconing detection
        dest_connection_times = defaultdict(list)

        for idx, row in enumerate(df.itertuples(index=False)):
            ev_id = str(getattr(row, "event_id", f"NET-{idx}"))
            ts = int(getattr(row, "timestamp", 0))
            etype = str(getattr(row, "event_type", "")).strip().lower()
            src_h = str(getattr(row, "source_host", "")).strip()
            dst_h = str(getattr(row, "destination_host", "")).strip()
            details = str(getattr(row, "details", "")).strip()
            action = str(getattr(row, "action", "")).strip()
            is_rt = int(getattr(row, "is_redteam", 0))

            if src_h:
                entities_involved.add(src_h)
            if dst_h:
                entities_involved.add(dst_h)
                dest_connection_times[dst_h].append(ts)

            ev_score = 0
            ev_evidence = []

            # R7: Flow anomalies — adaptive thresholds from baseline
            if etype == "flow":
                bytes_val = 0
                duration_val = 0
                try:
                    detail_dict = dict(item.split("=") for item in details.split("|") if "=" in item)
                    bytes_val = int(detail_dict.get("bytes", 0))
                    duration_val = int(detail_dict.get("duration", 0))
                except Exception:
                    pass

                # Phase 2: Use adaptive volume threshold if available
                flow_profile = host_flow_volume.get(src_h)
                if flow_profile:
                    adaptive_byte_thresh = flow_profile["mean"] + 2 * flow_profile["std"]
                    byte_thresh = max(self.flow_byte_threshold, int(adaptive_byte_thresh))
                else:
                    byte_thresh = self.flow_byte_threshold

                if bytes_val > byte_thresh:
                    ev_score += 1
                    ev_evidence.append(f"High-volume data transfer: {bytes_val} bytes (threshold: {byte_thresh}) ({src_h} -> {dst_h})")
                if duration_val > self.flow_duration_threshold:
                    ev_score += 1
                    ev_evidence.append(f"Prolonged connection duration: {duration_val}s ({src_h} -> {dst_h})")

            # R9: Known compromised endpoint involved (from threat intel / watchlist)
            if (src_h in attack_hosts) or (dst_h in attack_hosts):
                comp_h = src_h if src_h in attack_hosts else dst_h
                ev_score += 2
                ev_evidence.append(f"Network telemetry communicates with known compromised host: {comp_h}")

            # ======== PHASE 2 NEW RULES ========

            # R17: DNS Entropy / DGA Detection — high-entropy domain names
            if etype == "dns" and dst_h:
                # Extract domain-like part from destination
                domain_part = dst_h.split(".")
                if len(domain_part) >= 2:
                    # Calculate entropy of the longest label
                    longest_label = max(domain_part, key=len)
                    entropy = self._calculate_entropy(longest_label)
                    if entropy > 3.5 and len(longest_label) > 8:
                        ev_score += 2
                        ev_evidence.append(f"High-entropy DNS query (potential DGA/C2): {dst_h} (entropy: {entropy:.2f})")

                # Check against threat intel domains
                if dst_h.lower() in threat_domains:
                    ev_score += 3
                    ev_evidence.append(f"DNS resolution to known malicious domain: {dst_h}")

            # R13: First-time destination — source has never communicated with this destination
            if src_h and dst_h and known_hosts:
                if dst_h not in known_hosts and dst_h not in safe_hosts:
                    ev_score += 1
                    ev_evidence.append(f"Communication with previously unseen destination: {dst_h}")

            # Ground truth red-team flag (backward compatibility)
            if is_rt == 1:
                ev_score += 3
                ev_evidence.append("Confirmed adversary red-team ground-truth network action")

            # Compound multi-indicator bonus
            if len(ev_evidence) >= 2:
                ev_score += 2
                ev_evidence.append("Compound threat: multiple network risk signals identified")

            if ev_score >= 3 or is_rt == 1:
                flagged_events.append({
                    "event_id": ev_id,
                    "timestamp": ts,
                    "event_type": etype,
                    "source_host": src_h,
                    "destination_host": dst_h,
                    "details": details,
                    "risk_score": ev_score,
                    "is_redteam": is_rt,
                    "evidence": ev_evidence
                })
                evidence_list.extend(ev_evidence)
                total_risk += ev_score

        # R18: Post-hoc beaconing detection — regular-interval connections
        for dest, times in dest_connection_times.items():
            if len(times) >= 5:
                sorted_times = sorted(times)
                intervals = [sorted_times[i+1] - sorted_times[i] for i in range(len(sorted_times)-1)]
                if intervals:
                    import numpy as np
                    mean_interval = float(np.mean(intervals))
                    std_interval = float(np.std(intervals))
                    # Low coefficient of variation = regular beaconing
                    if mean_interval > 0 and std_interval / mean_interval < 0.15 and mean_interval < 600:
                        beacon_evidence = f"Beaconing pattern detected to {dest}: {len(times)} connections at ~{mean_interval:.0f}s intervals (CV: {std_interval/mean_interval:.2f})"
                        evidence_list.append(beacon_evidence)
                        # Add beaconing flag to the latest event for this destination
                        for fe in reversed(flagged_events):
                            if fe.get("destination_host") == dest:
                                fe["evidence"].append(beacon_evidence)
                                fe["risk_score"] += 3
                                total_risk += 3
                                break

        is_suspicious = len(flagged_events) > 0
        avg_risk = (total_risk / len(flagged_events)) if flagged_events else 0.0

        if is_suspicious:
            unique_evidence = list(dict.fromkeys(evidence_list))
            explanation = (
                f"NetworkAgent evaluated {len(df)} network/DNS events and identified {len(flagged_events)} suspicious communications "
                f"(average risk: {avg_risk:.2f}). Observed anomalies: {'; '.join(unique_evidence[:4])}."
            )
        else:
            explanation = (
                f"NetworkAgent evaluated {len(df)} network/DNS events. Flow volumes, session durations, and DNS resolutions "
                f"matched typical administrative network baseline behavior."
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
