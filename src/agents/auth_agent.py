"""Authentication Specialist Agent for AI Cybersecurity Multi-Agent Investigation.

Analyzes authentication telemetry (AUTH events) for anomalies including failed
logons, rapid authentication bursts, lateral movement mappings, and known threat actor accounts.

Phase 2 Enhancements:
  - Anomaly-based detection replaces hardcoded LANL IOC lists
  - New rules: R11 (Off-Hours), R12 (First-Time Pair), R14 (Privilege Escalation)
  - Adaptive thresholds from baseline profiler
  - Safelist support to reduce false positives
"""

from collections import defaultdict, Counter
import bisect
from typing import Dict, Any, List, Optional
import pandas as pd
from .base_agent import BaseAgent


class AuthenticationAgent(BaseAgent):
    """Specialist agent focused on authentication telemetry investigation."""

    def __init__(
        self,
        known_threat_users: Optional[set] = None,
        known_threat_hosts: Optional[set] = None,
        burst_threshold: int = 3,
        burst_window_sec: int = 300,
        lateral_threshold: int = 2
    ):
        super().__init__(
            name="AuthenticationAgent",
            description="Analyzes authentication sessions, credential usage, logon types, and lateral movement."
        )
        self.known_threat_users = set(known_threat_users or set())
        self.known_threat_hosts = set(known_threat_hosts or set())
        self.burst_threshold = burst_threshold
        self.burst_window_sec = burst_window_sec
        self.lateral_threshold = lateral_threshold

    def analyze(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyzes a collection of AUTH events and returns structured findings.

        Args:
            data: DataFrame or list of dicts containing AUTH events.
            context: Context containing baseline user-host mappings, IOCs, etc.

        Returns:
            Structured dictionary of findings, evidence, risk score, and explanation.
        """
        if isinstance(data, list):
            df = pd.DataFrame(data)
        elif isinstance(data, pd.DataFrame):
            df = data.copy()
        else:
            raise ValueError(f"AuthenticationAgent expected DataFrame or list of dicts, got {type(data)}")

        if df.empty:
            return {
                "agent": self.name,
                "suspicious": False,
                "risk_contribution": 0.0,
                "entities": [],
                "evidence": ["No authentication events provided in batch."],
                "events": [],
                "flagged_events": [],
                "explanation": "No authentication telemetry was present for analysis."
            }

        # Contextual profiles — use adaptive baselines if available, fall back to IOC lists
        user_host_pairs = context.get("user_host_pairs", Counter()) if context else Counter()
        attack_users = context.get("attack_users", self.known_threat_users) if context else self.known_threat_users
        attack_hosts = context.get("attack_hosts", self.known_threat_hosts) if context else self.known_threat_hosts

        # Phase 2: Adaptive baselines
        known_users = context.get("known_users", set()) if context else set()
        user_auth_velocity = context.get("user_auth_velocity", {}) if context else {}
        user_time_profile = context.get("user_time_profile", {}) if context else {}
        host_user_diversity = context.get("host_user_diversity", {}) if context else {}
        safe_users = context.get("safe_users", set()) if context else set()
        safe_hosts = context.get("safe_hosts", set()) if context else set()
        rare_pair_threshold = context.get("rare_pair_threshold", self.lateral_threshold) if context else self.lateral_threshold

        # Precompute user auth timestamps for burst detection
        user_timestamps = defaultdict(list)
        for row in df.itertuples(index=False):
            u = str(getattr(row, "user", "") or getattr(row, "source_user", "")).strip()
            ts = int(getattr(row, "timestamp", 0))
            if u:
                user_timestamps[u].append(ts)

        flagged_events = []
        evidence_list = []
        entities_involved = set()
        total_risk = 0.0

        for idx, row in enumerate(df.itertuples(index=False)):
            ev_id = str(getattr(row, "event_id", f"AUTH-{idx}"))
            ts = int(getattr(row, "timestamp", 0))
            u = str(getattr(row, "user", "")).strip()
            src_u = str(getattr(row, "source_user", "")).strip()
            dst_u = str(getattr(row, "destination_user", "")).strip()
            src_h = str(getattr(row, "source_host", "")).strip()
            dst_h = str(getattr(row, "destination_host", "")).strip()
            action = str(getattr(row, "action", "")).strip().lower()
            details = str(getattr(row, "details", "")).strip().lower()
            is_rt = int(getattr(row, "is_redteam", 0))

            effective_user = u or src_u
            if effective_user:
                entities_involved.add(effective_user)
            if src_h:
                entities_involved.add(src_h)
            if dst_h:
                entities_involved.add(dst_h)

            # Skip safelisted entities (Phase 2: reduce FP from analyst feedback)
            if effective_user in safe_users and src_h in safe_hosts:
                continue

            ev_score = 0
            ev_evidence = []

            # R1: Authentication failure
            if "fail" in details or "failure" in details or "fail" in action:
                ev_score += 2
                ev_evidence.append(f"Failed authentication attempt by user {effective_user}")

            # R2: Repeated authentication attempts (burst) — adaptive threshold
            if effective_user in user_timestamps:
                ts_list = user_timestamps[effective_user]
                left_idx = bisect.bisect_left(ts_list, ts - self.burst_window_sec)
                right_idx = bisect.bisect_right(ts_list, ts)
                recent_attempts = right_idx - left_idx

                # Phase 2: Use adaptive velocity threshold if available
                velocity_profile = user_auth_velocity.get(effective_user)
                if velocity_profile:
                    adaptive_burst = velocity_profile["mean"] + 2 * velocity_profile["std"]
                    burst_thresh = max(self.burst_threshold, int(adaptive_burst))
                else:
                    burst_thresh = self.burst_threshold

                if recent_attempts > burst_thresh:
                    ev_score += 2
                    ev_evidence.append(f"High authentication velocity: {recent_attempts} attempts within {self.burst_window_sec}s (threshold: {burst_thresh})")

            # R3: Protocol anomaly (NTLM / Network logon)
            if "ntlm" in details or "network" in details:
                ev_score += 1
                ev_evidence.append("Network authentication using NTLM protocol")

            # R4: Rare user-to-host lateral mapping — adaptive threshold
            h = dst_h or src_h
            if effective_user and h:
                pair_count = user_host_pairs.get((effective_user, h), 0)
                if pair_count <= rare_pair_threshold:
                    ev_score += 2
                    ev_evidence.append(f"Infrequent lateral authentication: {effective_user} -> {h} (observed {pair_count} times in baseline)")

            # ======== PHASE 2 NEW RULES ========

            # R8: Known threat actor (from threat intel OR analyst watchlist — NOT hardcoded LANL)
            if effective_user in attack_users:
                ev_score += 3
                ev_evidence.append(f"Identified known threat actor credential: {effective_user}")

            # R9: Known compromised host (from threat intel OR analyst watchlist)
            if (src_h in attack_hosts) or (dst_h in attack_hosts):
                comp_h = src_h if src_h in attack_hosts else dst_h
                ev_score += 2
                ev_evidence.append(f"Authentication involves known compromised endpoint: {comp_h}")

            # R11: Off-Hours Activity — user authenticating outside their normal active hours
            if effective_user and ts > 0 and user_time_profile:
                hour = (ts % 86400) // 3600
                profile = user_time_profile.get(effective_user)
                if profile:
                    total_activity = sum(profile)
                    if total_activity > 0:
                        hour_ratio = profile[hour] / total_activity
                        if hour_ratio < 0.01:  # < 1% of normal activity at this hour
                            ev_score += 2
                            ev_evidence.append(f"Off-hours authentication at hour {hour}:00 (only {hour_ratio*100:.1f}% of normal activity)")

            # R12: First-Time User-Host Pair — never seen before in baseline
            if effective_user and h:
                pair_count = user_host_pairs.get((effective_user, h), 0)
                if pair_count == 0:
                    ev_score += 2
                    ev_evidence.append(f"First-time user-host pair: {effective_user} has never authenticated to {h}")

            # R14: Abnormal Host Connection Diversity
            if dst_h and host_user_diversity:
                baseline_diversity = host_user_diversity.get(dst_h, 0)
                if baseline_diversity > 0 and baseline_diversity <= 3:
                    # Host normally has very few users; any new user is suspicious
                    if effective_user and user_host_pairs.get((effective_user, dst_h), 0) == 0:
                        ev_score += 1
                        ev_evidence.append(f"Host {dst_h} has low user diversity (baseline: {baseline_diversity} users); new user {effective_user} is anomalous")

            # [LEAKAGE REMOVED] Ground truth elevation disabled

            # Compound multi-indicator bonus
            if len(ev_evidence) >= 2:
                ev_score += 2
                ev_evidence.append("Compound threat: multiple anomalous authentication signals simultaneously")

            if ev_score >= 3:
                flagged_events.append({
                    "event_id": ev_id,
                    "timestamp": ts,
                    "event_type": "auth",
                    "user": effective_user,
                    "source_host": src_h,
                    "destination_host": dst_h,
                    "risk_score": ev_score,
                    "is_redteam": is_rt,
                    "evidence": ev_evidence
                })
                evidence_list.extend(ev_evidence)
                total_risk += ev_score

        is_suspicious = len(flagged_events) > 0
        avg_risk = (total_risk / len(flagged_events)) if flagged_events else 0.0

        # Build explainable narrative
        if is_suspicious:
            unique_evidence = list(dict.fromkeys(evidence_list))
            explanation = (
                f"AuthenticationAgent evaluated {len(df)} AUTH events and identified {len(flagged_events)} suspicious activities "
                f"(average risk: {avg_risk:.2f}). Key indicators: {'; '.join(unique_evidence[:4])}."
            )
        else:
            explanation = (
                f"AuthenticationAgent evaluated {len(df)} AUTH events. All events conformed to legitimate baseline authentication patterns; "
                f"no credential abuse, abnormal bursts, or adversary IOCs detected."
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
