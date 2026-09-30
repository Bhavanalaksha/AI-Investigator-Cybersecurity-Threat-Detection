"""Correlation Agent Module for AI Cybersecurity Multi-Agent Investigation Architecture.

Receives findings and flagged telemetry from specialist agents (AuthenticationAgent,
ProcessAgent, NetworkAgent), applies sliding-window temporal and entity-indexed correlation,
and constructs coherent multi-source security incidents with chronological timelines and provenance.
"""

from collections import defaultdict
from typing import Dict, Any, List, Optional
import pandas as pd
from .base_agent import BaseAgent


class FastCluster:
    """Internal cluster representation storing indices and entity sets."""

    def __init__(self, cluster_id: int, first_idx: int, ts: int, users: set, hosts: set, agent_name: str):
        self.id = cluster_id
        self.event_indices = [first_idx]
        self.start = ts
        self.end = ts
        self.users = set(users)
        self.hosts = set(hosts)
        self.processes = set()
        self.sources = set()
        self.agents_involved = {agent_name}
        self.active = True


class CorrelationAgent(BaseAgent):
    """Correlates cross-domain agent findings into contextual incidents."""

    def __init__(self, window_seconds: int = 600):
        super().__init__(
            name="CorrelationAgent",
            description="Performs entity-indexed sliding-window correlation across cross-domain agent findings."
        )
        self.window_seconds = window_seconds

    def analyze(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Correlates specialist agent findings into structured multi-source incidents.

        Args:
            data: List of finding dictionaries from specialist agents, or dict mapping agent names to findings.
            context: Context containing optional configuration such as window_seconds override.

        Returns:
            Structured dictionary of correlated incidents, timelines, and reduction statistics.
        """
        window_sec = context.get("window_seconds", self.window_seconds) if context else self.window_seconds

        all_candidate_events = []
        if isinstance(data, dict):
            agent_findings_list = list(data.values())
        elif isinstance(data, list):
            agent_findings_list = data
        else:
            agent_findings_list = []

        for finding in agent_findings_list:
            if not isinstance(finding, dict):
                continue
            agent_name = finding.get("agent", "UnknownAgent")
            flagged = finding.get("flagged_events", finding.get("events", []))
            for ev in flagged:
                if isinstance(ev, dict):
                    ev_copy = dict(ev)
                    ev_copy["_reporting_agent"] = agent_name
                    all_candidate_events.append(ev_copy)

        if not all_candidate_events:
            return {
                "agent": self.name,
                "window_seconds": window_sec,
                "incidents": [],
                "total_incidents": 0,
                "multi_agent_incidents_count": 0,
                "events_correlated": 0,
                "reduction_rate": 0.0,
                "explanation": "CorrelationAgent received no candidate events across specialist agents."
            }

        # Deduplicate candidate events by event_id if present
        seen_ids = set()
        deduped_events = []
        for ev in all_candidate_events:
            ev_id = ev.get("event_id")
            if ev_id and ev_id in seen_ids:
                continue
            if ev_id:
                seen_ids.add(ev_id)
            deduped_events.append(ev)

        # Sort strictly chronologically
        deduped_events.sort(key=lambda x: int(x.get("timestamp", 0)))

        clusters: List[FastCluster] = []
        active_by_entity = defaultdict(list)
        cluster_counter = 0

        for idx, ev in enumerate(deduped_events):
            ts = int(ev.get("timestamp", 0))
            rep_agent = ev.get("_reporting_agent", "SpecialistAgent")

            # Extract entities
            ev_users = set()
            for key in ["user", "source_user", "destination_user"]:
                val = str(ev.get(key, "")).strip()
                if val and val.lower() not in ["none", "nan", ""]:
                    ev_users.add(val)

            ev_hosts = set()
            for key in ["source_host", "destination_host"]:
                val = str(ev.get(key, "")).strip()
                if val and val.lower() not in ["none", "nan", ""]:
                    ev_hosts.add(val)

            all_entities = ev_users | ev_hosts

            candidate_cids = set()
            for ent in all_entities:
                for cid in active_by_entity[ent]:
                    c = clusters[cid]
                    if c.active and (ts - c.end <= window_sec):
                        candidate_cids.add(cid)

            if not candidate_cids:
                new_c = FastCluster(cluster_counter, idx, ts, ev_users, ev_hosts, rep_agent)
                proc = str(ev.get("process", "")).strip()
                if proc and proc.lower() not in ["none", "nan", ""]:
                    new_c.processes.add(proc)
                etype = str(ev.get("event_type", "")).strip().lower()
                if etype:
                    new_c.sources.add(etype)
                clusters.append(new_c)
                for ent in all_entities:
                    active_by_entity[ent].append(cluster_counter)
                cluster_counter += 1
            elif len(candidate_cids) == 1:
                cid = next(iter(candidate_cids))
                c = clusters[cid]
                c.event_indices.append(idx)
                c.end = ts
                c.agents_involved.add(rep_agent)
                proc = str(ev.get("process", "")).strip()
                if proc and proc.lower() not in ["none", "nan", ""]:
                    c.processes.add(proc)
                etype = str(ev.get("event_type", "")).strip().lower()
                if etype:
                    c.sources.add(etype)
                new_ents = all_entities - (c.users | c.hosts)
                c.users.update(ev_users)
                c.hosts.update(ev_hosts)
                for ent in new_ents:
                    active_by_entity[ent].append(cid)
            else:
                cids_list = sorted(list(candidate_cids))
                primary_cid = cids_list[0]
                primary = clusters[primary_cid]
                primary.event_indices.append(idx)
                primary.end = ts
                primary.agents_involved.add(rep_agent)
                proc = str(ev.get("process", "")).strip()
                if proc and proc.lower() not in ["none", "nan", ""]:
                    primary.processes.add(proc)
                etype = str(ev.get("event_type", "")).strip().lower()
                if etype:
                    primary.sources.add(etype)

                for other_cid in cids_list[1:]:
                    other = clusters[other_cid]
                    if other.active:
                        primary.event_indices.extend(other.event_indices)
                        primary.start = min(primary.start, other.start)
                        primary.end = max(primary.end, other.end)
                        primary.users.update(other.users)
                        primary.hosts.update(other.hosts)
                        primary.processes.update(other.processes)
                        primary.sources.update(other.sources)
                        primary.agents_involved.update(other.agents_involved)
                        other.active = False
                        other.event_indices = []

                primary.users.update(ev_users)
                primary.hosts.update(ev_hosts)
                for ent in (primary.users | primary.hosts):
                    active_by_entity[ent] = [
                        primary_cid if cid in candidate_cids else cid
                        for cid in active_by_entity[ent]
                        if clusters[cid].active
                    ]

        # Meaningful incident filtering
        active_clusters = [c for c in clusters if c.active and len(c.event_indices) > 0]
        meaningful_clusters = []
        for c in active_clusters:
            c_events = [deduped_events[i] for i in c.event_indices]
            has_rt = any(int(e.get("is_redteam", 0)) == 1 for e in c_events)
            max_risk = max((float(e.get("risk_score", 0)) for e in c_events), default=0.0)
            if has_rt or len(c.event_indices) >= 3 or max_risk >= 5:
                meaningful_clusters.append((c, c_events))

        meaningful_clusters.sort(key=lambda item: (item[0].start, -len(item[1])))

        incidents_output = []
        multi_agent_count = 0

        for idx, (c, c_events) in enumerate(meaningful_clusters):
            inc_id = f"INC-{idx+1:04d}"
            c_events.sort(key=lambda x: int(x.get("timestamp", 0)))
            
            rt_count = sum(1 for e in c_events if int(e.get("is_redteam", 0)) == 1)
            is_multi_agent = len(c.agents_involved) > 1
            if is_multi_agent:
                multi_agent_count += 1

            timeline = []
            for e in c_events:
                timeline.append({
                    "timestamp": int(e.get("timestamp", 0)),
                    "event_type": str(e.get("event_type", "unknown")),
                    "user": str(e.get("user", "")),
                    "source_host": str(e.get("source_host", "")),
                    "destination_host": str(e.get("destination_host", "")),
                    "risk_score": float(e.get("risk_score", 0)),
                    "is_redteam": int(e.get("is_redteam", 0)),
                    "agent": e.get("_reporting_agent", "Agent")
                })

            incidents_output.append({
                "incident_id": inc_id,
                "time_start": c.start,
                "time_end": c.end,
                "duration_sec": max(1, c.end - c.start),
                "entities": sorted(list(c.users | c.hosts)),
                "users": sorted(list(c.users)),
                "hosts": sorted(list(c.hosts)),
                "processes": sorted(list(c.processes)),
                "sources": sorted(list(c.sources)),
                "events": c_events,
                "event_count": len(c_events),
                "redteam_event_count": rt_count,
                "agents_involved": sorted(list(c.agents_involved)),
                "is_multi_agent": is_multi_agent,
                "timeline": timeline
            })

        total_evs = len(deduped_events)
        reduction = ((total_evs - len(incidents_output)) / total_evs * 100) if total_evs > 0 else 0.0

        explanation = (
            f"CorrelationAgent evaluated {total_evs} candidate events using a {window_sec}s (±{window_sec//60} min) sliding window. "
            f"Synthesized {len(incidents_output)} correlated incidents ({reduction:.2f}% alert reduction); "
            f"{multi_agent_count} incidents exhibited cross-domain multi-agent corroboration."
        )

        return {
            "agent": self.name,
            "window_seconds": window_sec,
            "incidents": incidents_output,
            "total_incidents": len(incidents_output),
            "multi_agent_incidents_count": multi_agent_count,
            "events_correlated": total_evs,
            "reduction_rate": round(reduction, 2),
            "explanation": explanation
        }
