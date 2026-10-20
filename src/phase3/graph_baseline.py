"""Isolated Graph-Only Baseline Module for Phase 3B Benchmarking.

Constructs an entity-interaction graph directly from native telemetry events over
a 600-second sliding temporal window without receiving specialist agent anomaly scores,
rule thresholds, heuristic weights, or ground-truth labels.

Topological Alert Criteria:
- Minimum Event Count >= 3 within 600s sliding window
- Minimum Distinct Host Count >= 2 (capturing structural lateral movement)
"""

from collections import defaultdict
from typing import Dict, Any, List, Set, Tuple
import pandas as pd
import numpy as np


class FastGraphCluster:
    """Internal cluster representation for graph connectivity."""

    def __init__(self, cluster_id: int, first_idx: int, ts: int, users: Set[str], hosts: Set[str]):
        self.id = cluster_id
        self.event_indices = [first_idx]
        self.start = ts
        self.end = ts
        self.users = set(users)
        self.hosts = set(hosts)
        self.active = True


class IsolatedGraphBaseline:
    """Pure Graph-Only baseline implementing entity-interaction sliding-window clustering.

    Guarantees 100% isolation from specialist agents, ML models, and ground-truth annotations.
    """

    def __init__(self, window_seconds: int = 600, min_events: int = 3, min_hosts: int = 2):
        self.window_seconds = window_seconds
        self.min_events = min_events
        self.min_hosts = min_hosts

    def extract_clusters(self, df_events: pd.DataFrame) -> Tuple[List[FastGraphCluster], List[FastGraphCluster]]:
        """Extracts active graph clusters and identifies alert clusters based purely on topology."""
        # Enforce native telemetry only
        if "event_type" in df_events.columns:
            clean_df = df_events[df_events["event_type"] != "redteam"].copy()
        else:
            clean_df = df_events.copy()

        # Sort chronologically
        clean_df = clean_df.sort_values("timestamp").reset_index(drop=True)

        clusters: List[FastGraphCluster] = []
        active_by_entity = defaultdict(list)
        cluster_counter = 0

        records = clean_df[["timestamp", "user", "source_host", "destination_host"]].to_dict("records")

        for idx, ev in enumerate(records):
            ts = int(ev["timestamp"])
            u = str(ev.get("user", "")).strip()
            sh = str(ev.get("source_host", "")).strip()
            dh = str(ev.get("destination_host", "")).strip()

            ev_users = {u} if u and u.lower() not in ["none", "nan", ""] else set()
            ev_hosts = set()
            for h in [sh, dh]:
                if h and h.lower() not in ["none", "nan", ""]:
                    ev_hosts.add(h)

            all_ents = ev_users | ev_hosts
            if not all_ents:
                continue

            candidate_cids = set()
            for ent in all_ents:
                for cid in active_by_entity[ent]:
                    c = clusters[cid]
                    if c.active and (ts - c.end <= self.window_seconds):
                        candidate_cids.add(cid)

            if not candidate_cids:
                new_c = FastGraphCluster(cluster_counter, idx, ts, ev_users, ev_hosts)
                clusters.append(new_c)
                for ent in all_ents:
                    active_by_entity[ent].append(cluster_counter)
                cluster_counter += 1
            elif len(candidate_cids) == 1:
                cid = next(iter(candidate_cids))
                c = clusters[cid]
                c.event_indices.append(idx)
                c.end = ts
                new_ents = all_ents - (c.users | c.hosts)
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
                for other_cid in cids_list[1:]:
                    other = clusters[other_cid]
                    if other.active:
                        primary.event_indices.extend(other.event_indices)
                        primary.start = min(primary.start, other.start)
                        primary.end = max(primary.end, other.end)
                        primary.users.update(other.users)
                        primary.hosts.update(other.hosts)
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

        active_clusters = [c for c in clusters if c.active and len(c.event_indices) > 0]
        alert_clusters = [
            c for c in active_clusters
            if len(c.event_indices) >= self.min_events and len(c.hosts) >= self.min_hosts
        ]
        return active_clusters, alert_clusters

    def predict_windows(self, df_events: pd.DataFrame, window_df: pd.DataFrame) -> np.ndarray:
        """Projects topological graph alerts onto the standardized 289 test windows."""
        _, alert_clusters = self.extract_clusters(df_events)
        predictions = []

        for _, row in window_df.iterrows():
            w_start = int(row["t_start"])
            w_end = int(row["t_end"])

            has_alert = any(
                not (c.end < w_start or c.start > w_end)
                for c in alert_clusters
            )
            predictions.append(1 if has_alert else 0)

        return np.array(predictions, dtype=int)
