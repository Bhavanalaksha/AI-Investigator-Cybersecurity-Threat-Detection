"""Adaptive Baseline Profiler for AI Cybersecurity Investigator.

Automatically builds behavioral baselines FROM the input data itself —
no pre-labeled IOCs, ground-truth files, or dataset-specific lists required.
Baselines are used by specialist agents to detect statistical anomalies.
"""

import math
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd


class BaselineProfiler:
    """Builds adaptive behavioral baselines from event data.

    Baselines computed:
        - user_host_pairs: frequency of each (user, host) pair
        - process_counts: frequency of each process binary
        - user_auth_velocity: mean/std auth events per user per 5-min window
        - host_flow_volume: mean/std bytes per host
        - user_time_profile: histogram of active hours per user
        - rare_user_threshold: adaptive threshold for rare user-host mappings
        - rare_process_threshold: adaptive threshold for rare processes
    """

    def __init__(
        self,
        auth_window_sec: int = 300,
        rare_pair_percentile: float = 5.0,
        rare_proc_percentile: float = 5.0,
    ):
        self.auth_window_sec = auth_window_sec
        self.rare_pair_percentile = rare_pair_percentile
        self.rare_proc_percentile = rare_proc_percentile

    def build_context(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Build a complete context dictionary from event data.

        Args:
            df: Normalized event DataFrame (output of UniversalLogParser).

        Returns:
            Context dict compatible with all specialist agents, containing
            adaptive baselines instead of hardcoded IOC lists.
        """
        print("[BaselineProfiler] Building adaptive baselines from input data...")

        # 1. User-host pair frequency
        user_host_pairs = self._build_user_host_pairs(df)

        # 2. Process frequency distribution
        process_counts = self._build_process_counts(df)

        # 3. User authentication velocity (mean/std per 5-min window)
        user_auth_velocity = self._build_auth_velocity(df)

        # 4. Host network flow volume (mean/std bytes)
        host_flow_volume = self._build_flow_volume(df)

        # 5. User time-of-day activity profiles
        user_time_profile = self._build_time_profiles(df)

        # 6. Adaptive thresholds
        rare_pair_threshold = self._compute_rare_threshold(
            list(user_host_pairs.values()), self.rare_pair_percentile
        )
        rare_proc_threshold = self._compute_rare_threshold(
            list(process_counts.values()), self.rare_proc_percentile
        )

        # 7. Known-good user set (all users seen in data)
        known_users = set(
            df["user"].dropna().astype(str).str.strip()
            .loc[lambda s: (s != "") & (s.str.lower() != "nan")]
        )

        # 8. Host activity baseline (hosts that are normally active)
        known_hosts = set(
            pd.concat([
                df["source_host"].dropna().astype(str).str.strip(),
                df["destination_host"].dropna().astype(str).str.strip(),
            ]).loc[lambda s: (s != "") & (s.str.lower() != "nan")]
        )

        # 9. Host connection diversity baseline
        host_user_diversity = self._build_host_user_diversity(df)

        context = {
            # Baselines (replace hardcoded LANL IOC lists)
            "user_host_pairs": user_host_pairs,
            "process_counts": process_counts,
            "user_auth_velocity": user_auth_velocity,
            "host_flow_volume": host_flow_volume,
            "user_time_profile": user_time_profile,
            "host_user_diversity": host_user_diversity,

            # Adaptive thresholds
            "rare_pair_threshold": rare_pair_threshold,
            "rare_proc_threshold": rare_proc_threshold,

            # Known entities from the data (NOT IOC lists)
            "known_users": known_users,
            "known_hosts": known_hosts,

            # Empty threat actor sets — will be populated by
            # ThreatIntelFeed or FeedbackLearner if available
            "attack_users": set(),
            "attack_hosts": set(),

            # Metadata
            "baseline_source": "adaptive",
            "total_events_profiled": len(df),
        }

        print(f"[BaselineProfiler] Profiled {len(df):,} events:")
        print(f"  Known users:          {len(known_users):,}")
        print(f"  Known hosts:          {len(known_hosts):,}")
        print(f"  User-host pairs:      {len(user_host_pairs):,}")
        print(f"  Unique processes:     {len(process_counts):,}")
        print(f"  Rare pair threshold:  <= {rare_pair_threshold}")
        print(f"  Rare proc threshold:  <= {rare_proc_threshold}")

        return context

    # ------------------------------------------------------------------
    # BASELINE BUILDERS
    # ------------------------------------------------------------------

    def _build_user_host_pairs(self, df: pd.DataFrame) -> Counter:
        pairs = Counter()
        for row in df.itertuples(index=False):
            u = str(getattr(row, "user", "") or "").strip()
            dst = str(getattr(row, "destination_host", "") or "").strip()
            src = str(getattr(row, "source_host", "") or "").strip()
            h = dst or src
            if u and h and u.lower() != "nan" and h.lower() != "nan":
                pairs[(u, h)] += 1
        return pairs

    def _build_process_counts(self, df: pd.DataFrame) -> Counter:
        proc_series = df["process"].dropna().astype(str).str.strip()
        proc_series = proc_series[proc_series != ""]
        proc_series = proc_series[proc_series.str.lower() != "nan"]
        return Counter(proc_series)

    def _build_auth_velocity(self, df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
        """Compute per-user auth event velocity (events per 5-min window)."""
        auth_df = df[df["event_type"].str.lower() == "auth"].copy()
        if auth_df.empty:
            return {}

        velocity = {}
        for user, group in auth_df.groupby("user"):
            user = str(user).strip()
            if not user or user.lower() == "nan":
                continue
            timestamps = sorted(group["timestamp"].astype(int).tolist())
            if len(timestamps) < 2:
                velocity[user] = {"mean": 1.0, "std": 0.5}
                continue

            # Count events per 5-min window
            window_counts = []
            window_start = timestamps[0]
            count = 0
            for ts in timestamps:
                if ts - window_start <= self.auth_window_sec:
                    count += 1
                else:
                    window_counts.append(count)
                    window_start = ts
                    count = 1
            window_counts.append(count)

            mean_vel = float(np.mean(window_counts))
            std_vel = float(np.std(window_counts)) if len(window_counts) > 1 else mean_vel * 0.5
            velocity[user] = {"mean": mean_vel, "std": max(std_vel, 0.5)}

        return velocity

    def _build_flow_volume(self, df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
        """Compute per-host network flow volume baselines."""
        flow_df = df[df["event_type"].str.lower() == "flow"].copy()
        if flow_df.empty:
            return {}

        host_bytes = defaultdict(list)
        for row in flow_df.itertuples(index=False):
            details = str(getattr(row, "details", ""))
            src_h = str(getattr(row, "source_host", "")).strip()
            try:
                detail_dict = dict(
                    item.split("=") for item in details.split("|") if "=" in item
                )
                byte_val = int(detail_dict.get("bytes", 0))
                if src_h and byte_val > 0:
                    host_bytes[src_h].append(byte_val)
            except Exception:
                continue

        volume = {}
        for host, byte_list in host_bytes.items():
            volume[host] = {
                "mean": float(np.mean(byte_list)),
                "std": float(np.std(byte_list)) if len(byte_list) > 1 else float(np.mean(byte_list)) * 0.5,
            }
        return volume

    def _build_time_profiles(self, df: pd.DataFrame) -> Dict[str, List[int]]:
        """Build hour-of-day activity histograms per user."""
        profiles = defaultdict(lambda: [0] * 24)
        for row in df.itertuples(index=False):
            u = str(getattr(row, "user", "")).strip()
            ts = int(getattr(row, "timestamp", 0))
            if u and u.lower() != "nan" and ts > 0:
                hour = (ts % 86400) // 3600
                profiles[u][hour] += 1
        return dict(profiles)

    def _build_host_user_diversity(self, df: pd.DataFrame) -> Dict[str, int]:
        """Count distinct users per destination host (connection diversity)."""
        diversity = defaultdict(set)
        for row in df.itertuples(index=False):
            u = str(getattr(row, "user", "")).strip()
            dst = str(getattr(row, "destination_host", "")).strip()
            if u and dst and u.lower() != "nan" and dst.lower() != "nan":
                diversity[dst].add(u)
        return {host: len(users) for host, users in diversity.items()}

    # ------------------------------------------------------------------
    # ADAPTIVE THRESHOLD COMPUTATION
    # ------------------------------------------------------------------

    def _compute_rare_threshold(self, values: List[int], percentile: float) -> int:
        """Compute an adaptive rarity threshold at the given percentile."""
        if not values:
            return 2  # default fallback
        threshold = max(1, int(np.percentile(values, percentile)))
        return threshold
