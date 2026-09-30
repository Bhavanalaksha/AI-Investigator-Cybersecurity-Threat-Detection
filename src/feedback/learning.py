"""Analyst Feedback Learning Loop for AI Cybersecurity Investigator.

Learns from human analyst verdicts to build local watchlists and safelists.
Confirmed threats add entities to watchlists (increasing future scores).
Confirmed false positives add entities to safelists (reducing future noise).
All lists persist to disk as JSON and are loaded on startup.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class FeedbackLearner:
    """Manages analyst feedback-driven learning for the threat detection pipeline.

    When a human analyst reviews an incident:
        - CONFIRMED_SUSPICIOUS -> entities are added to the watchlist
        - MARKED_BENIGN / FALSE_POSITIVE -> entities are added to the safelist
        - NEED_MORE_INVESTIGATION -> no learning action (awaiting verdict)

    Watchlists and safelists persist as JSON files and are loaded on startup.
    """

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = Path(data_dir) if data_dir else Path("data/feedback")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.watchlist_file = self.data_dir / "watchlist.json"
        self.safelist_file = self.data_dir / "safelist.json"
        self.history_file = self.data_dir / "feedback_history.json"

        # Watchlist: entities confirmed as malicious by analysts
        self.watched_users: Set[str] = set()
        self.watched_hosts: Set[str] = set()
        self.watched_processes: Set[str] = set()

        # Safelist: entities confirmed as benign by analysts
        self.safe_users: Set[str] = set()
        self.safe_hosts: Set[str] = set()
        self.safe_processes: Set[str] = set()

        # Feedback history for audit trail
        self.history: List[Dict[str, Any]] = []

        # Load persisted state
        self._load()

    # ------------------------------------------------------------------
    # FEEDBACK PROCESSING
    # ------------------------------------------------------------------

    def process_verdict(
        self,
        incident_id: str,
        verdict: str,
        users: Optional[List[str]] = None,
        hosts: Optional[List[str]] = None,
        processes: Optional[List[str]] = None,
        notes: str = "",
    ):
        """Process an analyst verdict and update watchlists/safelists.

        Args:
            incident_id: The incident being reviewed.
            verdict: One of CONFIRMED_SUSPICIOUS, MARKED_BENIGN, FALSE_POSITIVE,
                     NEED_MORE_INVESTIGATION.
            users: User entities from the incident.
            hosts: Host entities from the incident.
            processes: Process entities from the incident.
            notes: Optional analyst notes.
        """
        users = [u.strip() for u in (users or []) if u and u.strip()]
        hosts = [h.strip() for h in (hosts or []) if h and h.strip()]
        processes = [p.strip() for p in (processes or []) if p and p.strip()]

        verdict_upper = verdict.upper().replace(" ", "_")

        if verdict_upper in ("CONFIRMED_SUSPICIOUS", "CONFIRMED_THREAT", "SUSPICIOUS"):
            # Add to watchlist, remove from safelist
            for u in users:
                self.watched_users.add(u)
                self.safe_users.discard(u)
            for h in hosts:
                self.watched_hosts.add(h)
                self.safe_hosts.discard(h)
            for p in processes:
                self.watched_processes.add(p)
                self.safe_processes.discard(p)
            action = "ADDED_TO_WATCHLIST"

        elif verdict_upper in ("MARKED_BENIGN", "FALSE_POSITIVE", "BENIGN", "FP"):
            # Add to safelist, remove from watchlist
            for u in users:
                self.safe_users.add(u)
                self.watched_users.discard(u)
            for h in hosts:
                self.safe_hosts.add(h)
                self.watched_hosts.discard(h)
            for p in processes:
                self.safe_processes.add(p)
                self.watched_processes.discard(p)
            action = "ADDED_TO_SAFELIST"

        else:
            action = "NO_LEARNING_ACTION"

        # Record in history
        self.history.append({
            "incident_id": incident_id,
            "verdict": verdict_upper,
            "action": action,
            "users": users,
            "hosts": hosts,
            "processes": processes,
            "notes": notes,
            "timestamp": time.time(),
        })

        # Persist to disk
        self._save()

        print(f"[FeedbackLearner] {action} for {incident_id}: "
              f"{len(users)} users, {len(hosts)} hosts, {len(processes)} processes")

    # ------------------------------------------------------------------
    # CONTEXT ENRICHMENT
    # ------------------------------------------------------------------

    def enrich_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Merge watchlist/safelist into context for agents."""
        # Add watched entities to attack lists
        context["attack_users"] = context.get("attack_users", set()) | self.watched_users
        context["attack_hosts"] = context.get("attack_hosts", set()) | self.watched_hosts

        # Provide safelists for noise reduction
        context["safe_users"] = self.safe_users.copy()
        context["safe_hosts"] = self.safe_hosts.copy()
        context["safe_processes"] = self.safe_processes.copy()

        # Provide watchlists for elevated scoring
        context["watched_users"] = self.watched_users.copy()
        context["watched_hosts"] = self.watched_hosts.copy()
        context["watched_processes"] = self.watched_processes.copy()

        return context

    # ------------------------------------------------------------------
    # QUERY METHODS
    # ------------------------------------------------------------------

    def is_watched(self, entity: str, entity_type: Optional[str] = None) -> bool:
        """Check if an entity is on the watchlist."""
        entity = entity.strip()
        if entity_type == "user":
            return entity in self.watched_users
        elif entity_type == "host":
            return entity in self.watched_hosts
        elif entity_type == "process":
            return entity in self.watched_processes
        return (entity in self.watched_users
                or entity in self.watched_hosts
                or entity in self.watched_processes)

    def is_safe(self, entity: str, entity_type: Optional[str] = None) -> bool:
        """Check if an entity is on the safelist."""
        entity = entity.strip()
        if entity_type == "user":
            return entity in self.safe_users
        elif entity_type == "host":
            return entity in self.safe_hosts
        elif entity_type == "process":
            return entity in self.safe_processes
        return (entity in self.safe_users
                or entity in self.safe_hosts
                or entity in self.safe_processes)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "watchlist": {
                "users": len(self.watched_users),
                "hosts": len(self.watched_hosts),
                "processes": len(self.watched_processes),
            },
            "safelist": {
                "users": len(self.safe_users),
                "hosts": len(self.safe_hosts),
                "processes": len(self.safe_processes),
            },
            "total_verdicts": len(self.history),
        }

    # ------------------------------------------------------------------
    # PERSISTENCE
    # ------------------------------------------------------------------

    def _save(self):
        """Persist watchlists, safelists, and history to disk."""
        watchlist_data = {
            "users": sorted(list(self.watched_users)),
            "hosts": sorted(list(self.watched_hosts)),
            "processes": sorted(list(self.watched_processes)),
        }
        safelist_data = {
            "users": sorted(list(self.safe_users)),
            "hosts": sorted(list(self.safe_hosts)),
            "processes": sorted(list(self.safe_processes)),
        }

        self.watchlist_file.write_text(
            json.dumps(watchlist_data, indent=2), encoding="utf-8"
        )
        self.safelist_file.write_text(
            json.dumps(safelist_data, indent=2), encoding="utf-8"
        )
        self.history_file.write_text(
            json.dumps(self.history, indent=2), encoding="utf-8"
        )

    def _load(self):
        """Load persisted watchlists, safelists, and history from disk."""
        if self.watchlist_file.exists():
            try:
                data = json.loads(self.watchlist_file.read_text(encoding="utf-8"))
                self.watched_users = set(data.get("users", []))
                self.watched_hosts = set(data.get("hosts", []))
                self.watched_processes = set(data.get("processes", []))
                print(f"[FeedbackLearner] Loaded watchlist: "
                      f"{len(self.watched_users)} users, "
                      f"{len(self.watched_hosts)} hosts, "
                      f"{len(self.watched_processes)} processes")
            except Exception as e:
                print(f"[FeedbackLearner] Warning: could not load watchlist: {e}")

        if self.safelist_file.exists():
            try:
                data = json.loads(self.safelist_file.read_text(encoding="utf-8"))
                self.safe_users = set(data.get("users", []))
                self.safe_hosts = set(data.get("hosts", []))
                self.safe_processes = set(data.get("processes", []))
                print(f"[FeedbackLearner] Loaded safelist: "
                      f"{len(self.safe_users)} users, "
                      f"{len(self.safe_hosts)} hosts, "
                      f"{len(self.safe_processes)} processes")
            except Exception as e:
                print(f"[FeedbackLearner] Warning: could not load safelist: {e}")

        if self.history_file.exists():
            try:
                self.history = json.loads(
                    self.history_file.read_text(encoding="utf-8")
                )
            except Exception:
                self.history = []
