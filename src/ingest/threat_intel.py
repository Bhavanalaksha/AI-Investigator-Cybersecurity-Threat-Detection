"""Pluggable Threat Intelligence Feed for AI Cybersecurity Investigator.

Replaces hardcoded LANL IOC lists with an extensible, updatable mechanism.
Supports loading indicators from CSV files, JSON lists, and manual addition.
If no feed is loaded, the system operates purely on behavioral anomaly detection.
"""

import csv
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union


class ThreatIntelFeed:
    """Manages threat intelligence indicators (IOCs) from external feeds.

    Indicator types supported:
        - user: Known threat actor usernames/accounts
        - host: Known compromised hostnames/IPs
        - process: Known malicious process names/hashes
        - domain: Known malicious domains (for DNS correlation)
        - hash: Known malicious file hashes

    Usage:
        feed = ThreatIntelFeed()
        feed.load_from_csv("iocs.csv")
        feed.add_indicator("user", "evil_admin")

        # Enrich context for agents:
        context["attack_users"] = feed.known_bad_users
        context["attack_hosts"] = feed.known_bad_hosts
    """

    def __init__(self):
        self.known_bad_users: Set[str] = set()
        self.known_bad_hosts: Set[str] = set()
        self.known_bad_processes: Set[str] = set()
        self.known_bad_domains: Set[str] = set()
        self.known_bad_hashes: Set[str] = set()
        self._sources: List[str] = []

    # ------------------------------------------------------------------
    # LOADING FROM FILES
    # ------------------------------------------------------------------

    def load_from_csv(self, filepath: Union[str, Path]) -> int:
        """Load IOCs from a CSV file.

        Expected CSV format (flexible column names):
            indicator,type
            evil_user,user
            192.168.1.100,host
            malware.exe,process

        Also supports single-column CSV where each line is an indicator
        and the type is inferred from the filename or content.

        Returns:
            Number of indicators loaded.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            print(f"[ThreatIntel] Warning: File not found: {filepath}")
            return 0

        text = filepath.read_text(encoding="utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        count = 0

        # Check if CSV has typed columns
        fieldnames = [f.lower().strip() for f in (reader.fieldnames or [])]
        has_type = "type" in fieldnames or "indicator_type" in fieldnames or "ioc_type" in fieldnames

        for row in reader:
            row_lower = {k.lower().strip(): v.strip() for k, v in row.items() if v}
            indicator = row_lower.get("indicator", row_lower.get("value", row_lower.get("ioc", "")))
            ind_type = row_lower.get("type", row_lower.get("indicator_type", row_lower.get("ioc_type", "")))

            if not indicator:
                # Try first column value
                first_val = list(row.values())[0].strip() if row else ""
                if first_val:
                    indicator = first_val

            if indicator:
                if has_type and ind_type:
                    self.add_indicator(ind_type.lower(), indicator)
                else:
                    # Auto-detect type from content
                    self._auto_add(indicator)
                count += 1

        self._sources.append(str(filepath))
        print(f"[ThreatIntel] Loaded {count} indicators from {filepath.name}")
        return count

    def load_from_json(self, filepath: Union[str, Path]) -> int:
        """Load IOCs from a JSON file.

        Expected format:
            {
                "users": ["evil_user1", "evil_user2"],
                "hosts": ["192.168.1.100"],
                "processes": ["malware.exe"],
                "domains": ["evil.com"],
                "hashes": ["abc123..."]
            }

        Or a flat list of {"indicator": "...", "type": "..."} objects.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            print(f"[ThreatIntel] Warning: File not found: {filepath}")
            return 0

        data = json.loads(filepath.read_text(encoding="utf-8"))
        count = 0

        if isinstance(data, dict):
            for itype, indicators in data.items():
                if isinstance(indicators, list):
                    for ind in indicators:
                        self.add_indicator(itype.rstrip("s"), str(ind))
                        count += 1
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    ind = item.get("indicator", item.get("value", ""))
                    itype = item.get("type", item.get("indicator_type", ""))
                    if ind:
                        self.add_indicator(itype, str(ind))
                        count += 1

        self._sources.append(str(filepath))
        print(f"[ThreatIntel] Loaded {count} indicators from {filepath.name}")
        return count

    # ------------------------------------------------------------------
    # MANUAL INDICATOR MANAGEMENT
    # ------------------------------------------------------------------

    def add_indicator(self, indicator_type: str, value: str):
        """Add a single IOC indicator."""
        value = value.strip()
        if not value:
            return

        itype = indicator_type.lower().strip()
        if itype in ("user", "users", "account", "username"):
            self.known_bad_users.add(value)
        elif itype in ("host", "hosts", "ip", "address", "endpoint"):
            self.known_bad_hosts.add(value)
        elif itype in ("process", "processes", "binary", "executable"):
            self.known_bad_processes.add(value)
        elif itype in ("domain", "domains", "fqdn"):
            self.known_bad_domains.add(value)
        elif itype in ("hash", "hashes", "md5", "sha256", "sha1"):
            self.known_bad_hashes.add(value)

    def remove_indicator(self, indicator_type: str, value: str):
        """Remove a single IOC indicator."""
        itype = indicator_type.lower().strip()
        target_set = {
            "user": self.known_bad_users,
            "host": self.known_bad_hosts,
            "process": self.known_bad_processes,
            "domain": self.known_bad_domains,
            "hash": self.known_bad_hashes,
        }.get(itype)
        if target_set:
            target_set.discard(value.strip())

    # ------------------------------------------------------------------
    # QUERY METHODS
    # ------------------------------------------------------------------

    def is_known_threat(self, value: str, indicator_type: Optional[str] = None) -> bool:
        """Check if a value matches any known threat indicator."""
        value = value.strip()
        if indicator_type:
            target_set = {
                "user": self.known_bad_users,
                "host": self.known_bad_hosts,
                "process": self.known_bad_processes,
                "domain": self.known_bad_domains,
                "hash": self.known_bad_hashes,
            }.get(indicator_type.lower())
            return value in target_set if target_set else False
        # Check all sets
        return (
            value in self.known_bad_users
            or value in self.known_bad_hosts
            or value in self.known_bad_processes
            or value in self.known_bad_domains
            or value in self.known_bad_hashes
        )

    def enrich_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Merge threat intel indicators into an existing context dict."""
        context["attack_users"] = context.get("attack_users", set()) | self.known_bad_users
        context["attack_hosts"] = context.get("attack_hosts", set()) | self.known_bad_hosts
        context["threat_processes"] = self.known_bad_processes
        context["threat_domains"] = self.known_bad_domains
        context["threat_hashes"] = self.known_bad_hashes
        context["threat_intel_sources"] = self._sources
        return context

    def get_summary(self) -> Dict[str, int]:
        return {
            "users": len(self.known_bad_users),
            "hosts": len(self.known_bad_hosts),
            "processes": len(self.known_bad_processes),
            "domains": len(self.known_bad_domains),
            "hashes": len(self.known_bad_hashes),
            "sources": len(self._sources),
        }

    # ------------------------------------------------------------------
    # INTERNAL
    # ------------------------------------------------------------------

    def _auto_add(self, value: str):
        """Auto-detect indicator type from value format."""
        import re
        value = value.strip()
        # IP address pattern
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            self.known_bad_hosts.add(value)
        # Hash pattern (hex string 32+ chars)
        elif re.match(r"^[a-fA-F0-9]{32,}$", value):
            self.known_bad_hashes.add(value)
        # Domain pattern
        elif re.match(r"^[\w\-]+\.[\w\-]+", value) and "." in value and not value.endswith(".exe"):
            self.known_bad_domains.add(value)
        # Executable pattern
        elif value.endswith((".exe", ".dll", ".bat", ".ps1", ".sh", ".py", ".cmd")):
            self.known_bad_processes.add(value)
        # Default to user
        else:
            self.known_bad_users.add(value)
