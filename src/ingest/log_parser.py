"""Universal Log Parser for AI Cybersecurity Investigator.

Accepts multiple log formats (CSV, JSON/JSONL, Syslog, CEF) and normalizes
them into the internal event schema used by the multi-agent pipeline.
No dependency on LANL-specific formats or ground-truth labels.
"""

import csv
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd


# Standard internal schema columns
INTERNAL_SCHEMA = [
    "event_type", "timestamp", "user", "source_user", "destination_user",
    "source_host", "destination_host", "process", "action", "details",
    "is_redteam",
]

# Heuristic column name mappings: maps common external names -> internal names
_COLUMN_MAP = {
    # event_type
    "event_type": "event_type", "eventtype": "event_type", "type": "event_type",
    "log_type": "event_type", "category": "event_type", "event_category": "event_type",
    "source_type": "event_type",
    # timestamp
    "timestamp": "timestamp", "time": "timestamp", "datetime": "timestamp",
    "date_time": "timestamp", "event_time": "timestamp", "ts": "timestamp",
    "eventtime": "timestamp", "@timestamp": "timestamp", "log_time": "timestamp",
    "created": "timestamp", "occurred": "timestamp",
    # user
    "user": "user", "username": "user", "account": "user",
    "account_name": "user", "user_name": "user", "actor": "user",
    "subject_user": "user", "logon_user": "user",
    # source_user
    "source_user": "source_user", "src_user": "source_user",
    "subject_account": "source_user",
    # destination_user
    "destination_user": "destination_user", "dst_user": "destination_user",
    "target_user": "destination_user", "target_account": "destination_user",
    # source_host
    "source_host": "source_host", "src_host": "source_host",
    "source_ip": "source_host", "src_ip": "source_host", "src": "source_host",
    "source_address": "source_host", "client_ip": "source_host",
    "workstation": "source_host", "hostname": "source_host",
    "source_computer": "source_host", "computer_name": "source_host",
    # destination_host
    "destination_host": "destination_host", "dst_host": "destination_host",
    "destination_ip": "destination_host", "dst_ip": "destination_host",
    "dst": "destination_host", "dest": "destination_host",
    "destination_address": "destination_host", "server_ip": "destination_host",
    "target_host": "destination_host", "dest_ip": "destination_host",
    # process
    "process": "process", "process_name": "process", "image": "process",
    "executable": "process", "binary": "process", "command": "process",
    "command_line": "process", "cmdline": "process", "program": "process",
    # action
    "action": "action", "event_action": "action", "operation": "action",
    "activity": "action", "logon_type": "action", "status": "action",
    "result": "action", "outcome": "action",
    # details
    "details": "details", "message": "details", "description": "details",
    "info": "details", "raw": "details", "raw_log": "details",
    "event_data": "details",
}

# Syslog RFC 3164 pattern
_SYSLOG_PATTERN = re.compile(
    r"^(?:<(\d+)>)?"                           # optional priority
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"  # timestamp
    r"\s+(\S+)"                                 # hostname
    r"\s+(\S+?)(?:\[(\d+)\])?:"                 # program[pid]:
    r"\s+(.*)"                                  # message
)

# CEF pattern: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
_CEF_PATTERN = re.compile(
    r"^CEF:\d+\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)"
)

# Timestamp format candidates for auto-detection
_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%b %d %H:%M:%S",
    "%Y%m%d%H%M%S",
]


class UniversalLogParser:
    """Format-agnostic log parser that normalizes any supported format
    into the internal event schema DataFrame.

    Supported formats:
        - CSV (auto-detected column mapping)
        - JSON / JSONL (flat or nested)
        - Syslog (RFC 3164/5424)
        - CEF (Common Event Format)
    """

    def __init__(self):
        self._ts_format_cache: Optional[str] = None

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def parse(
        self,
        data: Union[str, bytes, Path],
        filename: Optional[str] = None,
        format_hint: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse raw log data into a normalized DataFrame.

        Args:
            data: Raw log content as string, bytes, or a file Path.
            filename: Original filename (used for format auto-detection).
            format_hint: One of 'csv', 'json', 'jsonl', 'syslog', 'cef'.
                         If None, format is auto-detected.

        Returns:
            pd.DataFrame with columns matching INTERNAL_SCHEMA.
        """
        if isinstance(data, Path):
            raw_text = data.read_text(encoding="utf-8", errors="replace")
            filename = filename or data.name
        elif isinstance(data, bytes):
            raw_text = data.decode("utf-8", errors="replace")
        else:
            raw_text = data

        fmt = format_hint or self._detect_format(raw_text, filename)

        if fmt == "csv":
            records = self._parse_csv(raw_text)
        elif fmt in ("json", "jsonl"):
            records = self._parse_json(raw_text)
        elif fmt == "syslog":
            records = self._parse_syslog(raw_text)
        elif fmt == "cef":
            records = self._parse_cef(raw_text)
        else:
            # Fall back to CSV
            records = self._parse_csv(raw_text)

        df = pd.DataFrame(records)
        df = self._normalize_schema(df)
        df = self._normalize_timestamps(df)
        return df

    def parse_file(self, filepath: Union[str, Path]) -> pd.DataFrame:
        """Convenience method to parse a file from disk."""
        return self.parse(Path(filepath))

    # ------------------------------------------------------------------
    # FORMAT DETECTION
    # ------------------------------------------------------------------

    def _detect_format(self, text: str, filename: Optional[str] = None) -> str:
        if filename:
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext == "csv":
                return "csv"
            if ext in ("json", "jsonl", "ndjson"):
                return "json"

        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            return "json"
        if stripped.startswith("CEF:"):
            return "cef"
        if _SYSLOG_PATTERN.match(stripped.split("\n", 1)[0]):
            return "syslog"
        # Default to CSV
        return "csv"

    # ------------------------------------------------------------------
    # CSV PARSER
    # ------------------------------------------------------------------

    def _parse_csv(self, text: str) -> List[Dict[str, Any]]:
        reader = csv.DictReader(io.StringIO(text))
        return list(reader)

    # ------------------------------------------------------------------
    # JSON / JSONL PARSER
    # ------------------------------------------------------------------

    def _parse_json(self, text: str) -> List[Dict[str, Any]]:
        stripped = text.strip()
        # Try JSON array first
        if stripped.startswith("["):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                pass

        # Try JSONL (one object per line)
        records = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
                elif isinstance(obj, list):
                    records.extend(obj)
            except json.JSONDecodeError:
                continue
        return records

    # ------------------------------------------------------------------
    # SYSLOG PARSER (RFC 3164)
    # ------------------------------------------------------------------

    def _parse_syslog(self, text: str) -> List[Dict[str, Any]]:
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _SYSLOG_PATTERN.match(line)
            if m:
                priority, ts_str, hostname, program, pid, message = m.groups()
                records.append({
                    "timestamp": ts_str,
                    "source_host": hostname,
                    "process": program,
                    "action": f"pid={pid}" if pid else "",
                    "details": message,
                    "event_type": self._infer_event_type_from_program(program),
                })
            else:
                # Unparseable line — store as raw detail
                records.append({
                    "details": line,
                    "event_type": "unknown",
                })
        return records

    def _infer_event_type_from_program(self, program: str) -> str:
        prog = (program or "").lower()
        if any(k in prog for k in ("sshd", "auth", "pam", "login", "sudo", "kerberos")):
            return "auth"
        if any(k in prog for k in ("named", "dnsmasq", "bind", "unbound")):
            return "dns"
        if any(k in prog for k in ("kernel", "cron", "systemd", "init")):
            return "process"
        if any(k in prog for k in ("iptables", "firewall", "netfilter", "ufw")):
            return "flow"
        return "system"

    # ------------------------------------------------------------------
    # CEF PARSER
    # ------------------------------------------------------------------

    def _parse_cef(self, text: str) -> List[Dict[str, Any]]:
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _CEF_PATTERN.match(line)
            if not m:
                continue
            vendor, product, version, sig_id, name, severity, extension = m.groups()

            # Parse extension key=value pairs
            ext_dict = {}
            for kv in re.findall(r"(\w+)=((?:[^ =]| (?!\w+=))*)", extension):
                ext_dict[kv[0]] = kv[1].strip()

            records.append({
                "event_type": self._cef_category(name, sig_id),
                "timestamp": ext_dict.get("rt", ext_dict.get("end", ext_dict.get("start", ""))),
                "user": ext_dict.get("suser", ext_dict.get("duser", "")),
                "source_user": ext_dict.get("suser", ""),
                "destination_user": ext_dict.get("duser", ""),
                "source_host": ext_dict.get("src", ext_dict.get("shost", "")),
                "destination_host": ext_dict.get("dst", ext_dict.get("dhost", "")),
                "process": ext_dict.get("sproc", ext_dict.get("dproc", "")),
                "action": name,
                "details": f"vendor={vendor}|product={product}|severity={severity}|sig={sig_id}",
            })
        return records

    def _cef_category(self, name: str, sig_id: str) -> str:
        combined = (name + sig_id).lower()
        if any(k in combined for k in ("auth", "logon", "login", "credential")):
            return "auth"
        if any(k in combined for k in ("process", "exec", "binary", "command")):
            return "process"
        if any(k in combined for k in ("dns", "resolve", "lookup")):
            return "dns"
        if any(k in combined for k in ("flow", "network", "connection", "traffic", "firewall")):
            return "flow"
        return "security"

    # ------------------------------------------------------------------
    # SCHEMA NORMALIZATION
    # ------------------------------------------------------------------

    def _normalize_schema(self, df: pd.DataFrame) -> pd.DataFrame:
        # Map columns using heuristic lookup
        rename_map = {}
        for col in df.columns:
            normalized_key = col.strip().lower().replace(" ", "_").replace("-", "_")
            if normalized_key in _COLUMN_MAP:
                target = _COLUMN_MAP[normalized_key]
                if target not in rename_map.values():
                    rename_map[col] = target

        df = df.rename(columns=rename_map)

        # Ensure all required columns exist
        for col in INTERNAL_SCHEMA:
            if col not in df.columns:
                df[col] = "" if col != "is_redteam" else 0

        # Collect unmapped columns into details
        unmapped = [c for c in df.columns if c not in INTERNAL_SCHEMA]
        if unmapped:
            def _merge_details(row):
                base = str(row.get("details", "") or "")
                extras = []
                for c in unmapped:
                    val = row.get(c, "")
                    if val and str(val).strip() and str(val).strip().lower() != "nan":
                        extras.append(f"{c}={val}")
                if extras:
                    return (base + " | " + " | ".join(extras)).strip(" |")
                return base
            df["details"] = df.apply(_merge_details, axis=1)

        # Auto-detect event_type if missing or all empty
        if df["event_type"].astype(str).str.strip().replace("", pd.NA).isna().all():
            df["event_type"] = df.apply(self._infer_event_type_from_row, axis=1)

        # Ensure is_redteam is always 0 for new data (no ground truth)
        df["is_redteam"] = pd.to_numeric(df["is_redteam"], errors="coerce").fillna(0).astype(int)

        # Clean string columns
        for col in INTERNAL_SCHEMA:
            if col != "is_redteam" and col != "timestamp":
                df[col] = df[col].fillna("").astype(str).str.strip()

        return df[INTERNAL_SCHEMA]

    def _infer_event_type_from_row(self, row) -> str:
        combined = " ".join(str(v).lower() for v in row.values if v)
        if any(k in combined for k in ("auth", "logon", "login", "credential", "kerberos", "ntlm")):
            return "auth"
        if any(k in combined for k in ("process", "exec", "spawn", "binary", "command")):
            return "process"
        if any(k in combined for k in ("dns", "resolve", "lookup", "query")):
            return "dns"
        if any(k in combined for k in ("flow", "netflow", "connection", "traffic", "bytes", "packet")):
            return "flow"
        return "security"

    # ------------------------------------------------------------------
    # TIMESTAMP NORMALIZATION
    # ------------------------------------------------------------------

    def _normalize_timestamps(self, df: pd.DataFrame) -> pd.DataFrame:
        # Try numeric conversion first (Unix epoch)
        numeric_ts = pd.to_numeric(df["timestamp"], errors="coerce")
        all_numeric = numeric_ts.notna().sum() > len(df) * 0.8

        if all_numeric:
            # Handle millisecond vs second epoch
            median_val = numeric_ts.dropna().median()
            if median_val > 1e12:
                numeric_ts = numeric_ts / 1000  # ms -> s
            elif median_val > 1e15:
                numeric_ts = numeric_ts / 1e6   # us -> s
            df["timestamp"] = numeric_ts.fillna(0).astype(int)
            return df

        # Try parsing with cached format first
        if self._ts_format_cache:
            try:
                parsed = pd.to_datetime(df["timestamp"], format=self._ts_format_cache, errors="coerce")
                if parsed.notna().sum() > len(df) * 0.8:
                    df["timestamp"] = parsed.apply(
                        lambda x: int(x.timestamp()) if pd.notna(x) else 0
                    )
                    return df
            except Exception:
                pass

        # Auto-detect timestamp format
        sample = df["timestamp"].dropna().head(20).astype(str)
        for fmt in _TS_FORMATS:
            try:
                parsed_sample = pd.to_datetime(sample, format=fmt, errors="coerce")
                if parsed_sample.notna().sum() >= len(sample) * 0.7:
                    self._ts_format_cache = fmt
                    parsed = pd.to_datetime(df["timestamp"], format=fmt, errors="coerce")
                    df["timestamp"] = parsed.apply(
                        lambda x: int(x.timestamp()) if pd.notna(x) else 0
                    )
                    return df
            except Exception:
                continue

        # Last resort: pandas general parser
        try:
            parsed = pd.to_datetime(df["timestamp"], errors="coerce", infer_datetime_format=True)
            df["timestamp"] = parsed.apply(
                lambda x: int(x.timestamp()) if pd.notna(x) else 0
            )
        except Exception:
            df["timestamp"] = 0

        return df
