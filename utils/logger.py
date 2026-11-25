"""Cloud Sentry — Local JSON Audit Logging System.

Records every simulated cloud storage access request to a local JSON file
(`data/audit_logs.json`), exposes Pandas DataFrame formatting for the Streamlit
dashboard, and calculates key security audit metrics:
  - total_requests
  - allowed_requests
  - denied_requests
  - unauthorized_attempts
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd

from access_control import AccessDecision


DEFAULT_AUDIT_LOG_PATH: Path = (
    Path(__file__).resolve().parent.parent / "data" / "audit_logs.json"
)


@dataclass(frozen=True)
class AuditLogEntry:
    """Represents a single recorded cloud storage access attempt."""

    timestamp: str
    user: str
    role: str
    cloud_object: str
    action: str
    decision: str  # "ALLOW" or "DENY"
    reason: str
    unauthorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize this audit log entry for JSON persistence."""
        return {
            "timestamp": self.timestamp,
            "user": self.user,
            "role": self.role,
            "cloud_object": self.cloud_object,
            "action": self.action,
            "decision": self.decision,
            "reason": self.reason,
            "unauthorized": self.unauthorized,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditLogEntry":
        """Deserialize an AuditLogEntry from a JSON dictionary."""
        decision = str(data["decision"]).upper()
        # Fallback: treat DENY entries as unauthorized if flag is absent
        unauthorized = bool(data.get("unauthorized", decision == "DENY"))
        return cls(
            timestamp=str(data["timestamp"]),
            user=str(data["user"]),
            role=str(data["role"]),
            cloud_object=str(data["cloud_object"]),
            action=str(data["action"]),
            decision=decision,
            reason=str(data.get("reason", "")),
            unauthorized=unauthorized,
        )


class AuditLogger:
    """Manages local JSON audit logging and summary metrics for Cloud Sentry."""

    def __init__(self, log_path: Path | str = DEFAULT_AUDIT_LOG_PATH) -> None:
        self.log_path: Path = Path(log_path)
        self._ensure_log_file()

    def _ensure_log_file(self) -> None:
        """Create the local JSON log file if it does not exist yet."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.write_text("[]\n", encoding="utf-8")

    def log_access(
        self,
        access_decision: AccessDecision,
        expected_allowed: Optional[bool] = None,
    ) -> AuditLogEntry:
        """Record a simulated access request from an AccessDecision object.

        An attempt is flagged as `unauthorized=True` when either:
          1. The access-control engine returned DENY (blocked unauthorized request), OR
          2. `expected_allowed` is explicitly False (e.g., Guest reading a
             misconfigured public-read Confidential file despite ALLOW).
        """
        is_unauthorized = (not access_decision.allowed) or (expected_allowed is False)
        entry = AuditLogEntry(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            user=access_decision.user,
            role=access_decision.role,
            cloud_object=access_decision.object,
            action=access_decision.action,
            decision=access_decision.decision,
            reason=access_decision.reason,
            unauthorized=is_unauthorized,
        )

        entries = self.get_logs()
        entries.append(entry)
        self._save_logs(entries)
        return entry

    def get_logs(self) -> list[AuditLogEntry]:
        """Load all audit log entries from local JSON storage."""
        self._ensure_log_file()
        try:
            with self.log_path.open("r", encoding="utf-8") as handle:
                raw_items = json.load(handle)
        except (json.JSONDecodeError, OSError):
            return []

        if not isinstance(raw_items, list):
            return []
        return [AuditLogEntry.from_dict(item) for item in raw_items]

    def _save_logs(self, entries: list[AuditLogEntry]) -> None:
        """Write audit log entries to disk as formatted JSON."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("w", encoding="utf-8") as handle:
            json.dump([entry.to_dict() for entry in entries], handle, indent=2)

    def clear_logs(self) -> None:
        """Reset the local audit log file to an empty list."""
        self._save_logs([])

    def get_metrics(self) -> dict[str, int]:
        """Calculate audit summary counts across all recorded requests."""
        entries = self.get_logs()
        total_requests = len(entries)
        allowed_requests = sum(1 for e in entries if e.decision == "ALLOW")
        denied_requests = sum(1 for e in entries if e.decision == "DENY")
        unauthorized_attempts = sum(1 for e in entries if e.unauthorized)

        return {
            "total_requests": total_requests,
            "allowed_requests": allowed_requests,
            "denied_requests": denied_requests,
            "unauthorized_attempts": unauthorized_attempts,
        }

    def get_logs_dataframe(self, newest_first: bool = True) -> pd.DataFrame:
        """Return audit logs as a Pandas DataFrame ready for Streamlit display."""
        columns = [
            "Timestamp",
            "User",
            "Role",
            "Cloud Object",
            "Action",
            "Decision",
            "Reason",
        ]
        entries = self.get_logs()
        if not entries:
            return pd.DataFrame(columns=columns)

        ordered = list(reversed(entries)) if newest_first else entries
        rows = [
            {
                "Timestamp": e.timestamp,
                "User": e.user,
                "Role": e.role,
                "Cloud Object": e.cloud_object,
                "Action": e.action,
                "Decision": e.decision,
                "Reason": e.reason,
            }
            for e in ordered
        ]
        return pd.DataFrame(rows, columns=columns)

    def filter_logs(
        self,
        role: Optional[str] = None,
        action: Optional[str] = None,
        decision: Optional[str] = None,
    ) -> pd.DataFrame:
        """Filter audit log rows by role, action, and/or decision."""
        df = self.get_logs_dataframe()
        if df.empty:
            return df
        if role and role != "All":
            df = df[df["Role"] == role]
        if action and action != "All":
            df = df[df["Action"] == action]
        if decision and decision != "All":
            df = df[df["Decision"] == decision]
        return df.reset_index(drop=True)
