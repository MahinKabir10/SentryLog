"""
sentrylog.detection.alert
=========================

The *alert model* for SentryLog's detection layer -- the output contract that
mirrors what :class:`~sentrylog.event.Event` is for ingestion.

Every rule emits exactly one type: :class:`Alert`. The CLI renders it, the MCP
server serializes it, a future storage backend persists it -- none of them ever
look inside a rule. Same layering argument as Phase 1: one strict shape at the
boundary, everything downstream works for free.

Severity philosophy (the thing to defend in an interview):
severity is **confidence x impact**, assigned by the rule that has the context,
not by the consumer. Four tiers is deliberate -- enough to drive a paging
policy (critical pages a human, high goes to the queue, medium is triaged in
business hours, low is audit trail), few enough that each tier still means
something. A ten-level scale just becomes noise with extra steps.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional

from sentrylog.event import Event


class Severity(str, Enum):
    """Alert severity tiers, ordered least to most urgent.

    A ``str`` enum for the same reason as :class:`~sentrylog.event.Outcome`:
    members compare and serialize as their plain string values.
    """

    LOW = "low"            # expected/routine, kept for the audit trail
    MEDIUM = "medium"      # suspicious intent shown, impact not realized
    HIGH = "high"          # strong attack signal or durable rights change
    CRITICAL = "critical"  # evidence the attack SUCCEEDED -- act now

    @property
    def rank(self) -> int:
        """Numeric order for sorting/filtering (low=0 .. critical=3).

        Kept as an explicit property rather than overloading ``<`` on the enum:
        comparisons stay readable (``a.severity.rank >= b.rank``) and the
        string-enum's value-equality semantics stay untouched.
        """
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass
class Alert:
    """A single detection finding.

    Parameters
    ----------
    rule_name:
        Stable identifier of the rule that fired (``"brute_force"``, ...).
        This is the pivot key for tuning, suppression, and metrics.
    severity:
        :class:`Severity` tier. Strings are coerced, unknown values fail loudly
        -- same boundary strictness as :class:`~sentrylog.event.Event`.
    timestamp:
        When the detection *triggered* -- by convention the timestamp of the
        last matched event, because that is the moment the pattern completed.
        Must be timezone-aware; stored as UTC.
    description:
        One human-readable sentence an analyst can act on without opening the
        matched events. Rules put the numbers here (counts, windows, targets).
    source_ip / user / host:
        The pivotable entities, when the pattern has a single one. ``None``
        when the rule cannot honestly name one (e.g. a spray across many
        users has no single ``user``) -- the description carries the nuance.
    matched_events:
        The full normalized events behind the finding, in chronological order.
        Lossless on purpose: an analyst must always be able to walk from the
        alert back to the raw log lines (each Event still carries ``raw``).
    """

    rule_name: str
    severity: Severity
    timestamp: datetime
    description: str
    source_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    matched_events: List[Event] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate at construction -- no invalid Alert can exist (cf. Event)."""
        self.severity = Severity(self.severity)

        if not isinstance(self.timestamp, datetime):
            raise TypeError(
                f"Alert.timestamp must be a datetime, got {type(self.timestamp)!r}"
            )
        if self.timestamp.tzinfo is None:
            raise ValueError(
                "Alert.timestamp must be timezone-aware. Rules derive it from "
                "Event timestamps, which the Event contract guarantees are UTC."
            )
        self.timestamp = self.timestamp.astimezone(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Stable, JSON-friendly dict (field order fixed, enums flattened)."""
        return {
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "source_ip": self.source_ip,
            "user": self.user,
            "host": self.host,
            "event_count": len(self.matched_events),
            "matched_events": [event.to_dict() for event in self.matched_events],
        }

    def to_json(self) -> str:
        """One-line JSON (NDJSON-friendly, mirrors Event.to_json)."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def summary(self) -> str:
        """Compact one-liner for terminal display."""
        where = f" ip={self.source_ip}" if self.source_ip else ""
        who = f" user={self.user}" if self.user else ""
        return (
            f"{self.timestamp:%Y-%m-%d %H:%M:%S} "
            f"[{self.severity.value.upper()}] {self.rule_name}:{who}{where} "
            f"({len(self.matched_events)} events) {self.description}"
        )
