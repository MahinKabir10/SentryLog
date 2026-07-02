"""
sentrylog.analysis
==================

Analysis helpers over the normalized :class:`~sentrylog.event.Event` stream --
the first slice of Phase 2 (detection).

Everything here consumes ``Iterable[Event]`` and knows nothing about files,
parsers, or transports. That separation is deliberate: the same three functions
serve the CLI (a future ``sentrylog detect`` subcommand), the MCP server
(``sentrylog_mcp.py``), and unit tests, because by the time events reach this
module every source -- SSH, RDP, whatever -- has already been normalized to
``action=login, outcome=failure`` and friends.

Like the rest of the core package, this module is standard-library only.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, List, Optional

from sentrylog.event import Action, Event, Outcome


def extract_failed_logins(events: Iterable[Event]) -> List[Event]:
    """Return every failed login attempt, preserving input order.

    "Failed login" means ``action == LOGIN and outcome == FAILURE`` -- which on
    Linux covers both ``Failed password`` lines and the standalone
    ``Invalid user`` notices (each is its own Event), and would equally cover a
    Windows 4625 if the events came from the EVTX parser.
    """
    return [
        event
        for event in events
        if event.action is Action.LOGIN and event.outcome is Outcome.FAILURE
    ]


@dataclass
class BruteForceFinding:
    """One source IP whose failed-login count crossed the threshold.

    ``users_targeted`` is sorted and de-duplicated; a long list of *different*
    users from one IP is the classic user-enumeration / password-spray shape,
    while many failures against one user is a focused brute force -- the caller
    can distinguish the two from this one field.
    """

    source_ip: str
    failure_count: int
    users_targeted: List[str]
    invalid_user_count: int  # failures against accounts that don't even exist
    first_seen: datetime
    last_seen: datetime

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly rendering (mirrors Event.to_dict())."""
        return {
            "source_ip": self.source_ip,
            "failure_count": self.failure_count,
            "users_targeted": list(self.users_targeted),
            "invalid_user_count": self.invalid_user_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "span_seconds": int((self.last_seen - self.first_seen).total_seconds()),
        }


def detect_bruteforce(
    events: Iterable[Event], threshold: int = 5
) -> List[BruteForceFinding]:
    """Group failed logins by source IP and flag IPs at/above ``threshold``.

    Failures with no source IP (e.g. local sudo failures are not logins, but
    defensively: any failed login lacking an IP) cannot be attributed to an
    attacker address and are excluded. Findings are sorted by failure count
    descending, then by IP for a stable order.
    """
    if threshold < 1:
        raise ValueError(f"threshold must be >= 1, got {threshold}")

    by_ip: dict[str, List[Event]] = defaultdict(list)
    for event in extract_failed_logins(events):
        if event.source_ip:
            by_ip[event.source_ip].append(event)

    findings = [
        BruteForceFinding(
            source_ip=ip,
            failure_count=len(fails),
            users_targeted=sorted({e.user for e in fails if e.user}),
            invalid_user_count=sum(
                1 for e in fails if e.metadata.get("invalid_user")
            ),
            first_seen=min(e.timestamp for e in fails),
            last_seen=max(e.timestamp for e in fails),
        )
        for ip, fails in by_ip.items()
        if len(fails) >= threshold
    ]
    findings.sort(key=lambda f: (-f.failure_count, f.source_ip))
    return findings


def summarize_events(events: Iterable[Event], top_n: int = 5) -> dict[str, Any]:
    """Aggregate an event stream into a JSON-friendly overview dict.

    Shape (stable -- the MCP server exposes it verbatim):

    * ``total_events`` -- events in the stream.
    * ``by_action`` / ``by_outcome`` -- counts keyed by the enum string values.
    * ``logins`` -- ``{"successful": n, "failed": n}`` convenience counts.
    * ``top_source_ips`` -- up to ``top_n`` entries of
      ``{"source_ip", "events", "failed_logins"}``, ranked by total events.
    * ``top_targeted_users`` -- up to ``top_n`` entries of
      ``{"user", "failed_logins"}`` ranked by *failed login* count, i.e. who
      attackers are aiming at (successful activity does not inflate this).
    * ``time_range`` -- ISO ``first``/``last`` timestamps, or ``None`` when
      the stream is empty.
    """
    if top_n < 1:
        raise ValueError(f"top_n must be >= 1, got {top_n}")

    materialized = list(events)
    failed = extract_failed_logins(materialized)

    action_counts = Counter(e.action.value for e in materialized)
    outcome_counts = Counter(e.outcome.value for e in materialized)

    ip_events = Counter(e.source_ip for e in materialized if e.source_ip)
    ip_failures = Counter(e.source_ip for e in failed if e.source_ip)
    user_failures = Counter(e.user for e in failed if e.user)

    successful_logins = sum(
        1
        for e in materialized
        if e.action is Action.LOGIN and e.outcome is Outcome.SUCCESS
    )

    time_range: Optional[dict[str, str]] = None
    if materialized:
        time_range = {
            "first": min(e.timestamp for e in materialized).isoformat(),
            "last": max(e.timestamp for e in materialized).isoformat(),
        }

    return {
        "total_events": len(materialized),
        "by_action": dict(action_counts),
        "by_outcome": dict(outcome_counts),
        "logins": {"successful": successful_logins, "failed": len(failed)},
        "top_source_ips": [
            {"source_ip": ip, "events": count, "failed_logins": ip_failures.get(ip, 0)}
            for ip, count in ip_events.most_common(top_n)
        ],
        "top_targeted_users": [
            {"user": user, "failed_logins": count}
            for user, count in user_failures.most_common(top_n)
        ],
        "time_range": time_range,
    }
