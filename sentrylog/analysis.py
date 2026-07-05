"""
sentrylog.analysis
==================

*Descriptive* analysis helpers over the normalized
:class:`~sentrylog.event.Event` stream: what happened, counted and ranked.
*Detection* (what's suspicious, with severities) lives in
:mod:`sentrylog.detection` -- the count-based brute-force helper that briefly
lived here was superseded by the windowed
:class:`~sentrylog.detection.brute_force.BruteForceRule` and removed rather
than kept as a second, disagreeing implementation.

Everything here consumes ``Iterable[Event]`` and knows nothing about files,
parsers, or transports, so the same functions serve the CLI, the MCP server
(``sentrylog_mcp.py``), and unit tests.

Like the rest of the core package, this module is standard-library only.
"""

from __future__ import annotations

from collections import Counter
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
