"""
SentryLog -- a minimal SIEM.
============================

Phase 1 ingests raw log sources and normalizes them into a single event type;
Phase 2 runs detection rules over that normalized stream and emits
severity-tiered alerts.

The pipeline is deliberately layered:

    raw log file
        -> a source-specific parser (sentrylog.parsers.*)
        -> normalized sentrylog.event.Event objects
        -> detection rules (sentrylog.detection.*) -> Alert objects
        -> summary / output (sentrylog.cli, sentrylog_mcp)

Public API re-exported here for convenience::

    from sentrylog import Event, SourceType, Outcome, Action
    from sentrylog.detection import default_rules, run_rules, Alert, Severity
"""

from __future__ import annotations

from sentrylog.event import Action, Event, Outcome, SourceType

__version__ = "0.2.0"

__all__ = ["Event", "SourceType", "Outcome", "Action", "__version__"]
