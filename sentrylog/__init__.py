"""
SentryLog -- a minimal SIEM.
============================

**Phase 1 scope: ingestion and normalization only.** This package reads raw log
sources and converts them into a single normalized event type. There is no
detection logic yet -- that's Phase 2.

The pipeline is deliberately layered:

    raw log file
        -> a source-specific parser (sentrylog.parsers.*)
        -> normalized sentrylog.event.Event objects
        -> summary / output (sentrylog.cli)

Public API re-exported here for convenience::

    from sentrylog import Event, SourceType, Outcome, Action
"""

from __future__ import annotations

from sentrylog.event import Action, Event, Outcome, SourceType

__version__ = "0.1.0"

__all__ = ["Event", "SourceType", "Outcome", "Action", "__version__"]
