"""
sentrylog.parsers.base
=======================

Small shared types every parser uses. Keeping these in one place means the CLI
can treat *all* parsers uniformly: each one consumes a path and returns a
:class:`ParseResult`, no matter how different the underlying formats are.

The field names here are deliberately source-agnostic ("total", "parsed",
"skipped", "errors") so the same counters describe text *lines* (Linux) and
binary *records* (Windows EVTX) without renaming.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from sentrylog.event import Event, SourceType


class UnparseableLine(Exception):
    """Raised by a parser when an input unit cannot be understood at all.

    This is distinct from "understood but intentionally ignored". A parser
    raises this only for genuinely malformed input (a line that does not even
    match the expected skeleton). The file-level loop catches it, counts it as
    an *error*, logs a warning, and keeps going -- it must never crash the run.
    """


@dataclass
class ParseStats:
    """Counters describing one parse run, used to build the CLI summary.

    The three non-total buckets are mutually exclusive, so
    ``parsed + skipped + errors == total`` always holds:

    * ``parsed``  -- successfully normalized into an :class:`Event`.
    * ``skipped`` -- understood, but intentionally not modeled (e.g. a CRON
      session line in auth.log, or a Windows Event ID we don't map). Not a
      problem, just noise we chose to drop.
    * ``errors``  -- could not be parsed; a warning was logged. We keep running.
    """

    total: int = 0
    parsed: int = 0
    skipped: int = 0
    errors: int = 0

    def as_line(self) -> str:
        """One-line rendering for the summary header."""
        return (
            f"{self.total} total | {self.parsed} parsed | "
            f"{self.skipped} skipped | {self.errors} errors"
        )


@dataclass
class ParseResult:
    """Everything a parser returns: the events plus the run statistics.

    Returning a fully materialized list (rather than a lazy generator) is a
    deliberate Phase-1 choice: building the summary table requires a complete
    pass over the data anyway, and auth logs / single EVTX files are small
    enough to hold in memory. If volumes grow, this is the seam where you'd
    switch to streaming.
    """

    events: List[Event] = field(default_factory=list)
    stats: ParseStats = field(default_factory=ParseStats)
    source_type: SourceType = SourceType.LINUX_AUTH
