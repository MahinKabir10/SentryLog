"""
sentrylog.parsers
=================

The parser layer. Each submodule knows how to read exactly one log format and
emit normalized :class:`~sentrylog.event.Event` objects, exposing a uniform
``parse_file(path) -> ParseResult`` entry point.

The ``PARSERS`` registry maps a :class:`~sentrylog.event.SourceType` to its
``parse_file`` callable so the CLI can dispatch without a chain of ``if``
statements -- adding a new source in a later phase is just a new module plus one
entry here.
"""

from __future__ import annotations

from typing import Callable

from sentrylog.event import SourceType
from sentrylog.parsers import linux_auth, windows_evtx
from sentrylog.parsers.base import ParseResult, ParseStats, UnparseableLine

# Source -> file parser. Each value has signature: (path) -> ParseResult.
PARSERS: dict[SourceType, Callable[[object], ParseResult]] = {
    SourceType.LINUX_AUTH: linux_auth.parse_file,
    SourceType.WINDOWS_EVTX: windows_evtx.parse_file,
}

__all__ = [
    "PARSERS",
    "ParseResult",
    "ParseStats",
    "UnparseableLine",
    "linux_auth",
    "windows_evtx",
]
