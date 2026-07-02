"""
sentrylog_mcp
=============

MCP (Model Context Protocol) server exposing SentryLog's log-analysis functions
as tools, so an MCP client (e.g. Claude Desktop) can investigate a Linux
``auth.log`` conversationally.

Architecture: this file is a *thin transport layer*. All parsing lives in
``sentrylog.parsers.linux_auth`` and all analysis in ``sentrylog.analysis`` --
the server only validates inputs (Pydantic), translates failures into
actionable error messages, and shapes JSON-friendly output.

Tools (all read-only -- nothing here writes, modifies, or deletes anything):

* ``list_failed_logins(log_path, limit)``  -- failed SSH login attempts.
* ``detect_bruteforce(log_path, threshold)`` -- source IPs whose failed-login
  count meets/exceeds the threshold.
* ``summarize_log(log_path)`` -- top source IPs, top targeted users, and
  event counts for the whole file.

Run directly (stdio transport, which is what Claude Desktop speaks):

    python sentrylog_mcp.py

Requires: pip install "mcp[cli]"
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Any

# The sentrylog package lives next to this file in the repo root. Python adds
# the script's directory to sys.path when run directly, but Claude Desktop
# launches MCP servers with an arbitrary working directory and some launchers
# skip that step -- so anchor the import path to *this file's* location
# explicitly, not the cwd.
_PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_PROJECT_ROOT))

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from sentrylog.analysis import (
    detect_bruteforce as _detect_bruteforce,
    extract_failed_logins,
    summarize_events,
)
from sentrylog.parsers.base import ParseResult
from sentrylog.parsers.linux_auth import parse_file as _parse_auth_log

# Shipped sample so every error message can point at something that works.
_SAMPLE_LOG = _PROJECT_ROOT / "samples" / "auth.log"

# EVTX files start with this signature; catching them early lets us return a
# useful "wrong format" message instead of "0 events parsed".
_EVTX_MAGIC = b"ElfFile"

mcp = FastMCP(
    "sentrylog",
    instructions=(
        "Read-only analysis of Linux auth.log files (SSH logins, sudo). "
        "All tools take a filesystem path to a log file; absolute paths are "
        f"most reliable. A sample log ships at: {_SAMPLE_LOG}"
    ),
)

_READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


# ---------------------------------------------------------------------------
# Shared input handling
# ---------------------------------------------------------------------------

def _load_events(log_path: str) -> tuple[Path, ParseResult]:
    """Resolve ``log_path``, parse it, and return (resolved_path, result).

    Every failure mode raises :class:`ToolError` with a message that says what
    was tried and what to do about it -- the model relaying the error to a user
    should never have to guess.
    """
    path = Path(log_path).expanduser()
    resolved = path if path.is_absolute() else (Path.cwd() / path)

    if not resolved.exists():
        raise ToolError(
            f"Log file not found: tried '{resolved}'"
            + (
                f" (relative path '{log_path}' was resolved against the server's "
                f"working directory '{Path.cwd()}' -- pass an absolute path instead)."
                if not path.is_absolute()
                else "."
            )
            + f" A sample log you can test with: {_SAMPLE_LOG}"
        )
    if resolved.is_dir():
        raise ToolError(
            f"'{resolved}' is a directory, not a log file. "
            f"Pass the path to a specific auth.log file, e.g. {_SAMPLE_LOG}"
        )

    try:
        with open(resolved, "rb") as handle:
            head = handle.read(len(_EVTX_MAGIC))
    except OSError as exc:
        raise ToolError(f"Could not read '{resolved}': {exc}") from exc
    if head.startswith(_EVTX_MAGIC):
        raise ToolError(
            f"'{resolved}' is a Windows EVTX file (binary). This MCP server's "
            "tools only analyze Linux auth.log text files. For EVTX, use the "
            "SentryLog CLI instead: python -m sentrylog ingest <file.evtx>"
        )

    try:
        result = _parse_auth_log(resolved)
    except OSError as exc:
        raise ToolError(f"Could not read '{resolved}': {exc}") from exc

    stats = result.stats
    if stats.total > 0 and stats.parsed == 0 and stats.skipped == 0:
        # Every single line failed even the syslog skeleton: wrong file format.
        raise ToolError(
            f"'{resolved}' does not look like a Linux auth.log: none of its "
            f"{stats.total} lines matched the syslog format "
            "(expected lines like 'May 27 08:14:02 host sshd[123]: ...'). "
            f"Check the path, or try the sample log: {_SAMPLE_LOG}"
        )
    return resolved, result


def _stats_dict(result: ParseResult) -> dict[str, int]:
    """Parse counters, included in every response so 'why is this empty?'
    is always answerable from the output itself."""
    stats = result.stats
    return {
        "total_lines": stats.total,
        "parsed": stats.parsed,
        "skipped": stats.skipped,
        "errors": stats.errors,
    }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool(annotations=_READ_ONLY)
def list_failed_logins(
    log_path: Annotated[
        str,
        Field(
            description=(
                "Path to a Linux auth.log file. Absolute paths are most "
                "reliable (the server may run from any working directory)."
            ),
            min_length=1,
        ),
    ],
    limit: Annotated[
        int,
        Field(
            ge=1,
            le=500,
            description="Maximum number of failed logins to return (1-500).",
        ),
    ] = 20,
) -> dict[str, Any]:
    """List failed SSH login attempts from a Linux auth.log file.

    Includes both 'Failed password' lines and 'Invalid user' notices, in log
    order. Returns at most `limit` entries plus the total count, so a truncated
    response is always detectable.
    """
    resolved, result = _load_events(log_path)
    failed = extract_failed_logins(result.events)

    return {
        "log_path": str(resolved),
        "parse_stats": _stats_dict(result),
        "total_failed_logins": len(failed),
        "returned": min(limit, len(failed)),
        "failed_logins": [
            {
                "timestamp": e.timestamp.isoformat(),
                "host": e.host,
                "user": e.user,
                "source_ip": e.source_ip,
                "port": e.metadata.get("port"),
                "auth_method": e.metadata.get("auth_method"),
                "invalid_user": bool(e.metadata.get("invalid_user")),
                "event_id": e.event_id,
                "raw": e.raw,
            }
            for e in failed[:limit]
        ],
    }


@mcp.tool(annotations=_READ_ONLY)
def detect_bruteforce(
    log_path: Annotated[
        str,
        Field(
            description=(
                "Path to a Linux auth.log file. Absolute paths are most "
                "reliable (the server may run from any working directory)."
            ),
            min_length=1,
        ),
    ],
    threshold: Annotated[
        int,
        Field(
            ge=1,
            le=10000,
            description=(
                "Minimum number of failed logins from a single source IP for "
                "it to be flagged (default 5)."
            ),
        ),
    ] = 5,
) -> dict[str, Any]:
    """Detect brute-force sources: IPs with at least `threshold` failed logins.

    Findings are sorted by failure count (highest first) and include the set of
    targeted usernames, how many attempts hit non-existent accounts, and the
    first/last timestamps of the activity.
    """
    resolved, result = _load_events(log_path)
    findings = _detect_bruteforce(result.events, threshold=threshold)

    return {
        "log_path": str(resolved),
        "parse_stats": _stats_dict(result),
        "threshold": threshold,
        "sources_flagged": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


@mcp.tool(annotations=_READ_ONLY)
def summarize_log(
    log_path: Annotated[
        str,
        Field(
            description=(
                "Path to a Linux auth.log file. Absolute paths are most "
                "reliable (the server may run from any working directory)."
            ),
            min_length=1,
        ),
    ],
) -> dict[str, Any]:
    """Summarize a Linux auth.log: top source IPs, top targeted users, counts.

    'Top targeted users' is ranked by FAILED login attempts (who attackers aim
    at), and every response carries the parse statistics so empty sections are
    explainable (e.g. a file full of CRON noise parses to zero auth events).
    """
    resolved, result = _load_events(log_path)
    summary = summarize_events(result.events, top_n=5)

    return {
        "log_path": str(resolved),
        "parse_stats": _stats_dict(result),
        **summary,
    }


if __name__ == "__main__":
    # stdio is the transport Claude Desktop uses to talk to local servers.
    mcp.run(transport="stdio")
