"""
sentrylog_mcp
=============

MCP (Model Context Protocol) server exposing SentryLog's analysis and
detection layers as tools, so an MCP client (e.g. Claude Desktop) can
investigate a Linux ``auth.log`` or Windows ``.evtx`` conversationally.

Architecture: this file is a *thin transport layer*. Parsing lives in
``sentrylog.parsers`` (dispatched through the ``PARSERS`` registry, so both
sources work), descriptive analysis in ``sentrylog.analysis``, and detection
in ``sentrylog.detection`` -- the server only validates inputs (Pydantic),
translates failures into actionable error messages, and shapes JSON-friendly
output.

Tools (all read-only -- nothing here writes, modifies, or deletes anything):

* ``list_failed_logins(log_path, limit)`` -- failed login attempts.
* ``summarize_log(log_path)`` -- top source IPs, top targeted users, counts.
* ``detect_bruteforce(log_path, threshold, window_seconds)`` -- sliding-window
  failed-login bursts per source IP (the Phase 2 rule).
* ``detect_privesc(log_path)`` -- sudo + Windows 4672/4720/4732 escalations.
* ``list_alerts(log_path, min_severity)`` -- run ALL detection rules, get the
  triage-ordered alert list.

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

from sentrylog.analysis import extract_failed_logins, summarize_events
from sentrylog.detection import (
    Alert,
    BruteForceRule,
    PrivilegeEscalationRule,
    Severity,
    default_rules,
    run_rules,
)
from sentrylog.event import SourceType
from sentrylog.parsers import PARSERS
from sentrylog.parsers.base import ParseResult
from sentrylog.parsers.linux_auth import parse_file as _parse_auth_log

# Shipped sample so every error message can point at something that works.
_SAMPLE_LOG = _PROJECT_ROOT / "samples" / "auth.log"

# EVTX files start with this signature; sniffing it lets us dispatch to the
# right parser regardless of the file's extension.
_EVTX_MAGIC = b"ElfFile"

# Cap on events embedded per alert in tool responses. Alerts stay lossless in
# the engine; this is transport economy -- a 500-failure burst should not ship
# 500 raw log lines through the context window.
_MAX_EVENTS_PER_ALERT = 20

mcp = FastMCP(
    "sentrylog",
    instructions=(
        "Read-only analysis and detection over Linux auth.log and Windows "
        ".evtx security logs (SSH/RDP logins, sudo, account changes). All "
        "tools take a filesystem path to a log file; absolute paths are most "
        f"reliable. A sample log ships at: {_SAMPLE_LOG}"
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
        # Binary Windows event log: dispatch through the parser registry. The
        # EVTX parser raises RuntimeError when python-evtx isn't installed.
        try:
            result = PARSERS[SourceType.WINDOWS_EVTX](resolved)
        except RuntimeError as exc:
            raise ToolError(
                f"'{resolved}' is a Windows EVTX file, but its parser is "
                f"unavailable: {exc}"
            ) from exc
        except OSError as exc:
            raise ToolError(f"Could not read '{resolved}': {exc}") from exc
        return resolved, result

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


def _alert_dict(alert: Alert) -> dict[str, Any]:
    """Alert.to_dict() with the evidence capped for transport (see the
    _MAX_EVENTS_PER_ALERT rationale). The true count is always reported."""
    payload = alert.to_dict()
    if len(payload["matched_events"]) > _MAX_EVENTS_PER_ALERT:
        payload["matched_events"] = payload["matched_events"][:_MAX_EVENTS_PER_ALERT]
        payload["matched_events_truncated"] = True
    return payload


_LOG_PATH_FIELD = Field(
    description=(
        "Path to a log file -- Linux auth.log text or Windows .evtx binary "
        "(detected automatically). Absolute paths are most reliable (the "
        "server may run from any working directory)."
    ),
    min_length=1,
)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool(annotations=_READ_ONLY)
def list_failed_logins(
    log_path: Annotated[str, _LOG_PATH_FIELD],
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
    log_path: Annotated[str, _LOG_PATH_FIELD],
    threshold: Annotated[
        int,
        Field(
            ge=1,
            le=10000,
            description=(
                "Failed logins from one source IP within the window that trip "
                "the rule (default 5)."
            ),
        ),
    ] = 5,
    window_seconds: Annotated[
        int,
        Field(
            ge=1,
            le=86400,
            description="Sliding window span in seconds (default 60).",
        ),
    ] = 60,
) -> dict[str, Any]:
    """Detect brute-force bursts: `threshold` failed logins from one source IP
    within a `window_seconds` sliding window.

    Runs SentryLog's windowed brute-force rule (one alert per burst, severity
    medium, escalating to high on 3x volume or a multi-user spray). Works on
    both Linux auth.log (SSH) and Windows EVTX (4625/RDP) files.
    """
    resolved, result = _load_events(log_path)
    detection = run_rules(
        result.events,
        [BruteForceRule(threshold=threshold, window_seconds=window_seconds)],
    )

    return {
        "log_path": str(resolved),
        "parse_stats": _stats_dict(result),
        "threshold": threshold,
        "window_seconds": window_seconds,
        "alert_count": len(detection.alerts),
        "alerts": [_alert_dict(a) for a in detection.alerts],
    }


@mcp.tool(annotations=_READ_ONLY)
def detect_privesc(
    log_path: Annotated[str, _LOG_PATH_FIELD],
) -> dict[str, Any]:
    """Detect privilege-escalation activity: sudo successes/failures on Linux,
    and Windows 4672 (special privileges), 4720 (account created), 4732
    (member added to a security group).

    Severity is tiered to fight noise: failed elevation and account creation
    are medium, addition to an admin-equivalent group is high, and routine
    successful elevation (sudo/4672) is aggregated into one low audit alert
    per user+host instead of one per event.
    """
    resolved, result = _load_events(log_path)
    detection = run_rules(result.events, [PrivilegeEscalationRule()])

    return {
        "log_path": str(resolved),
        "parse_stats": _stats_dict(result),
        "alert_count": len(detection.alerts),
        "alerts": [_alert_dict(a) for a in detection.alerts],
    }


@mcp.tool(annotations=_READ_ONLY)
def list_alerts(
    log_path: Annotated[str, _LOG_PATH_FIELD],
    min_severity: Annotated[
        str,
        Field(
            description=(
                "Only return alerts at or above this severity: "
                "'low', 'medium', 'high', or 'critical' (default 'low')."
            ),
            pattern="^(low|medium|high|critical)$",
        ),
    ] = "low",
) -> dict[str, Any]:
    """Run ALL detection rules (brute force, privilege escalation, compromise)
    over a log file and return the alerts in triage order (most severe first).

    This is the 'analyze this log' entry point; the compromise rule
    (failed logins followed by a success from the same IP -- critical) only
    runs here. Counts for every severity are always included, so filtered-out
    tiers remain visible.
    """
    resolved, result = _load_events(log_path)
    detection = run_rules(result.events, default_rules())

    minimum = Severity(min_severity)
    visible = [a for a in detection.alerts if a.severity.rank >= minimum.rank]

    return {
        "log_path": str(resolved),
        "parse_stats": _stats_dict(result),
        "rules_run": detection.rule_names,
        "total_alerts": len(detection.alerts),
        "counts_by_severity": dict(detection.counts_by_severity()),
        "min_severity": min_severity,
        "returned": len(visible),
        "alerts": [_alert_dict(a) for a in visible],
    }


@mcp.tool(annotations=_READ_ONLY)
def summarize_log(
    log_path: Annotated[str, _LOG_PATH_FIELD],
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
