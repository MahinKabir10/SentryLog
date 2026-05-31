"""
sentrylog.parsers.windows_evtx
==============================

Parser for Windows ``.evtx`` event log files. It reads the binary EVTX format
with the third-party ``python-evtx`` library, renders each record to XML, and
maps the security Event IDs we care about into normalized
:class:`~sentrylog.event.Event` objects.

Event IDs mapped in Phase 1 (the bread-and-butter of host auth telemetry):

===== ============================ ============ ==========
ID    Meaning                      action       outcome
===== ============================ ============ ==========
4624  An account logged on         login        success
4625  An account failed to log on  login        failure
4672  Special privileges assigned  priv-esc     success
4688  A new process was created    proc-create  unknown
===== ============================ ============ ==========

Why ``unknown`` for 4688? Process creation isn't an auth pass/fail -- it simply
occurred. The schema has a first-class ``UNKNOWN`` outcome exactly so we can say
that honestly instead of inventing a success.

Two implementation details worth defending:

* **Lazy import of ``Evtx``.** The dependency is imported *inside*
  :func:`parse_file`, not at module top. That means the rest of SentryLog (and
  the Linux path) runs with zero third-party deps; you only need
  ``python-evtx`` installed if you actually parse an ``.evtx`` file. If it's
  missing we raise a clear, actionable error instead of an import traceback.
* **Parsing record XML as bytes.** ``record.xml()`` returns a *str* that begins
  with an ``<?xml ... encoding=...?>`` declaration. ``ElementTree.fromstring``
  rejects a unicode string that carries an encoding declaration, so we encode
  to UTF-8 bytes first. (Classic EVTX-parsing gotcha.)
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sentrylog.event import Action, Event, Outcome, SourceType
from sentrylog.parsers.base import ParseResult, ParseStats

logger = logging.getLogger(__name__)

# Every element in a Windows event is in this XML namespace. ElementTree uses
# Clark notation ("{namespace}tag"), so we prefix it onto every lookup. Storing
# it once keeps the find() calls readable.
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# The four Event IDs we normalize in Phase 1. Anything else is "skipped".
_MAPPED_IDS = {"4624", "4625", "4672", "4688"}

# Windows logon types are integers; the friendly name is what an analyst reads.
# Type 3 (Network) vs 10 (RemoteInteractive/RDP) is, for example, the difference
# between a file-share auth and an interactive remote desktop session -- detail
# a Phase-2 rule will absolutely want. We store both the code and the name.
_LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",   # RDP
    "11": "CachedInteractive",
}


def parse_file(path) -> ParseResult:
    """Parse an ``.evtx`` file into a :class:`ParseResult`.

    Raises :class:`RuntimeError` (with install instructions) if ``python-evtx``
    isn't available. Individual records that fail to parse are counted as errors
    and logged -- one bad record never aborts the file.
    """
    # Lazy, guarded import -- see module docstring.
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise RuntimeError(
            "The Windows EVTX parser requires the 'python-evtx' package. "
            "Install it with:  pip install python-evtx"
        ) from exc

    result = ParseResult(source_type=SourceType.WINDOWS_EVTX)
    stats: ParseStats = result.stats

    with Evtx(str(path)) as log:
        for record in log.records():
            stats.total += 1
            try:
                xml = record.xml()
                # Encode to bytes so the embedded <?xml encoding?> declaration
                # is accepted by ElementTree (see module docstring).
                root = ET.fromstring(xml.encode("utf-8"))
            except Exception as exc:  # noqa: BLE001 - never crash on one record
                stats.errors += 1
                logger.warning(
                    "Failed to parse EVTX record #%d: %s", stats.total, exc
                )
                continue

            event_id = _system_text(root, "EventID")
            if event_id not in _MAPPED_IDS:
                # A security.evtx holds dozens of ID types; we model four.
                stats.skipped += 1
                logger.debug("Skipping unmapped Event ID: %s", event_id)
                continue

            event = _build_event(
                event_id=event_id,
                data=_event_data(root),
                host=_system_text(root, "Computer"),
                timestamp=_parse_time(_system_time(root)),
                raw=xml,
            )
            if event is None:
                stats.skipped += 1
                continue
            result.events.append(event)
            stats.parsed += 1

    return result


# ---------------------------------------------------------------------------
# XML extraction helpers. EVTX records have two halves:
#   <System>   -- provider metadata: EventID, Computer, TimeCreated, ...
#   <EventData> -- a list of <Data Name="...">value</Data> fields, the payload.
# ---------------------------------------------------------------------------

def _system_text(root: ET.Element, tag: str) -> Optional[str]:
    """Return the text of ``System/<tag>`` (e.g. EventID, Computer)."""
    element = root.find(f"{_NS}System/{_NS}{tag}")
    if element is None or element.text is None:
        return None
    return element.text.strip()


def _system_time(root: ET.Element) -> Optional[str]:
    """Return the ``SystemTime`` attribute of ``System/TimeCreated``.

    Unlike most System fields the timestamp lives in an *attribute*, not text:
    ``<TimeCreated SystemTime="2024-03-10T13:58:01.1234567Z"/>``.
    """
    element = root.find(f"{_NS}System/{_NS}TimeCreated")
    if element is None:
        return None
    return element.get("SystemTime")


def _event_data(root: ET.Element) -> dict[str, Optional[str]]:
    """Collect the ``<EventData>`` payload into a ``{Name: value}`` dict.

    Only *named* Data elements are kept -- the four security IDs we map all use
    named fields (TargetUserName, IpAddress, LogonType, ...), which is exactly
    what makes them reliably parseable.
    """
    data: dict[str, Optional[str]] = {}
    for node in root.findall(f"{_NS}EventData/{_NS}Data"):
        name = node.get("Name")
        if name is not None:
            data[name] = node.text
    return data


def _parse_time(value: Optional[str]) -> datetime:
    """Parse an EVTX ``SystemTime`` into a tz-aware UTC datetime.

    Windows already records these in UTC, so this is mostly format wrangling:
    ``fromisoformat`` historically dislikes a trailing ``Z`` and EVTX uses
    100-nanosecond precision (7 fractional digits) which exceeds Python's 6, so
    we trim. Anything we still can't parse falls back to "now" with a warning
    rather than dropping the event -- a slightly-wrong timestamp beats data loss
    at the ingestion layer.
    """
    if not value:
        return datetime.now(timezone.utc)

    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Trim sub-second precision to at most 6 digits (microseconds).
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        logger.warning("Unrecognized EVTX SystemTime %r; using current time", value)
        return datetime.now(timezone.utc)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Event ID -> normalized Event mapping.
# ---------------------------------------------------------------------------

def _clean(value: Optional[str]) -> Optional[str]:
    """Normalize EVTX placeholder values to ``None``.

    Windows writes ``"-"`` (and occasionally an empty string) when a field
    doesn't apply -- e.g. IpAddress on a local logon. Collapsing those to
    ``None`` keeps the normalized schema honest: absent means absent.
    """
    if value in (None, "-", ""):
        return None
    return value


def _logon_metadata(data: dict[str, Optional[str]], *, include_failure: bool) -> dict:
    """Build the metadata dict shared by 4624/4625 logon events."""
    logon_type = data.get("LogonType")
    metadata = {
        "domain": data.get("TargetDomainName"),
        "logon_type": logon_type,
        "logon_type_name": _LOGON_TYPES.get(logon_type or ""),
        "workstation": data.get("WorkstationName"),
        "logon_process": data.get("LogonProcessName"),
        "auth_package": data.get("AuthenticationPackageName"),
    }
    if include_failure:
        # 4625 carries the failure reason as Status / SubStatus NTSTATUS codes.
        metadata["status"] = data.get("Status")
        metadata["sub_status"] = data.get("SubStatus")
        metadata["failure_reason"] = data.get("FailureReason")
    # Drop keys the record didn't actually provide, so metadata stays tidy.
    return {key: val for key, val in metadata.items() if val is not None}


def _build_event(
    *,
    event_id: str,
    data: dict[str, Optional[str]],
    host: Optional[str],
    timestamp: datetime,
    raw: str,
) -> Optional[Event]:
    """Construct the normalized Event for one mapped security Event ID."""
    source_ip = _clean(data.get("IpAddress"))

    if event_id == "4624":  # successful logon
        return Event(
            timestamp=timestamp,
            source_type=SourceType.WINDOWS_EVTX,
            action=Action.LOGIN,
            outcome=Outcome.SUCCESS,
            raw=raw,
            event_id="4624",
            host=host,
            user=_clean(data.get("TargetUserName")),
            source_ip=source_ip,
            metadata=_logon_metadata(data, include_failure=False),
        )

    if event_id == "4625":  # failed logon
        return Event(
            timestamp=timestamp,
            source_type=SourceType.WINDOWS_EVTX,
            action=Action.LOGIN,
            outcome=Outcome.FAILURE,
            raw=raw,
            event_id="4625",
            host=host,
            user=_clean(data.get("TargetUserName")),
            source_ip=source_ip,
            metadata=_logon_metadata(data, include_failure=True),
        )

    if event_id == "4672":  # special privileges assigned to new logon
        # The subject here is the account that just received admin-equivalent
        # privileges -- a useful "who became powerful" signal.
        metadata = {
            "domain": data.get("SubjectDomainName"),
            "privileges": data.get("PrivilegeList"),
        }
        return Event(
            timestamp=timestamp,
            source_type=SourceType.WINDOWS_EVTX,
            action=Action.PRIVILEGE_ESCALATION,
            outcome=Outcome.SUCCESS,
            raw=raw,
            event_id="4672",
            host=host,
            user=_clean(data.get("SubjectUserName")),
            source_ip=source_ip,
            metadata={k: v for k, v in metadata.items() if v is not None},
        )

    if event_id == "4688":  # a new process was created
        metadata = {
            "new_process": data.get("NewProcessName"),
            "command_line": data.get("CommandLine"),
            "parent_process": data.get("ParentProcessName"),
            "domain": data.get("SubjectDomainName"),
        }
        return Event(
            timestamp=timestamp,
            source_type=SourceType.WINDOWS_EVTX,
            action=Action.PROCESS_CREATION,
            outcome=Outcome.UNKNOWN,  # creation has no pass/fail dimension
            raw=raw,
            event_id="4688",
            host=host,
            user=_clean(data.get("SubjectUserName")),
            source_ip=None,           # local process creation: no remote IP
            metadata={k: v for k, v in metadata.items() if v is not None},
        )

    return None  # defensive: _MAPPED_IDS gate should make this unreachable
