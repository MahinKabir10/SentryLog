"""
sentrylog.event
===============

The *normalized event model* for SentryLog.

Every log source (Linux ``auth.log``, Windows ``.evtx``, and anything we add in
later phases) is parsed into exactly one type: :class:`Event`. Detection logic
in Phase 2 will only ever look at :class:`Event` objects -- never at raw log
formats. That separation is the entire point of a SIEM's normalization layer:
you write a parser once per source, and every downstream rule, dashboard, or
alert works across *all* sources for free.

Design goals for this module (these are the things to defend in an interview):

* **Strict at the boundary.** ``timestamp`` must be timezone-aware UTC;
  ``source_type``, ``action`` and ``outcome`` are constrained to small,
  controlled vocabularies (enums). Bad data fails loudly *here*, where it
  enters the system, instead of silently poisoning a correlation rule later.
* **Source-native vs. normalized.** ``event_id`` keeps the *source's own*
  identifier (e.g. Windows "4625"); ``action`` is the *normalized* category a
  rule matches on without caring which OS produced it. Keeping the two separate
  is what lets a single Phase-2 rule -- "many failed logins in a short window"
  -- fire on an SSH brute force and an RDP brute force alike.
* **Lossless.** The original ``raw`` text and a free-form ``metadata`` dict are
  always retained, so an analyst can always pivot back to ground truth.
* **Serializable.** ``to_dict()`` / ``to_json()`` give a stable, JSON-friendly
  shape the CLI prints today and a storage backend can persist tomorrow.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class SourceType(str, Enum):
    """Which kind of log a normalized event came from.

    We inherit from ``str`` (a "string enum") so the member compares and
    serializes exactly like its underlying value -- ``SourceType.LINUX_AUTH ==
    "linux_auth"`` is ``True`` and ``json.dumps`` emits the plain string. That
    keeps table cells and JSON output clean without extra conversion code.
    """

    LINUX_AUTH = "linux_auth"
    WINDOWS_EVTX = "windows_evtx"


class Outcome(str, Enum):
    """Normalized result of the action.

    ``UNKNOWN`` is a deliberate, first-class value -- not an error sentinel.
    Some events genuinely have no success/failure dimension (e.g. a Windows
    4688 "a new process was created" record simply *happened*), and stating
    that explicitly is more honest than guessing ``SUCCESS``.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class Action(str, Enum):
    """Normalized, cross-platform action vocabulary.

    This is intentionally a *small* controlled set. A larger free-text field
    would be easier for parsers but far harder for detection: rules want to
    match ``action == Action.LOGIN`` regardless of whether the login arrived
    over SSH or RDP. ``OTHER`` is the escape hatch so a parser is never forced
    to lie when it meets something outside the vocabulary.
    """

    LOGIN = "login"                          # an authentication attempt
    LOGOUT = "logout"                        # a session teardown
    PRIVILEGE_ESCALATION = "privilege_escalation"  # sudo, Win 4672, runas
    PROCESS_CREATION = "process_creation"    # Win 4688, execve-style events
    OTHER = "other"                          # recognized but uncategorized


@dataclass
class Event:
    """A single normalized security event.

    All parsers emit this and nothing else. Required fields come first (no
    defaults); everything a given source might not provide is ``Optional`` and
    defaults to ``None`` so partial records are representable without hacks.

    Parameters
    ----------
    timestamp:
        When the event occurred, as a **timezone-aware** :class:`datetime`.
        ``__post_init__`` rejects naive datetimes and converts to UTC, so every
        ``Event.timestamp`` in the system is directly comparable. Localizing the
        time is each *parser's* job, because only the parser knows the source's
        timezone conventions (syslog, for instance, carries no offset at all).
    source_type:
        Which parser produced this event (:class:`SourceType`).
    action:
        Normalized cross-platform category (:class:`Action`).
    outcome:
        Normalized result (:class:`Outcome`).
    raw:
        The original, unmodified line (Linux) or record XML (Windows). Kept
        verbatim so an analyst can always audit the source of truth.
    event_id:
        The *source-native* identifier. Windows: the numeric Event ID as a
        string (``"4624"``). Linux: a stable synthetic mnemonic for the matched
        pattern (``"ssh_login_failed"``) -- syslog has no native IDs, so we mint
        one to give downstream rules a fixed key to pivot on.
    host:
        The machine the event was observed on (syslog hostname / EVTX Computer).
    user:
        The principal the event concerns (the account logging in, running sudo,
        etc.). ``None`` when the source does not provide one.
    source_ip:
        The remote IP when the action came over the network. ``None`` for local
        actions (e.g. an interactive sudo) or when the source omits it.
    metadata:
        Free-form dict for source-specific extras we want to keep but did not
        promote to a first-class field (auth method, logon type, command line,
        port, privilege list, ...). Defaults to an empty dict via
        ``default_factory`` so every Event gets its *own* dict (never a shared
        mutable default -- a classic Python footgun).
    """

    # --- required, normalized core --------------------------------------
    timestamp: datetime
    source_type: SourceType
    action: Action
    outcome: Outcome
    raw: str

    # --- optional, may be absent depending on the source ----------------
    event_id: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and normalize the inputs right after construction.

        Doing this in ``__post_init__`` means *no* invalid Event can exist:
        validation is part of construction, not an optional extra step a caller
        might forget. This is the "strict at the boundary" guarantee.
        """
        # Coerce the enum fields. Accepting plain strings here is an ergonomic
        # convenience for parsers (``outcome="failure"`` works), while still
        # guaranteeing the stored value is a valid enum member. An unknown
        # string raises ValueError -- exactly the loud failure we want.
        self.source_type = SourceType(self.source_type)
        self.action = Action(self.action)
        self.outcome = Outcome(self.outcome)

        # Strict timestamp contract: must be a tz-aware datetime, stored in UTC.
        if not isinstance(self.timestamp, datetime):
            raise TypeError(
                f"Event.timestamp must be a datetime, got {type(self.timestamp)!r}"
            )
        if self.timestamp.tzinfo is None:
            # A naive datetime is ambiguous (which timezone?). We refuse to
            # guess; the parser must attach tzinfo. This prevents silent
            # off-by-hours bugs in time-window correlation later.
            raise ValueError(
                "Event.timestamp must be timezone-aware. "
                "Parsers are responsible for localizing source times to UTC."
            )
        self.timestamp = self.timestamp.astimezone(timezone.utc)

        # metadata must be a dict so downstream code can rely on the shape.
        if not isinstance(self.metadata, dict):
            raise TypeError(
                f"Event.metadata must be a dict, got {type(self.metadata)!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a stable, JSON-friendly dict.

        Field order is fixed and the enums are flattened to their string
        values. Anything that reads SentryLog output (the CLI today, a database
        or SIEM forwarder tomorrow) can depend on this shape.
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_type": self.source_type.value,
            "event_id": self.event_id,
            "host": self.host,
            "user": self.user,
            "source_ip": self.source_ip,
            "action": self.action.value,
            "outcome": self.outcome.value,
            "raw": self.raw,
            "metadata": dict(self.metadata),
        }

    def to_json(self) -> str:
        """Serialize the event to a one-line JSON string (NDJSON-friendly)."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def summary(self) -> str:
        """A compact, human-readable one-liner for terminal display."""
        who = self.user or "-"
        where = f" from {self.source_ip}" if self.source_ip else ""
        return (
            f"{self.timestamp:%Y-%m-%d %H:%M:%S} "
            f"[{self.source_type.value}] {self.action.value}/{self.outcome.value} "
            f"user={who}{where} id={self.event_id or '-'}"
        )
