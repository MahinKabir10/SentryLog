"""
sentrylog.parsers.linux_auth
============================

Parser for Linux ``/var/log/auth.log`` style files (Debian/Ubuntu). It turns
the free-text syslog lines produced by ``sshd`` and ``sudo`` into normalized
:class:`~sentrylog.event.Event` objects.

Why regex with **named groups**?
--------------------------------
auth.log is semi-structured: a fixed syslog "skeleton" (timestamp, host,
program) wrapped around a free-text message that differs per program. Regex is
the right tool for line-oriented text like this, and *named* groups
(``(?P<user>...)``) keep the extraction self-documenting -- ``m.group("user")``
reads far better than ``m.group(3)`` and survives edits to the pattern.

Parsing strategy (two layers):
1. Match the syslog **skeleton** once to peel off timestamp / host / program /
   message. A line that fails this is genuinely malformed -> raise
   :class:`UnparseableLine` (counted as an error, logged, skipped -- never a
   crash).
2. Dispatch on the *program* (``sshd`` / ``sudo``) and match the message
   against program-specific patterns. A skeleton-valid line from a program we
   don't model (CRON, systemd, ...) returns ``None`` -> counted as *skipped*,
   not an error. This keeps the warning channel meaningful instead of screaming
   about every routine cron line.

Timestamp caveat (the #1 thing to call out in an interview):
Traditional syslog timestamps have **no year and no timezone** ("May 27
08:14:02"). We therefore (a) assume the line is in **UTC** and attach that
tzinfo to satisfy the strict ``Event`` contract, and (b) assume the current
year, with a small guard that rolls back to the previous year if the resulting
date would be in the future (the classic Dec-logs-read-in-Jan problem). In
production you would instead derive the host timezone and use the file's
metadata or RFC 5424 timestamps. The assumption is explicit and lives in one
place (:meth:`LinuxAuthParser._build_timestamp`).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from sentrylog.event import Action, Event, Outcome, SourceType
from sentrylog.parsers.base import ParseResult, ParseStats, UnparseableLine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Layer 1: the syslog skeleton.
#
# Example line:
#   May 27 08:14:02 ubuntu-web-01 sshd[2025]: Accepted password for deploy ...
#   └──month┘ └day┘ └──time──┘ └──host───┘ └prog┘└pid┘  └────── message ──────┘
#
# Notes on the choices:
#   * day uses \s+ before it so single-digit days ("May  7", space-padded) work.
#   * program allows word chars plus . / - to cover names like "postfix/smtpd".
#   * the PID in [..] is optional -- "sudo:" has no pid, "sshd[123]:" does.
# ---------------------------------------------------------------------------
_SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"          # 'May'
    r"(?P<day>\d{1,2})\s+"                    # '27' (or ' 7', space-padded)
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"         # '08:14:02'
    r"(?P<host>\S+)\s+"                       # 'ubuntu-web-01'
    r"(?P<program>[\w./-]+?)"                 # 'sshd' / 'sudo' / 'CRON'
    r"(?:\[(?P<pid>\d+)\])?"                  # optional '[2025]'
    r":\s+"                                   # the ': ' separator
    r"(?P<message>.*)$"                       # the program-specific message
)

# ---------------------------------------------------------------------------
# Layer 2: program-specific message patterns.
# ---------------------------------------------------------------------------

# sshd success: "Accepted password for deploy from 203.0.113.42 port 51234 ssh2"
# Also matches "Accepted publickey for ...": the auth method is captured, not
# hard-coded, so password / publickey / keyboard-interactive all work. No '$'
# anchor because some lines have a trailing fingerprint ("ssh2: RSA SHA256:..").
_SSH_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\w+) for (?P<user>\S+) "
    r"from (?P<source_ip>\S+) port (?P<port>\d+)"
)

# sshd failure: "Failed password for root from 45.155.205.233 port 40110 ssh2"
# The optional "(invalid user )" branch captures the very common brute-force
# variant "Failed password for invalid user oracle from ..." in one pattern --
# we set an invalid_user flag in metadata when it fires.
_SSH_FAILED_RE = re.compile(
    r"^Failed (?P<method>\w+) for (?:(?P<invalid>invalid user) )?(?P<user>\S+) "
    r"from (?P<source_ip>\S+) port (?P<port>\d+)"
)

# sshd standalone invalid-user notice: "Invalid user oracle from 45.. port 40190"
# sshd logs this *separately* from (and usually just before) the Failed password
# line, so we model it as its own event -- it is a strong recon signal on its own.
_SSH_INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<source_ip>\S+)(?: port (?P<port>\d+))?"
)

# sudo success: "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/..."
# The invoking user is before the colon; USER= is the *target* identity the
# command runs as (usually root). We keep both -- the privilege boundary being
# crossed is exactly what a Phase-2 rule cares about.
_SUDO_OK_RE = re.compile(
    r"^(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)$"
)

# sudo failure: "intern : user NOT in sudoers ; TTY=pts/1 ; ... ; COMMAND=/..."
# or "alice : 3 incorrect password attempts ; ...". The reason sits between the
# colon and the first TTY=; the trailing fields are optional and best-effort.
_SUDO_FAIL_RE = re.compile(
    r"^(?P<user>\S+)\s*:\s*"
    r"(?P<reason>user NOT in sudoers|\d+ incorrect password attempts?|"
    r"command not allowed|a password is required)\b"
    r"(?:\s*;\s*TTY=(?P<tty>\S+))?"
    r"(?:\s*;\s*PWD=(?P<pwd>\S+))?"
    r"(?:\s*;\s*USER=(?P<target_user>\S+))?"
    r"(?:\s*;\s*COMMAND=(?P<command>.*))?"
)

# Month abbreviation -> month number. A plain dict is clearer (and faster) than
# coaxing strptime into parsing a yearless, locale-sensitive timestamp.
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class LinuxAuthParser:
    """Stateless line parser + stateful file driver for Linux auth logs.

    :meth:`parse_line` is pure (input line -> Event / None / raises) which makes
    it trivial to unit-test. :meth:`parse_file` owns the I/O loop and the
    :class:`ParseStats` counters. Create a fresh instance per file so stats
    never bleed between runs.
    """

    def __init__(self, assume_year: Optional[int] = None) -> None:
        """
        Parameters
        ----------
        assume_year:
            Force the year used for yearless syslog timestamps (handy for
            deterministic tests). When ``None`` we use the current UTC year and
            apply the future-date rollover guard described in the module
            docstring.
        """
        self.assume_year = assume_year
        # Capture "now" once so a long file parses against a stable reference.
        self._now = datetime.now(timezone.utc)
        self._default_year = self._now.year

    # -- public API ------------------------------------------------------

    def parse_file(self, path) -> ParseResult:
        """Parse a whole auth.log file into a :class:`ParseResult`.

        Reads UTF-8 with ``errors="replace"`` so a stray non-UTF-8 byte can't
        abort the run -- robustness over purity for log ingestion. Blank lines
        are ignored entirely (not even counted), matching how an analyst thinks
        about a log file.
        """
        result = ParseResult(source_type=SourceType.LINUX_AUTH)
        stats: ParseStats = result.stats

        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                if not raw_line.strip():
                    continue  # blank line: not input, don't count it
                stats.total += 1
                try:
                    event = self.parse_line(raw_line)
                except UnparseableLine:
                    # Malformed beyond the syslog skeleton: log and carry on.
                    stats.errors += 1
                    logger.warning(
                        "Unparseable auth line skipped: %s", raw_line.strip()
                    )
                    continue
                if event is None:
                    # Skeleton was fine, but it's a program/message we don't
                    # model (CRON, systemd, an sshd "Received disconnect", ...).
                    stats.skipped += 1
                    logger.debug("Ignored non-auth line: %s", raw_line.strip())
                    continue
                stats.parsed += 1
                result.events.append(event)

        return result

    def parse_line(self, line: str) -> Optional[Event]:
        """Parse a single line.

        Returns an :class:`Event` for a recognized auth event, ``None`` for a
        skeleton-valid but unmodeled line, and raises :class:`UnparseableLine`
        for input that doesn't even look like syslog.
        """
        line = line.rstrip("\n")

        skeleton = _SYSLOG_RE.match(line)
        if not skeleton:
            raise UnparseableLine(line)

        program = skeleton.group("program")
        message = skeleton.group("message")
        host = skeleton.group("host")
        timestamp = self._build_timestamp(
            skeleton.group("month"),
            skeleton.group("day"),
            skeleton.group("time"),
        )

        # Dispatch on the emitting program. Anything else is intentionally
        # unmodeled in Phase 1 (return None -> "skipped").
        if program == "sshd":
            return self._parse_sshd(message, host, timestamp, line)
        if program == "sudo":
            return self._parse_sudo(message, host, timestamp, line)
        return None

    # -- per-program handlers -------------------------------------------

    def _parse_sshd(
        self, message: str, host: str, ts: datetime, raw: str
    ) -> Optional[Event]:
        """Map an sshd message to an Event, or None if it's sshd noise."""
        m = _SSH_ACCEPTED_RE.match(message)
        if m:
            return Event(
                timestamp=ts,
                source_type=SourceType.LINUX_AUTH,
                action=Action.LOGIN,
                outcome=Outcome.SUCCESS,
                raw=raw,
                event_id="ssh_login_accepted",
                host=host,
                user=m.group("user"),
                source_ip=m.group("source_ip"),
                metadata={
                    "service": "sshd",
                    "auth_method": m.group("method"),
                    "port": m.group("port"),
                },
            )

        m = _SSH_FAILED_RE.match(message)
        if m:
            metadata = {
                "service": "sshd",
                "auth_method": m.group("method"),
                "port": m.group("port"),
            }
            # The "invalid user" branch fired: the account doesn't exist, which
            # is a useful enrichment for brute-force / user-enumeration rules.
            if m.group("invalid"):
                metadata["invalid_user"] = True
            return Event(
                timestamp=ts,
                source_type=SourceType.LINUX_AUTH,
                action=Action.LOGIN,
                outcome=Outcome.FAILURE,
                raw=raw,
                event_id="ssh_login_failed",
                host=host,
                user=m.group("user"),
                source_ip=m.group("source_ip"),
                metadata=metadata,
            )

        m = _SSH_INVALID_USER_RE.match(message)
        if m:
            metadata = {"service": "sshd", "invalid_user": True}
            if m.group("port"):
                metadata["port"] = m.group("port")
            return Event(
                timestamp=ts,
                source_type=SourceType.LINUX_AUTH,
                action=Action.LOGIN,
                outcome=Outcome.FAILURE,
                raw=raw,
                event_id="ssh_invalid_user",
                host=host,
                user=m.group("user"),
                source_ip=m.group("source_ip"),
                metadata=metadata,
            )

        # Recognized program, unmodeled message (e.g. "Received disconnect").
        return None

    def _parse_sudo(
        self, message: str, host: str, ts: datetime, raw: str
    ) -> Optional[Event]:
        """Map a sudo message to an Event, or None if unrecognized."""
        m = _SUDO_OK_RE.match(message)
        if m:
            return Event(
                timestamp=ts,
                source_type=SourceType.LINUX_AUTH,
                action=Action.PRIVILEGE_ESCALATION,
                outcome=Outcome.SUCCESS,
                raw=raw,
                event_id="sudo_command",
                host=host,
                user=m.group("user"),            # the invoking (real) user
                source_ip=None,                  # sudo is local; no remote IP
                metadata={
                    "service": "sudo",
                    "target_user": m.group("target_user"),  # runs AS this user
                    "command": m.group("command"),
                    "tty": m.group("tty"),
                    "pwd": m.group("pwd"),
                },
            )

        m = _SUDO_FAIL_RE.match(message)
        if m:
            metadata = {"service": "sudo", "reason": m.group("reason")}
            # The trailing TTY/USER/COMMAND fields are optional on failure lines;
            # include whatever sudo happened to log.
            for key in ("tty", "target_user", "command"):
                value = m.group(key)
                if value:
                    metadata[key] = value
            return Event(
                timestamp=ts,
                source_type=SourceType.LINUX_AUTH,
                action=Action.PRIVILEGE_ESCALATION,
                outcome=Outcome.FAILURE,
                raw=raw,
                event_id="sudo_failed",
                host=host,
                user=m.group("user"),
                source_ip=None,
                metadata=metadata,
            )

        return None

    # -- helpers ---------------------------------------------------------

    def _build_timestamp(self, month: str, day: str, time_str: str) -> datetime:
        """Turn a yearless syslog timestamp into a tz-aware UTC datetime.

        See the module docstring for the full rationale. Briefly: attach UTC
        (the strict Event contract demands tz-awareness and the parser is the
        only layer that knows the convention), assume the current year, and if
        that lands more than a day in the future, treat it as last year's log.
        """
        year = self.assume_year if self.assume_year is not None else self._default_year
        hour, minute, second = (int(part) for part in time_str.split(":"))
        stamp = datetime(
            year, _MONTHS[month], int(day), hour, minute, second,
            tzinfo=timezone.utc,
        )
        # Rollover guard: only applied when we *inferred* the year. A log line
        # dated in the future almost certainly came from the previous calendar
        # year (e.g. a December line first read in January).
        if self.assume_year is None and stamp - self._now > timedelta(days=1):
            stamp = stamp.replace(year=year - 1)
        return stamp


def parse_file(path) -> ParseResult:
    """Module-level convenience wrapper used by the CLI.

    A fresh :class:`LinuxAuthParser` per call keeps the stats and the captured
    "now" isolated between files.
    """
    return LinuxAuthParser().parse_file(Path(path))
