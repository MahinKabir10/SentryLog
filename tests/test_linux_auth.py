"""
Unit tests for the Linux auth.log parser.

These exercise the *line-level* parser (``LinuxAuthParser.parse_line``), which is
pure and therefore easy to assert on: each test feeds one realistic syslog line
and checks the normalized fields. The Windows parser isn't unit-tested here
because it needs a binary .evtx fixture; the README documents how to try it.

Runs two ways:
  * ``pytest`` (nicer output):           pytest tests/
  * plain Python (no pytest installed):  python tests/test_linux_auth.py
"""

from __future__ import annotations

import os
import sys

# Make the project root importable when run as a bare script from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentrylog.event import Action, Outcome, SourceType
from sentrylog.parsers.base import UnparseableLine
from sentrylog.parsers.linux_auth import LinuxAuthParser

# Fix the year so timestamp assertions are deterministic regardless of "now".
PARSER = LinuxAuthParser(assume_year=2025)


def test_accepted_password():
    ev = PARSER.parse_line(
        "May 27 08:14:02 ubuntu-web-01 sshd[2025]: "
        "Accepted password for deploy from 203.0.113.42 port 51234 ssh2"
    )
    assert ev is not None
    assert ev.source_type is SourceType.LINUX_AUTH
    assert ev.action is Action.LOGIN
    assert ev.outcome is Outcome.SUCCESS
    assert ev.user == "deploy"
    assert ev.source_ip == "203.0.113.42"
    assert ev.event_id == "ssh_login_accepted"
    assert ev.metadata["auth_method"] == "password"
    # The strict Event contract: timestamp is tz-aware UTC.
    assert ev.timestamp.tzinfo is not None
    assert ev.timestamp.utcoffset().total_seconds() == 0


def test_accepted_publickey_method_is_captured():
    ev = PARSER.parse_line(
        "May 27 08:15:48 ubuntu-web-01 sshd[2031]: "
        "Accepted publickey for admin from 198.51.100.9 port 49002 ssh2: RSA SHA256:abc"
    )
    assert ev.outcome is Outcome.SUCCESS
    assert ev.user == "admin"
    assert ev.metadata["auth_method"] == "publickey"


def test_failed_password_root():
    ev = PARSER.parse_line(
        "May 27 08:16:10 ubuntu-web-01 sshd[2044]: "
        "Failed password for root from 45.155.205.233 port 40110 ssh2"
    )
    assert ev.action is Action.LOGIN
    assert ev.outcome is Outcome.FAILURE
    assert ev.user == "root"
    assert ev.source_ip == "45.155.205.233"
    assert ev.event_id == "ssh_login_failed"
    assert "invalid_user" not in ev.metadata


def test_failed_password_invalid_user_sets_flag():
    ev = PARSER.parse_line(
        "May 27 08:16:20 ubuntu-web-01 sshd[2050]: "
        "Failed password for invalid user oracle from 45.155.205.233 port 40190 ssh2"
    )
    assert ev.outcome is Outcome.FAILURE
    assert ev.user == "oracle"
    assert ev.metadata.get("invalid_user") is True


def test_standalone_invalid_user():
    ev = PARSER.parse_line(
        "May 27 08:16:20 ubuntu-web-01 sshd[2050]: "
        "Invalid user oracle from 45.155.205.233 port 40190"
    )
    assert ev.outcome is Outcome.FAILURE
    assert ev.event_id == "ssh_invalid_user"
    assert ev.user == "oracle"
    assert ev.source_ip == "45.155.205.233"
    assert ev.metadata.get("invalid_user") is True


def test_sudo_success():
    ev = PARSER.parse_line(
        "May 27 08:22:33 ubuntu-web-01 sudo:   deploy : TTY=pts/0 ; "
        "PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
    )
    assert ev.action is Action.PRIVILEGE_ESCALATION
    assert ev.outcome is Outcome.SUCCESS
    assert ev.user == "deploy"
    assert ev.metadata["target_user"] == "root"
    assert ev.metadata["command"] == "/usr/bin/systemctl restart nginx"
    # sudo is local: no remote IP.
    assert ev.source_ip is None


def test_sudo_failure_not_in_sudoers():
    ev = PARSER.parse_line(
        "May 27 08:23:01 ubuntu-web-01 sudo:   intern : user NOT in sudoers ; "
        "TTY=pts/1 ; PWD=/home/intern ; USER=root ; COMMAND=/usr/bin/apt update"
    )
    assert ev.action is Action.PRIVILEGE_ESCALATION
    assert ev.outcome is Outcome.FAILURE
    assert ev.user == "intern"
    assert ev.metadata["reason"] == "user NOT in sudoers"


def test_unmodeled_line_returns_none():
    # Valid syslog skeleton, but a program/message we don't model -> None (skip).
    ev = PARSER.parse_line(
        "May 27 08:30:00 ubuntu-web-01 systemd[1]: Started Session 42 of user deploy."
    )
    assert ev is None


def test_malformed_line_raises():
    # Doesn't match the syslog skeleton at all -> UnparseableLine (an error).
    try:
        PARSER.parse_line("this is not a syslog line at all")
    except UnparseableLine:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected UnparseableLine for malformed input")


def test_sample_file_counts():
    # End-to-end over the shipped sample: verify the parsed/skipped/error split.
    here = os.path.dirname(os.path.abspath(__file__))
    sample = os.path.join(here, "..", "sample_logs", "auth.log")
    result = LinuxAuthParser(assume_year=2025).parse_file(sample)
    assert result.stats.parsed == 12
    assert result.stats.skipped == 3   # CRON, sshd disconnect, systemd
    assert result.stats.errors == 1    # the deliberately malformed line
    failures = sum(1 for e in result.events if e.outcome is Outcome.FAILURE)
    successes = sum(1 for e in result.events if e.outcome is Outcome.SUCCESS)
    assert failures == 8
    assert successes == 4


def _run_all() -> int:
    """Tiny runner so the file works without pytest installed."""
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Exception as exc:  # noqa: BLE001 - this IS the test harness
            failures += 1
            print(f"FAIL {test.__name__}: {exc!r}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
