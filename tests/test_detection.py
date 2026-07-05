"""
Unit tests for the Phase 2 detection layer.

The events are built by hand rather than parsed from fixtures -- which is the
point: rules only ever see normalized Events, so a "Windows" event here is just
an Event with ``source_type=WINDOWS_EVTX`` and ``event_id="4625"``. Several
tests mix Linux and Windows events in one stream to prove a single rule fires
across both, i.e. the normalization layer doing its job.

Runs two ways (same as the Phase 1 suite):
  * ``pytest`` (nicer output):           pytest tests/
  * plain Python (no pytest installed):  python tests/test_detection.py
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

# Make the project root importable when run as a bare script from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentrylog.detection import (
    Alert,
    BruteForceRule,
    CompromiseRule,
    PrivilegeEscalationRule,
    Severity,
    default_rules,
    run_rules,
)
from sentrylog.event import Action, Event, Outcome, SourceType
from sentrylog.parsers.linux_auth import LinuxAuthParser
from sentrylog.parsers.windows_evtx import _build_event

BASE = datetime(2025, 5, 27, 12, 0, 0, tzinfo=timezone.utc)


def ev(
    offset_s: float = 0,
    *,
    action: Action = Action.LOGIN,
    outcome: Outcome = Outcome.FAILURE,
    ip: str | None = "203.0.113.99",
    user: str | None = "root",
    source: SourceType = SourceType.LINUX_AUTH,
    event_id: str | None = "ssh_login_failed",
    host: str = "host-01",
    metadata: dict | None = None,
) -> Event:
    """Build a synthetic normalized Event ``offset_s`` seconds after BASE."""
    return Event(
        timestamp=BASE + timedelta(seconds=offset_s),
        source_type=source,
        action=action,
        outcome=outcome,
        raw="synthetic test event",
        event_id=event_id,
        host=host,
        user=user,
        source_ip=ip,
        metadata=metadata if metadata is not None else {},
    )


# ---------------------------------------------------------------------------
# Brute force
# ---------------------------------------------------------------------------

def test_bruteforce_below_threshold_stays_silent():
    # threshold - 1 rapid failures: a human mistyping, not an attack.
    events = [ev(i * 2) for i in range(4)]
    alerts = list(BruteForceRule(threshold=5, window_seconds=60).analyze(events))
    assert alerts == []


def test_bruteforce_fires_at_threshold():
    events = [ev(i * 5) for i in range(5)]  # 5 failures across 20s
    alerts = list(BruteForceRule(threshold=5, window_seconds=60).analyze(events))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "brute_force"
    assert alert.severity is Severity.MEDIUM  # one user, threshold volume
    assert alert.source_ip == "203.0.113.99"
    assert alert.user == "root"               # single target -> named
    assert len(alert.matched_events) == 5
    # Trigger convention: alert timestamp = last matched event.
    assert alert.timestamp == events[-1].timestamp


def test_bruteforce_window_boundary_inclusive():
    # First and fifth failure exactly window_seconds apart: fires (span <= Y).
    events = [ev(s) for s in (0, 15, 30, 45, 60)]
    alerts = list(BruteForceRule(threshold=5, window_seconds=60).analyze(events))
    assert len(alerts) == 1


def test_bruteforce_just_outside_window_stays_silent():
    # Same five failures, but the last lands one second past the window.
    events = [ev(s) for s in (0, 15, 30, 45, 61)]
    alerts = list(BruteForceRule(threshold=5, window_seconds=60).analyze(events))
    assert alerts == []


def test_bruteforce_one_alert_per_burst():
    # 12 rapid failures = ONE alert carrying all 12, not 8 alerts.
    events = [ev(i * 3) for i in range(12)]
    alerts = list(BruteForceRule(threshold=5, window_seconds=60).analyze(events))
    assert len(alerts) == 1
    assert len(alerts[0].matched_events) == 12


def test_bruteforce_two_separate_bursts_two_alerts():
    # Two bursts separated by a gap far longer than the window.
    burst_one = [ev(i * 5) for i in range(5)]
    burst_two = [ev(500 + i * 5) for i in range(5)]
    rule = BruteForceRule(threshold=5, window_seconds=60)
    alerts = list(rule.analyze(burst_one + burst_two))
    assert len(alerts) == 2
    assert all(len(a.matched_events) == 5 for a in alerts)


def test_bruteforce_distributed_ips_do_not_aggregate():
    # 4 IPs x 3 failures each: no single IP crosses the threshold. A
    # distributed attack is real, but attributing it needs a different rule --
    # summing unrelated IPs would make this one fire on busy normal days.
    events = [
        ev(i * 2 + j, ip=f"198.51.100.{j}") for j in range(4) for i in range(3)
    ]
    alerts = list(BruteForceRule(threshold=5, window_seconds=60).analyze(events))
    assert alerts == []


def test_bruteforce_spray_escalates_to_high():
    users = ["alice", "bob", "carol", "dave", "erin"]
    events = [ev(i * 4, user=users[i]) for i in range(5)]
    alerts = list(BruteForceRule(threshold=5, window_seconds=60).analyze(events))
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.HIGH
    assert alerts[0].user is None  # no single honest value for a spray
    assert "spray" in alerts[0].description


def test_bruteforce_volume_escalates_to_high():
    # 15 failures against one user = 3x threshold -> determined attacker.
    events = [ev(i * 3) for i in range(15)]
    alerts = list(BruteForceRule(threshold=5, window_seconds=60).analyze(events))
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.HIGH


def test_bruteforce_fires_across_sources():
    # Three SSH failures and two RDP (4625) failures from the same IP: the
    # rule sees five normalized failures -- the cross-platform promise.
    events = [ev(i * 5) for i in range(3)] + [
        ev(
            20 + i * 5,
            source=SourceType.WINDOWS_EVTX,
            event_id="4625",
            host="WIN-DC01",
            metadata={"logon_type": "10", "logon_type_name": "RemoteInteractive"},
        )
        for i in range(2)
    ]
    alerts = list(BruteForceRule(threshold=5, window_seconds=60).analyze(events))
    assert len(alerts) == 1
    seen_sources = {e.source_type for e in alerts[0].matched_events}
    assert seen_sources == {SourceType.LINUX_AUTH, SourceType.WINDOWS_EVTX}


def test_bruteforce_ignores_failures_without_ip():
    events = [ev(i * 2, ip=None) for i in range(6)]
    alerts = list(BruteForceRule(threshold=5, window_seconds=60).analyze(events))
    assert alerts == []


# ---------------------------------------------------------------------------
# Privilege escalation
# ---------------------------------------------------------------------------

def test_privesc_sudo_failure_is_medium():
    event = ev(
        action=Action.PRIVILEGE_ESCALATION,
        outcome=Outcome.FAILURE,
        ip=None,
        user="intern",
        event_id="sudo_failed",
        metadata={"reason": "user NOT in sudoers", "command": "/usr/bin/apt update"},
    )
    alerts = list(PrivilegeEscalationRule().analyze([event]))
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.MEDIUM
    assert alerts[0].user == "intern"
    assert "user NOT in sudoers" in alerts[0].description


def test_privesc_sudo_success_aggregates_to_low():
    # Three sudo commands by one admin = ONE low audit alert, not three pages.
    events = [
        ev(
            i * 30,
            action=Action.PRIVILEGE_ESCALATION,
            outcome=Outcome.SUCCESS,
            ip=None,
            user="deploy",
            event_id="sudo_command",
            metadata={"command": f"/usr/bin/systemctl restart svc{i}"},
        )
        for i in range(3)
    ]
    alerts = list(PrivilegeEscalationRule().analyze(events))
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.LOW
    assert len(alerts[0].matched_events) == 3
    assert alerts[0].user == "deploy"


def test_privesc_4732_privileged_group_is_high():
    event = ev(
        action=Action.PRIVILEGE_ESCALATION,
        outcome=Outcome.SUCCESS,
        ip=None,
        user="Administrator",  # the actor
        source=SourceType.WINDOWS_EVTX,
        event_id="4732",
        host="WIN-DC01",
        metadata={"group": "Administrators", "member": "eve"},
    )
    alerts = list(PrivilegeEscalationRule().analyze([event]))
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.HIGH
    assert alerts[0].user == "eve"  # the beneficiary, not the actor


def test_privesc_4732_ordinary_group_is_medium():
    event = ev(
        action=Action.PRIVILEGE_ESCALATION,
        outcome=Outcome.SUCCESS,
        ip=None,
        user="Administrator",
        source=SourceType.WINDOWS_EVTX,
        event_id="4732",
        metadata={"group": "Marketing", "member": "eve"},
    )
    alerts = list(PrivilegeEscalationRule().analyze([event]))
    assert alerts[0].severity is Severity.MEDIUM


def test_privesc_4720_account_creation_is_medium():
    event = ev(
        action=Action.ACCOUNT_MANAGEMENT,
        outcome=Outcome.SUCCESS,
        ip=None,
        user="Administrator",
        source=SourceType.WINDOWS_EVTX,
        event_id="4720",
        metadata={"new_account": "svc-backup2"},
    )
    alerts = list(PrivilegeEscalationRule().analyze([event]))
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.MEDIUM
    assert alerts[0].user == "svc-backup2"
    assert "persistence" in alerts[0].description


# ---------------------------------------------------------------------------
# Compromise (failed logins followed by a success from the same IP)
# ---------------------------------------------------------------------------

def test_compromise_fires_on_failures_then_success():
    events = [ev(i * 10) for i in range(3)]
    events.append(ev(45, outcome=Outcome.SUCCESS, event_id="ssh_login_accepted"))
    alerts = list(CompromiseRule(min_failures=3, window_seconds=600).analyze(events))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity is Severity.CRITICAL
    assert alert.user == "root"                 # from the landing success
    assert len(alert.matched_events) == 4       # 3 failures + the success
    assert alert.matched_events[-1].outcome is Outcome.SUCCESS


def test_compromise_needs_min_failures():
    events = [ev(0), ev(10)]
    events.append(ev(20, outcome=Outcome.SUCCESS, event_id="ssh_login_accepted"))
    alerts = list(CompromiseRule(min_failures=3, window_seconds=600).analyze(events))
    assert alerts == []


def test_compromise_ignores_success_from_other_ip():
    events = [ev(i * 10) for i in range(3)]
    events.append(
        ev(45, outcome=Outcome.SUCCESS, ip="198.51.100.7", event_id="ssh_login_accepted")
    )
    alerts = list(CompromiseRule(min_failures=3, window_seconds=600).analyze(events))
    assert alerts == []


def test_compromise_success_before_failures_is_silent():
    # The pattern is directional: a success FOLLOWED BY failures is someone
    # logging in and then fat-fingering later -- not a compromise.
    events = [ev(0, outcome=Outcome.SUCCESS, event_id="ssh_login_accepted")]
    events += [ev(10 + i * 10) for i in range(3)]
    alerts = list(CompromiseRule(min_failures=3, window_seconds=600).analyze(events))
    assert alerts == []


def test_compromise_window_expiry():
    # Failures age out: a success 700s after the last failure sees an empty
    # window (window=600) and stays quiet.
    events = [ev(i * 10) for i in range(3)]
    events.append(ev(720, outcome=Outcome.SUCCESS, event_id="ssh_login_accepted"))
    alerts = list(CompromiseRule(min_failures=3, window_seconds=600).analyze(events))
    assert alerts == []


def test_compromise_fires_on_windows_rdp_stream():
    # Pure 4625/4624 stream: the same rule, zero Windows-specific code.
    fails = [
        ev(i * 10, source=SourceType.WINDOWS_EVTX, event_id="4625",
           user="administrator", host="WIN-SRV1")
        for i in range(3)
    ]
    landed = ev(40, source=SourceType.WINDOWS_EVTX, event_id="4624",
                outcome=Outcome.SUCCESS, user="administrator", host="WIN-SRV1")
    alerts = list(
        CompromiseRule(min_failures=3, window_seconds=600).analyze(fails + [landed])
    )
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.CRITICAL
    assert alerts[0].user == "administrator"


# ---------------------------------------------------------------------------
# Engine + Alert contract
# ---------------------------------------------------------------------------

def test_engine_sorts_unsorted_input():
    # Feed the compromise pattern in REVERSE order: run_rules must sort before
    # fan-out, so the rule still sees failures-then-success.
    events = [ev(i * 10) for i in range(3)]
    events.append(ev(45, outcome=Outcome.SUCCESS, event_id="ssh_login_accepted"))
    result = run_rules(list(reversed(events)), [CompromiseRule()])
    assert len(result.alerts) == 1
    assert result.events_analyzed == 4


def test_engine_reports_quiet_rules():
    # A rule that ran and found nothing must still appear (with a zero).
    result = run_rules([ev(0)], default_rules())
    assert result.rule_names == ["brute_force", "privilege_escalation", "compromise"]
    assert result.counts_by_rule() == {
        "brute_force": 0,
        "privilege_escalation": 0,
        "compromise": 0,
    }


def test_engine_orders_alerts_by_severity_then_time():
    # Build a stream producing a LOW (sudo success) and a CRITICAL
    # (compromise) where the LOW's timestamp is later: critical must come first.
    events = [ev(i * 10) for i in range(3)]
    events.append(ev(40, outcome=Outcome.SUCCESS, event_id="ssh_login_accepted"))
    events.append(
        ev(999, action=Action.PRIVILEGE_ESCALATION, outcome=Outcome.SUCCESS,
           ip=None, user="deploy", event_id="sudo_command",
           metadata={"command": "/bin/true"})
    )
    result = run_rules(events, default_rules())
    severities = [a.severity for a in result.alerts]
    assert severities == sorted(severities, key=lambda s: -s.rank)
    assert result.alerts[0].severity is Severity.CRITICAL


def test_alert_contract():
    # Strings coerce to the Severity enum (same ergonomics as Event's enums).
    alert = Alert(
        rule_name="x", severity="high", timestamp=BASE, description="d"
    )
    assert alert.severity is Severity.HIGH
    # Rank ordering drives triage sort and --min-severity filtering.
    assert (
        Severity.LOW.rank < Severity.MEDIUM.rank
        < Severity.HIGH.rank < Severity.CRITICAL.rank
    )
    # Naive timestamps violate the contract, exactly like Event.
    try:
        Alert(rule_name="x", severity="low",
              timestamp=datetime(2025, 1, 1), description="d")
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for a naive timestamp")


# ---------------------------------------------------------------------------
# Windows mapping for the new Phase 2 event IDs (4720/4732). _build_event is
# pure (dict in, Event out), so no binary .evtx fixture is needed.
# ---------------------------------------------------------------------------

def test_windows_4720_maps_to_account_management():
    event = _build_event(
        event_id="4720",
        data={"SubjectUserName": "Administrator", "TargetUserName": "svc-x",
              "TargetDomainName": "CORP"},
        host="WIN-DC01",
        timestamp=BASE,
        raw="<xml/>",
    )
    assert event.action is Action.ACCOUNT_MANAGEMENT
    assert event.outcome is Outcome.SUCCESS
    assert event.user == "Administrator"          # the actor
    assert event.metadata["new_account"] == "svc-x"


def test_windows_4732_maps_to_privilege_escalation():
    event = _build_event(
        event_id="4732",
        data={"SubjectUserName": "Administrator", "TargetUserName": "Administrators",
              "MemberName": "CN=eve,CN=Users,DC=corp"},
        host="WIN-DC01",
        timestamp=BASE,
        raw="<xml/>",
    )
    assert event.action is Action.PRIVILEGE_ESCALATION
    assert event.metadata["group"] == "Administrators"
    assert event.metadata["member"] == "CN=eve,CN=Users,DC=corp"


# ---------------------------------------------------------------------------
# End to end over the shipped sample
# ---------------------------------------------------------------------------

def test_sample_log_fires_every_rule():
    here = os.path.dirname(os.path.abspath(__file__))
    sample = os.path.join(here, "..", "samples", "auth.log")
    parsed = LinuxAuthParser(assume_year=2025).parse_file(sample)
    result = run_rules(parsed.events, default_rules())

    assert result.counts_by_rule() == {
        "brute_force": 1,            # 45.155.205.233's 12-failure spray
        "privilege_escalation": 2,   # intern's denial + deploy's audit trail
        "compromise": 1,             # 192.0.2.146: 3 failures then a success
    }
    assert result.counts_by_severity() == {
        "critical": 1, "high": 1, "medium": 1, "low": 1,
    }
    # The critical alert names the account the attacker landed on.
    critical = result.alerts[0]
    assert critical.rule_name == "compromise"
    assert critical.source_ip == "192.0.2.146"
    assert critical.user == "deploy"


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
