"""
sentrylog.detection.compromise
==============================

The "it worked" rule: failed logins from an IP **followed by a success from
that same IP** within a time window -- credential stuffing / brute forcing
that landed. This is the escalation path from the brute-force rule: that one
says *someone is trying*; this one says *someone got in*.

Why this is always CRITICAL: severity is confidence x impact, and this pattern
maxes both. The failure prefix rules out an ordinary login (high confidence
the success was earned by guessing), and a successful authentication from an
attacking IP is realized impact -- an active session on your box. It is the
one alert in the default set that should page a human immediately, and
diluting the tier that pages people is how pages get ignored.

Mechanics:

* Per-IP deque of recent failures, evicted past ``window_seconds`` -- same
  sliding-window machinery as the brute-force rule.
* On a successful login from an IP with >= ``min_failures`` recent failures,
  emit the alert with the full evidence chain (the failures + the landing
  success) and clear that IP's buffer, so one break-in yields one alert. The
  buffer is only cleared on *firing*: a success with too few prior failures
  neither fires nor erases the evidence, because the attacker's next attempt
  should still see the history.
* ``min_failures`` defaults to 3 -- deliberately *below* the brute-force
  threshold of 5. A success after even a few failures deserves scrutiny; the
  attacker who guesses right on attempt four should not escape both rules.
* ``window_seconds`` defaults to 600 (10 min) -- wider than the brute-force
  window because the interesting gap here is failures-to-success, and tools
  often pause between a successful guess and the actual login.

The success does not need to be the same *user* as the failures: a spray that
lands on any account from the same IP is the same incident. When the users do
match, the description says so -- that detail raises analyst confidence.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, Iterator

from sentrylog.detection.alert import Alert, Severity
from sentrylog.detection.base import Rule
from sentrylog.event import Action, Event, Outcome


class CompromiseRule(Rule):
    """Failed-then-successful login correlation per source IP."""

    name = "compromise"

    def __init__(self, min_failures: int = 3, window_seconds: int = 600) -> None:
        if min_failures < 1:
            raise ValueError(f"min_failures must be >= 1, got {min_failures}")
        if window_seconds < 1:
            raise ValueError(f"window_seconds must be >= 1, got {window_seconds}")
        self.min_failures = min_failures
        self.window_seconds = window_seconds

    def analyze(self, events: Iterable[Event]) -> Iterator[Alert]:
        failures: Dict[str, Deque[Event]] = defaultdict(deque)

        for event in events:
            if event.action is not Action.LOGIN or not event.source_ip:
                continue
            ip = event.source_ip
            window = failures[ip]

            # Slide the window relative to *this* event's time.
            while window and (
                (event.timestamp - window[0].timestamp).total_seconds()
                > self.window_seconds
            ):
                window.popleft()

            if event.outcome is Outcome.FAILURE:
                window.append(event)
            elif event.outcome is Outcome.SUCCESS:
                if len(window) >= self.min_failures:
                    yield self._build_alert(list(window), event)
                    window.clear()  # one break-in, one alert

    def _build_alert(self, fails: list[Event], success: Event) -> Alert:
        span = int((success.timestamp - fails[0].timestamp).total_seconds())
        targeted = sorted({e.user for e in fails if e.user})
        invalid = sum(1 for e in fails if e.metadata.get("invalid_user"))

        description = (
            f"{len(fails)} failed logins from {success.source_ip} followed by "
            f"a SUCCESSFUL login as '{success.user}' {span}s after the first "
            "failure -- credentials likely compromised; treat the session as "
            "hostile."
        )
        if success.user in targeted:
            description += (
                f" The compromised account '{success.user}' was among the "
                "brute-forced targets."
            )
        if invalid:
            description += (
                f" {invalid} of the failures probed non-existent accounts "
                "(enumeration)."
            )

        return Alert(
            rule_name=self.name,
            severity=Severity.CRITICAL,
            timestamp=success.timestamp,
            description=description,
            source_ip=success.source_ip,
            user=success.user,
            host=success.host,
            matched_events=[*fails, success],
        )
