"""
sentrylog.detection.brute_force
===============================

Brute-force detection: X failed logins from one source IP within a Y-second
**sliding** window. Because it matches on the normalized shape
(``action=login, outcome=failure`` + ``source_ip``), the same rule fires on an
SSH spray against auth.log and an RDP spray in a Windows 4625 stream -- which
is the entire argument for the normalization layer.

Design decisions worth defending:

**Sliding window, not fixed buckets.** A tumbling window with a boundary at
08:16:00 misses a burst spanning 08:15:58-08:16:03 -- and attackers don't align
to your clock. The sliding window is implemented as a per-IP deque of recent
failures: on each new failure, evict everything older than ``window_seconds``
and check the count. O(1) amortized per event, O(window) memory per IP.

**Boundary is inclusive.** Five failures whose first and last are exactly 60
seconds apart *do* fire with a 60-second window (``span <= Y``). Documented and
tested, because off-by-one at the boundary is exactly the kind of thing a rule
review asks about.

**One alert per burst, not per event.** After the threshold trips, the rule
keeps *accumulating* the burst and emits a single alert when the burst ends (a
gap longer than the window, or end of stream). The alternative -- an alert per
failure past the threshold -- turns a 500-attempt attack into 496 pages, and
alert fatigue is how detection tools get ignored. Deferred emission also means
the alert reports the burst's *true* size, which severity scoring needs. (In a
streaming SIEM you would emit at the threshold and update the case as it
grows; batch analysis lets us just tell the finished story.)

**Severity: medium by default, high on scale or spread.** Threshold-level
brute forcing is Internet background noise on any exposed SSH port -- real, but
routine (medium). It escalates to HIGH when the volume reaches 3x the
threshold (a determined attacker, not a drive-by) or when 3+ distinct
usernames are hit from one IP (password spraying / user enumeration -- intent
is unambiguous). It never reaches CRITICAL on its own: critical is reserved
for evidence of *success*, which is the compromise rule's job.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, Iterator, List, Optional

from sentrylog.detection.alert import Alert, Severity
from sentrylog.detection.base import Rule
from sentrylog.event import Action, Event, Outcome

#: Distinct targeted users from one IP at/above this -> password spray -> HIGH.
_SPRAY_USER_COUNT = 3
#: Burst size at/above (threshold * this factor) -> determined attacker -> HIGH.
_VOLUME_FACTOR = 3


class BruteForceRule(Rule):
    """Sliding-window failed-login burst detection, per source IP."""

    name = "brute_force"

    def __init__(self, threshold: int = 5, window_seconds: int = 60) -> None:
        """
        Parameters
        ----------
        threshold:
            Failures within the window that trip the rule. Default 5: two or
            three is a human mistyping a password; five in a minute is a tool.
        window_seconds:
            Sliding window span. Default 60s: spray bots fire seconds apart,
            and a short window keeps slow legitimate failures from stacking.
        """
        if threshold < 1:
            raise ValueError(f"threshold must be >= 1, got {threshold}")
        if window_seconds < 1:
            raise ValueError(f"window_seconds must be >= 1, got {window_seconds}")
        self.threshold = threshold
        self.window_seconds = window_seconds

    def analyze(self, events: Iterable[Event]) -> Iterator[Alert]:
        # Pre-trigger sliding windows, one deque per source IP.
        windows: Dict[str, Deque[Event]] = defaultdict(deque)
        # Triggered bursts still accumulating (IP -> events so far).
        open_bursts: Dict[str, List[Event]] = {}

        for event in events:
            if not (
                event.action is Action.LOGIN
                and event.outcome is Outcome.FAILURE
                and event.source_ip
            ):
                continue
            ip = event.source_ip

            if ip in open_bursts:
                burst = open_bursts[ip]
                gap = (event.timestamp - burst[-1].timestamp).total_seconds()
                if gap > self.window_seconds:
                    # The burst went quiet for longer than the window: it is
                    # over. Emit it, then treat this failure as a fresh start.
                    yield self._build_alert(open_bursts.pop(ip))
                    windows[ip] = deque([event])
                else:
                    burst.append(event)
                continue

            window = windows[ip]
            # Evict failures older than the window (inclusive boundary: an
            # event exactly window_seconds old stays -- span == Y fires).
            while window and (
                (event.timestamp - window[0].timestamp).total_seconds()
                > self.window_seconds
            ):
                window.popleft()
            window.append(event)

            if len(window) >= self.threshold:
                # Threshold tripped: promote the window contents to an open
                # burst and stop sliding -- everything from here until the
                # burst goes quiet belongs to the same attack.
                open_bursts[ip] = list(window)
                window.clear()

        # End of stream: any burst still open is complete by definition.
        for ip in sorted(open_bursts):  # sorted for deterministic output
            yield self._build_alert(open_bursts.pop(ip))

    def _build_alert(self, burst: List[Event]) -> Alert:
        """Score and describe one finished burst."""
        first, last = burst[0], burst[-1]
        span = int((last.timestamp - first.timestamp).total_seconds())
        users = sorted({e.user for e in burst if e.user})
        invalid = sum(1 for e in burst if e.metadata.get("invalid_user"))
        hosts = {e.host for e in burst if e.host}
        sources = {e.source_type.value for e in burst}

        escalations = []
        if len(burst) >= self.threshold * _VOLUME_FACTOR:
            escalations.append(f"volume >= {_VOLUME_FACTOR}x threshold")
        if len(users) >= _SPRAY_USER_COUNT:
            escalations.append(f"password spray across {len(users)} users")
        severity = Severity.HIGH if escalations else Severity.MEDIUM

        description = (
            f"{len(burst)} failed logins from {first.source_ip} in {span}s "
            f"targeting {len(users)} user(s) "
            f"({self.threshold} in {self.window_seconds}s trips this rule)"
        )
        if invalid:
            description += f"; {invalid} against non-existent accounts"
        if escalations:
            description += f". Escalated to high: {'; '.join(escalations)}"
        if len(sources) > 1:
            description += f". Seen across sources: {', '.join(sorted(sources))}"

        return Alert(
            rule_name=self.name,
            severity=severity,
            timestamp=last.timestamp,
            description=description,
            source_ip=first.source_ip,
            # Only name a user when the burst had exactly one -- a spray has
            # no single honest value for this field.
            user=users[0] if len(users) == 1 else None,
            host=hosts.pop() if len(hosts) == 1 else None,
            matched_events=list(burst),
        )
