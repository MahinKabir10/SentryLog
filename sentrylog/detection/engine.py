"""
sentrylog.detection.engine
==========================

The detection engine: feed it events and rules, get back a
:class:`DetectionResult`. Deliberately tiny -- the engine's whole job is the
contract, not the cleverness:

* **Sort once.** Events are sorted by timestamp here so every rule downstream
  can assume chronological order (see ``detection.base``). The sort is stable,
  so events with identical timestamps keep their source order -- which matters
  for failed-then-success correlation when a burst lands within one second.
* **Fan out.** Each rule sees the *same* sorted list. Rules are independent by
  design; there is no inter-rule communication to reason about.
* **Rank the output.** Alerts come back sorted by severity (critical first),
  then time -- the order a human should read them in. A SOC queue triages by
  urgency, not by when the log line happened to be written.

Batch, not streaming: Phase 1 already materializes events per file (documented
in ``parsers.base``), and rule windows need at most the same data. The seam to
make this streaming later is exactly one place -- this module.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, List, Sequence

from sentrylog.detection.alert import Alert
from sentrylog.detection.base import Rule
from sentrylog.event import Event


@dataclass
class DetectionResult:
    """Everything one detection run produces.

    ``rule_names`` records every rule that *ran* (not just those that fired),
    so a summary can honestly show "compromise: 0 alerts" -- silence from a
    rule that ran is information; silence from a rule that didn't run is a bug.
    """

    alerts: List[Alert] = field(default_factory=list)
    events_analyzed: int = 0
    rule_names: List[str] = field(default_factory=list)

    def counts_by_severity(self) -> Counter:
        """Alert count per severity value (e.g. ``{"high": 2, "low": 1}``)."""
        return Counter(alert.severity.value for alert in self.alerts)

    def counts_by_rule(self) -> dict[str, int]:
        """Alert count per rule, including zeros for rules that stayed quiet."""
        counts = Counter(alert.rule_name for alert in self.alerts)
        return {name: counts.get(name, 0) for name in self.rule_names}


def run_rules(events: Iterable[Event], rules: Sequence[Rule]) -> DetectionResult:
    """Run every rule over the (sorted) event stream and collect alerts.

    Rules receive fresh chronological order regardless of input order --
    callers may concatenate multiple files (Linux + Windows) without
    interleaving them by hand; that is the point of this function.
    """
    ordered = sorted(events, key=lambda event: event.timestamp)

    alerts: List[Alert] = []
    for rule in rules:
        alerts.extend(rule.analyze(ordered))

    # Critical first, then chronological within a tier: triage order.
    alerts.sort(key=lambda alert: (-alert.severity.rank, alert.timestamp))

    return DetectionResult(
        alerts=alerts,
        events_analyzed=len(ordered),
        rule_names=[rule.name for rule in rules],
    )
