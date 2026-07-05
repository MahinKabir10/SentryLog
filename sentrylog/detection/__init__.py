"""
sentrylog.detection
===================

The detection layer (Phase 2). Rules consume the normalized
:class:`~sentrylog.event.Event` stream and yield :class:`Alert` objects; the
engine (:func:`run_rules`) owns ordering and collection. Because rules match
on normalized fields, one rule fires across every source Phase 1 can ingest --
an SSH brute force and an RDP brute force are the same pattern by the time a
rule sees them.

``default_rules()`` is the registry, playing the role ``PARSERS`` plays for
ingestion: the CLI and the MCP server build their rule set here, so adding a
rule is one module plus one line below -- neither front-end changes. It is a
*factory* (fresh instances per call), because rules hold per-run window state;
sharing instances across runs would bleed state exactly like sharing a parser
across files would bleed stats.
"""

from __future__ import annotations

from typing import List

from sentrylog.detection.alert import Alert, Severity
from sentrylog.detection.base import Rule
from sentrylog.detection.brute_force import BruteForceRule
from sentrylog.detection.compromise import CompromiseRule
from sentrylog.detection.engine import DetectionResult, run_rules
from sentrylog.detection.privilege_escalation import PrivilegeEscalationRule


def default_rules(
    *,
    bf_threshold: int = 5,
    bf_window_seconds: int = 60,
    compromise_min_failures: int = 3,
    compromise_window_seconds: int = 600,
) -> List[Rule]:
    """Build a fresh instance of every registered rule.

    The keyword-only tunables are the knobs a deployment actually turns; each
    default is argued for in its rule's docstring. New rules join the returned
    list here and nowhere else.
    """
    return [
        BruteForceRule(threshold=bf_threshold, window_seconds=bf_window_seconds),
        PrivilegeEscalationRule(),
        CompromiseRule(
            min_failures=compromise_min_failures,
            window_seconds=compromise_window_seconds,
        ),
    ]


__all__ = [
    "Alert",
    "Severity",
    "Rule",
    "DetectionResult",
    "run_rules",
    "default_rules",
    "BruteForceRule",
    "PrivilegeEscalationRule",
    "CompromiseRule",
]
