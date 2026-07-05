"""
sentrylog.detection.base
========================

The rule interface -- the seam that keeps the engine and the rules decoupled.

A rule is anything with a ``name`` and an ``analyze(events) -> Iterator[Alert]``
method. The engine never knows *which* rules exist (they're assembled by
``detection.default_rules()``), and rules never know about files, parsers, or
transports -- they see normalized :class:`~sentrylog.event.Event` objects and
nothing else. Adding a fourth rule is a new module plus one registry line,
exactly like adding a parser was in Phase 1.

The contract between engine and rule (both sides rely on this):

1. **Input is chronologically sorted.** The engine sorts the stream once by
   timestamp before fan-out, so every rule can be written as a simple
   single-pass state machine (a deque per IP, a counter per user) instead of
   each rule re-sorting or handling out-of-order arrival. Sorting once at the
   boundary is cheaper and -- more importantly -- it means rule logic reads
   like the detection idea it implements.
2. **Rules are single-use.** A rule instance owns mutable window state, so a
   fresh instance is built per run (``default_rules()`` is a factory, not a
   list of singletons). Same reasoning as "fresh parser per file" in Phase 1:
   state must never bleed between runs.
3. **Rules yield; the engine collects.** ``analyze`` is a generator so a rule
   can emit findings as the pattern completes mid-stream *or* aggregate and
   emit at end-of-stream -- both are legitimate detection shapes (see the
   brute-force rule for why deferred emission is sometimes the honest choice).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Iterator

from sentrylog.detection.alert import Alert
from sentrylog.event import Event


class Rule(ABC):
    """Base class for detection rules.

    Subclasses set ``name`` (stable, snake_case -- it is the alert pivot key
    and must never change once analysts build suppressions on it) and
    implement :meth:`analyze`.
    """

    #: Stable rule identifier, stamped onto every Alert this rule emits.
    name: str = "unnamed_rule"

    @abstractmethod
    def analyze(self, events: Iterable[Event]) -> Iterator[Alert]:
        """Consume a chronologically-sorted event stream, yield Alerts.

        Implementations must not mutate the events -- the same stream is
        handed to every rule.
        """
        raise NotImplementedError
