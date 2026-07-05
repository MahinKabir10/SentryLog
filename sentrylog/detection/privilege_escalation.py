"""
sentrylog.detection.privilege_escalation
========================================

Privilege-escalation detection over sudo (Linux) and Windows account/privilege
events (4672 special privileges, 4720 account created, 4732 member added to a
security-enabled group).

The core design problem here is **noise**: on any real fleet, successful
elevation is mostly *legitimate administration*. A rule that pages on every
sudo or every 4672 (one fires on every admin logon!) trains analysts to ignore
the tool -- the classic SOC failure mode. So this rule tiers hard:

===========================================  ========  =====================
Signal                                       Severity  Why
===========================================  ========  =====================
Successful sudo / 4672                       low       Routine admin work.
                                                       Aggregated to ONE
                                                       alert per user+host --
                                                       audit trail, not a page.
Failed sudo (NOT in sudoers, bad password)   medium    Someone *tried* to be
                                                       root and the system
                                                       said no. Intent shown,
                                                       impact not realized.
4720 account created                         medium    Persistence staging
                                                       (MITRE T1136) -- watch
                                                       what the account does.
4732 added to a PRIVILEGED group             high      Durable elevation:
                                                       survives logoff, unlike
                                                       a session token.
4732 added to a non-privileged group         medium    Rights changed, but not
                                                       admin-equivalent.
===========================================  ========  =====================

``Alert.user`` convention for this rule: the account that **gained (or tried
to gain) rights** -- the sudo invoker, the newly created account (4720), the
added member (4732). The acting administrator, when different, is named in the
description; the beneficiary is what an analyst pivots on.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, Iterator, List, Tuple

from sentrylog.detection.alert import Alert, Severity
from sentrylog.detection.base import Rule
from sentrylog.event import Action, Event, Outcome

#: Group names (lowercased) whose membership is admin-equivalent. Being added
#: to one of these is a durable rights grant -> HIGH. Everything else is a
#: rights *change* -> MEDIUM. Extend as your environment dictates.
_PRIVILEGED_GROUPS = frozenset(
    {
        "administrators",
        "domain admins",
        "enterprise admins",
        "schema admins",
        "backup operators",
        "remote desktop users",
        "sudo",
        "wheel",
    }
)

#: Event IDs treated as routine successful elevation (aggregate, don't page).
_ROUTINE_ELEVATION_IDS = {"sudo_command", "4672"}


class PrivilegeEscalationRule(Rule):
    """Tiered detection of attempted and achieved privilege changes."""

    name = "privilege_escalation"

    def analyze(self, events: Iterable[Event]) -> Iterator[Alert]:
        # (user, host) -> their successful routine elevations, aggregated so
        # a hundred sudo calls by one admin become one LOW audit alert.
        routine: Dict[Tuple[str, str], List[Event]] = defaultdict(list)

        for event in events:
            if event.event_id == "4720":
                yield self._account_created(event)
            elif event.event_id == "4732":
                yield self._group_membership(event)
            elif event.action is Action.PRIVILEGE_ESCALATION:
                if event.outcome is Outcome.FAILURE:
                    yield self._failed_elevation(event)
                elif event.event_id in _ROUTINE_ELEVATION_IDS:
                    key = (event.user or "(unknown)", event.host or "(unknown)")
                    routine[key].append(event)

        # End of stream: one audit-trail alert per (user, host) that elevated.
        for (user, host), elevations in sorted(routine.items()):
            yield self._routine_summary(user, host, elevations)

    # -- per-signal builders ----------------------------------------------

    def _failed_elevation(self, event: Event) -> Alert:
        reason = event.metadata.get("reason", "unknown reason")
        command = event.metadata.get("command")
        description = (
            f"User '{event.user}' failed to elevate privileges ({reason})"
        )
        if command:
            description += f" attempting: {command}"
        description += ". Attempted escalation by a non-privileged principal."
        return Alert(
            rule_name=self.name,
            severity=Severity.MEDIUM,
            timestamp=event.timestamp,
            description=description,
            user=event.user,
            host=event.host,
            source_ip=event.source_ip,
            matched_events=[event],
        )

    def _account_created(self, event: Event) -> Alert:
        new_account = event.metadata.get("new_account", "(unknown)")
        return Alert(
            rule_name=self.name,
            severity=Severity.MEDIUM,
            timestamp=event.timestamp,
            description=(
                f"New account '{new_account}' created by '{event.user}' -- "
                "account creation is a common persistence step (MITRE T1136); "
                "verify it was a sanctioned change."
            ),
            user=new_account,  # the beneficiary, per the rule's convention
            host=event.host,
            source_ip=event.source_ip,
            matched_events=[event],
        )

    def _group_membership(self, event: Event) -> Alert:
        group = event.metadata.get("group", "(unknown group)")
        member = event.metadata.get("member", "(unknown member)")
        privileged = group.lower() in _PRIVILEGED_GROUPS
        severity = Severity.HIGH if privileged else Severity.MEDIUM
        description = (
            f"'{member}' added to group '{group}' by '{event.user}'"
        )
        description += (
            " -- admin-equivalent group: this is a durable privilege grant "
            "that survives logoff. Confirm it was authorized."
            if privileged
            else " -- non-privileged group; rights changed, verifying is cheap."
        )
        return Alert(
            rule_name=self.name,
            severity=severity,
            timestamp=event.timestamp,
            description=description,
            user=member,
            host=event.host,
            source_ip=event.source_ip,
            matched_events=[event],
        )

    def _routine_summary(
        self, user: str, host: str, elevations: List[Event]
    ) -> Alert:
        commands = sorted(
            {e.metadata["command"] for e in elevations if e.metadata.get("command")}
        )
        description = (
            f"User '{user}' successfully elevated privileges "
            f"{len(elevations)} time(s) on {host} (sudo / special privileges)"
        )
        if commands:
            shown = "; ".join(commands[:3])
            more = f" (+{len(commands) - 3} more)" if len(commands) > 3 else ""
            description += f". Commands: {shown}{more}"
        description += ". Routine if this user administers this host."
        return Alert(
            rule_name=self.name,
            severity=Severity.LOW,
            timestamp=elevations[-1].timestamp,
            description=description,
            user=user,
            host=host,
            matched_events=list(elevations),
        )
