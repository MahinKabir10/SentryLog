"""
sentrylog.cli
=============

The command-line entry point. Two subcommands::

    sentrylog ingest <path> [--type auto|linux_auth|windows_evtx]
                            [--show N] [-v]
    sentrylog detect <path> [<path> ...] [--type ...]
                            [--bf-threshold N] [--bf-window SECONDS]
                            [--cf-min-failures N] [--cf-window SECONDS]
                            [--min-severity LEVEL] [--show-events] [-v]

``ingest`` (Phase 1) parses and prints the normalization summary. ``detect``
(Phase 2) parses, then runs the detection rules over the normalized stream and
prints a triage-ordered alert table. ``detect`` accepts *multiple* paths and
merges them into one chronological stream -- ``sentrylog detect auth.log
security.evtx`` runs the same rules across Linux and Windows in one pass,
which is the normalization layer paying off.

The subcommand structure (``argparse`` sub-parsers) was set up in Phase 1
precisely so ``detect`` could slot in as a sibling without disturbing
``ingest``.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from sentrylog.detect import detect_source_type
from sentrylog.detection import Alert, DetectionResult, Severity, default_rules, run_rules
from sentrylog.event import Event, Outcome, SourceType
from sentrylog.parsers import PARSERS, ParseResult
from sentrylog.table import render_table

logger = logging.getLogger(__name__)

# Fixed column order for the outcome table -- stable output is easier to read
# and to diff/test against.
_OUTCOME_ORDER = [Outcome.SUCCESS.value, Outcome.FAILURE.value, Outcome.UNKNOWN.value]


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser (kept separate so tests can introspect it)."""
    parser = argparse.ArgumentParser(
        prog="sentrylog",
        description=(
            "SentryLog - a minimal SIEM. "
            "Phase 1: ingestion & normalization (ingest). Phase 2: detection (detect)."
        ),
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    ingest = subcommands.add_parser(
        "ingest",
        help="Parse and normalize a log file into events, then print a summary.",
    )
    ingest.add_argument("path", help="Path to the log file (.log/.txt or .evtx).")
    ingest.add_argument(
        "--type",
        choices=["auto", SourceType.LINUX_AUTH.value, SourceType.WINDOWS_EVTX.value],
        default="auto",
        help="Source type. 'auto' (default) detects by extension/content.",
    )
    ingest.add_argument(
        "--show",
        type=int,
        default=0,
        metavar="N",
        help="Also print the first N normalized events (default: 0).",
    )
    ingest.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose logging: show DEBUG (skipped lines) and WARNING (errors).",
    )

    detect = subcommands.add_parser(
        "detect",
        help="Run detection rules over one or more log files and print alerts.",
    )
    detect.add_argument(
        "paths",
        nargs="+",
        metavar="path",
        help=(
            "Log file(s) to analyze. Multiple files (even mixed Linux/Windows) "
            "are merged into one chronological stream."
        ),
    )
    detect.add_argument(
        "--type",
        choices=["auto", SourceType.LINUX_AUTH.value, SourceType.WINDOWS_EVTX.value],
        default="auto",
        help="Source type for ALL paths. 'auto' (default) detects per file.",
    )
    detect.add_argument(
        "--bf-threshold",
        type=int,
        default=5,
        metavar="N",
        help="Brute force: failed logins from one IP that trip the rule (default: 5).",
    )
    detect.add_argument(
        "--bf-window",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Brute force: sliding window in seconds (default: 60).",
    )
    detect.add_argument(
        "--cf-min-failures",
        type=int,
        default=3,
        metavar="N",
        help="Compromise: failures before a success that trip the rule (default: 3).",
    )
    detect.add_argument(
        "--cf-window",
        type=int,
        default=600,
        metavar="SECONDS",
        help="Compromise: failure-to-success window in seconds (default: 600).",
    )
    detect.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        default=Severity.LOW.value,
        help="Only show alerts at or above this severity (default: low).",
    )
    detect.add_argument(
        "--show-events",
        action="store_true",
        help="Also print each alert's matched events (the evidence chain).",
    )
    detect.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose logging: show DEBUG (skipped lines) and WARNING (errors).",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Program entry point. Returns a POSIX-style exit code (0 = success)."""
    # Box-drawing characters can blow up on a legacy Windows code page; force
    # UTF-8 on stdout so the summary table always renders. Guarded because not
    # every stream supports reconfigure().
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - best effort, never fatal
        pass

    args = build_arg_parser().parse_args(argv)

    # WARNING by default so parser warnings (unparseable lines) surface; DEBUG
    # with -v to also see the quietly-skipped lines.
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.command == "ingest":
        return cmd_ingest(args)
    if args.command == "detect":
        return cmd_detect(args)

    # argparse(required=True) should prevent reaching here.
    build_arg_parser().error(f"unknown command: {args.command!r}")
    return 2


def _parse_one(path: Path, type_flag: str) -> Tuple[SourceType, ParseResult]:
    """Resolve a file's source type and parse it (shared by ingest/detect).

    Raises the parser-layer exceptions unwrapped (ValueError for undetectable
    type, RuntimeError for a missing optional dependency, OSError for I/O);
    each command formats them into its own user-facing message, keeping the
    exit-code conventions it already documents.
    """
    if type_flag == "auto":
        source = detect_source_type(path)
    else:
        source = SourceType(type_flag)
    return source, PARSERS[source](path)


def cmd_ingest(args: argparse.Namespace) -> int:
    """Handle ``sentrylog ingest``."""
    path = Path(args.path)
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2

    try:
        source, result = _parse_one(path, args.type)
    except ValueError as exc:
        # Auto-detection came up empty; ask for an explicit --type.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        # e.g. python-evtx not installed for a .evtx file.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: could not read {path}: {exc}", file=sys.stderr)
        return 1

    _print_summary(path, source, result, show=args.show)
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    """Handle ``sentrylog detect``: parse all inputs, run the rules, print."""
    events: List[Event] = []
    parsed_files: List[Tuple[Path, SourceType, ParseResult]] = []

    for raw_path in args.paths:
        path = Path(raw_path)
        if not path.exists():
            print(f"error: file not found: {path}", file=sys.stderr)
            return 2
        try:
            source, result = _parse_one(path, args.type)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"error: could not read {path}: {exc}", file=sys.stderr)
            return 1
        events.extend(result.events)
        parsed_files.append((path, source, result))

    # Fresh rules per run (they hold window state); the engine re-sorts the
    # merged stream, so mixed-source inputs interleave correctly by time.
    rules = default_rules(
        bf_threshold=args.bf_threshold,
        bf_window_seconds=args.bf_window,
        compromise_min_failures=args.cf_min_failures,
        compromise_window_seconds=args.cf_window,
    )
    detection = run_rules(events, rules)

    minimum = Severity(args.min_severity)
    visible = [a for a in detection.alerts if a.severity.rank >= minimum.rank]

    _print_alerts(parsed_files, detection, visible, minimum, args.show_events)
    return 0


def _print_summary(
    path: Path, source: SourceType, result: ParseResult, show: int = 0
) -> None:
    """Render the ingestion summary to stdout."""
    events = result.events
    stats = result.stats

    print()
    print("SentryLog - Ingestion Summary")
    print("=" * 29)
    print(f"Source        : {path}")
    print(f"Detected type : {source.value}")
    print(f"Input units   : {stats.as_line()}")
    print()

    # --- Table 1: source type x outcome (the required breakdown) --------
    by_source: dict[str, Counter] = defaultdict(Counter)
    for event in events:
        by_source[event.source_type.value][event.outcome.value] += 1

    rows = []
    grand_total: Counter = Counter()
    for src in sorted(by_source):
        counts = by_source[src]
        row = [src] + [counts.get(o, 0) for o in _OUTCOME_ORDER] + [sum(counts.values())]
        rows.append(row)
        grand_total.update(counts)

    if rows:
        # A TOTAL row makes the table self-summarizing for multi-source runs.
        rows.append(
            ["TOTAL"]
            + [grand_total.get(o, 0) for o in _OUTCOME_ORDER]
            + [sum(grand_total.values())]
        )
    else:
        rows = [["(none)", 0, 0, 0, 0]]

    print(
        render_table(
            headers=["Source Type", "Success", "Failure", "Unknown", "Total"],
            rows=rows,
            aligns=["left", "right", "right", "right", "right"],
        )
    )
    print()

    # --- Table 2: breakdown by normalized action -----------------------
    action_counts = Counter(event.action.value for event in events)
    action_rows = [
        [action, count]
        # Sort by count desc, then name -- most significant activity on top.
        for action, count in sorted(action_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ] or [["(none)", 0]]
    print(
        render_table(
            headers=["Action", "Count"],
            rows=action_rows,
            aligns=["left", "right"],
        )
    )

    # --- Optional: a peek at the normalized events themselves -----------
    if show > 0 and events:
        shown = min(show, len(events))
        print()
        print(f"First {shown} normalized event(s):")
        event_rows = [
            [
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                event.source_type.value,
                event.action.value,
                event.outcome.value,
                event.user or "-",
                event.source_ip or "-",
                event.event_id or "-",
            ]
            for event in events[:shown]
        ]
        print(
            render_table(
                headers=[
                    "Timestamp (UTC)", "Type", "Action",
                    "Outcome", "User", "Source IP", "Event ID",
                ],
                rows=event_rows,
            )
        )


def _print_alerts(
    parsed_files: List[Tuple[Path, SourceType, ParseResult]],
    detection: DetectionResult,
    visible: List[Alert],
    minimum: Severity,
    show_events: bool,
) -> None:
    """Render the detection run: header, alert table, per-alert detail lines.

    Layout rationale: the table gives the triage view (severity-sorted, one
    line per alert, description truncated to keep rows scannable); the
    numbered detail block below carries each full description -- long prose
    doesn't belong in table cells. ``--show-events`` extends each detail block
    with the evidence chain, reusing ``Event.summary()``.
    """
    print()
    print("SentryLog - Detection Summary")
    print("=" * 29)
    for path, source, result in parsed_files:
        print(f"Source        : {path} [{source.value}] ({result.stats.as_line()})")
    print(f"Rules run     : {', '.join(detection.rule_names)}")

    by_severity = detection.counts_by_severity()
    tier_line = " | ".join(
        f"{by_severity.get(s.value, 0)} {s.value}"
        # Highest tier first: the reading order of a triage queue.
        for s in sorted(Severity, key=lambda s: -s.rank)
    )
    print(f"Alerts        : {len(detection.alerts)} total ({tier_line})")
    if minimum is not Severity.LOW:
        print(f"Showing       : {len(visible)} at/above severity '{minimum.value}'")
    print()

    if not visible:
        print("No alerts at the requested severity. (Quiet is a finding too.)")
        return

    rows = [
        [
            index,
            alert.severity.value.upper(),
            alert.rule_name,
            alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            alert.source_ip or "-",
            alert.user or "-",
            len(alert.matched_events),
        ]
        for index, alert in enumerate(visible, start=1)
    ]
    print(
        render_table(
            headers=["#", "Severity", "Rule", "Time (UTC)", "Source IP", "User", "Events"],
            rows=rows,
            aligns=["right", "left", "left", "left", "left", "left", "right"],
        )
    )

    print()
    print("Alert details:")
    for index, alert in enumerate(visible, start=1):
        print(f"[{index}] {alert.severity.value.upper()} {alert.rule_name}")
        print(f"    {alert.description}")
        if show_events:
            for event in alert.matched_events:
                print(f"      - {event.summary()}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
