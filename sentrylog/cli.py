"""
sentrylog.cli
=============

The command-line entry point. Phase 1 ships a single subcommand::

    sentrylog ingest <path> [--type auto|linux_auth|windows_evtx]
                            [--show N] [-v]

It detects (or is told) the source type, runs the matching parser, and prints a
clean summary: counts by source type x outcome, a breakdown by action, and the
ingestion stats (parsed / skipped / errors). ``--show N`` additionally prints
the first N normalized events so you can eyeball the normalization itself.

The subcommand structure (``argparse`` sub-parsers) is intentional: Phase 2's
detection engine will slot in as a sibling command (``sentrylog detect ...``)
without disturbing ``ingest``.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional, Sequence

from sentrylog.detect import detect_source_type
from sentrylog.event import Outcome, SourceType
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
        description="SentryLog - a minimal SIEM. Phase 1: ingestion & normalization.",
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

    # argparse(required=True) should prevent reaching here.
    build_arg_parser().error(f"unknown command: {args.command!r}")
    return 2


def cmd_ingest(args: argparse.Namespace) -> int:
    """Handle ``sentrylog ingest``."""
    path = Path(args.path)
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2

    # Resolve the source type (explicit flag wins over auto-detection).
    if args.type == "auto":
        try:
            source = detect_source_type(path)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        source = SourceType(args.type)

    # Dispatch to the matching parser via the registry.
    try:
        result = PARSERS[source](path)
    except RuntimeError as exc:
        # e.g. python-evtx not installed for a .evtx file.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: could not read {path}: {exc}", file=sys.stderr)
        return 1

    _print_summary(path, source, result, show=args.show)
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


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
