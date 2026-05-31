"""
sentrylog.table
===============

A tiny dependency-free table renderer for the CLI summary.

Why hand-rolled instead of ``rich`` / ``tabulate``? So SentryLog runs out of the
box with **zero** third-party packages for its core path -- nothing to ``pip
install`` before you can see output. It's ~30 lines, and it keeps the dependency
surface (and the attack surface) minimal, which is a reasonable instinct for a
security tool.
"""

from __future__ import annotations

from typing import List, Optional, Sequence


def render_table(
    headers: Sequence[object],
    rows: Sequence[Sequence[object]],
    aligns: Optional[Sequence[str]] = None,
) -> str:
    """Render a Unicode box-drawing table as a string.

    Parameters
    ----------
    headers:
        Column header labels.
    rows:
        Row data; each row must have one cell per header.
    aligns:
        Per-column alignment, ``"left"`` or ``"right"`` (defaults to all left).
        Numeric columns read better right-aligned.
    """
    columns = len(headers)
    aligns = list(aligns) if aligns is not None else ["left"] * columns

    # Column width = widest cell (header included) in that column.
    widths: List[int] = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def format_row(cells: Sequence[object]) -> str:
        rendered = []
        for i, cell in enumerate(cells):
            text = str(cell)
            rendered.append(
                text.rjust(widths[i]) if aligns[i] == "right" else text.ljust(widths[i])
            )
        return "│ " + " │ ".join(rendered) + " │"

    def border(left: str, mid: str, right: str) -> str:
        return left + mid.join("─" * (w + 2) for w in widths) + right

    lines = [
        border("┌", "┬", "┐"),
        format_row(headers),
        border("├", "┼", "┤"),
    ]
    lines.extend(format_row(row) for row in rows)
    lines.append(border("└", "┴", "┘"))
    return "\n".join(lines)
