"""
sentrylog.detect
================

Source-type auto-detection for the ``--type auto`` CLI mode.

The strategy goes from cheapest/most-reliable signal to most expensive:

1. **Extension.** ``.evtx`` is unambiguous -- trust it immediately.
2. **Binary magic.** Every EVTX file starts with the signature bytes
   ``b"ElfFile\\x00"``. This catches an ``.evtx`` saved under a different name
   and is far more reliable than an extension.
3. **Text shape.** For text files, we sniff the first handful of non-blank
   lines for the syslog skeleton (reusing the parser's own regex, so detection
   can't drift out of sync with parsing).
4. **Extension/name fallback.** ``.log`` / ``.txt`` or an "auth" in the name
   nudges us to ``linux_auth`` when content sniffing was inconclusive.

If nothing matches we raise ``ValueError`` -- the CLI turns that into a friendly
"pass --type" message rather than guessing wrong.
"""

from __future__ import annotations

from pathlib import Path

from sentrylog.event import SourceType
# Reuse the *exact* skeleton the parser uses, so detection and parsing agree.
from sentrylog.parsers.linux_auth import _SYSLOG_RE

# EVTX magic number: the first 8 bytes of every well-formed .evtx file.
_EVTX_MAGIC = b"ElfFile\x00"

# How many leading non-blank lines to inspect when sniffing text content.
_SNIFF_LINES = 25


def detect_source_type(path) -> SourceType:
    """Best-effort detection of a file's :class:`SourceType`.

    Raises ``FileNotFoundError`` if the path is missing and ``ValueError`` if
    the type can't be determined (so the caller can ask the user for ``--type``).
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"No such file: {p}")

    # 1. Extension shortcut.
    if p.suffix.lower() == ".evtx":
        return SourceType.WINDOWS_EVTX

    # 2. Binary magic -- authoritative even if the extension lies.
    try:
        with open(p, "rb") as handle:
            head = handle.read(len(_EVTX_MAGIC))
        if head.startswith(b"ElfFile"):
            return SourceType.WINDOWS_EVTX
    except OSError:
        head = b""

    # 3. Text shape: does it look like syslog? errors="replace" keeps a stray
    #    byte from derailing the sniff.
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as handle:
            checked = 0
            for line in handle:
                if not line.strip():
                    continue
                if _SYSLOG_RE.match(line):
                    return SourceType.LINUX_AUTH
                checked += 1
                if checked >= _SNIFF_LINES:
                    break
    except OSError:
        pass

    # 4. Weak hints from the filename.
    if p.suffix.lower() in (".log", ".txt") or "auth" in p.name.lower():
        return SourceType.LINUX_AUTH

    raise ValueError(
        f"Could not auto-detect the source type of {p}. "
        "Re-run with --type linux_auth or --type windows_evtx."
    )
