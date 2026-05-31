"""
Enables ``python -m sentrylog ...`` as an alternative to the installed
``sentrylog`` console script. Handy for running straight from a checkout
without ``pip install``.
"""

from __future__ import annotations

from sentrylog.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
