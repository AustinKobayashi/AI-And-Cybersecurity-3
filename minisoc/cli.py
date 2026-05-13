"""Project-root wrapper for the CLI in `src/minisoc`."""

from __future__ import annotations

import sys

from src.minisoc.cli import main


if __name__ == "__main__":
    sys.exit(main())
