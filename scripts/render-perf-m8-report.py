#!/usr/bin/env python3
"""Repository entry point for the PERF-M8-1 HTML renderer."""

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tests" / "benchmark"))

from perf_m8_report import main  # noqa: E402


if __name__ == "__main__":
    sys.exit(main())
