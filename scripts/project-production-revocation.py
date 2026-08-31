#!/usr/bin/env python3
"""Invoke the fail-closed external revocation projection authority."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from python.production_gates.revocation_projection import main


if __name__ == "__main__":
    raise SystemExit(main())
