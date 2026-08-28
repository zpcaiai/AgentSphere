#!/usr/bin/env python3
"""Invoke the fail-closed external revocation projection authority."""

from python.production_gates.revocation_projection import main


if __name__ == "__main__":
    raise SystemExit(main())
