#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HUNTER v6 — Autonomous Security Verification Agent."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from hunter_agent.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
