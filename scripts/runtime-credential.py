#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit local credential retrieval; intentionally not used in evidence logs."""
import json
import sys
from pathlib import Path
if len(sys.argv) != 2:
    raise SystemExit("usage: python3 scripts/runtime-credential.py <steward|owner|consumer|auditor|summit|engineer>")
values = json.loads((Path(__file__).resolve().parents[1] / ".local/bootstrap.json").read_text())
if sys.argv[1] not in values["personas"]:
    raise SystemExit("Unknown synthetic persona")
print(values["personas"][sys.argv[1]])
