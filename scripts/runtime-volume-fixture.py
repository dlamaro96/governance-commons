#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Finite local synthetic source repair for real volume acceptance tests."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import runtime

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/compose/volume-quality-fixture.sql"
STEPS = frozenset(("prepare", "read", "repair", "fail"))


def run_step(step):
    if type(step) is not str or step not in STEPS:
        raise ValueError("VOLUME_FIXTURE_STEP_REJECTED")
    runtime.require_local()
    runtime.require_bootstrap()
    if SOURCE.is_symlink() or not SOURCE.is_file():
        raise ValueError("VOLUME_FIXTURE_SOURCE_REJECTED")
    with SOURCE.open("rb") as stream:
        statement = stream.read(65537)
    if not 1 <= len(statement) <= 65536:
        raise ValueError("VOLUME_FIXTURE_SOURCE_REJECTED")
    result = subprocess.run(
        runtime.COMPOSE + ["exec", "-T", "source-postgres", "psql", "-X", "-q", "-A", "-t",
            "-U", "source_admin", "-d", "harbor", "-v", "ON_ERROR_STOP=1",
            "-v", "fixture_step=" + step, "--file", "-"],
        input=statement, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=45, check=False,
    )
    if result.returncode != 0 or len(result.stdout) > 256:
        raise RuntimeError("VOLUME_FIXTURE_REJECTED")
    try:
        def unique(pairs):
            value = {}
            for key, field in pairs:
                if key in value:
                    raise ValueError("VOLUME_FIXTURE_REJECTED")
                value[key] = field
            return value
        value = json.loads(result.stdout, object_pairs_hook=unique)
        if (type(value) is not dict or set(value) != {"result", "rows"}
                or value["result"] != "READY" or type(value["rows"]) is not int or value["rows"] not in (5, 6)
                or (step in ("prepare", "repair") and value["rows"] != 6)
                or (step == "fail" and value["rows"] != 5)):
            raise ValueError("VOLUME_FIXTURE_REJECTED")
    except (UnicodeError, ValueError, TypeError):
        raise RuntimeError("VOLUME_FIXTURE_REJECTED") from None
    return {**value, "step": step, "fixture": "public.volume_quality_fixture",
            "sqlSha256": hashlib.sha256(statement).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-core", action="store_true")
    parser.add_argument("--step", required=True, choices=sorted(STEPS))
    args = parser.parse_args(argv)
    if not args.run_core:
        parser.error("--run-core is required; no runtime action was attempted")
    try:
        print(json.dumps(run_step(args.step), sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({"result": "FAILED", "code": "VOLUME_FIXTURE_REJECTED"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
