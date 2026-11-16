#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit local installation/validation of the synthetic completeness fixture.

No container creation, credential rotation or existing data/grant repair.
The source file contains the same bounded transaction used by a fresh bootstrap.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import runtime

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/compose/source-fixture.sql"
BEGIN = "-- BEGIN QUALITY_FIXTURE_V1"
END = "-- END QUALITY_FIXTURE_V1"
READY = b"QUALITY_FIXTURE_READY_V1"


def fixture_sql(raw: bytes) -> str:
    if len(raw) > 65536:
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    try:
        source = raw.decode("utf-8")
    except UnicodeError:
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED") from None
    if source.count(BEGIN) != 1 or source.count(END) != 1:
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    before, rest = source.split(BEGIN, 1)
    body, after = rest.split(END, 1)
    if not before.endswith("\n") or not rest.startswith("\n") or after.strip():
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    if not body.lstrip().startswith("-- Also executed alone") or "\nBEGIN;\n" not in body or not body.endswith("\n"):
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    if not body.rstrip().endswith("SELECT 'QUALITY_FIXTURE_READY_V1';"):
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    return body


def install() -> dict:
    # These existing launcher guards refuse remote Docker and missing bootstrap.
    runtime.require_local()
    runtime.require_bootstrap()
    if SOURCE.is_symlink() or not SOURCE.is_file():
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    with SOURCE.open("rb") as stream:
        statement = fixture_sql(stream.read(65537))
    result = subprocess.run(
        runtime.COMPOSE + ["exec", "-T", "source-postgres", "psql", "-X", "-q", "-A", "-t",
                           "-U", "source_admin", "-d", "harbor", "-v", "ON_ERROR_STOP=1", "--file", "-"],
        input=statement.encode("utf-8"), cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=45, check=False,
    )
    # SQL has a 15-second statement ceiling and a 2-second lock ceiling. A host
    # timeout is an uncertain refusal, not a claim that a transaction rolled back.
    # Reinvocation validates any already committed table without repairing it.
    if result.returncode != 0 or len(result.stdout) > 128 or result.stdout.strip() != READY:
        raise RuntimeError("QUALITY_FIXTURE_INSTALL_REJECTED")
    return {"fixture": "public.quality_fixture", "result": "READY", "rows": 20, "nullRows": 5,
            "sqlSha256": hashlib.sha256(statement.encode("utf-8")).hexdigest()}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-core", action="store_true",
                        help="Explicitly install or verify the fixture in the existing local synthetic source.")
    args = parser.parse_args(argv)
    if not args.run_core:
        parser.error("--run-core is required; no runtime action was attempted")
    try:
        print(json.dumps(install(), sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({"fixture": "public.quality_fixture", "result": "FAILED",
                          "code": "QUALITY_FIXTURE_INSTALL_REJECTED"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
