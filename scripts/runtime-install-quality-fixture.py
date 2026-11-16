#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit local installation/validation of the synthetic aggregate quality fixtures.

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
REFERENCE_SOURCE = ROOT / "deploy/compose/reference-quality-fixture.sql"
BEGIN = "-- BEGIN QUALITY_FIXTURE_V1"
END = "-- END QUALITY_FIXTURE_V1"
READY = b"QUALITY_FIXTURE_READY_V1"


def fixture_sql(raw: bytes, *, reference: bool = False) -> str:
    begin = "-- BEGIN REFERENCE_QUALITY_FIXTURE_V1" if reference else BEGIN
    end = "-- END REFERENCE_QUALITY_FIXTURE_V1" if reference else END
    ready = "REFERENCE_QUALITY_FIXTURE_READY_V1" if reference else READY.decode("ascii")
    if len(raw) > 65536:
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    try:
        source = raw.decode("utf-8")
    except UnicodeError:
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED") from None
    if source.count(begin) != 1 or source.count(end) != 1:
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    before, rest = source.split(begin, 1)
    body, after = rest.split(end, 1)
    if not before.endswith("\n") or not rest.startswith("\n") or after.strip():
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    if not body.lstrip().startswith("-- Also executed alone") or "\nBEGIN;\n" not in body or not body.endswith("\n"):
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    if not body.rstrip().endswith("SELECT '" + ready + "';"):
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    return body


def install(*, reference: bool = False) -> dict:
    source = REFERENCE_SOURCE if reference else SOURCE
    ready = b"REFERENCE_QUALITY_FIXTURE_READY_V1" if reference else READY
    # These existing launcher guards refuse remote Docker and missing bootstrap.
    runtime.require_local()
    runtime.require_bootstrap()
    if source.is_symlink() or not source.is_file():
        raise ValueError("QUALITY_FIXTURE_SOURCE_REJECTED")
    with source.open("rb") as stream:
        statement = fixture_sql(stream.read(65537), reference=reference)
    result = subprocess.run(
        runtime.COMPOSE + ["exec", "-T", "source-postgres", "psql", "-X", "-q", "-A", "-t",
                           "-U", "source_admin", "-d", "harbor", "-v", "ON_ERROR_STOP=1", "--file", "-"],
        input=statement.encode("utf-8"), cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=45, check=False,
    )
    # SQL has a 15-second statement ceiling and a 2-second lock ceiling. A host
    # timeout is an uncertain refusal, not a claim that a transaction rolled back.
    # Reinvocation validates any already committed table without repairing it.
    if result.returncode != 0 or len(result.stdout) > 128 or result.stdout.strip() != ready:
        raise RuntimeError("QUALITY_FIXTURE_INSTALL_REJECTED")
    return {"fixture": "public.reference_quality_fixture" if reference else "public.quality_fixture", "result": "READY", "rows": 20, "nullRows": 4 if reference else 5,
            "sqlSha256": hashlib.sha256(statement.encode("utf-8")).hexdigest()}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-core", action="store_true",
                        help="Explicitly install or verify the fixture in the existing local synthetic source.")
    parser.add_argument("--reference", action="store_true", help="Select the closed reference-code fixture profile.")
    args = parser.parse_args(argv)
    if not args.run_core:
        parser.error("--run-core is required; no runtime action was attempted")
    try:
        print(json.dumps(install(reference=args.reference), sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({"fixture": "public.reference_quality_fixture" if args.reference else "public.quality_fixture", "result": "FAILED",
                          "code": "QUALITY_FIXTURE_INSTALL_REJECTED"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
