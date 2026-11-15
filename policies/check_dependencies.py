#!/usr/bin/env python3
"""SPDX-expression gate for the installed pnpm host profile, not release images.

SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "policies/dependencies.yml").read_text())


class SPDXExpression:
    def __init__(self, expression: str):
        self.tokens = re.findall(r"\(|\)|[A-Za-z0-9.+:-]+", expression)
        if "".join(self.tokens) != re.sub(r"\s+", "", expression):
            raise ValueError("Unrecognized SPDX syntax")
        self.position = 0

    def take(self, token: str | None = None):
        current = self.tokens[self.position] if self.position < len(self.tokens) else None
        if token is None:
            if current is None:
                raise ValueError("Unexpected end of SPDX expression")
            self.position += 1
            return current
        if current == token:
            self.position += 1
            return True
        return False

    def atom(self):
        if self.take("("):
            result = self.disjunction()
            if not self.take(")"):
                raise ValueError("Unclosed SPDX parenthesis")
            return result
        identifier = self.take()
        if identifier in {"AND", "OR", "WITH", ")"}:
            raise ValueError("Expected SPDX license identifier")
        result = ("license", identifier)
        if self.take("WITH"):
            exception = self.take()
            if exception in {"AND", "OR", "WITH", "(", ")"}:
                raise ValueError("Expected SPDX exception identifier")
            result = ("with", result, exception)
        return result

    def conjunction(self):
        result = self.atom()
        while self.take("AND"):
            result = ("and", result, self.atom())
        return result

    def disjunction(self):
        result = self.conjunction()
        while self.take("OR"):
            result = ("or", result, self.conjunction())
        return result

    def parse(self):
        result = self.disjunction()
        if self.position != len(self.tokens):
            raise ValueError("Trailing SPDX tokens")
        return result


def evaluate(node):
    kind = node[0]
    if kind == "license":
        license_id = node[1]
        return license_id in POLICY["allow"], [license_id], POLICY["allow"].get(license_id, [])
    if kind == "with":
        allowed, chosen, obligations = evaluate(node[1])
        exception = node[2]
        return allowed and exception in POLICY["allowed_exceptions"], [f"{chosen[0]} WITH {exception}"], obligations + POLICY["allowed_exceptions"].get(exception, [])
    left, right = evaluate(node[1]), evaluate(node[2])
    if kind == "or":
        return left if left[0] else right if right[0] else (False, left[1] + right[1], left[2] + right[2])
    return left[0] and right[0], left[1] + right[1], left[2] + right[2]


def decision(expression: str) -> dict:
    try:
        allowed, selected, obligations = evaluate(SPDXExpression(expression).parse())
        return {"status": "ALLOW" if allowed else "REVIEW_REQUIRED", "selected_license_options": selected,
                "obligations": sorted(set(obligations))}
    except ValueError as error:
        return {"status": "REVIEW_REQUIRED", "selected_license_options": [], "obligations": [], "reason": str(error)}


def inventory() -> dict:
    directory = ROOT / "node_modules/.pnpm"
    if not directory.is_dir():
        raise ValueError("Installed pnpm profile is missing; run pnpm install --frozen-lockfile first")
    paths = list(directory.glob("*/node_modules/*/package.json")) + list(directory.glob("*/node_modules/@*/*/package.json"))
    packages = {}
    exceptions = json.loads((ROOT / "policies/license-exceptions.yml").read_text())["exceptions"]
    license_evidence = json.loads((ROOT / "policies/license-evidence.json").read_text())["evidence"]
    for path in paths:
        if path.is_symlink() or not path.exists():
            continue
        data = json.loads(path.read_text())
        name, version = data.get("name"), data.get("version")
        if not name or not version or name.startswith("@governance-commons/"):
            continue
        expression = data.get("license", "NOASSERTION")
        if isinstance(expression, dict):
            expression = expression.get("type", "NOASSERTION")
        if not isinstance(expression, str):
            expression = "NOASSERTION"
        declared_expression = expression
        provenance = None
        for evidence in license_evidence:
            if evidence["package"] == name and evidence["version"] == version and expression == "NOASSERTION":
                license_file = path.parent / evidence["license_file"]
                if not license_file.is_file() or hashlib.sha256(license_file.read_bytes()).hexdigest() != evidence["license_file_sha256"]:
                    raise ValueError(f"License evidence changed for {name}@{version}; review again")
                expression = evidence["license_expression"]
                provenance = evidence
        result = decision(expression)
        context = "installed-development-host-profile"
        for exception in exceptions:
            mandatory = {"package", "version", "license_expression", "distribution_context", "justification", "owner", "reviewed_at", "expires_at", "obligations"}
            if not mandatory.issubset(exception):
                raise ValueError("Incomplete license exception")
            if exception["package"] == name and exception["version"] == version and exception["license_expression"] == expression and exception["distribution_context"] == context:
                if dt.date.fromisoformat(exception["expires_at"]) >= dt.date.today():
                    result = {"status": "REVIEWED_EXCEPTION", "selected_license_options": [expression], "obligations": exception["obligations"], "owner": exception["owner"], "expires_at": exception["expires_at"]}
        packages[(name, version)] = {"package": name, "version": version,
             "source_url": f"https://registry.npmjs.org/{quote(name, safe='')}/{version}",
             "declared_license_expression": declared_expression, "license_expression": expression,
             "license_evidence": provenance, "distribution_context": context,
             "redistributed_in_release": "UNKNOWN_UNTIL_ARTIFACT_SCAN", "decision": result}
    records = [packages[key] for key in sorted(packages)]
    unresolved = sum(row["decision"]["status"] == "REVIEW_REQUIRED" for row in records)
    return {"schema_version": 1, "generator": "python3 policies/check_dependencies.py",
            "lock_sha256": hashlib.sha256((ROOT / "pnpm-lock.yaml").read_bytes()).hexdigest(),
            "outcome": "FAIL" if unresolved else "PASS", "packages": records, "unresolved_count": unresolved,
            "limitations": ["Installed pnpm development host profile only; platform-specific uninstalled optional packages are outside this inventory.",
                            "Not a finished-artifact SBOM. Image OS layers, Python distributions, external drivers and model weights require separate qualification.",
                            "ALLOW identifies a policy-compatible declared license; required notices must still be preserved in each distribution."]}


def self_test() -> None:
    cases = {"MIT": "ALLOW", "MIT AND GPL-3.0-only": "REVIEW_REQUIRED", "MIT OR GPL-3.0-only": "ALLOW",
             "(MIT OR GPL-3.0-only) AND Apache-2.0": "ALLOW", "NOASSERTION": "REVIEW_REQUIRED",
             "MIT WITH Unknown-exception": "REVIEW_REQUIRED", "MIT Apache-2.0": "REVIEW_REQUIRED",
             "(MIT OR Apache-2.0": "REVIEW_REQUIRED", "MIT AND (Apache-2.0 OR GPL-3.0-only)": "ALLOW"}
    for expression, expected in cases.items():
        assert decision(expression)["status"] == expected, expression
    assert decision("MIT OR GPL-3.0-only")["selected_license_options"] == ["MIT"]
    print(json.dumps({"outcome": "PASS", "spdx_expression_cases": len(cases)}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        report = inventory()
    except (ValueError, OSError) as error:
        failure = {"outcome": "FAIL", "reason": str(error), "generator": "python3 policies/check_dependencies.py", "packages": [], "qualification_complete": False}
        if args.write:
            (ROOT / "docs/legal/dependency-inventory.json").write_text(json.dumps(failure, indent=2) + "\n")
        print(json.dumps(failure))
        return 1
    if args.write:
        (ROOT / "docs/legal/dependency-inventory.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"outcome": report["outcome"], "package_count": len(report["packages"]),
                      "unresolved_count": report["unresolved_count"],
                      "unresolved": [{"package": row["package"], "version": row["version"], "license": row["license_expression"]} for row in report["packages"] if row["decision"]["status"] == "REVIEW_REQUIRED"]}, indent=2))
    return 0 if report["outcome"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
