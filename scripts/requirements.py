#!/usr/bin/env python3
"""Maintain the frozen requirement register and deterministic public projections.

SPDX-License-Identifier: Apache-2.0

The .yaml registers use JSON syntax (a YAML 1.2 subset), intentionally requiring
only Python's standard library. Edit statuses/evidence in requirements.yaml;
generate never re-initializes or changes them. Source changes require a reviewed
baseline migration, not silently rerunning init over an existing register.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = ROOT / "docs/product"
REGISTER = PRODUCT / "requirements.yaml"
CONNECTORS = PRODUCT / "connector-support.yaml"
SPEC = PRODUCT / "BUILD_SPEC.md"
ID_PATTERN = (
    r"(?:CORE|MOD|CAT|SEM|NB|GOV|LIN|DQ|PRV|ACC|PROD|CON|REF|AI|MCP|DOC|INT|CX|DIF)-\d{3}"
    r"|UX-\d{2}|(?:AT|SYS)-[A-Z]+-\d{2,3}|E2E-\d{2}|OSS-\d{3}"
)
ID_RE = re.compile(r"\b(?:" + ID_PATTERN + r")\b")
SOURCE_RE = re.compile(r"\*\*((?:SRC-\d{2}|OSS-S\d+) +[—–-].+?)\*\*")
IMPLEMENTATION = {"NOT_STARTED", "IN_PROGRESS", "IMPLEMENTED"}
OUTCOMES = {"NOT_RUN", "PASS", "FAIL", "BLOCKED_EXTERNAL", "NOT_APPLICABLE"}
FEATURES = (
    "metadata table_lineage column_lineage transformations profile sample dq_pushdown "
    "classification tag_writeback grant_read grant_write mask_write row_filter_write "
    "ai_registry ai_metrics document_content acl_sync"
).split()

# Explicitly separate named products/profiles; slash-separated aliases remain
# aliases only when the specification says they are aliases. These are baseline
# targets, not supported-adapter claims or a completed marketplace inventory.
NAMED_ROUTES = {
    1: ["PostgreSQL"],
    2: ["SQL Server", "Azure SQL"],
    3: ["Oracle"],
    4: ["MySQL", "MariaDB"],
    5: ["Databricks Unity Catalog metadata", "Databricks Unity Catalog system-table lineage", "Databricks Unity Catalog outbound metadata and tags", "Databricks Unity Catalog source access management"],
    6: ["Snowflake"],
    7: ["BigQuery", "Google Cloud Data Lineage API"],
    8: ["Amazon Redshift"],
    9: ["Local S3-compatible object storage", "AWS S3"],
    10: ["ADLS Gen2", "Azure Blob", "Microsoft Purview schema enrichment"],
    11: ["Google Cloud Storage"],
    12: ["Microsoft Fabric lakehouse", "Microsoft Fabric warehouse", "Microsoft Fabric database items", "Microsoft Fabric notebook lineage", "Microsoft Fabric pipeline lineage"],
    13: ["Power BI Service"],
    14: ["Power BI Report Server", "SQL Server Reporting Services"],
    15: ["Tableau", "Looker"],
    16: ["Azure Data Factory"],
    17: ["dbt Core", "dbt Cloud"],
    18: ["OpenLineage", "Apache Airflow"],
    19: ["Informatica", "SQL Server Integration Services"],
    20: ["SAP S/4HANA"],
    21: ["SAP HANA"],
    22: ["SAP BW", "SAP BW/4HANA"],
    23: ["SAP BusinessObjects Data Services"],
    24: ["SAP Datasphere"],
    25: ["Salesforce"],
    26: ["Documentum"],
    27: ["SharePoint", "Local filesystem"],
    28: ["Microsoft Entra ID OIDC", "Microsoft Entra ID directory ingestion", "Okta OIDC", "Okta directory ingestion"],
    29: ["ServiceNow issue synchronization", "Jira issue synchronization", "ServiceNow JDBC catalog"],
    30: ["Azure AI Foundry", "Azure Machine Learning", "Databricks AI", "Amazon Bedrock", "Amazon SageMaker", "MLflow", "Dataiku", "OpenAI", "Anthropic", "Google Gemini", "SAP AI Core", "Snowflake Cortex"],
    31: ["MCP context server", "MCP tool gateway", "Independent MCP clients"],
    32: ["Amazon Athena", "Amazon DynamoDB"],
    33: ["AWS Glue", "AWS Lake Formation", "Amazon SageMaker Unified Studio"],
    34: ["Apache Cassandra", "Apache HBase", "IBM Cloudant", "Couchbase", "MongoDB", "Azure Cosmos DB"],
    35: ["Apache Hive", "Cloudera Hive", "Apache Impala", "Apache Spark SQL"],
    36: ["Apache Kafka", "Kafka Schema Registry"],
    37: ["Apache Avro", "CSV", "JSON", "Parquet", "XML", "SAS Data Sets"],
    38: ["Databricks Lakebase", "Google AlloyDB", "SingleStore"],
    39: ["Denodo", "Dremio", "Exasol", "Presto", "Starburst", "Trino", "Rocket Vertica"],
    40: ["Elastic", "Progress MarkLogic", "Splunk"],
    41: ["Google Cloud Spanner", "Greenplum", "IBM Db2 LUW", "IBM Informix", "Netezza", "Teradata", "SAP ASE/Sybase"],
    42: ["Google Knowledge Catalog/Dataplex", "Databricks Listings", "Google Cloud Data Products", "Snowflake Listings", "SAP Data Products"],
    43: ["Google Sheets", "Microsoft Excel files", "Microsoft Excel Online"],
    44: ["Alteryx", "IBM DataStage", "Fivetran", "Matillion"],
    45: ["Azure Analysis Services tabular", "SQL Server Analysis Services tabular", "SQL Server Analysis Services multidimensional"],
    46: ["Azure SQL Data Warehouse", "Azure Synapse Analytics dedicated SQL", "Azure Synapse Analytics serverless SQL", "Azure Table Storage"],
    47: ["Dynamics 365 Business Central", "Dynamics 365 Sales"],
    48: ["Oracle E-Business Suite", "JD Edwards EnterpriseOne", "PeopleSoft", "Siebel"],
    49: ["SAP ECC", "SAP ERP", "SAP Master Data Governance", "SAP SuccessFactors", "SAP Signavio"],
    50: ["SAP Analytics Cloud", "Qlik", "Sigma Computing", "Strategy/MicroStrategy", "ThoughtSpot"],
    51: ["Microsoft Teams", "Slack"],
    52: ["Workday"],
    53: ["Reltio"],
    54: ["Soda", "Precisely Trillium Discovery"],
    55: ["Solidatus", "SqlDBM"],
    56: ["Privacera"],
    57: ["Partner Vertex AI capability route", "Partner Tableau capability route", "Partner SSAS capability route", "Partner AAS capability route", "Partner SAP HANA capability route", "Partner Power BI capability route"],
    58: ["Unreconciled remaining partner/community marketplace listings"],
}

MILESTONES = {
    "CORE": "M1", "MOD": "M3", "CAT": "M2", "SEM": "M4", "NB": "M5",
    "GOV": "M3", "LIN": "M4", "DQ": "M4", "PRV": "M7", "ACC": "M5",
    "PROD": "M4", "CON": "M4", "REF": "M2", "AI": "M6", "MCP": "M6",
    "DOC": "M7", "INT": "M8", "CX": "M8", "DIF": "M7", "UX": "M2",
    "AT": "M10", "E2E": "M10", "SYS": "M0", "OSS": "M0", "SPEC": "M0",
}
FAMILY_DEPS = {
    "MOD": ["SYS-DATA-001", "SYS-SEC-002"],
    "CAT": ["SYS-DATA-001", "SYS-DATA-002", "SYS-SEC-003"],
    "SEM": ["MOD-001", "CAT-001"], "NB": ["INT-001", "SYS-DQ-001", "SYS-SEC-002"],
    "GOV": ["SYS-DATA-004", "SYS-SEC-005"], "LIN": ["SYS-DATA-003", "CAT-002"],
    "DQ": ["SYS-DQ-001", "SYS-EDGE-001"], "PRV": ["GOV-001", "SYS-DATA-005"],
    "ACC": ["SYS-SEC-002", "SYS-SEC-005", "INT-001"],
    "PROD": ["CAT-001", "GOV-001"], "CON": ["CAT-001", "SYS-API-001"],
    "REF": ["MOD-001", "GOV-001"], "AI": ["SYS-AI-001", "SYS-SEC-003"],
    "MCP": ["SYS-MCP-001", "SYS-SEC-002"], "DOC": ["SYS-SEC-004", "SYS-DATA-002"],
    "INT": ["SYS-EDGE-001", "SYS-EDGE-002"], "CX": ["INT-001", "INT-002", "INT-003"],
    "DIF": ["SYS-TEST-004"], "UX": ["SYS-API-001", "SYS-SEC-002"],
}
FAMILY_SOURCES = {
    "MOD": ["SRC-01", "SRC-02"], "CORE": ["SRC-01", "SRC-02"],
    "CAT": ["SRC-03", "SRC-04"], "SEM": ["SRC-37"], "NB": ["SRC-36"],
    "GOV": ["SRC-05", "SRC-06", "SRC-07", "SRC-38"],
    "LIN": ["SRC-08", "SRC-09"], "DQ": ["SRC-10"], "PRV": ["SRC-11", "SRC-12"],
    "ACC": ["SRC-13"], "PROD": ["SRC-14", "SRC-15", "SRC-16"],
    "CON": ["SRC-15", "SRC-35"], "REF": ["SRC-17"], "DOC": ["SRC-18"],
    "AI": ["SRC-19", "SRC-20"], "MCP": ["SRC-21", "SRC-22"],
    "INT": ["SRC-08", "SRC-09", "SRC-23", "SRC-24", "SRC-39", "SRC-40"],
    "CX": ["SRC-39", "SRC-40"],
}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def source_span(lines: list[str], start: int, end: int) -> dict:
    text = "\n".join(lines[start - 1:end])
    return {"path": "docs/product/BUILD_SPEC.md", "line_start": start, "line_end": end,
            "text": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}


def category(rid: str) -> str:
    if rid.startswith("CX-"):
        return "connector"
    if rid.startswith("SYS-"):
        return "architecture"
    if rid.startswith("OSS-"):
        return "repository"
    if rid.startswith(("E2E-", "AT-")):
        return "acceptance"
    if rid.startswith("UX-"):
        return "screen"
    if rid.startswith("SPEC-"):
        return "cross_cutting"
    return "capability"


def base_row(rid: str, title: str, description: str, acceptance: list[str], span: dict,
             section: str, kind: str = "baseline", parent: str | None = None) -> dict:
    prefix = rid.split("-")[0]
    acceptance_ids = sorted(set(re.findall(r"\b(?:AT-[A-Z]+-\d{2}|E2E-\d{2})\b", description + " " + " ".join(acceptance))))
    acceptance_ids = [x for x in acceptance_ids if x != rid]
    return {
        "id": rid, "kind": kind, "parent_id": parent, "category": category(rid),
        "title": title, "description": description, "required": True,
        "activation": "Required implementation; runtime activation follows the specification.",
        "source": span, "source_section": section,
        "source_references": FAMILY_SOURCES.get(prefix, []),
        "dependencies": [x for x in FAMILY_DEPS.get(prefix, []) if x != rid],
        "dependency_basis": "Initial engineering ordering; source text remains authoritative.",
        "acceptance_criteria": acceptance, "acceptance_ids": acceptance_ids,
        "implementation_status": "NOT_STARTED", "implementation_paths": [],
        "test_ids": [], "verification": {scope: {"outcome": "NOT_RUN", "evidence": []}
                                            for scope in ("fixture", "local", "vendor_live", "manual", "enterprise")},
        "qualification_profiles": [], "release_qualification": {"outcome": "NOT_RUN", "evidence": []},
        "limitations": [], "owner": "unassigned", "milestone": MILESTONES.get(prefix, "M10"),
    }


def blocks(lines: list[str], start: int, end: int):
    """Yield indivisible prose/list/table/code blocks with precise line spans."""
    current: list[str] = []
    beginning = start
    in_code = False
    for number in range(start, end + 1):
        line = lines[number - 1]
        if line.startswith("```"):
            if not in_code and current:
                yield beginning, number - 1, "\n".join(current)
                current = []
            if not current:
                beginning = number
            current.append(line)
            in_code = not in_code
            if not in_code:
                yield beginning, number, "\n".join(current)
                current = []
            continue
        if in_code:
            current.append(line)
            continue
        individual = bool(re.match(r"^(?:\||[-*] |\d+\. )", line))
        if not line.strip() or individual:
            if current:
                yield beginning, number - 1, "\n".join(current)
                current = []
            if individual:
                yield number, number, line
            continue
        if not current:
            beginning = number
        current.append(line)
    if current:
        yield beginning, end, "\n".join(current)


def parse_spec(spec: Path) -> tuple[dict, dict]:
    raw = spec.read_bytes()
    lines = raw.decode().splitlines()
    sections: dict[int, str] = {}
    section = "Specification introduction"
    headings = []
    for number, line in enumerate(lines, 1):
        if line.startswith("#"):
            section = line.lstrip("# ")
            headings.append((number, len(line) - len(line.lstrip("#")), section))
        sections[number] = section
    requirements = []
    covered = set()
    named = set()
    for number, line in enumerate(lines, 1):
        table = re.match(r"^\|\s*((?:" + ID_PATTERN + r"))(?:\s+([^|]*))?\s*\|", line)
        heading = re.match(r"^#{3,4} .*?(SYS-[A-Z]+-\d{3}|OSS-\d{3})(?:\]|:)(.*)$", line)
        if table:
            rid = table.group(1)
            cells = [x.strip() for x in line.strip("|").split("|")]
            suffix = cells[0][len(rid):].strip()
            if rid.startswith("CX-"):
                title, description = suffix, cells[-1]
                acceptance = [cells[-1]]
            elif rid.startswith("UX-"):
                title, description = cells[1], cells[2]
                acceptance = ["Functioning route or contextual view with real API data; defined empty, loading, error and permission states; browser coverage for its main action.", cells[2]]
            elif len(cells) >= 3:
                title, description = cells[1][:160], cells[1]
                acceptance = [cells[2]]
            else:
                raise ValueError(f"Unrecognized requirement row at line {number}")
            row = base_row(rid, title, description, acceptance, source_span(lines, number, number), sections[number])
            if rid.startswith("CX-") and len(cells) >= 3:
                row["public_comparison_baseline"] = cells[1]
            requirements.append(row)
            named.add(rid)
            covered.add(number)
        elif heading:
            rid = heading.group(1)
            level = len(line) - len(line.lstrip("#"))
            end = next((n - 1 for n, lev, _ in headings if n > number and lev <= level), len(lines))
            while end > number and not lines[end - 1].strip():
                end -= 1
            body = "\n".join(lines[number:end]).strip()
            row = base_row(rid, heading.group(2).strip(" :"), body,
                           ["Demonstrate every normative clause below with implementation and applicable automated/manual evidence; retain unexecuted qualifications as open."],
                           source_span(lines, number, end), sections[number])
            requirements.append(row)
            named.add(rid)
            covered.update(range(number, end + 1))
            child_number = 0
            for start, stop, text in blocks(lines, number + 1, end):
                if text.startswith("```") or text.startswith("|---") or text.startswith("| Concern") or text.startswith("| File") or text.startswith("| Profile"):
                    continue
                child_number += 1
                child = base_row(f"{rid}.{child_number:02d}", text[:140], text,
                                 [text], source_span(lines, start, stop), sections[number], "clause", rid)
                child["dependencies"] = []
                requirements.append(child)

    # Keep all non-numbered normative context in scope. Background reference
    # registers, the document contents list and example schemas are context in
    # BUILD_SPEC, not false implementation requirements.
    supplemental_number = 0
    omitted_sections = {"Sections:", "3.17 Source register", "Primary sources", "5.H Primary standards and documentation references", "11. Execution and design reference sources"}
    for start, stop, text in blocks(lines, 1, len(lines)):
        if any(n in covered for n in range(start, stop + 1)):
            continue
        section = sections[start]
        if text.startswith("#") or section in omitted_sections:
            continue
        if text.startswith("```"):
            if section == "7.3 Local operator commands":
                for number in range(start + 1, stop):
                    command = lines[number - 1].strip()
                    if not command:
                        continue
                    row = base_row(f"SYS-CLI-{number - start:03d}", command,
                                   f"Implement the documented operator command {command} with safe defaults, bounded execution, machine-readable outcome and an accurate nonzero failure exit code.",
                                   [f"Execute {command} against the documented applicable real profile; capture command, tool versions, environment, outcome, exit code and evidence. Destructive operations remain scoped to the explicitly named isolated environment."],
                                   source_span(lines, number, number), section, "operator_command")
                    row["dependencies"] = ["SYS-OPS-001", "SYS-TEST-002"]
                    requirements.append(row)
            continue
        if section in {"How to use this prompt", "Public capability baseline"}:
            continue
        if re.match(r"^\|(?:\s*:?-+:?\s*\|)+$", text) or re.match(r"^\| (?:ID|Test ID|Family|File|Persona|API group|Milestone)\b", text):
            continue
        if SOURCE_RE.search(text) or "https://" in text and section.startswith("Specific uncertainty") is False and start > 1350:
            continue
        supplemental_number += 1
        rid = f"SPEC-{supplemental_number:03d}"
        row = base_row(rid, text[:140], text, [text], source_span(lines, start, stop), section, "supplemental")
        # Supplemental lifecycle/format rules are requirements, even where an
        # equivalent named requirement has a separate, narrower acceptance test.
        requirements.append(row)

    # Split multi-sentence named product/screen requirements without deleting
    # their complete parent. Lists within a sentence remain bound by the parent.
    for parent in list(requirements):
        if parent["kind"] != "baseline" or parent["id"].startswith(("SYS-", "OSS-", "CX-")):
            continue
        parts = re.split(r"(?<=[.!?])\s+(?=[A-Z`])", parent["description"])
        if len(parts) <= 1:
            continue
        for index, text in enumerate(parts, 1):
            child = base_row(f"{parent['id']}.{index:02d}", text[:140], text,
                             [text, *parent["acceptance_criteria"]], parent["source"], parent["source_section"], "clause", parent["id"])
            child["dependencies"] = parent["dependencies"][:]
            requirements.append(child)

    parent_map = {r["id"]: r for r in requirements}
    connector_rows = []
    for number, names in NAMED_ROUTES.items():
        parent_id = f"CX-{number:03d}"
        parent = parent_map[parent_id]
        for index, name in enumerate(names, 1):
            rid = f"{parent_id}.SRC-{index:02d}"
            child = base_row(rid, name, f"Implement and independently qualify the named route {name}. Parent scope: {parent['description']}",
                             [f"A source-specific manifest, substantive adapter, fixture/conformance tests and qualification procedure exist for {name}.", parent["description"]],
                             parent["source"], parent["source_section"], "unreconciled_inventory" if number == 58 else "named_connector_route", parent_id)
            if name == "Microsoft Purview schema enrichment":
                child["required"] = False
                child["activation"] = "Conditional enhancement: required if claiming Purview-assisted schemas; the unconditional ADLS/Blob targets remain required."
            requirements.append(child)
            slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
            connector_rows.append({
                "connector_id": slug, "requirement_id": rid, "parent_requirement_id": parent_id,
                "name": name, "target_scope": parent["description"], "required": child["required"],
                "unreconciled_inventory": number == 58,
                "implementation_status": "NOT_STARTED", "adapter_paths": [], "manifest_path": None,
                "planned_manifest_path": f"connectors/manifests/{slug}.json", "source_versions": [],
                "capabilities": {flag: {"implemented": False, "tested_source_versions": [],
                                       "verification_level": None, "verification_outcome": "NOT_RUN",
                                       "limitations": ["No adapter or per-feature capability declaration has been qualified."],
                                       "test_evidence": []} for flag in FEATURES},
                "verification": {scope: {"outcome": "NOT_RUN", "evidence": []} for scope in ("fixture", "local", "vendor_live")},
                "qualification_prerequisites": [f"Document the supported {name} source/API version and authorized interface.",
                                               "Implement source-specific fixtures and conformance tests.",
                                               "For a live claim: an authorized isolated source, scoped test identity, required operation permissions, and redacted run evidence."],
                "installations": [], "limitations": ["Baseline target only; no implementation or supported-version claim."],
            })
    sources = []
    for number, line in enumerate(lines, 1):
        match = SOURCE_RE.search(line)
        if match:
            sources.append({"id": match.group(1).split(" ", 1)[0], "text": line,
                            "source_line": number, "urls": re.findall(r"https?://[^\s;]+", line),
                            "revalidation_status": "NOT_RUN", "retrieved_at": None, "content_sha256": None})
    all_refs = set(ID_RE.findall(raw.decode()))
    missing = all_refs - named
    if missing:
        raise ValueError(f"Referenced IDs lack definitions: {sorted(missing)}")
    requirements.sort(key=lambda row: (row["source"]["line_start"], row["id"]))
    register = {
        "schema_version": 1,
        "encoding": "JSON-compatible YAML 1.2; parse with Python json or a YAML 1.2 parser.",
        "baseline": {"name": "Governance Commons full programme", "version": "2026-11-15",
                     "source_path": "docs/product/BUILD_SPEC.md", "source_sha256": hashlib.sha256(raw).hexdigest(),
                     "source_line_count": len(lines), "named_requirement_ids": sorted(named),
                     "source_revalidation_status": "NOT_RUN"},
        "conventions": {"canonical_status_source": "This file; generated CSV and Markdown must not be edited directly.",
                        "parent_completion": "A parent is IMPLEMENTED only when its entire text and all required children are implemented. Passing a slice does not complete its parent.",
                        "verification": "PASS requires recorded executed evidence for the exact capability and profile; all other qualifications remain distinct.",
                        "runtime_health": "Belongs to connector installations and runs, never inferred from adapter implementation or qualification.",
                        "optional_activation": "Does not make required implementation optional.",
                        "dependency_review": "Dependencies are initial work ordering; review before implementation. They do not narrow the normative source.",
                        "child_scope": "Children improve testability; the complete parent remains binding, including lists not fully split into child clauses."},
        "source_register": sources,
        "requirements": requirements,
    }
    connectors = {
        "schema_version": 1, "baseline_version": "2026-11-15", "source_register": "docs/product/requirements.yaml",
        "status_authority": "Requirement implementation/evidence belongs in requirements.yaml; this matrix records independent per-feature and source-version qualification.",
        "verification_levels": {"null": "Not designed or verified; no V0 claim.", "V0": "Manifest and adapter contract exist; no working-runtime claim.",
                                "V1": "Fixture verified", "V2": "Real local source profile verified", "V3": "Named external service live verified"},
        "marketplace_reconciliation": {"outcome": "NOT_RUN", "complete": False,
                                       "requirements": ["INT-008", "INT-009", "CX-057", "CX-058", "AT-BASELINE-01"],
                                       "listing_urls": ["https://www.collibra.com/products/integrations-apis/integrations", "https://marketplace.collibra.com/search/?_solution_type=partner-integration"],
                                       "retrieved_at": None, "source_hashes": [], "mapped_listing_count": 0,
                                       "remaining_prerequisite": "Retrieve all directory/source and marketplace pages; freeze every distinct listing/capability route with URL, publisher, support/offer type, source hash, alias and original-adapter mapping. Named targets are not a complete marketplace inventory.",
                                       "unresolved_entries": ["Every remaining paginated partner/community listing; exact count unknown until traversal."]},
        "connectors": connector_rows,
    }
    return register, connectors


def projections(register: dict) -> dict[Path, str]:
    output = io.StringIO(newline="")
    fields = ["id", "description", "implementation_paths", "test_ids", "status", "evidence_paths", "known_limitations", "owner"]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in register["requirements"]:
        evidence = sorted({path for scope in row["verification"].values() for path in scope.get("evidence", [])})
        status = {"implementation": row["implementation_status"],
                  "verification": {key: value["outcome"] for key, value in row["verification"].items()},
                  "release_qualification": row["release_qualification"]["outcome"]}
        writer.writerow({"id": row["id"], "description": row["description"],
                         "implementation_paths": json.dumps(row["implementation_paths"]),
                         "test_ids": json.dumps(sorted(set(row["test_ids"] + row["acceptance_ids"]))),
                         "status": json.dumps(status, sort_keys=True), "evidence_paths": json.dumps(evidence),
                         "known_limitations": json.dumps(row["limitations"]), "owner": row["owner"]})
    markdown = ["# Capability parity and gap matrix", "", "Generated by `python3 scripts/requirements.py generate` from `requirements.yaml`. Do not edit this projection.", "",
                "The comparison baseline is the supplied specification dated 15 November 2026. Its cited external sources have not yet been independently revalidated. These rows are target requirements, not claims of competitor parity or supported integrations. Complete implementation still requires every parent clause and child route.", "",
                "Implementation, fixture/local/vendor-live verification, and release qualification remain separate. Connector runtime health belongs to configured installations. Unfetched marketplace pages remain an explicit gap under INT-008/CX-058.", "",
                "| ID | Baseline / original target | Product behavior | Implementation | Fixture / local / live | Gaps |",
                "|---|---|---|---|---|---|"]
    escape = lambda value: str(value).replace("|", "\\|").replace("\n", "<br>")
    for row in register["requirements"]:
        if row["category"] not in {"capability", "connector"} or row["kind"] == "clause":
            continue
        comparison = row.get("public_comparison_baseline", "Original target; see " + ", ".join(row["source_references"]))
        verification = " / ".join(row["verification"][scope]["outcome"] for scope in ("fixture", "local", "vendor_live"))
        gaps = "; ".join(row["limitations"]) or ("Implementation and qualification open" if row["implementation_status"] == "NOT_STARTED" else "See canonical register and evidence")
        markdown.append("| " + " | ".join(escape(x) for x in [row["id"], comparison, row["description"], row["implementation_status"], verification, gaps]) + " |")
    return {PRODUCT / "traceability.csv": output.getvalue(), PRODUCT / "parity-matrix.md": "\n".join(markdown) + "\n"}


def validate(register: dict, connectors: dict, spec: Path, check_generated: bool = True) -> dict:
    errors = []
    raw = spec.read_bytes()
    lines = raw.decode().splitlines()
    if hashlib.sha256(raw).hexdigest() != register["baseline"]["source_sha256"]:
        errors.append("Frozen specification hash changed; review and migrate the requirement baseline explicitly.")
    rows = register["requirements"]
    ids = [row["id"] for row in rows]
    duplicates = [rid for rid, count in Counter(ids).items() if count != 1]
    if duplicates:
        errors.append(f"Duplicate IDs: {duplicates}")
    id_set = set(ids)
    source_ids = set(ID_RE.findall(raw.decode()))
    named = {row["id"] for row in rows if row["kind"] == "baseline"}
    if source_ids != named:
        errors.append(f"Named-ID mismatch: missing={sorted(source_ids - named)}, unexpected={sorted(named - source_ids)}")
    by_id = {row["id"]: row for row in rows}
    for row in rows:
        rid = row["id"]
        if row["implementation_status"] not in IMPLEMENTATION:
            errors.append(f"{rid}: invalid implementation status")
        if row["implementation_status"] == "IMPLEMENTED" and not row["implementation_paths"]:
            errors.append(f"{rid}: IMPLEMENTED needs real implementation paths")
        for path in row["implementation_paths"]:
            if not (ROOT / path).exists():
                errors.append(f"{rid}: missing implementation path {path}")
        if not row["acceptance_criteria"]:
            errors.append(f"{rid}: no acceptance criteria")
        for linked in row["dependencies"] + row["acceptance_ids"]:
            if linked not in id_set:
                errors.append(f"{rid}: unknown linked requirement {linked}")
        if row["parent_id"] and row["parent_id"] not in id_set:
            errors.append(f"{rid}: missing parent")
        source = row["source"]
        actual = "\n".join(lines[source["line_start"] - 1:source["line_end"]])
        if actual != source["text"] or hashlib.sha256(actual.encode()).hexdigest() != source["sha256"]:
            errors.append(f"{rid}: source-span drift")
        for scope, verification in {**row["verification"], "release": row["release_qualification"]}.items():
            outcome = verification["outcome"]
            if outcome not in OUTCOMES:
                errors.append(f"{rid}/{scope}: invalid outcome {outcome}")
            if outcome in {"PASS", "FAIL"} and not verification.get("evidence"):
                errors.append(f"{rid}/{scope}: {outcome} needs executed evidence")
            if outcome == "NOT_APPLICABLE" and not verification.get("reason"):
                errors.append(f"{rid}/{scope}: NOT_APPLICABLE needs reason")
            if outcome == "BLOCKED_EXTERNAL" and not verification.get("prerequisite"):
                errors.append(f"{rid}/{scope}: BLOCKED_EXTERNAL needs exact prerequisite")
            for evidence in verification.get("evidence", []):
                if not (ROOT / evidence).exists():
                    errors.append(f"{rid}/{scope}: missing evidence {evidence}")
        if row["implementation_status"] == "IMPLEMENTED":
            incomplete = [child["id"] for child in rows if child["parent_id"] == rid and child["required"] and child["implementation_status"] != "IMPLEMENTED"]
            if incomplete:
                errors.append(f"{rid}: required children remain open: {incomplete}")
    # Ensure dependency cycles cannot accidentally make execution impossible.
    visiting, visited = set(), set()
    def visit(rid: str) -> None:
        if rid in visiting:
            errors.append(f"Dependency cycle through {rid}")
            return
        if rid in visited or rid not in by_id:
            return
        visiting.add(rid)
        for dependency in by_id[rid]["dependencies"]:
            visit(dependency)
        visiting.remove(rid)
        visited.add(rid)
    for rid in ids:
        visit(rid)
    expected_routes = {row["id"] for row in rows if row["kind"] in {"named_connector_route", "unreconciled_inventory"}}
    matrix_routes = [row["requirement_id"] for row in connectors["connectors"]]
    if expected_routes != set(matrix_routes) or len(matrix_routes) != len(set(matrix_routes)):
        errors.append("Connector matrix does not cover each named route exactly once")
    connector_ids = [row["connector_id"] for row in connectors["connectors"]]
    if len(connector_ids) != len(set(connector_ids)):
        errors.append("Duplicate connector IDs")
    for number in range(32, 57):
        parent_id = f"CX-{number:03d}"
        names = by_id[parent_id]["title"].split("; ")
        mapped = [row["name"].casefold() for row in connectors["connectors"] if row["parent_requirement_id"] == parent_id]
        for name in names:
            if not any(name.casefold() in target for target in mapped):
                errors.append(f"{parent_id}: semicolon-separated named source {name!r} has no individual route")
    for connector in connectors["connectors"]:
        if connector["implementation_status"] != by_id[connector["requirement_id"]]["implementation_status"]:
            errors.append(f"{connector['connector_id']}: implementation status differs from canonical register")
        if set(connector["capabilities"]) != set(FEATURES):
            errors.append(f"{connector['connector_id']}: incomplete capability dimensions")
        for feature, detail in connector["capabilities"].items():
            if detail["verification_level"] in {"V1", "V2", "V3"} and (not detail["implemented"] or not detail["test_evidence"] or not detail["tested_source_versions"]):
                errors.append(f"{connector['connector_id']}/{feature}: verified claim lacks implementation/version/evidence")
    if check_generated:
        for path, expected in projections(register).items():
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                errors.append(f"Generated projection drift: {path.relative_to(ROOT)}; run generate")
    summary = {"outcome": "FAIL" if errors else "PASS", "named_requirements": len(named),
               "registered_requirements": len(rows), "kinds": dict(sorted(Counter(row["kind"] for row in rows).items())),
               "categories": dict(sorted(Counter(row["category"] for row in rows).items())),
               "implementation_statuses": dict(sorted(Counter(row["implementation_status"] for row in rows).items())),
               "verification_outcomes": dict(sorted(Counter(v["outcome"] for row in rows for v in row["verification"].values()).items())),
               "named_connector_routes": sum(not row["unreconciled_inventory"] for row in connectors["connectors"]),
               "unreconciled_inventory_rows": sum(row["unreconciled_inventory"] for row in connectors["connectors"]),
               "source_references": len(register["source_register"]),
               "marketplace_reconciliation_complete": connectors["marketplace_reconciliation"]["complete"], "errors": errors}
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["init", "generate", "validate", "summary"])
    parser.add_argument("--spec", type=Path, default=SPEC)
    args = parser.parse_args()
    if args.command == "init":
        if REGISTER.exists() or CONNECTORS.exists():
            parser.error("init refuses to overwrite a canonical register; use generate or a reviewed baseline migration")
        register, connectors = parse_spec(args.spec)
        write_json(REGISTER, register)
        write_json(CONNECTORS, connectors)
    else:
        register = json.loads(REGISTER.read_text(encoding="utf-8"))
        connectors = json.loads(CONNECTORS.read_text(encoding="utf-8"))
    if args.command in {"init", "generate"}:
        preliminary = validate(register, connectors, args.spec, check_generated=False)
        if preliminary["errors"]:
            print(json.dumps(preliminary, indent=2))
            return 1
        for path, content in projections(register).items():
            path.write_text(content, encoding="utf-8")
    result = validate(register, connectors, args.spec)
    print(json.dumps(result, indent=2))
    return 0 if not result["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
