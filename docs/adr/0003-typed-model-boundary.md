# ADR 0003 — A shared bounded model validator

Status: accepted for implementation; module and ingress qualification remain in progress.

The operating model must produce the same validation decisions across REST, bulk imports, workflows and MCP. A separate schema implementation in each ingress would drift, especially for decimals, dates, nested objects and destructive changes.

Use a dependency-free TypeScript domain module with a bounded, discriminated JSON schema. Definitions and values are data; they cannot contain executable scripts or arbitrary validation expressions. Definitions have immutable tenant-scoped logical IDs and explicit positive versions. A shared parser returns structured issues with JSON Pointer paths. Decimal values remain canonical strings to avoid IEEE754 precision loss; rich text is bounded Markdown source and must be rendered with an explicitly safe renderer.

The first module covers typed attributes and upgrade previews. The initial module does not implement inheritance, relation cardinality, migration execution or all ingress integrations. The persisted increment below now includes a visual editor. Previewing affected records is distinct from performing a migration: removing/changing an existing field or invalidating stored values blocks publication until an explicit migration path exists. No implicit data truncation or type coercion is permitted.

The persisted integration stores tenant-scoped immutable model versions in PostgreSQL, uses the shared validator in application services, and connects a visual form/editor. APIs, imports, workflow tasks and MCP must call those application services rather than writing tables directly. Each integration needs real acceptance evidence before its requirement status advances.

The persisted attribute-model increment uses immutable version rows and explicit asset pins. Publishing a compatible definition does not repin existing assets. The server enumerates and validates all bound canonical assets, rejects incomplete visibility or bounded-profile overflow, and hashes the exact proposal, head, pins, values and asset versions into a preview digest. Publication rechecks that digest under canonical locks. Destructive changes use the explicit declarative migration service described in ADR0004; the ordinary publication path continues to reject them.

Audited tenant mutations acquire the tenant ledger advisory lock before canonical row locks. Model previews and mutations then acquire the tenant model lock and ordered asset locks. This consistent order prevents a multi-asset scan from holding the audit lock while waiting on an editor that holds an asset row and waits on the audit lock. It serializes tenant mutation transactions in the current development profile; measured enterprise throughput and any future partitioned audit design remain separate qualification work. Read-only catalog/search requests do not take this lock.
