# ADR 0003 — A shared bounded model validator

Status: accepted for implementation; module and ingress qualification remain in progress.

The operating model must produce the same validation decisions across REST, bulk imports, workflows and MCP. A separate schema implementation in each ingress would drift, especially for decimals, dates, nested objects and destructive changes.

Use a dependency-free TypeScript domain module with a bounded, discriminated JSON schema. Definitions and values are data; they cannot contain executable scripts or arbitrary validation expressions. Definitions have immutable tenant-scoped logical IDs and explicit positive versions. A shared parser returns structured issues with JSON Pointer paths. Decimal values remain canonical strings to avoid IEEE754 precision loss; rich text is bounded Markdown source and must be rendered with an explicitly safe renderer.

The first module covers typed attributes and upgrade previews. It does not implement inheritance, relation cardinality, model migration execution, the visual editor or all ingress integrations. Previewing affected records is distinct from performing a migration: removing/changing an existing field or invalidating stored values blocks publication until an explicit migration path exists. No implicit data truncation or type coercion is permitted.

The next integration stores tenant-scoped immutable model versions in PostgreSQL, uses the shared validator in application services, and connects a visual form/editor. APIs, imports, workflow tasks and MCP must call those application services rather than writing tables directly. Each integration needs real acceptance evidence before its requirement status advances.
