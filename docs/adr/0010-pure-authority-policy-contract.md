# ADR0010: Strict policy syntax and a closed compatibility registry

Status: accepted for the pure module, 2026-11-16. Runtime authorization, administration, storage and projection contracts remain separate implementation and qualification gates.

`SYS-SEC-002` requires one authoritative policy model across ingress and projection paths. The existing tenant permission checks must remain enforceable while scoped grants, responsibilities, field policy and service identities are added. A permissive policy parser or an implicit mapping from new actions to old permissions would broaden access before those boundaries exist.

We adopt [SCOPED_AUTHORITY_PURE_CONTRACT.md](../execution/SCOPED_AUTHORITY_PURE_CONTRACT.md) for `packages/authority`. Its closed registry contains 103 compatibility actions with literal all-of predicates over ten existing permission strings, 21 administration actions, two field actions and ten service actions. The pure mapping never grants the new action families or establishes authentication, active membership or runtime authority. An independent predicate oracle checks every one of the 1,024 permission subsets.

Policy definitions use an exact versioned AST. Parsing rejects unknown properties, duplicate JSON keys and set members, unsafe values, malformed Unicode, unsupported actions and unregistered field handles. Normalization sorts declared sets while preserving rule and expression-child order. Canonical serialization and SHA-256 are deterministic syntax identifiers, not signatures, grants or proof of PostgreSQL equivalence.

External documents must enter as raw UTF-8 text through the 64 KiB file parser before JSON materialization. In-memory policy, catalog and permission objects require admission by a trusted bounded loader. Their defensive checks reject proxies and accessors without executing them, but enumerating arbitrary preexisting own keys cannot have a universal constant bound in standard JavaScript. This limitation is explicit; future adapters must prove their admission limits. The parser does not load ancestry or evaluate the exported 32-ancestor limit.

The implementation is independently useful as a strict, testable contract without activating policy decisions. Exporting an unfinished evaluator, auto-installing compatible grants, treating ownership labels as authority, or claiming runtime safety from syntax tests would be incorrect. No such path is introduced. Complete resource/projection registries, aggregate budgets, administration/bootstrap, current canonical evidence, deny handling, SQL equivalence, revocation, leases and atomic ingress cutover remain required work.

See the verification report and execution state for actual checks and their exact source bindings. Unit/type checks do not qualify runtime authorization, vendor integrations, deployment profiles or release readiness.
