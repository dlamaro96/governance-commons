# Inactive authentication foundation

SQL012 introduces private, detached session provenance and finite native PostgreSQL login/API roles. It does not switch the existing browser login or grant tenant-content authority. The implementation and executed results are recorded separately in [STATE](../execution/STATE.md); the [contract](../execution/AUTHENTICATION_FOUNDATION_CONTRACT.md) fixes the exact schema, interfaces, limits and qualification scope.

`./dev bootstrap` preserves existing credentials and generates two additional local executor credentials in the private `.local/bootstrap.json`. These are not injected into existing application pools. `./dev up --profile core` starts PostgreSQL, stages a SET-only ownership-transfer membership, executes the checksum migrator as the native non-privileged migration owner, removes the transfer grants in a `finally` path, then creates or validates the two inactive executor roles. The application never receives the cluster administrator credential. Existing executors are validated without password rotation, grant repair or re-enabling LOGIN.

A startup interrupted after preparation can be recovered with `python3 scripts/runtime-authentication-roles.py finish`, which removes the exact temporary grants before validating final role flags. Retry startup after correcting the reported prerequisite. Preserve bootstrap credentials; replacing them does not rotate existing PostgreSQL passwords. Direct `pnpm db:migrate` requires the same independently installed role prerequisites. Neither the migration owner nor runtime role may gain CREATEROLE, superuser or BYPASSRLS.

Canonical installation is a separate operation. Store one complete strict manifest in a private regular file, mode0600, at most64KiB. The nine operations are register executor, advance its generation, register issuer, bind an existing canonical identity, initialize an inactive tenant fence, advance its generation, and revoke an executor, issuer or binding. The [candidate](../execution/AUTHENTICATION_FOUNDATION_CANDIDATE.md) and adopted contract list every field. No default identity, membership, issuer or executor registration is synthesized.

```sh
node --import tsx scripts/authentication-install.ts --check --input .local/installation-request.json
./dev authn-install --input .local/installation-request.json
```

The first command validates the manifest and reports its canonical hash without connecting. The second sends it through private stdin to the owner-only fixed SQL operation, verifies the exact returned hash and target, commits, and returns a receipt containing identifiers and timestamps. It never prints SQL, connection strings, raw inputs or database errors. Reuse the same complete manifest after an uncertain commit: request/hash matching returns the original immutable receipt; a changed request cannot be substituted. Native deployments can run the same TypeScript command with an existing securely supplied `MIGRATION_DATABASE_URL`; supported production packaging and activation remain separate release gates.

```sh
./dev test --suite authority-authn-foundation
```

This gate uses real PostgreSQL and SCRAM-authenticated connections in a separate `authn-foundation-tmpfs` profile. It requires cached images, at least1GiB host free space and observed Docker headroom; it never builds or pulls. PostgreSQL and a single helper have a combined896MiB hard memory ceiling, no host ports, read-only roots and bounded tmpfs storage. The gate checks exact SQL001–011 history preservation, SQL012 rollback/replay, least privilege, typed receipt codecs, real CLI behavior, sessions, revocation and concurrency. It preserves failed attempts under `.local/evidence` and removes only its own labelled containers. The existing2GiB build/upgrade floors remain unchanged. A unit/type result cannot substitute for this native gate.

External JWT validation, browser cookies/CSRF, canonical content authority, SQL/OpenSearch equivalence, policy administration, service leases and the atomic all-ingress cutover still require implementation and qualification. Disabling runtime activation does not remove those requirements.
