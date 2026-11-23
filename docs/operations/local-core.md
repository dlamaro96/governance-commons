# Operate the local development core

The core profile runs PostgreSQL, OpenSearch, Temporal, Keycloak, SeaweedFS and
the application/source workers with synthetic Harbor and Summit data. It is a
development environment. Deployment availability, backup/restore and supported
release qualification remain tracked in [release readiness](../release/READINESS.md).

Install the tools described in [CONTRIBUTING](../../CONTRIBUTING.md), then run:

```sh
./dev doctor
./dev bootstrap
./dev up --profile core
./dev seed --dataset harbor-demo
./dev authn-core-install
./dev status
```

Open [the local application](http://127.0.0.1:4310). Bootstrap generates the
synthetic persona credentials in the private `.local/bootstrap.json` file.
Existing credentials are preserved on subsequent bootstrap runs. The initial
core startup creates the required service roles, applies forward migrations and
waits for healthy dependencies. `./dev doctor` reports actual capacity and port
admission; its disk floor is 8 GiB when required images are missing and 4 GiB
when they are cached. Image builds need additional working space.

`./dev authn-core-install` is an explicit owner installation step after seeding.
It verifies the local Keycloak client and installs protected login registrations,
identity bindings and the SQL037 application session bridge. The application
uses `http://127.0.0.1:4310`; the Keycloak issuer remains
`http://localhost:4311/realms/governance`. Use the application origin shown above
so callback, cookie and origin checks agree.

The first installation creates a private plan with a fixed 24-hour lifetime and
persists it in the `authn-installation` Compose volume. Repeating the command
replays the exact saved manifests. Bootstrap, seed, container restarts and
`--no-build` startup neither install new authority nor renew or reactivate an
expired or revoked installation. A replay receipt confirms the recorded
operation, not current sign-in readiness. Preserve this volume and its manifests
when diagnosing a failure; do not delete or edit the saved plan to renew access.

A separate, explicit successor installation is required after expiry or
revocation. Apply private typed manifests through the native owner installer:

```sh
./dev authn-install --input /absolute/path/to/private-authentication-manifest.json
./dev application-authn-install --input /absolute/path/to/private-application-bridge-manifest.json
```

The first command applies a SQL012 authentication installation operation; the
second applies a SQL037 `application-bridge-install` or
`application-bridge-revoke` operation. Each input must be a private regular file
(mode `0600`, at most 64 KiB). Prepare the explicit target, predecessor, generation
and expiry fields using the [authentication manifest contract](../../packages/authority/src/authentication-installation.ts)
and [application bridge contract](../../packages/authn/src/application-installation.ts).
Revoke the existing application bridge before installing its successor. These
commands use the migration owner's connection, verify the recorded receipt and
never choose a new generation or extend an expiry automatically. After an
uncertain commit, replay the identical manifest. Installing the session bridge
does not activate canonical content authority.

After a successful normal startup, reuse its verified images with:

```sh
./dev up --profile core --no-build
```

This mode requires every Compose image to be cached and the private build
receipt produced by the normal command. It verifies exact image IDs, selected
source files and build recipes before database startup or migration. It neither
builds nor pulls. A missing receipt, changed recipe/source or replaced image
requires another normal `./dev up --profile core`. Do not copy or edit receipts.

Keep `.local/` private. It contains credentials, source configuration, local
build receipts and raw test evidence. Run the launcher from the checkout that
owns this runtime; another checkout can carry older migration or bootstrap code.
Applied migration files are immutable. A correction uses a forward migration
and the corresponding isolated upgrade test.

The following checks execute real services and synthetic mutations:

```sh
./dev test --suite smoke
./dev test --suite security
./dev test --suite connectors
./dev test --suite image-security
```

Run mutation suites sequentially in this shared core. The security suite checks
the real API and storage boundaries. Connector conformance tests table/column
rename identity, permission loss and deletion on the synthetic PostgreSQL source.
Image scans retain full findings and inventories; their result belongs to the
exact image and advisory database recorded in the report. Browser commands,
browser selection and accessibility checks are documented in
[CONTRIBUTING](../../CONTRIBUTING.md).

Use `./dev status` to identify an unhealthy service. Its bounded logs are available
through the project's Compose configuration:

```sh
docker compose --project-name governance-commons \
  --env-file .local/runtime.env -f deploy/compose/compose.yaml \
  logs --tail 100 api
```

Logs are local diagnostic material; review and redact them before sharing. Keep
failed test evidence when retrying a corrected command. Do not edit migration
checksums or remove volumes to make an upgrade pass.

`./dev down` stops and removes core containers while preserving volumes. It does
not produce a backup. Backup, restore, the full profile and production recovery
must pass their own implementation and qualification gates before use; see
`./dev help` and the [current state](../execution/STATE.md).
