# Business domains: local operation and recovery

This runbook covers the implemented domain types, hierarchy, lifecycle, ownership,
asset placement and bounded migration workflows. Use the current
[execution state](../execution/STATE.md) for qualification status. The
[final isolated SQL gate](../verification/business-domains-upgrade-final-source.json)
and [local startup/seed report](../verification/business-domains-seed-runtime.json)
have separate scopes. The latter records startup and seed recovery through
2026-11-16T02:15:47Z; it does not qualify HTTP/API or browser workflows.
The complete [build specification](../product/BUILD_SPEC.md) remains the target.

## Prepare and qualify local core

Use the repository's pinned toolchain and existing private bootstrap state.
Reserve an exclusive core mutation window before seed recovery, API or browser
qualification; the seed harness's local file lock excludes only another copy of
that harness. Require at least 2 GiB free disk and no queued or running jobs.
Run heavy gates sequentially and retain each original failed attempt.

```sh
./dev doctor
./dev test --suite business-domains-upgrade
./dev up --profile core
./dev seed --dataset harbor-demo
./dev test --suite business-domain-seed
```

The upgrade gate uses its own disposable PostgreSQL service. It does not apply
SQL011 to core. Core startup runs the actual checksum migrator; SQL001–011 are
now applied and immutable. A correction needs a new forward migration and a
fresh isolated upgrade gate. The seed qualification requires exactly the reviewed
SQL001–011 checksums and matching source/image hashes; it never applies migrations.

A worktree needs the intended private `.local/source-secrets.json` regular file
before Compose starts the source coordinator. An absent bind source may become
a directory. If this happens, stop that startup attempt, verify the exact empty
directory and bind configuration, then restore the intended existing private
bootstrap-file binding without changing its contents. Preserve the failed log
and rerun startup. Do not replace secrets, delete unrelated paths or copy private
file contents into evidence. For a genuinely new checkout, `./dev bootstrap`
is the supported creation/preservation command.

The seed creates two independent synthetic typed trees: Retail operations with
Customer services and Supply operations, and Logistics operations with Fleet
services and Delivery operations. Each tenant gets the version-one `business_area`
type, required ownership, a criticality enum and draft/active lifecycle. The seed
uses the real domain service as `gc_app`, with canonical revisions, audit and
outbox. It creates no scans or asset placements. Its one-time synthetic permission
upgrade marker preserves later revoked permissions and deleted memberships on
replay; do not remove the marker to force grants back into place.

`./dev test --suite business-domain-seed` dispatches
`python3 scripts/runtime-test-business-domain-seed.py --run-core` with a
900-second outer limit. Run it only on the initialized local synthetic dataset.
It checks two unchanged real seed replays, then temporarily revokes one known
synthetic permission and removes one known synthetic membership, runs the seed
again and restores their exact original rows. These deliberate fixture changes
make concurrent API/browser/seed activity unsafe for the gate.

After seed qualification, execute the separately recorded service and UI gates:

```sh
./dev test --suite security
pnpm exec playwright test tests/e2e/business-domains.spec.ts
pnpm exec playwright test --config .github/playwright.ci.config.ts
```

The targeted browser file declares three journeys. The CI configuration declares
19 journeys in sequential project dependencies, with business domains following
relation migrations. Discovery is not execution. Preserve reports, exact image
and source bindings and screenshots before another run overwrites latest output;
inspect actual rendered screens before claiming UI qualification.

## Use the domain screens

Sign in through the normal OIDC browser flow at the local app, normally
`http://localhost:4310`. Tenant scope comes from the authenticated membership.
Domain selection and recorded ownership do not grant permissions.

- `/domain-types` lists authorized types. `/domain-types/new` and
  `/domain-types/:id/edit` provide visual and declarative editing, exact parent
  pins, required ownership and lifecycle controls. Review a complete preview
  before publication. Compatible publication preserves existing domain pins.
- `/domain-types/:id/migrate` loads the complete authorized migration context.
  Review the target definition, complete plan, issues and exact before/after
  result, then confirm a ready preview. Inspect the immutable receipt at
  `/domain-types/:id/migrations/:migrationId`.
- `/domains` lists the permitted active or retired domains. Create through
  `/domains/new`, inspect hierarchy/history at `/domains/:id`, and edit through
  `/domains/:id/edit`. Administrative retirement is distinct from business
  lifecycle state. Move, retire and restore use an explicit hierarchy preview.
- The catalog asset detail provides placement and placement history. Read the
  current asset and placement versions before assigning or unassigning. A scan
  can advance the asset version independently, requiring a refresh even when
  placement is unchanged.

A domain has an immutable UUID, one nullable parent and an exact type version.
An asset has at most one primary domain in this increment. First placement is
version 1; absent placement is version 0 with no fabricated history. Unassignment
adds a revision with a null domain. Moving or renaming a domain preserves asset
identity and recorded historical references. Retirement requires no current
placements and no active children. Restore retired domains before ordinary edits
or assignments; explicit type migration remains available subject to authorization.

## API contract and safe retries

All routes are under `/api/v1`. Use the authenticated server-side session and
existing CSRF flow, as the web client does; do not store browser bearer tokens.
The [adopted contract](../execution/BUSINESS_DOMAINS.md) defines exact request and
response DTOs. The registered handlers are in
`apps/api/src/business-domains.ts`; strict schemas reject duplicate JSON keys,
unknown fields, coercion and malformed queries.

| Workflow | Existing routes |
| --- | --- |
| Type inventory, validation and creation | `GET/POST /domain-types`; `POST /domain-types/validate`; `POST /domain-types/migration-plans/validate` |
| Exact type and compatible publication | `GET /domain-types/:typeId`; `GET /domain-types/:typeId/versions/:version`; `POST /domain-types/:typeId/previews`; `POST /domain-types/:typeId/versions` |
| Complete type migration | `GET /domain-types/:typeId/migration-context`; `POST /domain-types/:typeId/migration-previews`; `POST /domain-types/:typeId/migrations`; `GET /domain-types/:typeId/migrations/:id` |
| Domain administration | `GET/POST /domains`; `GET /domains/owner-candidates`; `GET/PATCH /domains/:id`; `POST /domains/:id/state` |
| Hierarchy and history | `POST /domains/:id/hierarchy-previews`; `POST /domains/:id/hierarchy-changes`; `GET /domains/:id/history`; `GET /domains/:id/assets` |
| Asset placement | `GET/PUT /assets/:id/domain-placement`; `GET /assets/:id/domain-placement/history` |

All successful mutations need an `Idempotency-Key`. Versioned edits, publication,
migration and hierarchy operations require the current `If-Match` value. Placement
uses its own version in `If-Match`, including 0 before the first assignment; its
body contains the current positive `assetVersion`, `domainId`, `domainVersion`
and `reason`. Both domain fields are null for unassignment, and both identify
the current active target for assignment. Do not substitute the asset version
for the placement version.

Publication, migration and hierarchy execution require a fresh, ready preview
and its exact `previewDigest`. A changed plan, expected version or authorized
scope requires a new preview. After a lost response, retry the identical request
with the same key; successful replay reauthorizes the complete originally
recorded scope. Reusing a key with changed content conflicts. For `DOMAIN_RETRY`,
wait the supplied five-second interval before retrying the unchanged request.
For version/preview conflicts, reload current state and review again. For
`DOMAIN_PAGE_STALE`, restart traversal from its first page. Integrity errors need
investigation using the sanitized correlation ID, not fabricated history.

Current domain reads require `domains:read`; writes also need `domains:write`.
Type authoring requires `models:read/write`; complete type previews additionally
need domain read, and migration execution needs domain write. Placement reads
need catalog/domain read and actual asset visibility; writes additionally need
`catalog:write` and `domains:assign`. Complete hierarchy scopes with assets must
be authorized before counts or issues are returned. Current membership and
original receipt scope are checked again on replay and history access.

## Development bounds

The aggregate profile permits 1,000 affected domains, 1,000 affected assets,
32 hierarchy levels, 2,001 distinct principals, 64 attribute transformation
operations, 100 returned issues, 100,000 retained JSON nodes, 256 KiB per
definition and 512 KiB retained operation data. Copies and nested inputs share
that budget. Type inheritance permits eight immediate parents, 64 distinct
transitive pins and eight ancestry edges. Limits refuse complete operations;
no partial migration or sampled preview is an accepted result.

List pages default to 50 and permit 1–100 rows. Search is a literal substring
of at most 200 characters. Signed cursors bind actor, tenant, purpose, filters
and scope; they provide neither totals nor hidden counts. Names/labels permit
1–200 Unicode characters, reasons 1–500 and descriptions 0–4,000.

All queries and nested work share the original 30-second transaction deadline,
with a lock timeout bounded by five seconds and remaining time. The application
arms each statement timer before issuing its protected query. Direct SQL with
an outer timeout disabled has cooperative clock checks; the isolated tests do
not prove a universal hard 30-second interrupt for arbitrary direct statements.
Do not extend budgets or edit protected claims to force an operation through.

## Preserve evidence and recover

Domain writes atomically commit canonical rows, immutable revisions, audit,
outbox and idempotency success. A failed operation rolls back those writes.
Successful history is append-only: use a new authorized edit or explicit
migration to correct it. No receipt rewrite, manual epoch adjustment or direct
private-claim mutation is a recovery path.

The seed harness writes ignored, mode-0600 evidence under
`.local/evidence/business-domain-seed-attempts/<attempt>/`, including the original
execution record, exact synthetic membership backup and private restoration SQL.
Its snapshot covers all 19 domain tables, domain-only audit/outbox and the selected
domain/bootstrap idempotency rows. Outbox delivery drains before the baseline;
all columns of those selected rows are then checked. Unrelated legacy rows and
legacy transaction bindings are outside this equality claim.

If the harness fails or is interrupted, first keep other core mutation gates
stopped and preserve the original report. Confirm that its exact owned seed
process/container has exited before restoration. Ownership checks use the recorded
Compose project/service/one-off labels, generated name and expected image;
never stop unrelated containers. The harness attempts exact restoration in
`finally`, then verifies both captured rows and the digest of all six synthetic
persona memberships. Failed or uncertain cleanup blocks safe restoration.

After SIGKILL, host failure or a `fixture_restore` result of `PENDING`/`FAIL`, a
maintainer must review the private backup and restoration SQL, confirm seed
idleness, restore under the recorded ledger/identity/membership lock order, and
independently read back the exact two rows and all-six-persona digest. Do not
publish that SQL or fixture payload. Preserve the failed execution bytes and
record recovery as a separate attestation. The current harness refuses any prior
unresolved `PENDING`/`FAIL` record; it has no automatic acknowledgement command.
A separately reviewed recovery/resume mechanism is required before another gate
can proceed. Never edit the original report to make that guard pass.

## Remaining programme scope

Placement currently supplies curated context; configurable domain-scoped authority,
roles/responsibilities and consistent enforcement across every ingress remain
required follow-on work. The scoped-authority documents are DRAFT proposals.
Collections/multiple assignments, full model kinds and all-ingress import/workflow/
MCP validation, multilingual glossary and approvals, effective-dated reference
data, actual DQ integration, larger durable migrations and production restore
remain open. The current seed also does not supply every required synthetic
scenario. These local checks do not close M2, the full acceptance stories,
enterprise deployment, hosted qualification or release gates. Optional runtime
activation never removes a required implementation.
