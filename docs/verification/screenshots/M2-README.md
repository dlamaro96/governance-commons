# M2 typed-model browser screenshots

The `m2-model-*.png` files show the real local Docker `core` profile on
2026-11-15 with synthetic Harbor Retail data. They are separate from the
historical M1 screenshot set. The browser uses Keycloak sessions, PostgreSQL
canonical records, a real source scan and OpenSearch catalog projection.

The final combined browser run passed all six tests in 95.8 seconds, with no
skipped tests, flaky results or retries. The two model tests and four M1
regressions ran against the same image. The model suite waits for the real
request-budget reset before and after its checks when needed; the final run
exercised 17-second and 50-second waits with no production limit changes.

The eleven screenshots cover visual model editing, immutable model inspection,
typed asset forms, persisted typed values and the server-generated impact
preview at 390 and 1440 CSS pixels, plus Arabic RTL model editing at 390.
The preview discloses checked assets and links to the actual catalog record;
publication keeps existing asset version pins. The form distinguishes unset
values from false and preserves decimal strings beyond JavaScript precision.
Long forms scroll within the dialog, and nested JSON has a keyboard-focusable
scroll region. The implementation agent inspected the actual PNGs for overlap,
readability, clipping, control layout and unintended document overflow.

The model journey creates a definition visually, adds all twelve supported
attribute types through validated JSON, exports and reimports it unchanged,
rejects duplicate JSON keys and invalid typed values, binds values to a real
scanned table, and recovers a preserved draft after a concurrent edit. It also
rejects a stale impact preview, publishes a compatible next version, verifies
that the old definition and asset pin remain unchanged, and blocks destructive
publication. A second browser test checks consumer denial and tenant isolation.
Axe checks use WCAG 2 A/AA, 2.1 AA and 2.2 AA tags without exclusions.

The tested app image is
`sha256:11b3da6538177d7ba81bf4cd4e8ef6aace03442847e42813a29683e392c93446`,
serving `index-B9q0sL2w.js` and `index-BcSr_bKc.css`. Browser and runner versions
are Chrome 157.0.8103.51, Playwright 1.65.1 and axe 4.14.0. Exact source hashes,
image binding, execution results and screenshot hashes are recorded in the
[scoped M2 browser evidence](../m2-ui.json). The raw runner report is retained
locally in `.local/evidence/playwright-m2-docker-final-results.json`. Fresh M1
regression captures are retained under `.local/evidence/m2-regression-screenshots`;
the fifteen tracked M1 PNGs were restored byte-for-byte from the checkpoint.

These are partial MOD-001/002/003 and UX checks, not complete requirement or
release qualification. Asset/domain/relation inheritance, constrained relations,
lifecycle rules, model layouts, migration execution and rollback, every ingress,
and typed search/filter/sort remain open. Rich text currently uses safe plain
Markdown source without formatted rendering. Independent accessibility and
native-speaker review, screen-reader use, actual 200% zoom and component stories
remain pending. New M2 screens were checked in light theme; M2-specific dark
theme qualification remains open. Runtime controls, including CSRF and rate
limits, stay enabled.
