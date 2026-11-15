# Rendered browser evidence

Each increment retains its own source/image binding, execution time and inspected
screenshots. New runs do not rewrite the historical images that earlier reports
reference. The [evidence manifest](../evidence-manifest.json) and
[current state](../../execution/STATE.md) distinguish passing execution from
ongoing qualification and outstanding human review.

Later model evidence is recorded in `m2-ui.json`, `m2-migration-ui.json`,
`m2-asset-type-ui.json` and `m2-type-migration-ui.json` in the parent directory.
Constrained-relation execution and inspected screenshots are recorded in
[m2-relations-ui.json](../m2-relations-ui.json). Screenshots alone never establish
functionality or completion of the full product programme.

## Historical M1 browser screenshots

These PNGs were captured from the real local Docker `core` profile on 2026-11-15,
with installed Chrome 157.0.8103.51 and Playwright 1.65.1. They show synthetic
Harbor Retail data returned by the application after actual PostgreSQL scans.
The authenticated journey includes source registration, asynchronous scanning,
catalog search, owner and description changes, and audit history.

The final browser run passed all four tests in 15.8 seconds. It exercised English
catalog layouts at 390, 768, 1024, 1280 and 1440 CSS pixels; light and dark themes;
Arabic RTL at 390, 768 and 1440; asset details at 390 and 1440; and keyboard focus
containment and restoration for the source dialog. Axe checks used WCAG 2 A/AA,
2.1 AA and 2.2 AA tags without rule exclusions. Finite theme transitions settle
before automated contrast inspection.

The web implementation agent inspected all 15 PNGs. Shells, controls and entity
panels reflow without overlap or document overflow. Wide tables and metadata
code intentionally scroll within their own containers. Counts and timestamps
reflect the actual local data at capture time; repeated test runs create distinct
synthetic sources.

Execution results and SHA-256 file bindings are recorded locally in
`.local/evidence/playwright-docker-final-results.json` and
`.local/evidence/ui-verification.json`. The deployed app image prefix was
`7e1a66b7dcf1`, with `index-D0nVuQoj.js` and `index-C6JDWdw6.css`. The tested source
was the working tree based on `026611973a9fef5d02fb5a879beecf16fdcc44f3`; the evidence
includes hashes for the changed UI and test files.

This is scoped automated and agent-reviewed M1 evidence. Independent human
accessibility review, screen-reader use, actual 200% browser zoom, native-speaker
Arabic review, component stories and the remaining product programme are still
pending. The source connection UI currently supports the bundled synthetic local
PostgreSQL profile. These images do not qualify an external vendor integration
or an enterprise release.


## Constrained asserted relations

The 20 `m2-relation-*.png` files come from the final real Docker browser gate
started at 2026-11-15T20:32:41.290Z. All 14 journeys passed once, without skips or
retries, in 557.595 seconds. The preceding targeted two-journey gate also passed.
The implementation agent inspected every final image; the evidence report records
the separate root-agent spot-check. These are agent observations, not independent
human accessibility or native Arabic sign-off.

The captures show relation-type editing at 390, 768, 1024 and 1440 CSS pixels;
relation creation, details, immutable history, tables and removal at 390 and 1440;
and English/light and Arabic/dark graphs at both widths. Graph cards remain
complete after resize, and localized actions repaint correctly when language
changes. Wide tables and JSON snapshots scroll inside their containers.

The real journeys verify constraints, stale-write recovery, type-version pins,
exact decimal values, lifecycle transitions, authorized graph pagination,
restricted-edge and tenant isolation, and preservation after a second PostgreSQL
source scan. Axe checks retain all configured WCAG rules. The final runtime image
is `sha256:309f28b6153c822533b01c29a72b79db58c9ecbaaf1f803c8386c511ec059651`;
the report binds 65 source files, 19 served assets and all image/source evidence.
The 60 backend files match the separately executed 98-case API gate; the UI
rebuild is not reported as another API execution.

All 75 historical screenshot files remain byte-identical to their original
reports. Earlier failed runs and automated passes with visual defects remain
recorded separately. Positive participation, explicit relation migrations,
additional relation authorities and the full M2/release gates remain open.
