# M1 browser screenshots

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
