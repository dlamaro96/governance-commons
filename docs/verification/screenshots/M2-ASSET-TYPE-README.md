# Inherited asset-type browser evidence

The 17 `m2-asset-type-*.png` images come from the real Docker `core` browser gate that began at **2026-11-15T17:38:23.175Z**. All ten tests passed in 311,116.315 ms, with no skipped, retried or flaky tests. The API image was `sha256:de9b7c6c33f995ea7c01abde6035ab5585fe8d32b8c6e15f09a439aee039b282`; all eight served JavaScript/CSS files matched the frozen production build.

The [verification record](../m2-asset-type-ui.json) contains exact source, artifact, report and screenshot hashes, the separate two-test targeted pass, and the initial request-budget diagnostic. Tests used real Keycloak sessions, PostgreSQL scans and canonical typed writes with synthetic Harbor Retail and Summit Logistics data. Production rate limits remained enabled; bounded test preflight waits use the actual response headers.

| View | File suffixes | Widths |
| --- | --- | --- |
| Visual field authoring | `editor-en` | 1440, 1024, 768, 390 |
| Owner and lifecycle authoring | `lifecycle-editor-en` | 1440, 390 |
| Exact parent pin and explicit override | `inheritance-en` | 1440, 390 |
| Immutable resolved type | `resolved-en` | 1440, 390 |
| Complete impact preview and publication consent | `preview-en` | 1440, 390 |
| Asset lifecycle controls | `lifecycle-en` | 1440, 390 |
| Arabic dark lifecycle | `lifecycle-ar-dark` | 390 |
| Arabic dark type editor | `editor-ar-dark` | 390 |
| Consumer permission state | `readonly-en` | 390 |

Every image is a 960-pixel-high viewport capture. The implementation agent visually inspected all 17 final images: fields, exact pins, controls and review consent were legible, with no observed overlap or horizontal document overflow. Long source JSON remains inside its own scrollable panel. Axe checks ran at each captured view with no rule or element exclusions; keyboard consent was exercised in the real publication journey. This is scoped automated and agent visual evidence, not an independent human accessibility or language sign-off.

The 41 earlier M1, model and migration images were restored byte-for-byte after this regression run. Fresh copies of their current-run captures remain in ignored local evidence; their historical manifests were not rebound to this run. The root agent's three preliminary spot checks belong to the initial targeted run, separately identified in the verification record.

This increment does not complete M2, MOD-001/002/003, AT-MOD-01, E2E-06 or release qualification. Inherited-type destructive migrations, constrained relations and the other outstanding programme requirements remain open. Arabic remains provisional; full manual screen-reader, zoom and cross-platform qualification remain open.
