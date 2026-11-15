# Authored asset-type migration UI evidence

The seventeen `m2-type-migration-*.png` files are actual authenticated synthetic-data captures from the full twelve-journey browser gate on 2026-11-15, starting at 18:26:36.422 UTC. All twelve journeys passed in 358136.359 ms with no failures, skips or retries. The runtime image is `sha256:2d2f04f1b75e774b7831d8d0d9e1df928e142c442138b8f451f7506385fdfa34`.

[The scoped UI report](../m2-type-migration-ui.json) records exact source, served-bundle, raw-report and screenshot hashes, along with the earlier failed diagnostics and their fixes. The two targeted journeys also passed before the full gate. No identity, API response or source service was mocked.

| Captures | Views |
| --- | --- |
| `definition-en-*` | Visual target definition and exact parent pins at 1440, 1024, 768 and 390 pixels |
| `policy-en-*` | Explicit per-asset ownership choices at 1440 and 390 pixels |
| `preview-en-*` | Complete server-enumerated impact, policy changes and version/digest metadata at 1440 and 390 pixels |
| `values-en-*` | Full before/after attribute, owner and lifecycle tuples at 1440 and 390 pixels |
| `confirmation-en-*` | Digest-bound execution consent at 1440 and 390 pixels |
| `receipt-en-*` | Immutable migration receipt at 1440 and 390 pixels |
| `receipt-ar-dark-390` | Arabic RTL receipt in dark mode |
| `editor-ar-dark-390` | Arabic RTL owner-policy editor in dark mode |
| `readonly-en-390` | Authorized consumer receipt view |

The implementation agent visually inspected every final capture. Labels, controls, hashes, tuple comparisons and primary actions were legible in the recorded views, with no observed overlap or horizontal document overflow. Long JSON remains inside its scrolling container. Each capture also passed scoped axe WCAG 2 A/AA, 2.1 AA and 2.2 AA checks without exclusions; execution consent was exercised by keyboard.

All fifty-eight historical PNGs were restored and verified byte-identical. Fresh regression copies remain in ignored local evidence, so earlier manifests retain their original execution bindings.

This is a scoped development check. It does not establish complete accessibility, independent human Arabic review, production restore, release readiness or completion of MOD/AT-MOD/M2 or the full programme.
