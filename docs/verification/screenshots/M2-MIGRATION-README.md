# M2 explicit migration browser screenshots

The fifteen `m2-migration-*.png` files are actual authenticated browser captures
of the local Docker product using synthetic Harbor Retail data. The full
CI-ordered browser gate passed all eight tests without retries or skips on
2026-11-15. The web implementation agent inspected every new image; this is not
independent human or accessibility sign-off.

The captures cover the searched, paged model list and asset model chooser;
visual transformation plan; server-enumerated preview and exact before/after
values; explicit approval bound to a preview fingerprint; and immutable receipt.
List, chooser, plan, preview, confirmation and receipt are captured at 390 and
1440 pixels. Additional 390-pixel captures show stacked value comparison, a dark
preview and an Arabic RTL receipt. Long tables and code retain intentional
internal scrolling. The mobile model header action wrap is also checked by the
existing model regression test.

This full run used image
`sha256:0f7ebbb1646e8f4eadc8fda961dc494e430034fac1726dbb4d8b13b465d751eb`,
serving `index-CGNPNh3-.js`, `ModelMigrations-OwyBEMlS.js` and
`index-YXB9h8oP.css`. Served bytes were compared with the local production build.
Chrome 157.0.8103.51, Playwright 1.65.1 and axe 4.14.0 were used. Exact source,
image, execution and screenshot hashes are in the
[scoped migration browser evidence](../m2-migration-ui.json). The raw report is
retained locally at `.local/evidence/playwright-migrations-docker-final-results.json`.
The 26 historical M1 and initial M2 PNGs were restored byte-for-byte; fresh
regression captures are retained under `.local/evidence/migration-regression-screenshots`.
Later backend qualification must retain a separate image and run binding.

Authentication, PostgreSQL source scans, API validation and persistence were real.
Missing acknowledgements and invalid transformations left canonical values
unchanged. A concurrent edit invalidated execution; reloading scope preserved the
draft while requiring fresh acknowledgements and preview approval. The committed
migration preserved exact decimals, false and nested values, and produced a
reloadable, exportable receipt. Role and tenant isolation were tested. Runtime
CSRF and rate limits remained enabled; test fixtures paced requests using the
actual reset header.

These checks qualify a bounded synchronous migration slice. Full MOD/M2 and
AT-MOD-01 remain open, including inheritance, constrained relations, lifecycle
and scoped overrides, all ingress, typed catalog search/filter/sort and larger
migration profiles. Backend fault-injection rollback and database enforcement
have separate integration evidence. Independent accessibility/native-speaker
review, screen-reader use, actual 200% zoom and wider browser/device coverage
remain pending. Dark qualification in this increment covers the preview and
existing catalog; other new screens were checked in light theme. Hosted CI and
release qualification remain separate gates.

A later focused run used the unchanged UI with signed model-list cursors on
image `sha256:d6f56071a8331a0a55b81462b6215498273d5e9e76f321210c7f39a252a6e981`.
Both model-project tests passed with `--no-deps`, checking paging/search,
selected-model preservation, typed-value and version workflows, and permissions.
Its separate report and image binding are in `follow_up_qualification` of the
same evidence JSON. This does not reattribute the earlier eight-test run to the
later image. All 41 public PNGs retain their original hashes; the fifteen focused
run captures remain under `.local/evidence/migration-signed-cursor-screenshots`.
