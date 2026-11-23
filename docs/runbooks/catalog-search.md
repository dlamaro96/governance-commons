# Catalog search and ordering

The catalog supports name ascending, name descending and recently updated order
across all matching, authorized assets. The API accepts `sort=name` (default),
`sort=name-desc` or `sort=updated`. Unknown values are rejected.

OpenSearch supplies bounded candidate IDs. PostgreSQL applies tenant and asset
visibility, type and retirement checks, counts the eligible set, and orders it
before selecting a page. Canonical names and update timestamps determine order;
stale indexed names do not determine the displayed order. Names use PostgreSQL
`C` collation, and asset UUID breaks ties. Only the selected page is hydrated.

Cursors bind identity, tenant, query, type, page size and order. Changing order in
the browser returns to the first page. A cursor from a different order is refused.
The browser keeps a bounded predecessor trail in each history entry. Back/Forward,
reload and browser Back from an asset restore that trail. A direct link or invalid
history shows “Current page” with a “First page” recovery action. The explicit
asset “Back to catalog” link opens the first page. History is a presentation hint;
the API authenticates every cursor independently.

Each request has its own primary-database snapshot: concurrent changes can move
assets between requests. This is not a frozen export or a locale-aware sort.

The existing candidate, response, hydration and time bounds remain enforced.
Exceeding a bound returns an explicit failure rather than an incomplete success.
The canonical content-authority foundation remains inactive; this path uses the
currently implemented membership and asset-visibility controls.

## Verification

```sh
pnpm exec tsx --test tests/unit/asset-search.test.ts
./dev test --suite security
pnpm exec playwright test tests/e2e/catalog-sorting.spec.ts
```

Run the real core services and seed synthetic data before integration/browser
checks. The browser journey signs in through Keycloak, scans PostgreSQL, checks
all three orders across two pages, pagination reset, history restoration and
direct-link recovery. Desktop,
mobile and Arabic captures accompany the journey. See the scoped
[local evidence](../verification/catalog-global-sorting-local.json); hosted
qualification must refer to its own executed revision.

The subsequent [navigation evidence](../verification/catalog-navigation-local.json)
records the expanded local journey and its exact source binding.
