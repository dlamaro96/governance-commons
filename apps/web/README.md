# Governance Commons web

React, TypeScript and Vite application. The API serves `dist/` at the application origin. During development Vite proxies `/api` and `/auth` to port 4310. Root dependencies and lockfile are authoritative.

The first vertical slice implements identity handoff, a permission-aware shell, tenant switching when multiple memberships are returned, catalog keyword search and type facets, asset/schema inspection, versioned owner/description edits, PostgreSQL source registration and asynchronous scan status, and audit event inspection. All data comes from the live API. No mock authentication or fixture response is substituted at runtime.

`pnpm --filter @governance-commons/web build` checks TypeScript then builds the app. `pnpm test:e2e` runs the real identity/source/ownership journey and automated accessibility suite when the local core stack is running and seeded. See root development instructions for credentials generated under ignored `.local/`; they must not be copied into tests or public documentation.

Tokens are in `packages/ui/src/tokens.css`; reusable headless components are in `packages/ui/src/index.tsx`. A route manifest is in `packages/config/routes.json`. Text is externalised in `src/i18n.tsx`. Arabic is an initial machine translation; independent human translation review is pending. Light and dark themes, logical CSS properties, visible keyboard focus, reduced motion and internal horizontal table scrolling are included.

## Current limits

This is an intermediate slice, not the complete screen baseline. No task inbox, recently viewed history, followed changes, saved views, bulk mutations, semantic search, quality/lineage/contract/access tabs, field-permission administration, collection scheduling, source preview, scan cancellation, audit exports or independent audit-chain verification is implemented in this slice. Sorting currently applies to the loaded catalog page and is labelled accordingly. Audit text filtering applies to the service-returned event set and is labelled accordingly. The local development source form exposes the bundled synthetic PostgreSQL target as read-only connection settings because the M1 API accepts only that explicit target. Other targets are not yet supported. Runtime roles and permissions are enforced by the API.

Storybook, visual regression baselines, screen-reader review, human RTL/translation review and actual browser 200% zoom qualification are not completed. The Playwright suite includes real-service route screenshots at 390/768/1024/1280/1440 and automated axe checks; those are only evidence after execution, and do not replace manual review. See the central evidence manifest for executed status.

On 2026-11-15 all four browser tests passed against the real local Docker core stack with Chrome 157.0.8103.51. Fifteen screenshots were captured and inspected by the implementation agent. See [the scoped screenshot evidence](../../docs/verification/screenshots/README.md) for the exercised paths, versions and remaining review limits.
