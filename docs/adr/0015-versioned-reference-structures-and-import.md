# Versioned reference structures and governed import

Status: accepted for development implementation; runtime and release qualification are recorded separately.

Reference hierarchies and crosswalks use immutable, tenant-scoped releases with exact endpoint version and publication-hash pins. Hierarchies enforce cycle and multi-parent policy over half-open validity intervals. Crosswalks preserve mapping method, transformation notes and confidence. Independent approval and Temporal publication share the existing canonical transaction, audit and outbox boundary. Endpoint visibility or authority loss suppresses effective entries without deleting historical evidence. SQL024 is a forward migration; earlier migrations remain immutable.

Import accepts bounded UTF-8 code-row JSON or closed-column CSV. A read-only preview reconciles against an exact published head, shows complete additions, changes and removals, and rechecks current authorization and owner membership. Applying the preview changes only the browser draft. The existing proposal, independent review and publication path remains authoritative; a preview is not an authorization token. Merge and replace are explicit operations, and malformed or duplicate input cannot partially apply.

When enabled by operator configuration, the ClamD adapter scans admitted bytes before opening the preview transaction and fails closed on rejection, timeout or unavailability. It stores no upload and exposes no scanner diagnostics. Scanner engine operation and signature freshness require separate deployment qualification.

Bounded development limits are explicit in the contracts and UI. Bulk import is reference stewardship, not entity matching or a customer/supplier master-data engine. Required contract bindings, publication webhooks, additional quality families and all other programme capabilities remain separate implementation obligations.
