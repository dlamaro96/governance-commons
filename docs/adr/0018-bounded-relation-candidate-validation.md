# ADR0018: Bound exact relation validation to nominal candidates

Date: 17 November 2026

Status: Accepted for implementation; runtime and release qualification are recorded separately.

## Problem

Glossary publication validates relation cardinality against catalog assets. On a populated catalog, PostgreSQL can evaluate exact endpoint eligibility before restricting the input to the relation's nominal candidates. Repeated policy evaluation over unrelated assets exceeds the existing operation budget. Raising that budget would retain the unnecessary work.

Applied migrations remain immutable. The historical SQL018-only failure must remain visible even when a later migration repairs its execution path.

## Decision

SQL032 changes only the two candidate queries in `gc_relation_check_type`: the eligible-population count and the required-participation check. A materialized candidate query joins nominal candidate identifiers to assets in the authenticated tenant before exact eligibility is evaluated.

The change preserves tenant/RLS checks, hidden-resource refusal, exact cardinality, relation and participation limits, immutable policy pins, locking and deadlines. It adds no cached authorization decisions, indexes, planner settings or larger budgets. Remaining function behavior and execution grants stay unchanged.

Isolated qualification covers both the original SQL001–018 prefix followed by SQL032 and the current SQL001–031 prefix followed by SQL032. Each path checks preservation and replay as well as the original assertions. Additional tests cover boundary populations, foreign-tenant identifiers, generic/custom plans and concurrent membership revocation.

## Qualification and pipeline consequences

The historical commands remain available with their original meaning. Separate repaired-chain commands identify the forward repair explicitly and retain the original downstream tests. Their reports cannot substitute for historical outcomes, nor can one selected repaired mode claim that other modes ran.

The runner verifies exact test identities, unique results, sequential TAP numbering, passing totals and mounted source bytes at process startup and exit. It permits Node to order test files differently from command-line arguments; it does not permit a missing, duplicate, skipped or failing test.

The CI collector exports bounded diagnostic metadata for failures. Raw runtime output and credentials remain outside published artifacts. Current execution and release limitations belong in the [evidence manifest](../verification/evidence-manifest.json) and [current state](../execution/STATE.md).
