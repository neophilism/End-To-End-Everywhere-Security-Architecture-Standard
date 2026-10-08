# ADR-0043: Reference fixtures cover lifecycle boundaries as well as successful profiles

- **Status:** Accepted
- **Date:** 2026-10-08
- **Decision class:** Invariant
- **Affected components:** profile catalog, compatibility solver, reference corpus
- **Security properties affected:** none directly; validates architecture/lifecycle coverage

## Context

A reference corpus that contains only happy-path production configurations can drift away from the catalog and can hide lifecycle mistakes.

E2EESA also contains provisional, experimental and prohibited entries whose correct behavior is rejection unless their lifecycle conditions are satisfied.

The original PR 43 milestone requires reference fixtures for every supported architecture option.

## Decision

Every exact catalog profile appears exactly once in the PR 43 fixture manifest.

Recommended/allowed profiles receive positive production fixtures.

A provisional profile receives a positive Candidate fixture only when PR 38 records exact Candidate state; otherwise it receives a negative unpromoted-provisional fixture.

Legacy/deprecated profiles receive positive migration compatibility fixtures.

Experimental and prohibited profiles receive negative lifecycle fixtures.

Positive cases are materialized through PR 42 and re-resolved through PR 2. No fixture introduces a separate compatibility implementation.

## Consequences

Catalog additions cannot silently escape reference coverage.

Negative lifecycle behavior becomes part of the regression corpus.

Lexicographic selection of one generated reference solution is serialization only and carries no ranking meaning.

## Compatibility constraints

PR 44 interoperability tests may consume the PR 43 generated corpus but must preserve PR 42/PR 40 lifecycle semantics.

## Reconsideration triggers

Re-open if the catalog adopts a new lifecycle status or a later fixture standard provides stronger portable coverage semantics.
