# ADR-0037: Research registration does not imply production approval

- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision class:** Invariant
- **Affected components:** experimental protocol/profile research, evidence, future promotion
- **Security properties affected:** all properties studied by experimental work

## Context

A standards project needs a place to preserve experimental protocol work, negative results, test vectors, prototypes and verification evidence without creating the impression that registration itself makes an experiment safe for production.

Conflating a research registry with the production profile catalog would weaken the lifecycle boundary.

## Alternatives considered

### Put experimental work directly in the production catalog

Rejected. The profile resolver supports explicit experimental examples, but a general research pipeline needs richer provenance/results metadata and stronger non-production semantics.

### Keep research only in papers/issues

Rejected. Important threat-model assumptions, negative results, vectors and exact implementation provenance would be difficult to validate and compare mechanically.

### Separate machine-readable research registry

Accepted.

## Decision

PR 37 entries are always `experimental` and `production_selectable=false`.

They bind threat/property/algorithm context, immutable evidence, hypotheses, experiments, test vectors, implementations, limitations and reproducibility data.

PR 38 is the sole E2EESA 0.1 mechanism for promotion toward Candidate, Recommended and Required states.

## Security consequences

Failed and inconclusive experiments can be preserved alongside successful results without contaminating production conformance.

Experimental code cannot become production-approved through naming or registry placement alone.

## Compatibility constraints

Unknown experimental threats/properties/components use explicit EXP-* namespaces.

Promotion must reconcile any surviving experimental identifiers with production registries.

## Reconsideration triggers

Re-open if a later standardized research-artifact registry provides equivalent lifecycle separation and provenance semantics.
