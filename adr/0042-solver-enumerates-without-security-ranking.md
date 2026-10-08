# ADR-0042: Compatibility solving enumerates without hidden security ranking

- **Status:** Accepted
- **Date:** 2026-10-08
- **Decision class:** ⚖️ Multi-option
- **Affected components:** profile selection, configuration authoring, Candidate evaluation, migration planning
- **Security properties affected:** all properties requested from solver output

## Context

E2EESA intentionally keeps multiple serious architecture choices where expert practice does not support one indisputable universal answer.

A configuration solver that secretly scores those choices would reintroduce the very policy judgment the profile system was designed to expose.

At the same time, users need a practical way to find exact compatible sets across profile dependencies, incompatibilities, lifecycle status and Required promotion state.

## Decision

PR 42 enumerates valid configurations without a security score.

The caller supplies explicit requirements:

- families;
- properties;
- pins;
- exclusions;
- forbidden families; and
- lifecycle mode.

The solver returns unique effective profile sets in deterministic lexical order.

PR 2 remains authoritative for configuration validity.

PR 38 Candidate/Required state constrains eligible solutions.

PR 40 remains authoritative for conformance.

## Consequences

All surviving serious architecture alternatives remain visible.

Callers may apply their own product constraints after enumeration, but those preferences are outside the E2EESA compatibility verdict.

Large search spaces require an explicit search budget, and partial search is never mislabeled exhaustive.

## Reconsideration triggers

Re-open if E2EESA later adopts a separately governed, evidence-backed recommendation-ranking system. Such a ranking would remain distinct from basic compatibility solving.
