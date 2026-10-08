# ADR-0038: Sequential promotion with multiple serious evidence paths

- **Status:** Accepted
- **Date:** 2026-10-08
- **Decision class:** ⚖️ Multi-option
- **Affected components:** research lifecycle, production profile catalog, future conformance enforcement
- **Security properties affected:** any property claimed by promoted research

## Context

There is broad agreement that experimental cryptographic/protocol work should not become a production default without substantial independent evidence.

There is not one universally accepted weighting between implementation diversity, formal verification, operational experience, and completed external standardization.

IETF-style standards maturity emphasizes stable, well-understood specifications, independent interoperable implementations and operational experience. NIST cryptographic standardization emphasizes prolonged public evaluation, external cryptanalysis/review, correctness testing and iterative narrowing.

## Decision

Promotion is sequential:

`Experimental → Candidate → Recommended → Required`.

Common non-negotiable invariants apply to every path.

Candidate has one baseline gate.

Recommended supports three serious paths:

- implementation-led;
- formal-assurance-led;
- external-standard-led.

Required supports two serious paths:

- operational-maturity;
- standards-and-deployment.

All thresholds are machine-readable in the promotion registry.

Formal evidence cannot replace implementation/interoperability evidence entirely.

External standardization cannot replace local target/profile reconciliation and evidence binding.

## Existing profile-catalog mapping

Candidate maps to production status `provisional`.

Recommended and Required map to production status `recommended`.

Required is preserved in a separate promotion-state registry and will be enforced by PR 40 when the family is in scope.

## Security consequences

No single organization can satisfy an independence gate merely by producing more artifacts.

Research with unresolved promotion-critical hypotheses cannot graduate.

Negative/inconclusive research remains part of the historical record.

The cost is a deliberately high evidence burden for Recommended/Required states.

## Reconsideration triggers

Re-open thresholds when independent review of E2EESA identifies a materially stronger maturity model, or when widely adopted standards bodies converge on a more precise general-purpose promotion framework.
