# ADR-0028: Content-addressed exact-scope certification evidence

- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision class:** Invariant
- **Affected components:** assurance, certification, verification, formal verification, supply chain
- **Security properties affected:** assurance evidence for all certification claims

## Context

Certification must not become a collection of screenshots, vendor assertions or loosely named audit documents that cannot be tied to an exact product version and architecture.

## Serious alternatives considered

### Document-only application packet

Rejected as the canonical representation. Human-readable documents remain useful but are too weak as the sole machine-verifiable scope boundary.

### Vendor self-attestation only

Rejected as sufficient evidence for independent assurance requirements.

### Content-addressed evidence bundle

Accepted. Every item is immutable by digest and linked to exact product/configuration/source/artifact scope.

## Decision

E2EESA certification evidence uses a machine-readable bundle containing:

- exact subject identity;
- exact resolved profiles;
- assurance-plan binding;
- evidence manifest;
- claim-to-evidence matrix;
- source-access declaration; and
- time-bounded exception records.

Independent evidence types require independent-assessor issuance when used to satisfy assurance requirements.

## Security consequences

This sharply reduces scope ambiguity, stale-report reuse and evidence substitution.

A cryptographic digest establishes artifact identity, not correctness or assessor competence. Human and independent review remain necessary.

## Compatibility constraints

A bundle for one product/version/platform/configuration cannot certify another.

A2+ requires source-review access but does not require public source code.

E2EESA MUST requirements are not waivable through PR 28 exception records.

## Evidence and references

The model composes PR 23–27 evidence and profile-resolution machinery.

## Reconsideration triggers

Re-open if later certification infrastructure adopts a standard evidence-envelope format that can preserve the same exact-scope and fail-closed semantics with better interoperability.
