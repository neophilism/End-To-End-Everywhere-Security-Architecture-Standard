# ADR-0040: Conformance claims are scope-specific and compose lower-level validators

- **Status:** Accepted
- **Date:** 2026-10-08
- **Decision class:** ⚖️ Multi-option
- **Affected components:** product conformance, Candidate evaluation, migration operations, certification
- **Security properties affected:** all profile-declared security properties

## Context

E2EESA already has deterministic profile resolution, assurance levels and certification evidence.

Those layers answer different questions:

- which profiles are selected;
- what assurance depth is requested; and
- whether the required evidence bundle is valid.

They do not alone establish a complete product conformance claim.

Candidate evaluation and retirement/migration operations also have legitimate uses but must not be labeled as ordinary production conformance.

## Decision

PR 40 composes existing validators and adds a complete scope/lifecycle/claim layer.

Three explicit claim scopes are supported:

- production-conformance;
- candidate-evaluation;
- migration-only.

Only a passing production-conformance result is eligible to support a production certification/conformance claim.

Every evaluation binds exact input digests and a complete family-scope declaration.

Every security property promised by in-scope non-evidence-only effective profiles must be part of the assurance/evidence claim set.

PR 38 Required profiles are enforced when their family is in scope.

## Security consequences

A product cannot earn a conformance result while silently omitting a selected profile's promised property from the assessment.

Candidate and migration exceptions remain usable without being confused with production approval.

The cost is more explicit scope metadata and stronger evidence completeness requirements.

## Compatibility constraints

PR 41 CLI must expose these same semantics without weakening them.

PR 42 compatibility solving may propose configurations, but PR 40 remains authoritative for final conformance evaluation.

## Reconsideration triggers

Re-open if later conformance standards or independent review identify a stronger general mechanism for complete scope declaration or evidence-claim semantics.
