# ADR-0018: Separate diagnostic minimization from differential privacy

- **Status:** Accepted for pre-1.0 development
- **Date:** 2026-10-07
- **Decision class:** Profile choice
- **Affected components:** telemetry profiles, event schemas and accountant evidence
- **Security properties affected:** SP-METADATA-MINIMIZATION

## Context

Diagnostics can leak E2EE material and identifiers. Aggregate or pseudonymous
data should not automatically be treated as anonymous or differentially private.

## Serious alternatives considered

No exports provide the narrowest boundary. Coarse opt-in events support debugging.
Central DP supports protected publications while trusting the collector. Local
DP and distributed aggregation have different utility, implementation and
non-collusion assumptions and require their own reviewed profiles.

## Decision

Support no exports, minimized diagnostics and a fixed central pure-Laplace count
profile. Require closed event types, explicit consent and a lifetime accountant
with bounded contributions, exact epsilon arithmetic and no silent resets.

## Security consequences

DP output guarantees remain conditional on real noise/contribution/accountant
verification. The central collector sees inputs. Minimization does not establish
unlinkability, and successful schema checking does not authenticate external facts.

## Compatibility constraints

DP aggregate exports cannot include individual events. All architectures prohibit
secrets, personal identifiers, stable pseudonyms and automatic opt-in. Privacy
budgets span product/platform upgrades within the accounting domain.

## Evidence and references

RFC 6973 and NIST SP 800-226 (2025 final). Adversarial cases include budget
exhaustion, collector overclaims, consent absence and unsafe retention.

## Reconsideration triggers

New reviewed mechanisms, a finalized distributed aggregation standard, or evidence
requiring new metrics or revised finite-precision/accounting controls.
