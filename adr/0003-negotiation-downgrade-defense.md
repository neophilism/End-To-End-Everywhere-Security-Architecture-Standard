# ADR-0003: Fail-closed negotiation and downgrade defense

- **Status:** Accepted
- **Date:** 2026-10-06
- **Decision class:** Security invariant
- **Affected components:** protocol negotiation, profile binding, cryptographic suite selection, conformance evidence
- **Security properties affected:** downgrade resistance, confidentiality, integrity, peer authentication, post-quantum transition safety

## Context

E2EESA permits multiple cryptographic algorithms and later multiple architecture profiles. Flexibility is dangerous if an attacker or compatibility path can silently force participants onto a weaker or unintended option.

## Serious alternatives considered

### Best-effort compatibility fallback

Rejected. Automatically retrying with weaker versions or suites converts ordinary incompatibility into a downgrade path.

### Lexical or numeric comparison of version strings

Rejected. Protocol version identifiers are not universally ordered by their textual representation.

### Unaudited provider-default negotiation

Rejected. Library or provider defaults can change and cannot establish reproducible E2EESA conformance.

### Explicit ordered versions, exact pins, and authenticated transcript binding

Selected. The policy declares the acceptable universe; endpoints authenticate what was offered and selected; failure does not expand that universe.

## Decision

E2EESA negotiation is fail closed.

Policies explicitly order protocol versions, set a minimum, pin an exact cryptographic registry version and suite set, and pin the exact effective E2EESA profile set.

The highest mutually supported policy version must be selected. Downgrade-sensitive negotiation inputs and the result must be bound into the authenticated transcript. Automatic weaker fallback is prohibited.

## Security consequences

Benefits:

- active stripping of stronger versions becomes detectable or causes failure;
- provider defaults cannot silently widen the accepted suite set;
- registry/profile mismatches fail instead of drifting;
- ordinary interoperability failure cannot silently weaken policy;
- conformance evidence can test downgrade behavior deterministically.

Costs:

- some peers will fail to connect rather than fall back;
- deliberate compatibility changes require explicit policy updates;
- protocols must expose enough authenticated transcript state for conformance testing.

## Compatibility constraints

A concrete protocol may use its own wire format and freshness mechanism, but it must preserve the version-floor, highest-mutual, suite-pinning, transcript-binding, profile/registry-binding, no-fallback, and replay-resistance invariants.

## Evidence and references

RFC 8446 and RFC 9325 provide mature examples of authenticated protocol negotiation, preference for newer supported protocol versions, and avoidance of insecure fallback. E2EESA adopts the general security principles, not TLS-specific wire encodings.

## Reconsideration triggers

Reconsider the reference evidence model if:

- a later E2EESA protocol cannot faithfully map its negotiation state into this structure;
- formal analysis identifies a downgrade path not covered by the bound fields;
- a protocol uses a stronger freshness mechanism that should become the new baseline; or
- interoperability testing shows an invariant is underspecified.
