# ADR-0030: Portable signed certification attestations

- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision class:** Profile choice
- **Affected components:** certification publication, verifier ecosystem, status/revocation
- **Security properties affected:** integrity, authenticity and rollback resistance of certification status

## Context

Open E2EE Verified must publish portable machine-verifiable certificates without forcing every ecosystem into one signature container.

JOSE/JWS, COSE and DSSE are all serious deployed signing formats. Post-quantum signatures now have standardized JOSE/COSE ML-DSA identifiers through RFC 9964.

## Serious alternatives considered

### One mandatory envelope format

Rejected. It would create avoidable ecosystem coupling.

### Custom E2EESA signature container

Rejected. Existing reviewed standards already solve signature-envelope binding.

### Multiple standardized envelopes over one canonical payload

Accepted.

## Decision

E2EESA defines one canonical certification payload and permits JWS compact, COSE_Sign1 and DSSE envelopes.

Two initial signing-policy classes are supported:

- classical threshold; and
- dual classical + post-quantum.

Cryptographic verification is delegated to a standards-compliant verifier backend; the E2EESA semantic engine fails closed without one.

Signed status statements use the same machinery and add monotonic sequence/previous-digest rollback defense.

## Security consequences

Payload semantics remain stable across ecosystems and no home-grown signature construction is introduced.

Dual-signature deployments can add ML-DSA without dropping interoperable classical signatures.

The cost is verifier complexity and key lifecycle management across multiple algorithms/formats.

## Compatibility constraints

All counted signatures cover identical canonical payload bytes.

Envelope key identifiers are not trust anchors; signing policy authorizes exact key/algorithm identities.

A current lifecycle and valid certification evidence bundle are prerequisites to issuance.

## References

- RFC 7515
- RFC 9052
- RFC 9053
- RFC 9964
- DSSE protocol

## Reconsideration triggers

Re-open if a later cross-ecosystem signed-statement standard supersedes these envelopes while preserving exact payload binding, key authorization and post-quantum migration properties.
