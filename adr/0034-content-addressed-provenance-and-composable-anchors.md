# ADR-0034: Content-addressed provenance with composable integrity anchors

- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision class:** Invariant with optional complementary proof mechanisms
- **Affected components:** Observatory ingestion, evidence storage, citations, later confidence/classification
- **Security properties affected:** provenance integrity, tamper detection, auditability

## Context

The Observatory needs evidence that remains inspectable even when a live source changes or disappears.

A URL alone is insufficient. A hash identifies bytes but does not establish authorship or trustworthy time. A signature can establish signer control but not independently prove time. A trusted timestamp or transparency log adds different evidence.

## Serious alternatives considered

### Mutable source records keyed by URL

Rejected. Later source changes would silently alter the evidence base.

### Hash-only records

Accepted as the mandatory identity baseline but insufficient as the only possible integrity evidence.

### Require one universal external anchoring system

Rejected. Signatures, RFC 3161 timestamps and transparency logs provide different guarantees and operational tradeoffs.

### Content-addressed evidence plus composable anchors

Accepted.

## Decision

Every entity is content-addressed with SHA-256 and every bundle has a deterministic manifest digest and bundle digest.

The evidence graph follows W3C PROV concepts of Entity, Activity and Agent.

Optional integrity anchors are:

- detached signature;
- RFC 3161 timestamp; and
- transparency-log proof.

They may coexist.

Cryptographic/timestamp/log proof validation is performed by external standards-compliant verifiers; E2EESA stores and validates the resulting verification evidence rather than implementing a new cryptographic protocol.

## Security consequences

Source changes cannot silently rewrite prior evidence.

A hash is never described as proof of authorship or time.

Anchors can strengthen provenance without coupling the Observatory to one vendor or trust infrastructure.

## Compatibility constraints

Citations bind immutable entity IDs.

Bundle revisions are append-only and point to the previous bundle digest.

PR 35 storage projections must preserve these canonical identities and relations.

## References

- W3C PROV-DM.
- W3C PROV-CONSTRAINTS.
- RFC 8785.
- RFC 3161.

## Reconsideration triggers

Re-open if a later widely deployed provenance/transparency standard provides equivalent semantics with stronger interoperable proof packaging.
