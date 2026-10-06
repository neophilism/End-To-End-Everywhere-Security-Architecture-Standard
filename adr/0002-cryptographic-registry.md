# ADR-0002: Standardized cryptographic registry with lifecycle states

- **Status:** Accepted
- **Date:** 2026-10-06
- **Decision class:** Cryptographic registry infrastructure
- **Affected components:** registry, profiles, validators, later protocol profiles
- **Security properties affected:** confidentiality, integrity, authenticity, downgrade resistance, post-quantum confidentiality, post-quantum authentication

## Context

E2EESA needs to support several defensible standardized cryptographic choices without inventing a new primitive or allowing arbitrary implementation-defined algorithms.

## Serious alternatives considered

### One mandatory algorithm per primitive class

Rejected as the global model. It would unnecessarily constrain interoperability, hardware acceleration, software-only deployments, security-margin choices, and future migrations.

### Free-form algorithm strings

Rejected. Informal names make lifecycle management, conformance, downgrade analysis, and reproducibility unreliable.

### Registry of standardized primitives with lifecycle states

Selected. Exact identifiers allow profiles to choose from a controlled set, while status transitions can prohibit or deprecate algorithms without pretending that every registered item is equally preferred.

### Inventing new E2EESA cryptographic primitives

Rejected. E2EESA should compose well-reviewed standardized mechanisms rather than create novel cryptography without necessity.

## Decision

Create a closed-world cryptographic registry of exact algorithm and suite identifiers.

The initial registry includes standardized classical and post-quantum primitives, multiple defensible options in disputed or deployment-dependent areas, and explicit prohibited historical entries.

Classical/post-quantum hybrid protocol composition is deferred to dedicated profiles because it requires protocol-level security analysis rather than registry metadata.

## Security consequences

Benefits:

- no hidden or informal primitive selection;
- explicit algorithm lifecycle;
- reproducible conformance;
- multiple serious options without arbitrary feature flags;
- deterministic rejection of prohibited algorithms;
- early registration of standardized post-quantum primitives without overstating product-level PQ security.

Costs:

- registry maintenance becomes security-sensitive;
- profile authors must explicitly bind primitives into protocols;
- migration requires deliberate registry/profile updates.

## Compatibility constraints

Suites may reference only registered algorithms. A suite may not be assigned a stronger lifecycle status than its weakest component. Prohibited algorithms may not appear in conformant security suites.

## Evidence and references

Initial entries reference NIST FIPS and SP publications and IETF RFCs, including FIPS 203, FIPS 204, FIPS 180-4, FIPS 202, FIPS 186-5, SP 800-56A Rev. 3, SP 800-38D, RFC 7748, RFC 8032, RFC 8439, RFC 8452, RFC 5869, and RFC 9180.

## Reconsideration triggers

Reconsider entries or lifecycle status when:

- a standards body publishes relevant security guidance or deprecation;
- cryptanalysis materially changes the security posture of an entry;
- interoperability evidence shows a registered alternative is impractical;
- a new standardized construction provides a meaningful security or deployment advantage; or
- dedicated post-quantum transition profiles impose stronger requirements.
