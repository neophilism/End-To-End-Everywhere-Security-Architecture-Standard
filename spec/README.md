# Specification

This directory contains E2EESA specification material.

## Document classes

- **Normative** — requirements necessary for conformance.
- **Informative** — rationale, examples, guidance, and explanatory material.
- **Provisional** — material tied to an external specification that is not yet stable enough to be treated as final.
- **Experimental** — research material that MUST NOT be treated as production-recommended merely because it appears in this repository.

Normative requirements use RFC 2119 / RFC 8174 terminology intentionally and sparingly.

## Current normative documents

1. [Normative Language](normative-language.md) — requirement keywords, scope, configuration, claims, conflicts, external specifications, and experimental status.
2. [Terminology](terminology.md) — core actor, trust-boundary, cryptographic, E2EE, identity, compromise, recovery, group, assurance, and threat-model terms.
3. [Unified Threat Model](threat-model.md) — protected assets, adversary capabilities, compromise classes, composite scenarios, temporal compromise, service/endpoint assumptions, recovery and hardware assumptions, and post-quantum threat scope.
4. [Security Properties Model](security-properties.md) — machine-readable security claims, claim states, temporal phases, property definitions, property independence, threat coverage, assumptions, limitations, and fail-closed interpretation.
5. [Profile and Configuration Model](profile-configuration.md) — exact version pinning, profile families, lifecycle status, deterministic dependency expansion, incompatibility, cardinality, and fail-closed configuration resolution.
6. [Cryptographic Registry and Lifecycle](cryptographic-registry.md) — standardized cryptographic building blocks, exact registry identifiers, lifecycle status, named suites, post-quantum scope, and fail-closed algorithm selection.
7. [Negotiation and Downgrade Defense](negotiation-downgrade.md) — explicit version ordering, minimum-version enforcement, exact suite/registry/profile pinning, authenticated transcript binding, no weaker fallback, and freshness/replay requirements.\n8. [Identity and Device Architecture](identity-device-architecture.md) — server-independent device authorization, enrollment, rotation, revocation, state binding, and account-root/cross-signing/quorum profile alternatives.\n9. [Pairwise End-to-End Encryption Profiles](pairwise-e2ee.md) — asynchronous X3DH/PQXDH initialization, Double Ratchet/SPQR/Triple Ratchet alternatives, forward secrecy, post-compromise security, replay handling, key deletion, and post-quantum claim boundaries.\n10. [Group End-to-End Encryption Profiles](group-e2ee.md) — MLS 1.0, Sender-Keys-style AEAD, and pairwise-fanout alternatives with authenticated membership epochs, rekeying, device revocation, replay defense, and explicit FS/PCS boundaries.

## Planned top-level specification areas

1. terminology;
2. threat model;
3. security properties;
4. profile model and compatibility;
5. cryptographic registry and lifecycle;
6. identity, messaging, recovery, metadata, media, transport, and client profiles;
7. secure development and verification;
8. certification;
9. vulnerability handling;
10. observatory/evidence provenance;
11. research promotion and emergency migration.
