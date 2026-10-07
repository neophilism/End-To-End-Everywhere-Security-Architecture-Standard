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
7. [Negotiation and Downgrade Defense](negotiation-downgrade.md) — explicit version ordering, minimum-version enforcement, exact suite/registry/profile pinning, authenticated transcript binding, no weaker fallback, and freshness/replay requirements.\n8. [Identity and Device Architecture](identity-device-architecture.md) — server-independent device authorization, enrollment, rotation, revocation, state binding, and account-root/cross-signing/quorum profile alternatives.\n9. [Pairwise End-to-End Encryption Profiles](pairwise-e2ee.md) — asynchronous X3DH/PQXDH initialization, Double Ratchet/SPQR/Triple Ratchet alternatives, forward secrecy, post-compromise security, replay handling, key deletion, and post-quantum claim boundaries.\n10. [Group End-to-End Encryption Profiles](group-e2ee.md) — MLS 1.0, Sender-Keys-style AEAD, and pairwise-fanout alternatives with authenticated membership epochs, rekeying, device revocation, replay defense, and explicit FS/PCS boundaries.\n11. [Key Verification](key-verification.md) — canonical safety-number and QR verification with account-root and active-device-set subject profiles, explicit out-of-band confirmation, change invalidation, and the subject-digest interface for key transparency.

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

12. [Key Transparency](key-transparency.md) — IETF Key Transparency deployment profiles for authenticated directory lookup, consistency, monitoring, split-view detection, third-party auditing/management, and PR #11 subject-digest binding.

13. [Backup and Recovery Profiles](backup-recovery.md) — no-backup, Argon2id user-secret, and hardware/HSM-assisted recovery profiles with client-side encryption, fresh backup keys, rollback protection, and strict separation of restore from device authorization.

14. [Metadata Privacy Profiles](metadata-privacy.md) — bounded metadata minimization, sender-hidden delivery, and RFC 9458 OHTTP relay partitioning with explicit source-address, recipient-routing, traffic-analysis, and non-collusion boundaries.

15. [Contact Discovery Profiles](contact-discovery.md) — exact-handle/invite discovery, RFC 9497 VOPRF private membership, and attested confidential-compute private-set discovery with normalization, discoverability, enumeration, and side-channel boundaries.

16. [Attachments and File Encryption](attachments-file-encryption.md) — fresh-key chunked AEAD attachments with exact nonce/AAD construction, authenticated private manifests, safe streaming/range retrieval, E2EE key distribution, substitution/replay protection, and non-misleading deletion semantics.

17. [Real-Time Media](real-time-media.md) — RFC 9605 SFrame voice/video E2EE with sender-key and MLS key-management profiles, exact MLS KID derivation, membership/compromise rekeying, replay/CTR state, SFU trust boundaries, and explicit recording-participant semantics.

18. [Secret Storage and Hardware Protection](secret-storage-hardware-protection.md) — OS keystore, Secure Enclave/StrongBox/TEE/TPM/HSM, external PKCS #11 token, and Argon2id software-vault profiles with non-exportability, attestation, rollback anchors, lifecycle rotation, and live-endpoint claim boundaries.

19. [Transport Security Profiles](transport-security.md) — RFC 9846 TLS 1.3 classical and RFC 10024 ML-KEM/traditional hybrid profiles for stream TLS and QUIC, with RFC 9525 identity verification, mTLS service-to-service support, safe resumption, explicit 0-RTT replay controls, and E2EE-layer independence.

20. [Native and Web Client Security](native-web-client-security.md) — signed native, hardened web, and independently verified web-bootstrap profiles with release manifest binding, transparency witnesses, rollback/freeze controls, origin hardening, and explicit execution trust assumptions.

21. [Server Trust Minimization](server-trust-minimization.md) — ciphertext-only service infrastructure with exhaustive component/key inventory, client-authorized recipient sets, bounded retention, encrypted derivatives and explicit routing/availability limitations.

22. [Privacy-Preserving Telemetry](privacy-preserving-telemetry.md) — no-export, opt-in minimized diagnostics and pure-DP aggregate alternatives with closed event schemas, explicit collector trust, contribution clipping and lifetime privacy-budget accounting.

23. [Secure Development Standard](secure-development-standard.md) — SSDF-aligned process controls, independent exact-source review, test/fuzz/scanning release gates, dependency/change control and checked remediation or limited expiring risk acceptance.
