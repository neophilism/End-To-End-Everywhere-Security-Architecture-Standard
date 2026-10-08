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
7. [Negotiation and Downgrade Defense](negotiation-downgrade.md) — explicit version ordering, minimum-version enforcement, exact suite/registry/profile pinning, authenticated transcript binding, no weaker fallback, and freshness/replay requirements.
8. [Identity and Device Architecture](identity-device-architecture.md) — server-independent device authorization, enrollment, rotation, revocation, state binding, and account-root/cross-signing/quorum profile alternatives.
9. [Pairwise End-to-End Encryption Profiles](pairwise-e2ee.md) — asynchronous X3DH/PQXDH initialization, Double Ratchet/SPQR/Triple Ratchet alternatives, forward secrecy, post-compromise security, replay handling, key deletion, and post-quantum claim boundaries.
10. [Group End-to-End Encryption Profiles](group-e2ee.md) — MLS 1.0, Sender-Keys-style AEAD, and pairwise-fanout alternatives with authenticated membership epochs, rekeying, device revocation, replay defense, and explicit FS/PCS boundaries.
11. [Key Verification](key-verification.md) — canonical safety-number and QR verification with account-root and active-device-set subject profiles, explicit out-of-band confirmation, change invalidation, and the subject-digest interface for key transparency.
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
24. [Software Supply Chain](software-supply-chain.md) — immutable transitive inventories, SPDX/CycloneDX SBOM evidence, authenticated SLSA 1.2 build-provenance expectations and independent byte reproduction, plus a deterministic source-release builder.
25. [Security Verification Framework](security-verification-framework.md)
26. [Formal Verification Profiles](formal-verification-profiles.md) — symbolic protocol, computational cryptographic, and code/refinement proof profiles with exact evidence binding. — black-box, white-box and combined assessment profiles with exact configuration/artifact binding, per-profile method/threat/property coverage, corpus/model evidence and bounded seeded reference security checks.
27. [Assurance Levels](assurance-levels.md) — monotonic A1–A5 evidence tiers composing external/source assessment, secure development, supply chain and formal proof depth.
28. [Certification Evidence Model](certification-evidence-model.md) — content-addressed exact-scope certification evidence bundles, claim-to-evidence linkage, source-access declarations, and non-MUST exception records.
29. [Certification Lifecycle](certification-lifecycle.md) — event-sourced application, evaluation, remediation, decision, surveillance, renewal, suspension, revocation, expiry, and appeal state machine.
30. [Signed Certification Attestations](certification-attestations.md) — canonical certification payloads, JWS/COSE/DSSE envelope options, classical and dual classical+PQ signing policies, and signed rollback-resistant status statements.
31. [Vulnerability Disclosure Profiles](vulnerability-disclosure-profiles.md) — RFC 9116 intake, reporter protection, active-exploitation escalation, and selectable risk-adaptive or fixed 90+30 disclosure clocks.
32. [Vulnerability Handling](vulnerability-handling.md) — event-sourced validation, prioritization, root-cause analysis, remediation, retesting, emergency handling, risk acceptance, and disclosure-clock enforcement.
33. [Advisory Interoperability](advisory-interoperability.md) — normalized vulnerability advisories with stable CSAF 2.0/ISO 20153 and provisional CSAF 2.1 exports, modern risk-signal provenance, and external conformance evidence.
34. [Observatory Evidence Model](observatory-evidence-model.md) — immutable content-addressed evidence, W3C-PROV-style entities/activities/agents, acquisition history, citations, revisions, real-world events, and composable integrity anchors.
35. [Observatory Data Architecture](observatory-data-architecture.md) — append-only canonical relational evidence with deterministic property-graph, W3C PROV RDF, and search projections plus PostgreSQL reference DDL.
36. [Confidence and Classification Model](confidence-classification.md) — human-reviewed, automated, and mixed classification with explicit dimensional, STIX 0–100, and calibrated-probability confidence semantics.
37. [Research Profile Registry](research-profile-registry.md) — content-addressed experimental research entries with threat/property/algorithm context, hypotheses, experiments, vectors, implementations, results, limitations, and reproducibility.
38. [Research → Production Promotion Gates](research-production-promotion.md) — sequential Experimental → Candidate → Recommended → Required promotion with machine-readable independent-review/evidence paths and production-catalog projection.
39. [Deprecation and Emergency Migration](deprecation-emergency-migration.md) — planned and emergency retirement state machines, downgrade-safe cutover, bounded historical processing, dependency impact, registry projection, and overdue enforcement.
40. [Conformance Engine](conformance-engine.md) — deterministic production, Candidate-evaluation, and migration-only conformance with complete family scope, Required-profile enforcement, full property evidence, and exact standards/product digest binding.
41. [Conformance CLI](conformance-cli.md) — deterministic no-network CLI for basis discovery, request binding, PR 40 evaluation, saved-result verification, and human-readable explanation with stable CI exit codes.
42. [Compatibility and Configuration Solver](compatibility-configuration-solver.md) — deterministic no-ranking enumeration of PR 2-compatible configurations constrained by lifecycle mode, PR 38 Candidate/Required state, pins/exclusions, family scope inputs, desired properties, and explicit search limits.
43. [Reference Fixtures](reference-fixtures.md) — executable catalog-complete positive and negative lifecycle fixtures for every exact profile ref, materialized through PR 42 and re-resolved through PR 2.
44. [Cross-Profile Interoperability Suite](cross-profile-interoperability.md) — full production-profile pair matrix distinguishing co-configuration, exclusive alternatives, direct incompatibility, dependency composition and contextual conflicts without inferring wire interoperability.
45. [Six-Project Integration Contracts](integration-contracts.md) — stable content-addressed artifact contracts for SDK, Verified, Security Lab, Incident Exchange, Observatory, and Research Lab.

## Remaining specification areas

Formal verification, assurance levels, certification, vulnerability handling, observatory/evidence models, research promotion, conformance/interoperability, integration contracts, crosswalk/rationale and release review remain subsequent milestones.
