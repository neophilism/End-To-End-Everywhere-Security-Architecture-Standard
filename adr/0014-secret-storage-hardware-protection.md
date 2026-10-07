# ADR 0014: Secret storage and hardware protection

**Status:** Accepted for pre-1.0 development

## Context

E2EE protocols eventually place durable secrets on endpoints. Protecting network traffic is insufficient if long-lived identity keys, ratchet state, recovery wrappers, or group state are trivially extractable from local storage.

No single storage mechanism works everywhere. Mobile systems offer OS keystores and secure hardware, desktops commonly expose TPMs, enterprises may use HSMs or external tokens, and some platforms have only software protection.

## Serious alternatives considered

1. **Plain application files/database.** Rejected for secrets at rest.
2. **Native OS keystore/keychain.** Selected as the general recommended baseline.
3. **Secure Enclave / StrongBox / TEE / TPM / HSM.** Selected as the stronger hardware-isolated profile.
4. **External cryptographic token.** Selected for removable/high-assurance deployments using PKCS #11 or equivalent.
5. **Software encrypted vault.** Selected only as an explicit fallback with Argon2id and honest weaker claims.
6. **Put every ratchet/session secret directly in hardware.** Rejected as a universal requirement because many hardware modules cannot efficiently represent fast-changing arbitrary protocol state.
7. **Non-exportable hardware root protecting a software vault.** Selected as the primary architecture pattern.
8. **Authenticated encryption alone as rollback protection.** Rejected because old authenticated ciphertext can be replayed.
9. **Silent hardware-to-software fallback.** Rejected because it creates an undetectable security downgrade.

## Decision

E2EESA defines four mutually exclusive secret-storage profiles:

- secret-platform-keystore@0.1.0
- secret-hardware-isolated@0.1.0
- secret-external-token@0.1.0
- secret-software-vault@0.1.0

The hardware-isolated mechanism registry includes Apple Secure Enclave, Android TEE/StrongBox, and TCG TPM 2.0 Version 185.

External-token deployments use PKCS #11 v3.2 or an equivalently reviewed token API.

Rollback resistance is orthogonal to encryption and requires a hardware-monotonic or independent-witness anchor.

## Security consequences

Hardware isolation strongly improves raw-key extraction resistance but does not prevent a compromised authorized process from requesting permitted cryptographic operations or reading plaintext after authorized decryption.

Software fallback can protect offline storage when the unlock secret is strong but cannot claim non-exportability.

Per-device roots avoid turning multi-device synchronization into raw hardware-key replication.

## Current standards basis

- TCG TPM 2.0 Library Specification Version 185, March 2026.
- OASIS PKCS #11 Specification Version 3.2.
- Apple Secure Enclave key protection documentation.
- Android Keystore/KeyMint and StrongBox documentation.
- RFC 9106 Argon2id for the software-vault fallback.
- FIPS 140-3 may be used as supporting assurance evidence for applicable HSM boundaries.

## Reconsideration triggers

Revisit when platform hardware APIs expose stronger portable rollback counters, when PKCS #11 or TPM revisions change required semantics, when passkey/security-key APIs safely expose general-purpose secret wrapping suitable for this profile, or when standardized confidential-computing local-vault APIs provide stronger cross-platform guarantees.
