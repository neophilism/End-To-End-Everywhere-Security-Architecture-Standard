# ADR 0009: Backup and recovery profiles

**Status:** Accepted for pre-1.0 development

## Context

E2EE creates a genuine availability tradeoff. If all endpoint-held keys are lost, historical content is unrecoverable unless some recovery mechanism exists. A server-held decryption key would defeat the end-to-end trust model, while password-only recovery can be vulnerable to offline guessing. Hardware-backed release can add online rate limiting and an independent security boundary, but it must not become a unilateral server decryption path.

## Serious alternatives considered

1. **No recoverable backup.** Strongest backup-service confidentiality and simplest trust model, but historical data is permanently lost when all authorized copies disappear.
2. **Server escrow of plaintext or a server-readable content key.** Rejected because the service could decrypt user content.
3. **User-secret encrypted backup.** Practical and service-independent, provided the secret is protected by a memory-hard KDF and the product is honest about offline guessing risk.
4. **Hardware/HSM-assisted recovery.** Adds authenticated and rate-limited hardware release around the already user-secret-encrypted recovery envelope. Stronger against online guessing and some service compromise, at the cost of an additional availability/trust dependency.
5. **HSM-only recovery with no user-held secret.** Rejected because compromise or abuse of the recovery service/HSM could become sufficient for plaintext recovery.
6. **Threshold HSM recovery.** Potentially valuable, but not standardized by this ADR; E2EESA will not fake threshold guarantees without a concrete threshold protocol.

## Decision

E2EESA defines three mutually exclusive profiles:

- `backup-none@0.1.0` — allowed;
- `backup-user-secret@0.1.0` — recommended; and
- `backup-hardware-assisted@0.1.0` — recommended when an appropriate hardware recovery service is available.

Recoverable profiles use a fresh random BDEK for every generation.

The user secret is processed with Argon2id (RFC 9106) and then a registered HKDF for domain separation.

The hardware-assisted profile wraps the already user-secret-protected inner envelope under a non-exportable hardware key. Hardware/service compromise alone therefore remains insufficient.

Recovery never authorizes a device; PR #8 authorization happens first.

## Security consequences

The no-backup profile deliberately sacrifices recovery availability.

The user-secret profile protects against storage-service compromise, but user-chosen passphrases remain subject to offline guessing.

The hardware-assisted profile adds rate limiting and a hardware security boundary without giving that hardware direct access to the BDEK.

Rollback protection requires retained authenticated generation state outside the untrusted storage service.

## Standards basis

- RFC 9106, Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications.
- NIST SP 800-57 Part 1 Rev. 5, key backup and recovery guidance.
- FIPS 140-3, Security Requirements for Cryptographic Modules.
- NIST SP 800-63B-4, current password-verifier guidance on salted, costly password hashing and rate limiting.

## Reconsideration triggers

Revisit if a broadly standardized password-authenticated recovery protocol offers superior offline-attack properties, if E2EESA adopts a concrete threshold-HSM protocol, if hardware attestation standards materially change, or if post-quantum requirements change the backup key-wrapping threat model.
