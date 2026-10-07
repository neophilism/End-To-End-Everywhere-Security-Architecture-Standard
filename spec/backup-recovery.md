# Backup and Recovery Profiles

**Status:** Normative

This document defines E2EESA backup and recovery architectures for protected content and content-decryption keying material. It distinguishes availability from authorization: recovering encrypted history is never sufficient to authorize a device or endpoint.

## 1. Core invariant

A backup or recovery mechanism **MUST NOT** give the storage service, backup provider, recovery service, hardware operator, or any other non-recipient the ability to recover ordinary protected-content plaintext by itself.

A successful restore **MUST NOT** authorize the restoring device. The restoring device **MUST** already be authorized under the selected PR #8 identity/device architecture before protected history is released to it.

Backup recovery and account/device recovery are separate security operations.

## 2. Fresh backup data keys

Every recoverable backup generation **MUST** use a fresh randomly generated backup data-encryption key (BDEK) containing at least 256 random bits.

A BDEK **MUST NOT** be reused across backup generations.

The backup generation number **MUST** increase monotonically. Full replacement of a backup generation therefore rotates the BDEK.

The BDEK **MUST NOT** be uploaded to or retained by the storage service in unwrapped form.

## 3. Authenticated backup manifest

Every recoverable backup **MUST** include an authenticated manifest that binds at least:

- backup identifier;
- owning cryptographic identity;
- backup/recovery profile reference;
- generation number;
- content AEAD algorithm;
- BDEK identifier;
- chunk/object identifiers or authenticated digests; and
- format/schema version.

The manifest **MUST** be authenticated before any restored plaintext is released.

Changing the identity, generation, algorithm selection, or object set without detection **MUST** be impossible within the selected AEAD/authentication construction.

## 4. Content encryption

Recoverable backup content **MUST** be encrypted client-side with a registered, non-prohibited AEAD algorithm under the generation's BDEK.

Nonce/IV construction **MUST** satisfy the requirements of the selected AEAD. Implementations **MUST NOT** reuse an AEAD nonce under the same key.

Backup storage MAY reside on an untrusted service.

The service **MUST NOT** receive plaintext content, the recovery secret, or the unwrapped BDEK.

## 5. Profile A — no recoverable backup

Profile reference: `backup-none@0.1.0`

This profile retains no recoverable copy of protected content or content-decryption keying material outside currently authorized E2EE endpoints.

The service **MUST NOT** hold a server-restorable encrypted history whose decryption authority is recoverable after all authorized endpoints lose the relevant key material.

Direct device-to-device migration remains permitted when:

- the source device is currently authorized;
- the destination device is already authorized under PR #8; and
- content is transferred through an authenticated E2EE channel.

Such migration is not a persistent recovery backup.

This profile maximizes confidentiality against backup-service compromise but intentionally provides no historical recovery after all authorized copies are lost.

## 6. Profile B — user-secret recovery

Profile reference: `backup-user-secret@0.1.0`

This is a recommended general-purpose recovery profile.

The client generates the BDEK locally. The BDEK is wrapped inside a user-secret recovery envelope.

The user secret **MUST** be processed with `ALG-ARGON2ID` using Argon2 version 0x13, a random salt of at least 16 bytes, and parameters meeting at least one E2EESA 0.1 floor:

1. at least 2 GiB memory and at least 1 pass; or
2. at least 64 MiB memory and at least 3 passes.

These floors correspond to the first and second recommended Argon2id configurations in RFC 9106.

The Argon2id output **MUST** be domain-separated through a registered HKDF before use as the key-encryption material for the inner recovery envelope.

The policy **MUST** store the exact Argon2id and HKDF parameters required to reproduce the derivation.

## 7. Recovery-secret classes

The user-secret and hardware-assisted profiles support two secret classes.

### 7.1 Generated high-entropy recovery secret

A generated recovery secret **MUST** contain at least 128 random bits before human encoding.

This is the recommended secret class.

The encoded representation SHOULD include transcription-error detection where practical, but error-detection data **MUST NOT** be counted toward secret entropy.

### 7.2 User-chosen passphrase

A user-chosen passphrase MAY be supported.

Argon2id increases the cost of an offline guessing attack but cannot convert a low-entropy passphrase into a high-entropy secret.

Products **MUST NOT** claim equivalent offline resistance between an arbitrary user-chosen passphrase and a uniformly generated 128-bit recovery secret.

The product SHOULD apply current password usability guidance and SHOULD make the weaker offline-guessing boundary visible in security documentation.

## 8. Profile C — hardware/HSM-assisted recovery

Profile reference: `backup-hardware-assisted@0.1.0`

This is a recommended defense-in-depth profile when a trustworthy hardware-backed recovery service is available.

The client first creates the same Argon2id/HKDF-protected **inner** recovery envelope required by the user-secret profile.

That already-encrypted inner envelope is then wrapped again under a non-exportable hardware/HSM key using a registered AEAD algorithm.

The hardware layer **MUST NOT** receive the user recovery secret or the unwrapped BDEK.

The service or HSM therefore obtains, at most, the encrypted inner envelope. Compromise of the hardware/service alone remains insufficient to recover backup plaintext.

## 9. Hardware requirements

For the hardware-assisted profile:

- the hardware wrapping key **MUST** be non-exportable through ordinary application interfaces;
- the hardware security boundary and key lifecycle **MUST** be documented;
- hardware identity/attestation **MUST** be verified before accepting a release operation;
- recovery release requests **MUST** be authenticated;
- failed recovery attempts **MUST** be rate limited;
- hardware key rotation and destruction procedures **MUST** be documented; and
- the outer envelope **MUST** bind the backup identifier, generation, profile, and inner-envelope digest as authenticated data.

FIPS 140-3 validation is acceptable evidence for an HSM security boundary. E2EESA also permits equivalently evaluated HSMs or platform secure hardware when their assurance claims are explicitly documented.

E2EESA 0.1 does not define threshold-HSM cryptography. A product **MUST NOT** claim threshold recovery merely because multiple replicas of the same wrapping key exist.

## 10. Rollback resistance

A restore operation **MUST** compare the candidate backup generation with the latest authenticated generation known to the client or recovery state.

A stale generation **MUST** be rejected by the normal restore path.

Products MAY implement an explicit historical-export feature, but such an operation **MUST** be represented separately from ordinary recovery and **MUST NOT** silently roll security-relevant application state backward.

The service **MUST NOT** be trusted as the sole source of the latest-generation value.

## 11. Restore sequence

A conforming restore proceeds in this order:

1. authorize the restoring device under PR #8;
2. retrieve encrypted backup material;
3. authenticate the manifest and generation;
4. enforce rollback protection;
5. for hardware-assisted recovery, verify the hardware endpoint and complete the authenticated, rate-limited outer unwrap;
6. obtain the user recovery secret locally;
7. derive recovery key material locally with the exact Argon2id and HKDF policy parameters;
8. unwrap the BDEK locally;
9. authenticate backup ciphertext before exposing plaintext; and
10. preserve evidence that recovery did not itself grant device authority.

The storage/recovery service **MUST NOT** receive restored plaintext or the unwrapped BDEK during this process.

## 12. Key and secret deletion

Used transient Argon2id output, HKDF output, unwrapped BDEKs, and plaintext staging buffers **SHOULD** be erased from memory as soon as practical after use.

When a backup generation is deleted, clients SHOULD destroy any locally retained recovery material that exists solely for that generation.

Cryptographic erasure claims **MUST** state which remaining copies, replicas, hardware keys, and user-held secrets are assumed destroyed.

## 13. Backup metadata

Encryption of content does not automatically hide backup metadata.

A storage provider may still learn information such as backup existence, approximate size, upload timing, object count, or account association unless another profile conceals it.

The backup profiles therefore **MUST NOT** imply `SP-METADATA-CONFIDENTIALITY` unless a separate valid claim establishes it.

## 14. Availability and denial of service

Backup confidentiality and recovery confidentiality do not guarantee availability.

A storage service can delete or withhold ciphertext. A hardware recovery service can be unavailable. A user can lose a recovery secret.

Products **MUST** document these failure modes instead of weakening confidentiality requirements to make recovery appear guaranteed.

## 15. Security claim boundaries

`SP-BACKUP-CONFIDENTIALITY` covers encrypted backup material against the declared backup adversary.

`SP-RECOVERY-CONFIDENTIALITY` covers the ordinary recovery mechanism and its recovery authorities.

For user-chosen passphrases, recovery confidentiality against an offline storage adversary is conditional on passphrase strength and Argon2id cost.

For hardware-assisted recovery, the claim assumes that the user secret and hardware security boundary are not simultaneously compromised in a way that exposes both layers.

The no-backup profile does not claim recoverability.

## 16. Conformance evidence

A conforming implementation **MUST** demonstrate, as applicable:

1. exact backup/recovery profile;
2. registered AEAD/KDF selections;
3. fresh ≥256-bit BDEK per generation;
4. authenticated manifest binding identity and generation;
5. no server plaintext or unwrapped-BDEK access;
6. no upload of the user recovery secret;
7. exact Argon2id version, salt, memory, iteration, parallelism, and output parameters;
8. local secret derivation;
9. rollback protection;
10. prior authorization of the restoring device;
11. recovery not granting device authority;
12. for hardware recovery, non-exportable wrapping key, attestation, authenticated release, and rate limiting; and
13. successful ciphertext authentication before plaintext release.

The reference semantic validator consumes evidence of these operations. It does not substitute for correct Argon2id, HKDF, AEAD, HSM, secure-storage, or memory-erasure implementations.
