# Secret Storage and Hardware Protection

**Status:** Normative

This document defines E2EESA protection for long-lived device keys and mutable local E2EE secret state.

Profiles:

- secret-platform-keystore@0.1.0
- secret-hardware-isolated@0.1.0
- secret-external-token@0.1.0
- secret-software-vault@0.1.0

## 1. Protected local assets

Protected assets include device identity private keys, prekeys, ratchet state, MLS state, attachment/media key state, recovery wrappers, transparency checkpoints, local authorization state, and other secrets whose disclosure or rollback can weaken E2EE.

No profile allows plaintext secret material to be persistently stored at rest.

## 2. Root/wrapping key architecture

E2EESA does not require every rapidly changing ratchet or protocol secret to execute directly inside a hardware module.

A conforming implementation MAY keep mutable protocol state inside an authenticated encrypted local vault protected by a 256-bit vault key.

The vault key or key-encryption root MUST be protected according to the selected profile.

Hardware profiles SHOULD keep the high-value root/wrapping key non-exportable and use it to unwrap or derive access to the software vault.

This preserves practical protocol performance while reducing exposure of the durable root key.

## 3. Common invariants

All profiles MUST:

- use a registered non-prohibited AEAD for the encrypted vault;
- authenticate the vault before releasing secret state;
- maintain monotonically increasing vault generations;
- prohibit raw root-key export;
- prohibit raw root-key cloud synchronization;
- prohibit persistent plaintext secrets at rest;
- bind key use to an application/device authorization policy;
- rotate/reprotect keying when the relevant local authentication policy materially changes; and
- document what happens when the protecting key becomes unavailable or is invalidated.

Encrypted vault ciphertext MAY be backed up or synchronized only when the applicable recovery/backup profile permits it. The raw local root/wrapping key MUST NOT accompany it.

## 4. Profile A — native platform keystore

Profile reference: secret-platform-keystore@0.1.0

This profile uses the platform's native keystore or keychain to confine a root/private/wrapping key from ordinary application export.

Hardware backing MAY be used when available but is not required or claimed by this profile.

An implementation MUST verify that the platform API actually marks the protecting key non-exportable or equivalently confines raw key extraction.

Merely storing bytes in application preferences, a database, or a filesystem location named "keystore" does not satisfy this profile.

Platform access-control options SHOULD require a recent device unlock or user authentication for particularly sensitive long-lived identity/recovery operations when the product threat model permits the usability cost.

## 5. Profile B — hardware-isolated storage

Profile reference: secret-hardware-isolated@0.1.0

This profile requires a hardware-isolated key manager such as:

- Apple Secure Enclave;
- Android StrongBox;
- Android hardware-backed Keystore/TEE;
- TPM 2.0;
- a local HSM; or
- another independently reviewed equivalent.

The root/wrapping key MUST be non-exportable from the hardware boundary.

The implementation MUST verify attestation or equivalent authoritative platform evidence demonstrating the selected security boundary and key attributes.

A configuration that requests StrongBox, Secure Enclave, TPM, or HSM operation but silently falls back to software MUST NOT continue claiming this profile.

## 6. Apple Secure Enclave

Apple Secure Enclave deployments MUST use APIs that cause the private key to be generated/held by Secure Enclave rather than merely storing an exportable private key in the Keychain.

The application MUST document which key operations remain inside the Secure Enclave and which secret state is encrypted outside it.

This profile does not assume that Apple exposes an application-usable secure monotonic counter. Rollback resistance therefore requires a separate valid anchor when claimed.

## 7. Android Keystore, TEE, and StrongBox

Android implementations MUST inspect the resulting key security level rather than inferring hardware protection from the API call used to request it.

TrustedEnvironment or StrongBox evidence MAY satisfy the hardware-isolated profile when the attestation/security-level verification succeeds.

If StrongBox is requested but unavailable and the application falls back to TEE or software, the resulting profile and evidence MUST reflect the actual boundary.

Hardware-backed key attestation MUST validate the attestation chain, security level, key properties, and applicable revocation information before it is trusted.

## 8. TPM 2.0

TPM deployments use the TCG TPM 2.0 Library Specification Version 185 baseline in E2EESA 0.1.

A TPM-protected root key MUST be created or loaded with attributes and authorization policy that prevent raw private/secret extraction through the application's normal interface.

Where rollback protection is required, a correctly authorized TPM NV monotonic counter or equivalent TPM-backed monotonic state MAY serve as the rollback anchor.

PCR/sealing policy MAY additionally bind a key to measured platform state, but measured boot is not mandatory for every E2EESA secret-storage deployment.

## 9. Profile C — external hardware token

Profile reference: secret-external-token@0.1.0

This profile uses an external cryptographic token/HSM, normally through PKCS #11 v3.2 or an equivalent reviewed interface.

The root/wrapping key MUST be created or imported as non-extractable according to the token's security model.

The token MUST require an explicit authorization such as PIN, user verification, or user-presence-equivalent control before sensitive key use when supported.

Removing the token MAY intentionally make the local encrypted vault unavailable.

A product MUST document whether token cloning, administrative duplication, backup objects, or vendor recovery can create another usable copy of the key.

## 10. Profile D — software vault fallback

Profile reference: secret-software-vault@0.1.0

This profile exists for platforms that lack a trustworthy keystore/hardware boundary.

It MUST NOT claim hardware isolation or non-exportability.

The local vault is protected by a user-held or generated secret processed locally with ALG-ARGON2ID, Argon2 version 0x13.

The Argon2id configuration MUST meet at least one RFC 9106 recommendation floor:

- at least 2 GiB and 1 pass; or
- at least 64 MiB and 3 passes.

A generated unlock secret MUST contain at least 128 random bits before encoding.

A user-chosen passphrase MAY be supported, but the implementation MUST document that Argon2id increases guessing cost and does not turn a low-entropy passphrase into a high-entropy secret.

## 11. User authentication and key-use authorization

Key non-exportability is distinct from authorization to use the key.

Policies MAY require device authentication, biometric/user verification, PIN, token presence, or other local authorization before sensitive operations.

Hardware-backed keys SHOULD encode key-use restrictions in the hardware/keystore policy when the platform supports them.

An implementation MUST NOT treat successful app-process access alone as proof of user presence when the selected policy requires explicit user authentication/presence.

## 12. Rollback protection

Encrypted integrity alone does not prevent an attacker from replacing a current authenticated vault with an older authenticated vault.

A policy that claims rollback protection MUST therefore use an anchor that is not rolled back with the vault.

E2EESA 0.1 supports:

- hardware-monotonic — TPM NV counter or independently equivalent monotonic hardware state; and
- independent-witness — an authenticated monotonic state held by a separate trusted/witnessed system whose rollback would be detected under its own trust model.

The anchor value MUST increase when the protected vault generation advances.

A profile with rollback_anchor_mode = none MUST NOT claim SP-ROLLBACK-RESISTANCE for local state.

A remote ordinary database controlled by the same adversary as the rollbackable vault is not an independent witness.

## 13. Vault generations

Every durable secret-state update MUST produce a monotonically increasing vault generation.

For the reference profile, the next committed generation is exactly previous_generation + 1.

Writers MUST use atomic replacement or an equivalent crash-consistent commit protocol so a power loss cannot leave a partially authenticated current generation.

A previous generation MAY be retained briefly for crash recovery only if the product can distinguish recovery from attacker-driven rollback and its rollback policy remains satisfied.

## 14. Key rotation and invalidation

Root/wrapping keys MUST be rotated when:

- the key is suspected compromised;
- hardware/token attestation no longer satisfies policy;
- a material local authentication policy change requires new key authorization;
- a device ownership/reset transition invalidates the old trust boundary; or
- the selected platform requires migration.

Rotation MUST rewrap/reprotect the vault under fresh keying before the old key is invalidated, unless emergency compromise handling deliberately chooses destructive invalidation.

A normal completed rotation MUST invalidate the superseded key for future encryption/decryption use.

## 15. Device reset, biometric change, and enrollment change

Platforms differ in how key validity reacts to passcode reset, biometric enrollment, OS reinstall, secure-element reset, or device migration.

The implementation MUST test and document the selected platform behavior.

If a key becomes invalidated, E2EESA recovery MUST proceed through an applicable PR #13 recovery path or reauthorization flow; the application MUST NOT silently export or escrow the local root key merely to avoid such failures.

## 16. Cloud sync and multi-device use

Raw local root/wrapping keys MUST NOT be synchronized between devices.

Each device SHOULD have its own local root key and authorization boundary.

Cross-device account access is established through PR #8 device authorization and applicable key-distribution/recovery protocols, not by copying the same local hardware key to every device.

Encrypted vault backups MAY be synchronized only if their decryptability and recovery semantics satisfy PR #13.

## 17. Live endpoint compromise boundary

Hardware isolation greatly improves resistance to storage extraction and raw key theft.

It does not make an already-authorized live endpoint trustworthy.

Malware executing with sufficient privileges while the user/app is authorized may be able to ask a non-exportable key to perform allowed cryptographic operations, read plaintext after legitimate decryption, or capture newly generated protocol secrets before they are sealed.

Profiles MUST distinguish raw-key extraction resistance from live-use authorization abuse.

## 18. Memory handling

Plaintext vault contents, unwrapped vault data keys, ratchet state, and derived secrets SHOULD have the shortest practical lifetime in general-purpose memory.

Implementations SHOULD avoid unnecessary copies, crash dumps, swap/page exposure where controllable, diagnostic logging, and serialization into unmanaged temporary files.

Hardware-backed root keys MUST never be copied into application memory if the platform provides non-exportable operation handles.

## 19. Attestation boundaries

Attestation proves only the properties actually covered by the attestation statement and verification policy.

An implementation MUST verify the complete chain/evidence and compare the reported hardware/security level, key attributes, application binding, firmware/security version where relevant, and revocation status to policy.

Attestation MUST NOT be interpreted as proof that the entire application, operating system, user, or device is uncompromised unless the attestation mechanism explicitly establishes that claim.

## 20. Failure behavior

If the required hardware boundary, attestation, non-exportability, user-authentication policy, rollback anchor, or token presence cannot be established, the implementation MUST fail closed for that profile.

It MAY explicitly select a weaker allowed profile when product policy permits, but MUST expose the actual selected profile to configuration/conformance evidence.

Silent downgrade is prohibited by PR #7 downgrade/negotiation rules.

## 21. Conformance evidence

A conforming implementation MUST demonstrate, as applicable:

1. exact storage profile and mechanism;
2. registered vault AEAD;
3. root-key non-exportability;
4. actual hardware isolation/security level when claimed;
5. attestation/equivalent evidence when required;
6. key-use and user-authentication policy;
7. authenticated vault verification before plaintext use;
8. monotonic vault generation;
9. independent rollback-anchor advancement when rollback resistance is required;
10. no persistent plaintext secret state;
11. no raw root-key export or cloud synchronization;
12. local Argon2id derivation for software fallback;
13. root-key rotation/invalidation semantics;
14. rewrap before normal rotation completion; and
15. accurate failure/downgrade behavior when stronger hardware is unavailable.
