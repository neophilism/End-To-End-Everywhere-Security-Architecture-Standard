# Pairwise End-to-End Encryption Profiles

**Status:** Normative

This document defines E2EESA profiles for asynchronous one-to-one end-to-end encrypted sessions between authorized devices. E2EESA does not invent a new secure-messaging primitive in this area. The profiles bind published protocol specifications to E2EESA identity, algorithm-lifecycle, downgrade, evidence, and conformance rules.

## 1. Scope and invariant

A pairwise E2EE session is a cryptographic session between exactly two authorized endpoints. The service MAY store prekey material, relay ciphertext, and coordinate delivery, but it **MUST NOT** possess the information necessary to derive ordinary message plaintext.

A conforming implementation **MUST**:

- bind the session to two device identities authorized by the identity/device architecture;
- authenticate the prekey material required by the selected initialization protocol;
- initialize the exact ratchet protocol named by the selected profile;
- derive a distinct message key for each protected message;
- authenticate protocol headers and identity-binding associated data required by the selected protocol;
- reject replay according to the selected initialization and ratchet protocols;
- delete message keys and superseded secret state when the protocol no longer requires them; and
- fail closed rather than silently falling back to a weaker pairwise profile.

## 2. Published protocol registry

Pairwise profiles **MUST** use protocol identifiers from `registry/pairwise-protocols.json`.

The initial registry pins:

- `PROTO-X3DH-R1` — Signal X3DH Revision 1, 2016-11-04;
- `PROTO-PQXDH-R3-2024` — Signal PQXDH Revision 3, last updated 2024-01-23;
- `PROTO-DOUBLE-RATCHET-R4` — Signal Double Ratchet Revision 4, 2025-11-04;
- `PROTO-SPQR-MLKEM-BRAID-R4` — the Sparse Post-Quantum Ratchet instantiated with ML-KEM Braid under Double Ratchet Revision 4;
- `PROTO-TRIPLE-RATCHET-R4` — the hybrid Triple Ratchet under Double Ratchet Revision 4; and
- `PROTO-SESAME-R2` — Signal Sesame Revision 2 for compatible multi-device session management.

A later change to an externally published protocol **MUST NOT** silently change the meaning of an existing E2EESA protocol identifier. A materially different external revision requires a new registry identifier and compatibility review.

## 3. Identity binding

The X3DH/PQXDH identity key used for a session **MUST** be cryptographically bound to the E2EESA-authorized device identity that is the session endpoint.

The service's assertion that a key belongs to a device is insufficient by itself. The binding **MUST** be derived from the current identity/device state and, when the applicable verification or transparency profiles are deployed, their verified view of that state.

The initialization protocol's identity keys **MUST** be included in authenticated associated data as required by the selected external protocol.

## 4. Prekey publication and verification

A responder MAY publish signed prekeys and one-time prekeys through an untrusted service.

The initiator **MUST** verify signed-prekey authentication before accepting the prekey bundle. If the selected initialization protocol includes a post-quantum signed prekey, that binding **MUST** also be verified as required by PQXDH.

If an applicable one-time prekey is available, a conforming E2EESA policy **MUST** use it. A consumed one-time private prekey **MUST** be deleted as specified by X3DH or PQXDH.

A service **MUST NOT** be trusted to guarantee one-time semantics by itself. Endpoints **MUST** implement the replay/key-reuse protections required by the selected protocol.

## 5. Initial-message replay and key reuse

X3DH and PQXDH permit cases where an initial message can be replayed when no one-time prekey was consumed.

The post-initialization protocol **MUST** ensure that the responder does not reuse the same encryption key material for its first encrypted response. A conforming implementation **MUST** reject a known replay and **MUST** initialize fresh ratchet state according to the selected profile.

Initial-message identifiers or equivalent replay state MAY be retained for replay protection, subject to metadata-minimization requirements.

## 6. Ratchet invariants

Every accepted protected message **MUST** use a message key unique to that message under the selected ratchet construction.

Message keys **MUST** be deleted after their permitted use. Superseded sending-chain, receiving-chain, root, epoch, and other secret state **MUST** be deleted when the selected protocol no longer requires it.

Out-of-order delivery MAY require temporary storage of skipped message keys. Implementations **MUST** configure and enforce an explicit finite maximum. A peer **MUST NOT** be able to force unbounded skipped-key storage.

## 7. Profile A — X3DH plus Double Ratchet

Profile reference: `pairwise-x3dh-double-ratchet@0.1.0`

This profile uses:

- `PROTO-X3DH-R1` for asynchronous initialization; and
- `PROTO-DOUBLE-RATCHET-R4` for ongoing secure messaging.

This is a classical profile. It **MUST NOT** claim post-quantum confidentiality or post-quantum authentication.

It remains an allowed interoperability profile for environments that deliberately choose classical cryptography.

## 8. Profile B — PQXDH plus Double Ratchet

Profile reference: `pairwise-pqxdh-double-ratchet@0.1.0`

This profile uses:

- `PROTO-PQXDH-R3-2024`; and
- `PROTO-DOUBLE-RATCHET-R4`.

It adds post-quantum protection at asynchronous session establishment while retaining the classical Double Ratchet.

Any post-quantum confidentiality claim **MUST** state its quantum threat model and limitations. This profile **MUST NOT** claim post-quantum authentication and **MUST NOT** claim that the classical Double Ratchet provides post-quantum post-compromise healing.

This profile is allowed as a transition/interoperability option.

## 9. Profile C — PQXDH plus Sparse Post-Quantum Ratchet

Profile reference: `pairwise-pqxdh-spqr@0.1.0`

This profile uses:

- `PROTO-PQXDH-R3-2024`; and
- `PROTO-SPQR-MLKEM-BRAID-R4`.

The E2EESA 0.1 SPQR profile fixes the SCKA construction to ML-KEM Braid. Implementations **MUST NOT** substitute a different SCKA under the same profile reference.

SPQR can provide post-quantum forward-secrecy and post-compromise-security properties, but healing is sparse rather than guaranteed on every application message. Dropped messages can delay public-ratchet progress and therefore delay post-compromise healing. Claims **MUST** preserve that limitation.

This profile is allowed for deployments that intentionally choose the pure post-quantum ratchet path without the additional classical ratchet hedge.

## 10. Profile D — PQXDH plus Triple Ratchet

Profile reference: `pairwise-pqxdh-triple-ratchet@0.1.0`

This is the recommended E2EESA 0.1 pairwise profile.

It uses:

- `PROTO-PQXDH-R3-2024`; and
- `PROTO-TRIPLE-RATCHET-R4`, combining the classical Double Ratchet and SPQR instantiated with ML-KEM Braid.

Both ratchet components **MUST** remain active. Removing either component changes the security construction and **MUST** require a different profile.

The Triple Ratchet combines classical and post-quantum message-key outputs so an implementation retains the classical security hedge while adding post-quantum forward-secrecy and post-compromise-security behavior.

Current PQXDH mutual authentication remains based on classical assumptions. Therefore this profile **MUST NOT** claim `SP-PQ-AUTHENTICATION`.

## 11. Cryptographic parameters

E2EESA 0.1 pairwise profiles pin `ALG-X25519` for the elliptic-curve key-agreement role because that is the currently registered curve compatible with the pinned X3DH/PQXDH specifications.

The policy **MUST** also exactly select:

- a registered KDF;
- a registered AEAD; and
- for PQXDH-based profiles, a registered post-quantum KEM.

Algorithms with `prohibited` lifecycle status **MUST NOT** be selected.

The application-info/domain-separation string **MUST** be explicit and at least eight ASCII characters. Implementations **MUST** use distinct protocol/domain-separation constants wherever the pinned external specifications require them.

## 12. Multi-device session management

A multi-device product normally maintains independent pairwise sessions for relevant device pairs.

`PROTO-SESAME-R2` MAY be used for compatible asynchronous multi-device session management. Session management **MUST NOT** override the authoritative E2EESA device set.

When a recipient device is revoked, a conforming product **MUST** stop creating new pairwise sessions to it and **MUST** ensure subsequent protected content is not intentionally encrypted to that revoked device.

## 13. Downgrade resistance

Pairwise profile negotiation is governed by the E2EESA negotiation and downgrade-defense rules.

An implementation **MUST NOT** automatically retry a failed PQ-capable session under a weaker profile merely because a peer, service, or network path caused the stronger attempt to fail.

Profile changes **MUST** be explicit, policy-authorized, transcript-bound where negotiation occurs, and visible to conformance evidence.

## 14. Security claims

A profile name is not itself a sufficient security claim.

Forward secrecy, post-compromise security, post-quantum confidentiality, authentication, and related properties **MUST** be stated through the E2EESA security-property claim model with the relevant threats, temporal phases, assumptions, exposure windows, healing conditions, and limitations.

In particular:

- current PQXDH does not provide post-quantum authentication;
- post-quantum ratchet healing depends on protocol progress;
- endpoint compromise while an adversary continuously observes plaintext is outside ordinary PCS healing; and
- device identity verification and global key consistency depend on the verification/transparency profiles selected elsewhere in E2EESA.

## 15. Conformance evidence

Conformance evidence **MUST** demonstrate at least:

1. exact pairwise profile and protocol-registry versions;
2. exact algorithm identifiers;
3. verified signed-prekey and identity binding;
4. correct one-time-prekey use and consumption when available;
5. authenticated identity-associated data;
6. rejection of replayed initialization;
7. successful initialization of the selected ratchet;
8. unique per-message keys;
9. secure deletion of message keys and superseded secret state;
10. enforcement of the skipped-message-key bound; and
11. presence of the exact classical/PQ ratchet components required by the selected profile.

The machine-readable reference validator checks these semantic invariants. It does not replace cryptographic implementation tests, protocol test vectors, formal verification, or independent security review.
