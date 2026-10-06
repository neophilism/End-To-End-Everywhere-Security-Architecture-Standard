# Key Verification

**Status:** Normative

This document defines manual cryptographic key verification for E2EESA. It gives users a deterministic safety number and QR representation of the exact cryptographic identity subject they are comparing.

Key verification answers: **"Are both endpoints comparing the same E2EESA cryptographic identity state?"** It does not, by itself, prove a person's real-world identity, legal identity, organization, phone-number ownership, or account-control history.

## 1. Core invariant

A product **MUST NOT** preserve a manual "verified" state when the cryptographic subject that was actually verified has changed.

Manual verification **MUST** require an explicit out-of-band comparison performed through a channel whose trust is independent of the in-band service being verified. In-person comparison, a trusted voice/video conversation, or another independently authenticated channel MAY satisfy this requirement.

The server being verified **MUST NOT** be accepted as the sole authority that the displayed verification value matched.

## 2. Canonical verification subject

E2EESA derives one perspective-independent verification subject from exactly two identity snapshots.

The canonical subject **MUST** contain:

- domain separator `E2EESA-KEY-VERIFICATION-v1`;
- schema version;
- exact key-verification profile reference; and
- the two party subjects sorted lexicographically by `identity_id`.

Canonical JSON serialization **MUST** sort object keys, use UTF-8, use no insignificant whitespace, and preserve the exact field values defined by the selected profile.

The selected registered hash algorithm is then applied to the canonical subject.

## 3. Human-readable safety number

The manual numeric representation **MUST** be derived from the same subject digest used by the QR representation.

E2EESA 0.1 renders the first 192 digest bits as twelve unsigned 16-bit big-endian integers, each displayed as a zero-padded five-digit decimal group. The groups are separated by a single ASCII space, yielding 60 displayed decimal digits.

The numeric representation is a comparison aid, not a password, PIN, recovery code, authentication secret, or key-derivation input.

## 4. QR verification payload

The QR payload **MUST** begin with `e2eesa-kv1:` followed by unpadded base64url encoding of canonical JSON containing:

- `v: 1`;
- profile reference;
- hash-algorithm identifier;
- the two sorted identity identifiers; and
- the full subject digest in lowercase hexadecimal.

A QR scanner **MUST** reject an unsupported version, profile, hash, malformed identity set, malformed digest, or unexpected field.

The QR and numeric forms are alternate representations of the same cryptographic subject. A product **MUST NOT** display them as if they verify different security properties.

## 5. Profile A — account-root verification

Profile reference: `verify-account-root@0.1.0`

This profile verifies the stable client-controlled account-root public key from the PR #8 account-root identity architecture.

The party subject contains:

- `identity_id`; and
- account-root public-key fingerprint.

Both parties **MUST** use `identity-account-root@0.1.0`.

An ordinary device enrollment, rotation, or revocation that is validly authorized beneath an unchanged verified account root does **not** change the verification subject.

Changing the account root **MUST** invalidate the prior verification.

This profile provides a stable user-facing verification value, but the account root is a high-value authorization anchor. The security of inherited device trust depends on the account-root authorization rules defined by the identity architecture.

## 6. Profile B — active device-set verification

Profile reference: `verify-device-set@0.1.0`

This profile verifies the complete active device-key set for each party.

Each party subject contains:

- `identity_id`; and
- every active device, sorted by `device_id`, including:
  - device identifier;
  - key generation;
  - signing-key fingerprint; and
  - agreement-key fingerprint.

Any addition, removal, key rotation, generation change, or other change to the active verified device-key set **MUST** change the verification subject and invalidate the prior verification.

This profile avoids inheriting trust from a separate account-root key, but it intentionally produces more verification changes in multi-device systems.

## 7. Identity-state source

Verification snapshots **MUST** be derived from identity/device state already accepted under the E2EESA identity architecture.

A service-provided key list that has not passed the applicable identity/device authorization rules **MUST NOT** be treated as a verification snapshot.

The reference engine includes a projection from PR #8 identity state into the PR #11 snapshot format.

## 8. Verification record

A manual verification record **MUST** preserve:

- exact verification profile;
- exact hash-algorithm identifier;
- both identity identifiers;
- full subject digest;
- displayed numeric safety number;
- QR payload;
- method used (`numeric` or `qr`);
- explicit user confirmation; and
- verification status.

Manual verification **MUST NOT** be recorded unless the user affirmatively confirms the out-of-band comparison.

Verification state is local to the relying party unless an application explicitly synchronizes it end-to-end. One participant marking a peer verified **MUST NOT** imply that the peer performed the same action.

## 9. Change handling

Before relying on an existing manual verification record, the implementation **MUST** recompute the current canonical subject from currently accepted identity state.

If the digest differs:

1. prior `verified` status **MUST** be treated as invalidated;
2. the product **MUST** make the change visible before representing the peer as verified again; and
3. restoration of manual `verified` status **MUST** require a new explicit out-of-band comparison.

A product **MUST NOT** silently copy verification status from an obsolete subject to a new subject.

Queued or unsent protected messages whose recipient identity changed SHOULD be re-evaluated before delivery according to the pairwise/group profile and product risk policy.

## 10. Hash algorithms

The key-verification policy **MUST** select a hash algorithm from the E2EESA cryptographic registry.

E2EESA 0.1 permits:

- `ALG-SHA256`;
- `ALG-SHA384`; and
- `ALG-SHA512`.

A prohibited algorithm **MUST NOT** be used.

Changing the hash algorithm changes the verification representation and therefore requires fresh verification.

## 11. Automatic verification and transparency boundary

Manual comparison and key transparency are distinct mechanisms.

PR #12 may attach key-transparency evidence to the same canonical `subject_digest_hex` defined here. That evidence can establish consistency properties according to the transparency threat model.

A transparency result **MUST NOT** be represented as proof of a person's real-world identity.

A key-transparency success **MUST NOT** retroactively claim that a user manually compared a safety number or QR code. Manual and automatic/transparency verification evidence **MUST** remain distinguishable.

Conversely, manual verification does not establish global key-directory consistency against selective server views. That is the responsibility of the key-transparency architecture.

## 12. Security properties

A successful manual comparison can support `SP-PEER-AUTHENTICATION` for the exact compared cryptographic subject, subject to the trustworthiness of the out-of-band comparison.

It can also support local `SP-KEY-CONSISTENCY` between the two compared views.

It does not establish global consistency, non-repudiation, real-world identity, or post-quantum authentication unless those properties are separately and validly claimed.

## 13. Conformance

A conforming implementation **MUST** demonstrate:

1. deterministic perspective-independent subject construction;
2. identical numeric and QR subject binding;
3. exact profile and hash pinning;
4. rejection of malformed QR payloads;
5. explicit out-of-band user confirmation;
6. invalidation when the selected verification subject changes;
7. account-root verification remaining stable across authorized subordinate device changes when the root is unchanged;
8. device-set verification changing on active device/key changes;
9. inability of server-provided unverified state to create a verified record; and
10. a stable subject-digest interface that later key-transparency evidence can reference without being confused with manual verification.
