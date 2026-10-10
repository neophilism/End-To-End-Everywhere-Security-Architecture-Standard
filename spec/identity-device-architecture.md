# Identity and Device Architecture

**Status:** Normative

This document defines the E2EESA identity and device architecture invariants and supported profile choices for authorizing devices that can receive protected plaintext.

## 1. Core invariant

A service provider or intermediary that is not itself an intended recipient **MUST NOT** be able, by unilateral server-side action, to add a device or endpoint that becomes authorized to decrypt protected content.

Every active recipient device **MUST** have a distinct device identifier, signing key identity, agreement or KEM key identity, and key-generation counter. Device identifiers and retired key identifiers **MUST NOT** be reused.

Identity transitions **MUST** be authenticated, state-bound events binding the identity, event, subject device, monotonically increasing sequence, exact preceding-state hash, any replacement keys, and the verified authorizer set required by the selected profile.

## 2. Account identity is not cryptographic authority

A service account MAY be used for routing, login, billing, abuse controls, or synchronization. Possession of a service session, password reset token, server database row, administrator privilege, or other service-side credential **MUST NOT**, by itself, authorize a new E2EE recipient device.

Recovery that can change the cryptographic device set is governed by the selected recovery profile and **MUST NOT** be treated as ordinary enrollment.

## 3. Device state

Canonical device state contains the current sequence, optional account-root public key, all known devices, each device's status and key generation, and retired key identifiers.

A state consumer **MUST** reject duplicate device identifiers, duplicate current key identifiers, reuse of retired key identifiers, duplicate current public-key fingerprints, unknown or prohibited algorithms, and algorithms used in the wrong cryptographic role.

At least one device **MUST** remain active during ordinary enrollment, rotation, and revocation flows.

## 4. Enrollment

Enrollment adds exactly one previously unseen device identifier. A new device **MUST** begin at key generation 1. Its signing and agreement keys **MUST** be distinct and **MUST NOT** reuse any current or retired key identifier.

## 5. Key rotation

Rotation changes the keys of an already-active device without changing its device identifier. The new key generation **MUST** equal the prior generation plus one. Replaced keys **MUST** be recorded as retired and **MUST NOT** later be reused.

## 6. Revocation

Revocation changes an active device to revoked status. A revoked device **MUST NOT** authorize later identity transitions and **MUST NOT** remain an intended recipient of newly protected content.

Messaging and group profiles that cache device or membership keys **MUST** define how revocation excludes the revoked device from subsequent protected state.

## 7. Profile A — account-root authorization

Profile reference: `identity-account-root@0.1.0`

A stable client-controlled account cryptographic root authorizes enrollment, rotation, and revocation. The account-root private key **MUST NOT** be available to the service provider merely because it operates the account service.

This profile is operationally simple but concentrates authority in one long-term root.

## 8. Profile B — existing-device cross-signing

Profile reference: `identity-device-cross-signing@0.1.0`

There is no separate persistent account-root signing key. Enrollment **MUST** be authorized by at least one currently active device.

For rotation or revocation, when more than one device is active, authorization **MUST** come from at least one other active device. A sole remaining active device MAY authorize its own key rotation but **MUST NOT** revoke itself through the ordinary revocation flow.

## 9. Profile C — threshold device quorum

Profile reference: `identity-threshold-quorum@0.1.0`

Device-set changes require a strict majority of eligible active devices. For enrollment and rotation, all current active devices are eligible. For revocation, the target device is excluded.

For N eligible devices, the required quorum is floor(N / 2) + 1.

## 10. Verified authorizers

Machine-readable transition evidence uses `verified_authorizers`.

A production implementation **MUST** populate this field only after verifying each authorizing signature over the canonical identity-event payload with a key authorized by the exact preceding state. The reference evaluator checks transition and authorization semantics; it does not perform algorithm-specific signature verification.

## 11. State binding, replay, and rollback

Every identity event **MUST** carry a sequence exactly one greater than current state and a cryptographic hash of the exact current state.

An implementation **MUST** reject mismatched sequence or preceding-state hash. These local rules do not alone solve global split-view attacks; key transparency is a separate profile area.

## 12. Cryptographic registry integration

Identity signing and key-agreement/KEM algorithms **MUST** use E2EESA registry identifiers and obey their lifecycle status and constraints. This document defines no new cryptographic primitive.

## 13. Recovery boundary

A recovery mechanism MAY create new cryptographic state after device loss, but recovery **MUST** be explicitly distinguishable from ordinary enrollment.

Password reset, support intervention, administrative action, email access, or telephone-number control **MUST NOT** silently satisfy an identity profile's ordinary authorization rule.

## 14. Conformance

A conforming implementation **MUST** exactly version-pin one supported identity architecture profile when identity/device management is in scope, enforce the common invariants, fail closed on unknown data, reject server-only recipient authorization, and demonstrate valid and invalid enrollment, rotation, and revocation cases.

## 15. Total loss, recovery authority, and replacement

Loss of every active device does not make a service account, support operator,
password reset, elapsed waiting period, or server-supplied predecessor link into
cryptographic authority. Products **MUST** select and disclose one of these
development contracts:

1. **No recovery.** The old cryptographic identity cannot be recovered. A new
   identity is unlinked and begins unverified.
2. **Retained authority.** A separately protected, pre-authorized,
   high-entropy authority may authorize fresh device state only when it binds
   the exact trusted prior-state hash, resulting identity, and fresh history
   epoch.
3. **Pre-authorized contact threshold.** A threshold of contacts recorded
   before loss may authorize a *replacement identity*. This does not prove
   control of the old identity and does not preserve its verified status.

A server-supplied history is untrusted unless the endpoint validates it against
a retained local view or the selected key-transparency mechanism. Revoked
authority and stale, missing, forked, or concurrent history **MUST** fail closed.
A delay is policy friction, not proof of authority.

## 16. Non-transferable trust and membership

Recovery and replacement events **MUST NOT** automatically transfer peer
verification or group membership. Peers need an explicit, visible
re-verification decision, and groups need a fresh authenticated enrollment
under their membership policy. Queued content and newly protected content
**MUST NOT** be sent to the recovered or replacement endpoint until the
applicable authorization and membership transitions are accepted.

Revocation can protect new content after participants synchronize accepted
history. It does not establish immediate global propagation, deletion from
offline devices, or erasure of plaintext and keys already copied.

## 17. Machine-readable AUD-08 contract

`schemas/identity-recovery-policy.schema.json`,
`schemas/identity-recovery-trusted-state.schema.json`, and
`schemas/identity-recovery-event.schema.json` define closed inputs. The
reference evaluator in `scripts/identity_recovery_engine.py` rejects account
takeover, support override, stale state, revoked authority, threshold failure,
and cross-result substitution.

These mechanisms remain `development-only` and their results carry
`production_eligible=false` until the relevant designs and implementations
receive independent review. Registry presence and passing fixtures are not
claims that a new recovery protocol is mature.
