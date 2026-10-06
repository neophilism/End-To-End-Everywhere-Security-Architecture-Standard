# Group End-to-End Encryption Profiles

**Status:** Normative

This document defines E2EESA group-messaging architectures for asynchronous groups of authorized devices. It covers membership changes, epochs, removal and addition semantics, message fanout, replay, device revocation, forward secrecy, and post-compromise-security boundaries.

## 1. Common group invariant

A service provider that is not an intended recipient **MUST NOT** be able to add itself or another device to the cryptographic recipient set by unilateral server-side action.

Every accepted group state **MUST** identify:

- a stable group identifier;
- a monotonically increasing epoch;
- the exact authorized device membership for that epoch;
- the selected group E2EE profile and protocol version; and
- the identity/device state to which the membership view was bound.

A membership-changing operation **MUST** advance the epoch by exactly one and **MUST** cryptographically bind all subsequent protected content to the resulting membership.

## 2. Device identity and membership

Group membership is device-granular. Adding an account or user to an application-level group does not itself authorize every current or future device of that account.

Every recipient device **MUST** be authorized by the identity/device architecture before it can become a cryptographic group member.

A device revoked by the identity/device architecture **MUST** be removed from every group in which it is a recipient, and the group **MUST** complete the profile-required membership transition before subsequent protected content is sent to the new epoch.

## 3. Membership authorization

The application MAY define administrators, owners, voting rules, role-based permissions, or other membership policy.

Regardless of the application policy, a membership transition **MUST** carry cryptographically verified authorization from a principal that the prior group state recognizes as eligible under that policy.

A service-side database row, administrator API call, support action, or delivery-service instruction **MUST NOT**, by itself, satisfy E2EESA cryptographic membership authorization.

## 4. Additions

When a device is added, the new epoch **MUST** exclude that device from access to protected content from earlier epochs unless a separate, explicit history-sharing capability authorizes such access.

The default E2EESA group conformance path therefore requires evidence that an added device does not receive prior-epoch group secrets.

History export or deliberate re-encryption of older content is a separate capability and **MUST NOT** be represented as ordinary group membership.

## 5. Removals

When a device is removed, the transition **MUST** establish fresh future-content keying state that the removed device cannot derive from its prior group state.

No protected application message for the new epoch may be intentionally encrypted to the removed device.

If delivery ordering allows a device to receive old-epoch ciphertext after removal, that ciphertext **MUST** remain cryptographically attributable to its original old epoch rather than being accepted as new-epoch content.

## 6. Epoch, replay, and rollback rules

Membership-changing transitions **MUST** use `new_epoch = previous_epoch + 1`.

A group implementation **MUST** reject stale membership transitions, replayed protected messages, and protected messages whose epoch does not match the accepted group state.

The service **MUST NOT** be trusted to provide the sole replay or rollback defense.

## 7. Profile A — MLS 1.0

Profile reference: `group-mls-rfc9420@0.1.0`

This is the recommended E2EESA 0.1 group profile.

It uses Messaging Layer Security 1.0 as specified by RFC 9420. MLS provides asynchronous group key establishment using a ratchet tree, with forward secrecy and post-compromise security across epochs.

E2EESA 0.1 permits these RFC 9420 cipher suites:

- `0x0001 MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` — recommended and mandatory-to-implement in MLS 1.0;
- `0x0003 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` — allowed.

The exact cipher suite **MUST** be pinned by policy.

### 7.1 Membership commits

Every E2EESA membership-changing MLS Commit **MUST**:

- authenticate successfully;
- produce exactly the next epoch;
- be accepted only after application membership authorization succeeds;
- include a fresh UpdatePath under the E2EESA profile, even where base RFC 9420 could omit one;
- use single-use KeyPackages for ordinary additions; and
- generate one appropriate Welcome for every added device.

The mandatory fresh UpdatePath is an E2EESA strengthening that ensures every membership change contributes fresh path key material rather than using the least-strong Commit form permitted by base MLS.

### 7.2 Removal and PCS

A Remove transition **MUST** complete before new-epoch application data is sent. The UpdatePath **MUST** exclude the removed leaf from the new epoch secrets.

PCS claims remain subject to the MLS condition that honest members introduce fresh secret state after compromise. Continuous endpoint compromise remains outside ordinary PCS healing.

## 8. Profile B — Sender-Keys-style AEAD

Profile reference: `group-sender-key-aead@0.1.0`

This profile adopts the deployed Sender Keys architecture: each sending device owns an outbound symmetric chain plus a signing key; sender state is distributed to group recipients over authenticated pairwise E2EE sessions; each group message advances the sender chain and derives a fresh message key.

The E2EESA profile is an architecture profile, not a claim of wire compatibility with Signal, WhatsApp, Messenger, or Matrix. It uses algorithms from the E2EESA registry rather than freezing a historical deployed cipher construction.

Policy **MUST** select:

- a registered KDF;
- a registered AEAD;
- a registered signature algorithm; and
- a conformant E2EESA pairwise profile for sender-state distribution.

The sender-key payload and every protected message **MUST** bind the group identifier, epoch, sender device identity, sender-chain generation/counter, and algorithm/profile identifiers into authenticated data or the signed transcript.

### 8.1 Forward secrecy

After deriving a message key, the sender **MUST** advance the one-way sender chain and delete the used message key.

Recipients MAY retain bounded skipped message keys for out-of-order delivery. The maximum retained count **MUST** be explicit and finite.

This profile claims forward-secrecy behavior from one-way chain evolution but **MUST NOT** claim automatic post-compromise security. A compromised sender chain remains dangerous until explicit sender-state rotation.

### 8.2 Membership changes

Every membership change **MUST** rotate every active sender's sender-key state and redistribute the fresh state only to the complete new membership using conformant pairwise E2EE.

A sender-key transition is not complete until all active senders have fresh state for the new epoch or the application explicitly marks non-updated senders unable to send.

Removed devices **MUST NOT** receive replacement sender state.

## 9. Profile C — pairwise fanout

Profile reference: `group-pairwise-fanout@0.1.0`

This profile maintains no shared group content key.

For every group application message, the sender **MUST** encrypt an independent protected copy to every other current member device using the selected E2EESA pairwise profile.

The number of protected ciphertexts therefore grows linearly with recipient devices.

This profile is allowed for smaller groups, high-assurance deployments that prefer minimal group-key state, or products that value architectural reuse over fanout efficiency.

Membership changes update the authorized recipient set. A removed device disappears from the recipient set before the next group message. An added device receives only future pairwise ciphertexts unless a separate history capability is invoked.

The group profile inherits pairwise forward-secrecy and PCS behavior only to the extent that every underlying pairwise session satisfies those claims.

## 10. Sender authentication

A protected group message **MUST** be attributable to an authorized sending device within the selected group architecture.

MLS messages use MLS sender authentication and group transcript semantics.

Sender-key messages **MUST** verify the sender's per-epoch sender signature.

Pairwise-fanout messages **MUST** validate every underlying pairwise session and bind the group identifier, group epoch, and group message identifier into pairwise associated data.

## 11. Recipient completeness

For ordinary group broadcast semantics, the intended recipient set for a message **MUST** equal every current member device other than the sending device.

Applications that intentionally address only a subgroup MUST model that subgroup as a distinct cryptographic recipient scope or capability rather than falsely claiming full-group delivery evidence.

## 12. Service compromise

The delivery service MAY:

- delay, reorder, duplicate, or drop messages;
- withhold membership proposals;
- present stale data; or
- attempt to create inconsistent delivery views.

The cryptographic group architecture **MUST** prevent those capabilities from granting the service protected plaintext or unilateral membership authority.

Global detection of selective split views can require additional transparency, consistency, or gossip mechanisms and is addressed by later E2EESA key-transparency work.

## 13. Downgrade resistance

Group profile and MLS cipher-suite selection are security-sensitive negotiation decisions.

A product **MUST NOT** silently fall back from MLS to Sender Keys or pairwise fanout, or from one group profile to another, because a network or service path caused the preferred profile to fail.

Profile changes **MUST** be explicit, policy-authorized, and recorded in conformance evidence.

## 14. Security-claim boundaries

The presence of a profile does not itself prove every security property.

- MLS may claim FS and PCS only with the temporal, compromise, update, and endpoint assumptions required by RFC 9420 and the E2EESA security-property model.
- Sender Keys **MUST NOT** claim automatic PCS.
- Pairwise fanout may claim PCS only when every relevant pairwise session legitimately provides PCS.
- None of these E2EESA 0.1 group profiles claims post-quantum group authentication merely because some underlying pairwise distribution path is post-quantum capable.
- New-member history exclusion and removed-member future exclusion are epoch-scoped claims and do not erase plaintext already exported or observed at an endpoint.

## 15. Conformance evidence

A conforming implementation **MUST** demonstrate:

1. exact profile and group-protocol registry versions;
2. authenticated membership authorization;
3. exact prior and new membership sets;
4. monotonic epoch transition;
5. added-device prior-epoch exclusion;
6. removed-device new-epoch exclusion;
7. device-revocation-driven rekey or recipient-set update;
8. profile-specific rekey behavior;
9. replay rejection;
10. sender authentication;
11. service inability to obtain plaintext; and
12. complete recipient coverage for full-group messages.

MLS evidence additionally **MUST** demonstrate Commit authentication, the E2EESA-required UpdatePath, single-use KeyPackages, and Welcome generation for additions.

Sender-key evidence additionally **MUST** demonstrate complete sender-key rotation on membership change, authenticated pairwise redistribution, one-way chain advancement, used message-key deletion, signature verification, and skipped-key bounds.

Pairwise-fanout evidence additionally **MUST** demonstrate one valid pairwise ciphertext per current recipient device.
