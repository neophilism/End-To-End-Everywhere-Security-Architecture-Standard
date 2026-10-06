# ADR 0006: Group E2EE architecture profiles

**Status:** Accepted for pre-1.0 development

## Context

Group messaging has materially different scaling and compromise behavior from pairwise messaging. A group can use a standardized tree-based group key agreement, distribute per-sender symmetric chains over pairwise channels, or avoid shared group state and encrypt independently to each recipient. These architectures trade bandwidth, state complexity, interoperability, and post-compromise behavior.

## Serious alternatives considered

1. **MLS 1.0 / RFC 9420.** Standards-based asynchronous group key agreement with efficient scaling, forward secrecy, and post-compromise security.
2. **Sender Keys.** Widely deployed one-to-many architecture in which each sender distributes a symmetric sender chain through pairwise E2EE and sends one ciphertext per group message.
3. **Pairwise fanout.** Encrypt every group message separately to every recipient device with the pairwise E2EE architecture. Simple and strong, but O(n) in ciphertext generation and delivery.
4. **A single static shared group key.** Rejected because membership changes, sender attribution, forward secrecy, compromise recovery, and device revocation are too weak.
5. **Mandate MLS only.** Rejected for pre-1.0 because deployed sender-key systems and smaller-group pairwise fanout are serious architectures with legitimate interoperability and simplicity tradeoffs.

## Decision

E2EESA defines three group profiles:

- `group-mls-rfc9420@0.1.0` — recommended;
- `group-sender-key-aead@0.1.0` — allowed;
- `group-pairwise-fanout@0.1.0` — allowed.

The group family is `at-most-one` during foundation development so earlier configuration fixtures remain valid. A product implementing group E2EE must select one profile when group messaging is in scope.

The MLS profile pins MLS 1.0 and permits cipher suites 0x0001 and 0x0003. E2EESA requires a fresh UpdatePath for every membership-changing Commit.

The Sender-Keys-style profile uses E2EESA-registered KDF, AEAD, and signature algorithms and pairwise E2EE for sender-state distribution. It is architecture-compatible with the Sender Keys model but does not claim wire compatibility with a particular deployed product.

Pairwise fanout composes the pairwise profile from PR 9 and maintains no shared group key.

## Security consequences

MLS is the recommended profile because it combines efficient large-group operation with standardized FS and PCS semantics.

Sender-key architecture is efficient but does not self-heal after sender-state compromise; membership changes therefore require complete sender-state rotation.

Pairwise fanout inherits pairwise session security with simple membership semantics, but bandwidth and computation grow linearly with the number of recipient devices.

All three profiles reject unilateral server membership authority and make device revocation a cryptographic membership event.

## Compatibility constraints

Group membership is device-granular and depends on the identity/device architecture. Pairwise-dependent profiles must use a registered E2EESA pairwise profile.

Group profile changes are subject to negotiation/downgrade defense. Later key-verification and transparency profiles may strengthen detection of identity-key or membership split views without silently changing these group semantics.

## Evidence and references

- RFC 9420, The Messaging Layer Security (MLS) Protocol.
- Meta Messenger End-to-End Encryption Overview, Sender Keys group-session architecture.
- Balbás, Collins, and Gajland, Analysis and Improvements of the Sender Keys Protocol for Group Messaging.
- E2EESA identity/device architecture and pairwise E2EE profiles.

## Reconsideration triggers

Revisit if MLS gains broadly deployed post-quantum cipher suites, formal review identifies stronger safe sender-key recovery semantics, pairwise fanout needs a distinct subgroup abstraction, or independent review finds that the required MLS UpdatePath policy harms interoperability without meaningful security benefit.
