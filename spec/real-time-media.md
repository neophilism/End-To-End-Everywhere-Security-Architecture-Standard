# Real-Time Media

**Status:** Normative

This document defines E2EESA end-to-end encryption for real-time voice and video using RFC 9605 Secure Frame (SFrame).

E2EESA defines two selectable key-management profiles:

- media-sframe-sender-keys@0.1.0
- media-sframe-mls@0.1.0

SFrame encrypts encoded media end to end while allowing a Selective Forwarding Unit (SFU) to process routing metadata without media plaintext.

## 1. Core invariant

Every protected audio/video frame MUST be end-to-end encrypted and authenticated between authorized endpoints.

An SFU, TURN/media relay, conference service, signaling service, or transport terminator MUST NOT receive SFrame base keys or protected media plaintext merely because it forwards the call.

Hop-by-hop transport encryption remains REQUIRED in addition to SFrame E2EE.

## 2. Protocol and cipher suites

E2EESA 0.1 pins RFC 9605 as SFRAME-RFC9605.

Supported RFC 9605 suites are:

- 0x0005 AES_256_GCM_SHA512_128 — recommended;
- 0x0004 AES_128_GCM_SHA256_128 — allowed;
- 0x0001 AES_128_CTR_HMAC_SHA256_80 — allowed for bandwidth-sensitive deployments;
- 0x0002 AES_128_CTR_HMAC_SHA256_64 — legacy; and
- 0x0003 AES_128_CTR_HMAC_SHA256_32 — prohibited for new E2EESA deployments.

The pending draft-barnes-sframe-iana-256-06 registrations are not normative in E2EESA 0.1 until standardized.

## 3. Two encryption layers

A conference using an SFU has two distinct protection layers.

Hop-by-hop transport encryption protects media packets, metadata, and feedback on the network path between endpoint and SFU.

SFrame protects encoded media content end to end across the SFU.

A product MUST NOT describe hop-by-hop SRTP/DTLS transport encryption alone as end-to-end media encryption when an SFU terminates that transport.

## 4. SFrame sender uniqueness

Each sender MUST have an encryption key space that is not used by another sender.

Each (base_key, KID, CTR) combination MUST be used for at most one SFrame encryption operation.

A base_key MUST NOT be used for encryption by multiple senders.

CTR state that can survive process restart MUST be persisted before the corresponding value is used for encryption so a crash cannot roll the counter backward and reuse a key/nonce pair.

## 5. Profile A — sender-key SFrame

Profile reference: media-sframe-sender-keys@0.1.0

Each active sender generates a fresh SFrame base_key and distributes it to the other authorized call participants through an already authenticated E2EE control channel.

The control channel MAY be an E2EESA pairwise or group E2EE profile.

The SFU and signaling service MUST NOT be recipients of these base keys.

This profile is recommended for 1:1 calls and smaller conferences where a pre-existing secure control channel makes explicit sender-key distribution straightforward.

## 6. Sender-key membership changes

On every endpoint join, leave, compromised-device removal, or rejoin:

- the media epoch MUST advance;
- every active sender MUST rotate to fresh sender keying before media resumes;
- the new keys MUST be distributed only to the resulting authorized participant set;
- a new/rejoining endpoint MUST NOT receive prior-epoch media keys; and
- a removed endpoint MUST NOT receive any new media key.

A rejoining device is treated as a new authorized endpoint and MUST NOT reuse the sender key from its previous membership.

## 7. Profile B — MLS-derived SFrame

Profile reference: media-sframe-mls@0.1.0

This profile requires group-mls-rfc9420@0.1.0 as the conference control plane.

SFrame base keying is derived from the MLS epoch as described by RFC 9605 using the MLS exporter label:

SFrame 1.0 Base Key

Each sender receives a unique KID space derived from MLS epoch, sender index, and sender-chosen context.

For group size g, let S be the minimum number of bits needed to encode a member index. Let E be the configured epoch-bit count.

KID = (context << (S + E)) + (sender_index << E) + (epoch mod 2^E)

The application MUST ensure that context, sender index, and epoch encoding fit in 64 bits.

## 8. MLS membership changes

An authenticated MLS commit that changes conference membership MUST produce a new MLS epoch before protected media resumes.

A join/rejoin MUST NOT reveal prior-epoch media key material to the new device.

A leave or compromised-device removal MUST exclude that endpoint from the new MLS epoch.

All active SFrame sender keying MUST change as a consequence of the new epoch.

The application MUST discard superseded epoch state once the configured bounded reordering/overlap window no longer requires it.

## 9. Key rotation during long calls

Membership changes are mandatory rotation events, but they are not the only rotation trigger.

Every real-time-media policy MUST define both:

- maximum_key_lifetime_seconds; and
- maximum_frames_per_sender_key.

An endpoint MUST rotate the sender key when either bound is reached, before encrypting further frames.

A periodic rotation in the same membership epoch MUST use a fresh base key and a fresh KID.

## 10. Replay and counter rollback

RFC 9605 leaves replay policy to the application. E2EESA therefore requires replay rejection.

Receivers MUST remember enough per-sender KID/CTR state to reject duplicate SFrame ciphertexts within the supported reordering window.

A CTR value at or below an already accepted maximum for the same sender/KID MUST be rejected unless a formally defined out-of-order replay window proves the frame was not previously accepted.

The reference E2EESA validator models the strict monotonic case.

A media epoch lower than previously accepted authenticated state MUST be rejected.

## 11. Authentication before media release

SFrame authentication MUST succeed before decoded media from the protected frame is released to an audio renderer, video decoder output, recorder, transcription engine, content-analysis system, or application consumer.

An SFU modification of protected media MUST therefore be detected by endpoints.

Packet loss and frame loss MAY occur without authentication failure; missing media is an availability event, not permission to bypass authentication.

## 12. SFU-visible metadata

SFrame deliberately leaves some routing information visible.

Depending on transport/integration, an SFU can observe data such as:

- SFrame KID and CTR;
- SSRC or equivalent stream identifiers;
- codecs;
- packet/frame sizes;
- timing;
- RTP header extensions; and
- RTCP feedback.

KID values are not encrypted by SFrame.

Applications SHOULD avoid encoding unnecessary privacy-sensitive semantics into visible KID/context values.

This profile protects media content, not all call metadata.

## 13. Recording bots and server recording

A server MUST NOT silently decrypt an E2EE conference for recording.

A cloud recorder, transcription bot, moderation bot, or media processor that needs plaintext MUST join as an explicitly authorized conference participant and receive keys under the same membership rules as another endpoint.

Products MUST make such plaintext-capable participants visible to users through the conference membership model.

Removing the bot MUST trigger the same rekey rules as removing any other participant.

A policy MAY prohibit recording bots entirely.

## 14. Compromise and rejoin

When a device is suspected or known compromised, it MUST be removed from the call's authorized participant set and the media epoch MUST advance before protected media continues.

For sender-key mode, all remaining active senders distribute fresh keys excluding the compromised device.

For MLS mode, an authenticated MLS removal commit advances the epoch and new SFrame keying is derived from that epoch.

If the user later reauthorizes the device, it joins as a new participant state. Old sender keys, old replay checkpoints, and old membership authority MUST NOT be reused as if no compromise occurred.

## 15. Multi-device users

Call membership is device-granular.

Authorizing one user's phone does not automatically authorize all devices owned by that user.

Every receiving device that obtains a media key MUST be represented in the conference authorization state or be reached through an explicitly defined authorized endpoint fanout mechanism.

Device addition/removal follows PR #8 identity/device authorization before it changes the media participant set.

## 16. Per-frame versus per-packet SFrame

RFC 9605 permits SFrame to be applied per encoded frame or per packet.

E2EESA allows both.

Per-frame use generally has lower authentication overhead, while per-packet protection can simplify some packet-loss/reordering behavior.

The application MUST use the same semantics consistently for a stream and MUST include the application metadata required to authenticate the media interpretation.

## 17. WebRTC integration

Browser implementations MAY use the W3C WebRTC Encoded Transform API or an equivalent encoded-frame transform mechanism to apply SFrame before media leaves the endpoint E2EE boundary.

As of E2EESA 0.1, WebRTC Encoded Transform remains a W3C Working Draft. It is therefore an implementation interface, not the normative E2EESA wire protocol.

Implementations outside WebRTC MAY use SFrame over RTP, WebTransport, or another transport provided the RFC 9605 and E2EESA invariants remain satisfied.

## 18. Forward secrecy and post-compromise limits

Membership rekeying prevents a newly joined endpoint from receiving prior media keys and prevents a removed endpoint from receiving future media keys.

Sender-key mode does not automatically inherit the same post-compromise-healing guarantees as MLS. Its security depends on the control channel and successful rotation of every active sender.

The MLS profile may claim post-compromise security only to the extent that the underlying E2EESA MLS profile and endpoint compromise assumptions support it.

Neither profile protects media captured as plaintext while an authorized endpoint is actively compromised.

## 19. Conference restarts and persisted state

A resumed application process MUST NOT restart SFrame CTR values under an unchanged base_key/KID.

Implementations that persist SFrame state MUST persist the next safe CTR before encrypting with the current counter value, or rotate to fresh keying after restart.

If the client cannot prove counter continuity, it MUST rotate to a fresh base key/KID before sending media.

## 20. Security claim boundaries

A conforming profile can support media-content confidentiality, integrity, replay resistance, and membership-bound forward secrecy under its declared threat model.

It does not by itself conceal:

- who joined the call;
- call timing/duration;
- packet/frame sizes;
- network addresses;
- SFU routing metadata;
- visible KID/CTR values; or
- plaintext at an authorized compromised endpoint.

PR #14 metadata-privacy mechanisms may reduce some network/application metadata, but low-latency media traffic remains especially exposed to traffic analysis.

## 21. Conformance evidence

A conforming implementation MUST demonstrate, as applicable:

1. exact RFC 9605 cipher suite;
2. active SFrame E2EE plus hop-by-hop transport encryption;
3. no SFU media plaintext or SFrame base keys;
4. distinct sender key spaces;
5. no accepted duplicate (base_key, KID, CTR);
6. persistent CTR/restart protection;
7. correct sender-key or MLS key-management mode;
8. exact RFC 9605 MLS KID derivation for MLS mode;
9. authenticated membership change;
10. epoch advancement and rekey before media resumes;
11. no prior-epoch keys to new/rejoining devices;
12. no future keys to departed/compromised devices;
13. replay and media-epoch rollback rejection;
14. media authentication before plaintext release;
15. explicit authorization of any recording/transcription participant; and
16. no reuse of old sender keying when a compromised device rejoins.
