# ADR 0013: Real-time media encryption

**Status:** Accepted for pre-1.0 development

## Context

Real-time group calls need low-overhead media encryption while allowing an SFU to perform bandwidth adaptation and forwarding without receiving media plaintext.

Transport encryption such as DTLS-SRTP is not end-to-end when an SFU terminates it.

RFC 9605 SFrame was designed specifically to add media-payload E2EE across an SFU and deliberately separates media framing from key management.

## Serious alternatives considered

1. **Hop-by-hop SRTP only.** Rejected as an E2EE profile because the SFU terminates the encryption and can access media.
2. **SRTP double encryption.** Standards-based but RFC 9605 identifies complexity/efficiency drawbacks in realistic SFU scenarios; not selected as the primary E2EESA media profile.
3. **SFrame with sender keys.** Selected for 1:1/smaller groups using an existing authenticated E2EE control channel.
4. **SFrame with MLS.** Selected and recommended for multiparty membership churn. RFC 9605 defines an MLS exporter/KID construction directly.
5. **One shared conference encryption key used by every sender.** Rejected because SFrame requires per-sender encryption key space to avoid key/nonce reuse.
6. **Server-held recording key.** Rejected. A plaintext-capable recorder must be an explicit authorized participant.
7. **32-bit SFrame authentication tags.** Prohibited for new E2EESA deployments due to forgery risk.
8. **Draft-only 256-bit CTR/HMAC registrations.** Deferred until standardized; E2EESA does not silently promote Internet-Draft registry additions to stable normative suites.

## Decision

E2EESA defines two profiles:

- media-sframe-sender-keys@0.1.0
- media-sframe-mls@0.1.0

Both use RFC 9605 SFrame and require hop-by-hop transport encryption in addition to SFrame.

The full-tag AES_256_GCM_SHA512_128 SFrame suite (0x0005) is recommended.

Sender-key mode rotates every active sender's key on membership changes.

MLS mode requires group-mls-rfc9420@0.1.0 and uses the RFC 9605 MLS exporter/KID construction.

## Security consequences

SFUs retain access to routing/transport metadata but not protected media plaintext or SFrame base keys.

Membership churn becomes a cryptographic key-boundary event.

Replay protection and persistent counter continuity are application responsibilities layered on top of SFrame.

Recording/transcription that needs plaintext becomes visible as an endpoint authorization event rather than a hidden server privilege.

## Current browser integration

The W3C WebRTC Encoded Transform API can provide an endpoint hook for applying SFrame to encoded media. As of June 25, 2026 it remains a Working Draft, so E2EESA treats it as an implementation interface rather than a stable wire protocol requirement.

## Evidence and references

- RFC 9605, Secure Frame (SFrame): Lightweight Authenticated Encryption for Real-Time Media.
- RFC 9420, The Messaging Layer Security Protocol.
- W3C WebRTC Encoded Transform Working Draft.
- draft-barnes-sframe-iana-256-06, tracked as a pending non-normative registry update.

## Reconsideration triggers

Revisit when the pending SFrame registry update becomes an RFC, when W3C encoded-transform reaches a stable Recommendation, when standardized media key-management profiles improve on RFC 9605's sender-key/MLS mechanisms, or when independent review identifies replay/epoch-overlap limits requiring tighter rules.
