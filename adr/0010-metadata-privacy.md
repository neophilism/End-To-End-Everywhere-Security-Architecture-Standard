# ADR 0010: Metadata privacy profiles

**Status:** Accepted for pre-1.0 development

## Context

End-to-end encryption protects message content but does not automatically hide communication metadata. A service can still learn sender identity, recipient, source network address, timing, and message size. These are separate privacy dimensions and require different mitigations.

## Serious alternatives considered

1. **Minimization only.** Keep direct authenticated delivery but sharply bound metadata retention and prohibit durable social-graph construction.
2. **Sender-hidden delivery.** Move sender authentication inside the recipient-decryptable envelope so the service can route to a recipient without learning the sender's ordinary account identity.
3. **Relay-partitioned sender-hidden delivery.** Combine sender hiding with an independent RFC 9458 OHTTP relay so the service also does not receive the client's network source address.
4. **Single ordinary forward proxy.** Rejected as the strongest profile because one proxy can observe both the client and target/service relationship and therefore does not provide the desired two-party metadata partition.
5. **Mix networks / high-latency onion routing as the default.** Not selected for E2EESA 0.1 messaging because their latency, availability, abuse, mobile, and operational tradeoffs require a separate architecture profile rather than being implied by ordinary messaging conformance.
6. **Claim complete metadata anonymity from sealed sender alone.** Rejected because direct transport still exposes source network metadata and traffic analysis remains.

## Decision

E2EESA defines three mutually exclusive complete profiles:

- `metadata-minimized@0.1.0`;
- `metadata-sender-hidden@0.1.0`; and
- `metadata-relay-partitioned@0.1.0`.

The relay-partitioned profile uses RFC 9458 OHTTP and the privacy-partitioning principles documented in RFC 9614. RFC 9540 discovery is allowed for OHTTP service/key discovery.

The sender-hidden architecture follows the deployed Sealed Sender pattern: transport-visible sender identity is removed while recipient-side authentication remains inside the encrypted envelope. E2EESA does not claim wire compatibility with Signal.

## Security consequences

Minimization reduces retained metadata but does not conceal metadata visible during live processing.

Sender-hidden delivery removes the ordinary authenticated sender identifier from the service view but does not hide the client's network source address.

Relay-partitioned delivery hides both ordinary sender identity and client source address from the messaging service, assuming relay/gateway independence and absent collusion. It still leaks recipient routing to the service and remains susceptible to traffic correlation.

## Retention decision

E2EESA 0.1 sets profile maxima of 24 hours for baseline post-delivery/source-IP metadata and one hour for sender-hidden post-delivery/source-IP metadata.

The relay-partitioned profile requires zero durable source-IP retention at both service and relay after request completion.

These are E2EESA profile limits, not claims that operational systems require those exact durations.

## Evidence and references

- RFC 9458, Oblivious HTTP.
- RFC 9540, Discovery of Oblivious Services via Service Binding Records.
- RFC 9614, Partitioning as an Architecture for Privacy.
- Signal, "Technology preview: Sealed sender for Signal".
- E2EESA pairwise/group E2EE and identity/device profiles.

## Reconsideration triggers

Revisit if standardized oblivious messaging transport emerges, if mix-network or multi-hop relay profiles become deployable at acceptable latency, if real-world measurements show the retention limits are operationally infeasible, or if independent review identifies sender-capability abuse-control weaknesses.
