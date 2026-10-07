# Metadata Privacy Profiles

**Status:** Normative

This document defines E2EESA messaging-metadata privacy profiles. It separates three questions that are often incorrectly collapsed into "metadata privacy":

1. what metadata the messaging service collects and retains;
2. whether the messaging service learns the authenticated sender identity; and
3. whether the messaging service receives the client's network source address.

No E2EESA 0.1 profile claims to hide the recipient routing identifier from the service responsible for asynchronous delivery.

## 1. Common minimization invariant

Every metadata-privacy profile **MUST** minimize collection and durable retention of ordinary delivery metadata.

A conforming service **MUST NOT**:

- build a durable sender-recipient social graph from ordinary message-delivery records;
- persist classifications derived from protected message content;
- attach a stable identifier intended to correlate the user across unrelated services; or
- retain post-delivery routing or source-address metadata longer than the selected profile permits.

Operational counters MAY be retained when they are aggregated or otherwise structured so they do not recreate per-user communication histories.

## 2. Protected content remains E2EE

Metadata privacy **MUST NOT** replace or terminate the pairwise/group E2EE layer.

The messaging service, relay, and OHTTP gateway **MUST NOT** receive protected-message plaintext as a consequence of selecting a metadata profile.

Metadata privacy evidence is invalid if the underlying protected content is not end-to-end encrypted under an applicable E2EESA messaging profile.

## 3. Profile A — minimized service metadata

Profile reference: `metadata-minimized@0.1.0`

This baseline profile permits the messaging service to observe the authenticated sender identity, recipient routing identifier, and client network source address while the request is being processed.

It nevertheless limits durable collection:

- post-delivery metadata retention **MUST NOT** exceed 24 hours;
- source network-address retention **MUST NOT** exceed 24 hours;
- durable sender-recipient relationship records are prohibited; and
- service processing of protected content must remain impossible.

This profile claims `SP-METADATA-MINIMIZATION`, not sender anonymity or source-network-address confidentiality.

## 4. Profile B — sender-hidden delivery

Profile reference: `metadata-sender-hidden@0.1.0`

This is a recommended E2EESA profile.

It uses a sealed-sender-style architecture in which the transport-visible submission does not disclose the ordinary authenticated sender identity to the messaging service.

The recipient **MUST** authenticate the sender from credential/key material carried inside the recipient-decryptable E2EE envelope.

A recipient-scoped delivery capability or equivalent privacy-preserving mechanism **MUST** allow the service to perform abuse control and recipient authorization without requiring the sender's ordinary account identity in the delivery request.

E2EESA defines this as an architecture profile; it does not claim wire compatibility with Signal's deployed Sealed Sender protocol.

For this profile:

- post-delivery metadata retention **MUST NOT** exceed one hour;
- service source-address retention **MUST NOT** exceed one hour; and
- the service **MUST NOT** persist a sender-recipient relationship record.

The service can still observe the client's network source address during direct transport. Therefore this profile **MUST NOT** claim that the sender's network location or IP address is concealed from the messaging service.

## 5. Sender credential lifecycle

Sender-hidden credentials **MUST** be authenticated by the receiving endpoint and **MUST** be bound to an identity/device state valid under PR #8.

The credential **MUST NOT** be accepted merely because the delivery service asserted a sender identifier.

Credential expiration, revocation, and key rotation **MUST** track the selected identity architecture closely enough that a revoked device cannot continue to authenticate sender-hidden messages indefinitely.

The precise credential encoding is an implementation profile and is not frozen by E2EESA 0.1.

## 6. Recipient-scoped delivery capability

A sender-hidden submission **MUST** demonstrate authorization to deliver to the recipient without revealing the sender's ordinary account identifier.

A delivery capability:

- **MUST** be scoped to the intended recipient;
- **MUST NOT** function as a stable cross-service tracking identifier;
- **SHOULD** be rotated when the recipient blocks or revokes a sender relationship; and
- **MUST** be protected from disclosure to unrelated parties.

Abuse controls MAY reject, rate-limit, or challenge senders, but they **MUST NOT** silently convert the sender-hidden profile into ordinary authenticated delivery while still reporting sender-hidden conformance.

## 7. Profile C — relay-partitioned sender-hidden delivery

Profile reference: `metadata-relay-partitioned@0.1.0`

This is the strongest E2EESA 0.1 store-and-forward messaging metadata profile.

It combines sender-hidden delivery with RFC 9458 Oblivious HTTP (OHTTP).

The client sends an encapsulated request to an ingress relay. The relay forwards the encapsulated request to the OHTTP gateway/message service.

Under the selected deployment:

- the relay may observe the client's network address but **MUST NOT** see the application request plaintext;
- the gateway/message service may see the recipient routing identifier after OHTTP decapsulation but **MUST NOT** receive the client's network connection or source address;
- the sender's ordinary authenticated identity remains hidden inside the recipient-decryptable E2EE envelope; and
- the relay and gateway/service **MUST** be operated by administratively independent entities for the E2EESA metadata-confidentiality claim.

The service and relay **MUST** retain client source addresses for zero seconds after request completion under this profile; transient in-memory processing is not durable retention.

## 8. OHTTP configuration

The OHTTP gateway key configuration **MUST** be authenticated and integrity protected.

Clients **MUST NOT** accept a gateway key configuration that is uniquely personalized per client when doing so could become a correlation identifier.

RFC 9540 discovery MAY be used. An implementation MAY instead use another authenticated configuration-distribution channel, provided it does not defeat the privacy partition by revealing unique client identity to the gateway.

The policy **MUST** select registered E2EESA algorithms corresponding to the OHTTP HPKE KEM, KDF, and AEAD choices.

## 9. Relay forwarding behavior

The OHTTP relay **MUST NOT** add `Forwarded`, `Via`, proprietary headers, pseudonymous identifiers, or equivalent fields that identify or stably distinguish the client at the gateway beyond information explicitly allowed by the profile.

Differential treatment used for abuse control can reduce the client's anonymity set. A product **MUST NOT** claim stronger unlinkability than its actual relay behavior supports.

The relay and gateway/service **MUST NOT** share per-request identifying logs as part of ordinary operation.

## 10. Replay protection

RFC 9458 permits encapsulated requests to be copied and replayed by a relay or network adversary.

The relay-partitioned E2EESA profile therefore **MUST** apply application-level replay protection to message-submission requests.

A message identifier, OHTTP encapsulated-key identifier, request date/window, or equivalent mechanism MAY be used, provided a replay cannot cause duplicate security-sensitive processing.

A retry that requires changing the OHTTP plaintext request **MUST** use a fresh OHTTP encryption context.

## 11. Padding

The relay-partitioned profile **MUST** pad encapsulated binary HTTP requests.

E2EESA 0.1 requires a configured padding multiple of at least 256 bytes.

Padding reduces information leaked by message size but does not eliminate traffic analysis.

The precise bucketing strategy MAY be deployment-specific and SHOULD balance latency/bandwidth costs against the anonymity set required by the product.

## 12. Traffic-analysis boundary

OHTTP and sender-hidden delivery do not make traffic analysis disappear.

Timing, request size, response size, request frequency, relay load, endpoint behavior, and active differential treatment can reveal or correlate information.

A global passive observer that can observe both sides of the relay may correlate flows.

A malicious relay and gateway/service that collude may reconstruct the partitioned metadata view.

Therefore `metadata-relay-partitioned@0.1.0` **MUST NOT** claim protection against a global passive observer or relay-gateway collusion unless an additional mechanism independently establishes that claim.

## 13. Recipient visibility

All E2EESA 0.1 messaging-metadata profiles assume that the asynchronous delivery service sees the recipient routing identifier needed to queue or deliver the message.

A product **MUST NOT** describe these profiles as concealing "who is messaging whom" without qualifying that the service still learns the recipient and may infer relationships through timing or other side channels.

Future destination-hiding or mix-network profiles require separate standardization.

## 14. Calls and real-time media

This specification governs store-and-forward messaging submission.

Real-time voice/video metadata has different latency, NAT traversal, relay, conferencing, and traffic-analysis constraints and is addressed by the later E2EESA real-time-media profile.

A product **MUST NOT** extend a messaging-metadata conformance result to calls unless the call path separately satisfies an applicable profile.

## 15. Conformance evidence

A conforming delivery event **MUST** preserve enough evidence to determine, as applicable:

1. exact metadata profile;
2. whether protected content remained E2EE;
3. recipient-routing visibility;
4. sender-identity visibility at service and recipient;
5. sender credential/capability handling;
6. whether durable sender-recipient mappings were written;
7. content-derived and cross-service tracking metadata behavior;
8. actual post-delivery and source-address retention;
9. whether a relay was used;
10. OHTTP encapsulation and gateway-key authentication;
11. whether gateway configuration was personalized;
12. source-address visibility at relay, gateway, and messaging service;
13. relay-added identifying metadata;
14. relay/gateway operational independence;
15. request padding; and
16. OHTTP/application replay protection.

The semantic validator checks these declared and cryptographically verified facts. It does not implement OHTTP, sender-hidden envelope encryption, traffic padding, log deletion, or organizational non-collusion.
