# Transport Security Profiles

**Status:** Normative

This document defines E2EESA transport-security profiles for authenticated TLS 1.3 connections over stream transports and QUIC.

Profiles:

- `transport-tls13-classical@0.1.0`
- `transport-tls13-hybrid@0.1.0`

Transport security protects a network hop or transport connection. It does not replace application-layer end-to-end encryption.

## 1. TLS baseline

E2EESA 0.1 pins TLS 1.3 as specified by RFC 9846.

RFC 9846 obsoletes RFC 8446 while retaining TLS version 1.3.

A conforming E2EESA transport endpoint MUST NOT negotiate TLS 1.2 or earlier.

Every connection MUST use a fresh key share as required by RFC 9846. Reusing an ephemeral KeyShare between connections is prohibited.

## 2. Profile A — classical TLS 1.3

Profile reference: `transport-tls13-classical@0.1.0`

This profile uses ephemeral traditional ECDHE with one or more of:

- X25519 — recommended;
- secp256r1 — allowed; or
- secp384r1 — allowed.

This profile provides ordinary TLS 1.3 confidentiality, integrity, peer authentication, forward secrecy, and downgrade resistance.

It MUST NOT claim post-quantum confidentiality.

It exists for interoperability and environments where standardized hybrid PQ/T groups are unavailable or not required.

## 3. Profile B — hybrid PQ/traditional TLS 1.3

Profile reference: `transport-tls13-hybrid@0.1.0`

This profile uses an RFC 10024 post-quantum/traditional hybrid key agreement.

Permitted groups are:

- X25519MLKEM768, IANA 4588 / 0x11EC — recommended;
- SecP256r1MLKEM768, IANA 4587 / 0x11EB — allowed; and
- SecP384r1MLKEM1024, IANA 4589 / 0x11ED — allowed.

A connection claiming this profile MUST actually negotiate one of those hybrid groups.

A client or server MUST NOT silently negotiate a traditional-only group and continue reporting hybrid conformance.

## 4. ML-KEM basis

The post-quantum components are ML-KEM-768 or ML-KEM-1024 as standardized by FIPS 203 and instantiated in RFC 10024.

RFC 10024 applies the TLS hybrid construction described by RFC 9954.

The hybrid profile is designed so confidentiality remains protected if either the traditional or post-quantum component remains secure under the construction's assumptions.

The profile does not require or imply that certificate authentication is post-quantum.

## 5. Hybrid group selection

X25519MLKEM768 is the default E2EESA hybrid group because RFC 10024 marks it Recommended and describes it as the practical choice for a single PQ/T combiner.

SecP256r1MLKEM768 is available where a deployment requires a P-256 traditional component or has FIPS-oriented implementation constraints.

SecP384r1MLKEM1024 is available for higher-security deployments that accept its larger computational and handshake-size cost.

Deployments MUST document their selected group set and preferred group.

## 6. Obsolete pre-standard Kyber groups

The pre-standard groups X25519Kyber768Draft00 and SecP256r1Kyber768Draft00 are obsolete under RFC 10024.

They MUST NOT be negotiated by an E2EESA 0.1 transport profile.

A deployment migrating from those experimental groups MUST move to the RFC 10024 ML-KEM groups rather than treating the old code points as equivalent.

## 7. TLS cipher suites

E2EESA 0.1 permits the TLS 1.3 suites:

- TLS_AES_256_GCM_SHA384 — recommended;
- TLS_CHACHA20_POLY1305_SHA256 — recommended; and
- TLS_AES_128_GCM_SHA256 — allowed.

TLS 1.3 key-exchange groups and record-layer cipher suites are separate negotiation dimensions.

Selecting an AES-256 record cipher does not make a classical key exchange post-quantum.

## 8. Service authentication

Certificate-based service identity verification MUST follow RFC 9525.

The client MUST construct and verify the appropriate reference identifier for the application service.

The certificate chain MUST validate to the configured trust model.

The service certificate MUST be within its validity period.

Common Name fallback MUST NOT be used for service identity.

A certificate that chains successfully but does not match the expected RFC 9525 service identity MUST fail the connection.

## 9. Trust models

E2EESA supports:

- public-web-pki for Internet-facing services; and
- private-pki for controlled service-to-service environments.

A private trust anchor MUST be provisioned through an authenticated administrative or deployment path independent of the connection being authenticated.

Blind trust-on-first-use of an unauthenticated server certificate is not equivalent to private PKI.

Certificate pinning MAY be layered on top by an application, but it is not required by this transport profile and MUST include an operational rotation/recovery design.

## 10. Mutual TLS and service-to-service transport

A transport policy MAY require mutual certificate authentication.

When `authentication_mode = mutual-certificate`:

- the server MUST request client authentication;
- the client MUST present a certificate;
- the certificate chain MUST validate under the configured trust model; and
- the authenticated client identity MUST be authorized for the intended service role.

Successful mTLS authentication does not replace application authorization.

Service meshes, sidecars, gateways, and internal proxies MUST expose the actual authenticated peer identity to the authorization layer rather than treating network location alone as identity.

## 11. ALPN and cross-protocol safety

Every profile MUST negotiate an allowed Application-Layer Protocol Negotiation identifier.

A TLS connection MUST NOT be accepted for an application protocol that was not explicitly permitted by policy.

Certificate reuse across different application services can create cross-protocol risk. Deployments SHOULD use service-scoped identifiers and ALPN constraints that prevent one protocol endpoint from impersonating another.

## 12. Session resumption

TLS 1.3 session resumption MAY be used.

E2EESA requires ephemeral key exchange on resumed sessions.

A resumed connection MUST use `psk_dhe_ke` or an equivalent mode that contributes fresh ephemeral key agreement.

PSK-only `psk_ke` is prohibited because it does not provide the forward-secrecy and hybrid-key-exchange properties required by these profiles.

A hybrid profile MUST negotiate an RFC 10024 hybrid group again on resumed connections when it continues to claim hybrid/PQ transport confidentiality.

## 13. 0-RTT early data

0-RTT is disabled by default.

RFC 9846 states that TLS does not provide inherent replay protection for 0-RTT application data.

A policy MAY enable 0-RTT only when a separately documented application profile:

- identifies exactly which operations are safe for early data;
- treats replay as an explicit application threat;
- provides replay protection appropriate to the deployment;
- defines behavior when early data is rejected; and
- prevents automatic replay from creating security-sensitive duplicate effects.

Security-sensitive writes, authorization changes, key-management operations, payments, destructive actions, and non-idempotent state transitions SHOULD NOT use 0-RTT.

If the required application replay-safety profile is absent, 0-RTT MUST remain disabled.

## 14. QUIC

E2EESA MAY carry either transport profile over QUIC using TLS as defined by RFC 9001.

QUIC version 1 or version 2 may be selected by policy.

The TLS version, key-exchange group, certificate identity, ALPN, hybrid-downgrade, and 0-RTT requirements in this document still apply.

QUIC transport encryption does not replace application-layer E2EE.

Deployments SHOULD account for the larger ClientHello/key-share sizes created by hybrid groups when sizing QUIC anti-amplification, path-MTU, and handshake infrastructure.

## 15. Downgrade resistance

A transport policy MUST fail closed when the negotiated TLS version, cipher suite, group, ALPN, trust model, or authentication mode falls outside policy.

The hybrid profile MUST fail closed rather than fall back to a classical-only group while continuing the same security claim.

PR #7 negotiation/downgrade rules apply to configuration selection before the TLS handshake.

This PR additionally validates the result actually negotiated on the wire.

## 16. Certificate and signature boundary

TLS certificate authentication and TLS key agreement are separate.

The hybrid profile provides a PQ/traditional key-agreement claim and may support `SP-PQ-CONFIDENTIALITY`.

It MUST NOT automatically claim `SP-PQ-AUTHENTICATION`.

A deployment using a post-quantum certificate signature algorithm still needs a separately defined and validated certificate/profile chain before E2EESA will attribute PQ authentication to transport.

## 17. TLS termination, proxies, and load balancers

A TLS-terminating reverse proxy, CDN, load balancer, API gateway, or service-mesh sidecar is a plaintext endpoint for that transport connection.

If an application uses separate E2EE above TLS, the terminating intermediary MUST still see only application E2EE ciphertext unless it is itself an authorized E2EE endpoint.

A product MUST NOT describe ordinary TLS through a terminating proxy as end-to-end encryption between application users.

## 18. Application E2EE independence

E2EESA messaging, group, attachment, and media E2EE profiles remain cryptographically independent of TLS.

Transport security protects metadata and ciphertext in transit to the next transport endpoint and provides service authentication.

The transport layer MUST NOT terminate, unwrap, or downgrade the separate application E2EE layer.

A loss of TLS therefore does not become permission to send application plaintext when the selected application profile requires E2EE.

## 19. Logging and debugging

TLS key logging, decrypted packet capture, debug proxies, and observability tooling can defeat transport confidentiality.

Production profiles MUST disable export of live TLS traffic secrets unless an explicitly authorized diagnostic mode defines:

- who can enable it;
- how activation is audited;
- how secrets are protected;
- how long they are retained; and
- how normal secure operation is restored.

Such a diagnostic mode is outside ordinary conformance.

## 20. Conformance evidence

A conforming handshake MUST demonstrate:

1. TLS 1.3 under RFC 9846;
2. permitted transport mode and QUIC version where applicable;
3. selected group was offered and allowed;
4. actual traditional or RFC 10024 hybrid group required by profile;
5. no obsolete draft Kyber group;
6. allowed TLS 1.3 cipher suite;
7. fresh key share;
8. allowed ALPN;
9. certificate-chain and validity verification;
10. exact RFC 9525 reference-identifier match without Common Name fallback;
11. required client-certificate validation/authorization for mTLS;
12. `psk_dhe_ke` rather than PSK-only resumption;
13. explicit application replay profile before any 0-RTT;
14. fail-closed hybrid downgrade behavior;
15. no unsupported PQ-authentication claim; and
16. preservation of a separate application E2EE layer.
