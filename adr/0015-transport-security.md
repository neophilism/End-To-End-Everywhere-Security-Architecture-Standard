# ADR 0015: Transport security profiles

**Status:** Accepted for pre-1.0 development

## Context

E2EESA application encryption still needs authenticated transport for API calls, directory access, ciphertext delivery, uploads, telemetry, service-to-service communication, and QUIC.

In 2026 the transport standards baseline changed materially: RFC 9846 replaced RFC 8446 as the current TLS 1.3 specification, and RFC 10024 standardized ML-KEM/traditional hybrid TLS groups.

A transport standard therefore needs both a conventional interoperability profile and a standardized hybrid profile without conflating either one with application E2EE.

## Serious alternatives considered

1. **TLS 1.2 compatibility.** Rejected from E2EESA 0.1 profiles. TLS 1.3 only keeps the policy smaller and avoids legacy cipher/key-exchange behavior.
2. **Classical TLS 1.3.** Retained as an allowed interoperability profile using X25519/P-256/P-384.
3. **Draft X25519Kyber768 groups.** Rejected as obsolete by RFC 10024.
4. **RFC 10024 hybrid TLS.** Selected as the recommended profile.
5. **PQ-only ML-KEM TLS.** Not selected; RFC 10024 standardizes hybrid combinations specifically to preserve security if one component fails.
6. **PSK-only resumption.** Rejected because it loses fresh ephemeral key exchange.
7. **0-RTT everywhere.** Rejected because TLS does not inherently prevent early-data replay.
8. **mTLS for every public client.** Not required. Server authentication fits ordinary clients; mTLS remains selectable for service-to-service deployments.
9. **Certificate pinning as the default trust model.** Not required due operational rotation/recovery hazards; public PKI and authenticated private PKI remain the standard trust models.
10. **Treating hybrid key exchange as PQ authentication.** Rejected. Key agreement and certificate authentication are separate claims.

## Decision

E2EESA defines:

- `transport-tls13-classical@0.1.0` — allowed; and
- `transport-tls13-hybrid@0.1.0` — recommended.

Both pin RFC 9846 TLS 1.3.

The hybrid profile uses RFC 10024 groups, with X25519MLKEM768 as default.

Service identity follows RFC 9525.

Stream TLS and QUIC/RFC 9001 are both supported.

0-RTT is disabled by default and requires an explicit application replay-safety profile if enabled.

## Security consequences

The hybrid profile improves resistance to harvest-now-decrypt-later attacks on transport confidentiality while preserving a traditional component.

It does not make certificate authentication quantum-safe by itself.

TLS termination at infrastructure remains a transport trust boundary. Application E2EE remains independent and can continue across that infrastructure.

## Standards basis

- RFC 9846 — TLS 1.3, current 2026 specification.
- RFC 10024 — X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024.
- RFC 9954 — hybrid TLS key-exchange construction.
- FIPS 203 — ML-KEM.
- RFC 9525 — service identity in TLS.
- RFC 9325 / BCP 195 — secure TLS deployment guidance.
- RFC 9001 — TLS securing QUIC.

## Reconsideration triggers

Revisit when post-quantum certificate/signature deployment receives a stable interoperable TLS/X.509 profile, when TLS/QUIC cipher guidance changes, when a successor to RFC 10024 is standardized, or when 0-RTT application standards provide stronger general replay guarantees.
