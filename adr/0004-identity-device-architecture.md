# ADR 0004: Identity and device authorization profiles

**Status:** Accepted for pre-1.0 development

## Context

An E2EE architecture must decide who can add, rotate, and revoke devices that receive protected plaintext. Service-authoritative device enrollment would let a compromised or malicious service add a recipient endpoint and defeat the end-to-end boundary. Multiple client-side authorization models have legitimate security/availability tradeoffs.

## Serious alternatives considered

1. **Service-authoritative enrollment** — rejected because unilateral server authority can create a new plaintext recipient.
2. **Stable account cryptographic root** — simple and durable, but creates a high-value long-term root secret.
3. **Existing-device cross-signing** — avoids a separate root secret, but one compromised eligible device can authorize some changes.
4. **Threshold device quorum** — reduces single-device authorization power as the device set grows, but increases availability complexity.
5. **Mandate one client-side model globally** — rejected because the serious alternatives have product-dependent tradeoffs.

## Decision

E2EESA prohibits server-only authorization of a device that becomes an E2EE recipient and defines three profiles:

- `identity-account-root@0.1.0`
- `identity-device-cross-signing@0.1.0`
- `identity-threshold-quorum@0.1.0`

All share state-hash binding, monotonic sequence, device/key uniqueness, registered-algorithm use, explicit enrollment/rotation/revocation events, and fail-closed validation.

The profile family is initially `at-most-one` so existing pre-1.0 resolver fixtures remain valid. Product conformance requires an identity profile when identity/device management is in scope.

## Security consequences

The service cannot silently turn account administration into recipient-device authorization. Account-root deployments concentrate authority in one root. Cross-signing accepts more single-device authorization risk. Threshold deployments reduce that risk for larger device sets but may be less available.

The local event chain does not solve global split views by itself; key transparency remains separate.

## Compatibility constraints

Identity keys must use registered E2EESA algorithms. Later pairwise, group, verification, transparency, and recovery profiles must consume device state without weakening these authorization rules.

Recovery is intentionally not modeled as an ordinary identity event in this milestone.

## Evidence and references

- E2EESA unified threat model.
- E2EESA cryptographic registry and downgrade-defense invariants.
- Deployed secure-messaging designs using long-term identity keys and linked-device authorization.
- Multi-device designs using cross-signing and quorum authorization.

## Reconsideration triggers

Revisit if independent review identifies a materially better authorization model, transparency integration requires state-chain changes, formal verification finds ambiguous semantics, or later recovery profiles cannot compose safely.
