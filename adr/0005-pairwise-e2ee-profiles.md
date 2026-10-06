# ADR 0005: Pairwise asynchronous E2EE protocol profiles

**Status:** Accepted for pre-1.0 development

## Context

E2EESA needs a real asynchronous one-to-one secure-messaging architecture with forward secrecy and post-compromise security. The design must support offline recipients and multi-device products while avoiding invention of a new cryptographic protocol. The post-quantum transition also creates a real architectural choice: classical-only ratcheting, PQ-protected initialization with classical ratcheting, a post-quantum sparse ratchet, or a hybrid ratchet that preserves both classical and post-quantum assumptions.

## Serious alternatives considered

1. **Invent an E2EESA-specific prekey and ratchet protocol.** Rejected. Mature published protocols already exist and creating a new primitive would add avoidable cryptographic risk.
2. **X3DH + Double Ratchet.** Mature and widely deployed classical architecture, but it has no post-quantum confidentiality claim.
3. **PQXDH + Double Ratchet.** Useful transition architecture that protects asynchronous initialization against relevant post-quantum confidentiality threats, but its ratchet does not provide post-quantum healing.
4. **PQXDH + SPQR/ML-KEM Braid.** Provides a post-quantum ratchet with sparse healing; dropped messages can slow healing.
5. **PQXDH + Triple Ratchet.** Runs the classical Double Ratchet and SPQR together and combines their outputs, preserving a classical hedge while adding PQ ratcheting.
6. **Require only the newest profile and prohibit classical/transition profiles.** Rejected during pre-1.0 because interoperability, bandwidth, implementation maturity, and deployment constraints are legitimate profile-level choices when made explicitly.

## Decision

E2EESA defines four complete pairwise profile alternatives:

- `pairwise-x3dh-double-ratchet@0.1.0` — allowed;
- `pairwise-pqxdh-double-ratchet@0.1.0` — allowed transition profile;
- `pairwise-pqxdh-spqr@0.1.0` — allowed PQ-ratchet profile; and
- `pairwise-pqxdh-triple-ratchet@0.1.0` — recommended.

The profile family is `at-most-one` during foundation development so existing configuration fixtures remain valid; a pairwise-capable product must select one when pairwise E2EE is in scope.

External protocol revisions are pinned through a machine-readable pairwise protocol registry. E2EESA adds semantic invariants and conformance evidence but does not fork or silently modify the external cryptographic constructions.

## Security consequences

The selected profile determines whether post-quantum confidentiality and post-quantum ratchet healing can be claimed. Triple Ratchet is recommended because it retains the classical Double Ratchet while adding the post-quantum sparse ratchet.

Current PQXDH authentication is not post-quantum. No PQXDH-based E2EESA 0.1 profile may claim post-quantum authentication.

One-time-prekey use, replay handling, skipped-key bounds, per-message key uniqueness, and secure deletion become testable conformance requirements rather than informal implementation advice.

## Compatibility constraints

Pairwise endpoints must be current authorized devices from the identity/device architecture. Pairwise profile negotiation is subject to downgrade-defense rules. Cryptographic algorithms must be selected from the E2EESA cryptographic registry.

Session-management logic may use Sesame-compatible semantics but cannot resurrect or authorize a revoked device.

Group messaging remains a separate profile family and is not implemented by this ADR.

## Evidence and references

- Signal X3DH Revision 1 (2016-11-04).
- Signal PQXDH Revision 3 (last updated 2024-01-23).
- Signal Double Ratchet Revision 4 (2025-11-04), including SPQR and Triple Ratchet.
- Signal ML-KEM Braid specification.
- Signal Sesame Revision 2 (2017-04-14).
- E2EESA identity/device architecture, cryptographic registry, threat model, security-property model, and negotiation/downgrade defense.

## Reconsideration triggers

Revisit when PQXDH gains post-quantum authentication, a newer ratchet revision materially changes the security model, standardized secure-messaging protocols provide superior interoperability, independent review identifies unsafe profile composition, or E2EESA formal-verification work requires narrower parameter choices.
