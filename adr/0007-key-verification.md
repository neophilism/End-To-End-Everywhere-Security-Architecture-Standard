# ADR 0007: Manual key-verification subject profiles

**Status:** Accepted for pre-1.0 development

## Context

Users need a way to compare cryptographic identity state outside the service they are trying to verify. Multi-device E2EE creates a real design choice: verify a stable root that authorizes devices, or verify every active device key. A verification UI also needs numeric and QR forms to represent the same subject deterministically, and future key-transparency evidence needs a stable object to reference.

## Serious alternatives considered

1. **Verify a stable account-root key.** Produces a durable safety value across subordinate device changes, but inherits trust in a high-value root authorization key.
2. **Verify the complete active device set.** Avoids a separate root trust anchor, but any device enrollment/removal/rotation changes the safety value.
3. **Verify only the current pairwise session key.** Rejected because session keys ratchet frequently and are unsuitable as stable user-facing identity verification anchors.
4. **Let the service declare that keys match.** Rejected because that gives the service being verified control over the verification result.
5. **Treat key transparency as the same thing as manual identity verification.** Rejected. Directory consistency and out-of-band human authentication answer different security questions.

## Decision

E2EESA defines two selectable manual verification profiles:

- `verify-account-root@0.1.0`; and
- `verify-device-set@0.1.0`.

Both derive one canonical perspective-independent subject, hash it with a registered hash, and display the same digest through a 60-digit numeric safety number and a versioned QR payload.

A prior verified state is invalidated whenever the selected subject changes. Silent re-verification is prohibited.

PR #12 key transparency will bind automatic consistency evidence to the same canonical subject digest while keeping transparency evidence distinct from manual user confirmation.

## Security consequences

Account-root verification has lower verification churn but concentrates trust in the root. Device-set verification has higher churn but directly exposes every active endpoint key to the verification subject.

Neither profile proves real-world identity unless the out-of-band channel provides that additional assurance.

A compromised service cannot create a legitimate manual verification record without the user's explicit confirmation, though it can still deny service or attempt social-engineering attacks.

## Compatibility constraints

Verification snapshots must come from PR #8 identity/device state. Pairwise and group protocols may consume verification state for UI/policy decisions but must not redefine the canonical verification subject.

Hash algorithms come from the E2EESA cryptographic registry. Later transparency evidence must reference, rather than silently replace, the canonical subject digest.

## Evidence and references

- Signal safety-number practice: numeric comparison or QR scanning over an independent channel.
- Signal safety-number change handling and explicit verified state.
- Signal automatic key verification/key transparency: global key consistency is complementary to, not identical with, manual safety-number verification.
- E2EESA identity/device architecture.

## Reconsideration triggers

Revisit if independent usability/security studies show the numeric encoding materially increases comparison error, if future identity profiles lack either a stable root or deterministic device-set representation, if key transparency requires a stronger canonical commitment, or if formal analysis identifies ambiguity in cross-perspective serialization.
