# ADR 0045: Recovery authority does not imply inherited trust

**Status:** Accepted for pre-1.0 development; independent review pending

## Context

Total device loss creates pressure to let an account service, support operator,
or waiting period add a new decryption endpoint. That silently turns service
control into cryptographic authority. A historical link supplied by the same
service does not prove control of the prior identity or freshness.

Availability needs differ. Some products choose permanent loss, some retain a
separately protected authority, and some pre-authorize trusted contacts. These
options have different continuity properties and must not be collapsed into a
generic account-recovery flag.

## Decision

E2EESA models three explicit development modes:

- `no-recovery`, which cannot recover the old identity;
- `retained-authority`, which requires a pre-authorized high-entropy
  authority bound to exact trusted history; and
- `preauthorized-contact-threshold`, which may create a replacement identity
  but cannot claim continuity.

Trusted history comes from an endpoint-retained view or verified key
transparency. Every authorization binds the prior state, history epoch, and
resulting identity. Revoked authorities, stale views, account credentials,
support overrides, and elapsed delays do not count.

No mode automatically transfers peer verification or group membership.
Offline peers must synchronize accepted history, re-verify as required, and
perform explicit group enrollment before sending new protected content.

## Consequences

The design fails closed during total loss and exposes the availability cost of
each choice. It also avoids claiming global revocation, deletion, or freshness
that local evidence cannot prove. Contact threshold is a replacement policy,
not a cryptographic continuity protocol.

The contracts and evaluator remain development-only pending independent
cryptographic and protocol review. They introduce no new primitive and do not
promote a registry entry into production eligibility.

## Reconsideration triggers

Revisit after independent analysis of retained-authority custody, contact
collusion and coercion, transparency split views, concurrent recovery, offline
revocation propagation, and usable re-verification flows.
