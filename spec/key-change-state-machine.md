# AUD-09.2 — Cryptographic identity-change notices and send decisions

**Status:** normative reference boundary; *not* an endpoint integration or certification.

The caller MUST obtain an authenticated, currently accepted identity subject from the identity/device architecture, then compare it against the locally committed subject **before** queueing, encrypting, or sending. Every changed subject, including an unverified contact, MUST produce a durable ordered change event; verified state MUST become invalidated. An explicit new out-of-band comparison tied to the exact current subject is required to restore verified state. Returning to a previously seen digest does not restore trust.

## Policies and transitions

Two versioned policy modes are supported: \`strict-reverification\` blocks all sends until a new valid manual comparison; \`acknowledge-change\` permits sending to a changed non-replacement subject *only* after the user explicitly acknowledges the latest security notice, with clear persistent **unverified** labeling. Identity replacement always requires fresh verification, never mere acknowledgement. This policy does not assert security of an unverified recipient.

An authorized subordinate-device change is classifiable as routine only when the caller independently verifies the applicable authorization evidence; a string reference alone is **not evidence**. For account-root verification, an unchanged verified root should not be invalidated by an authorized subordinate change that leaves its cryptographic verification subject unchanged.

Every accepted subject change is recorded as a sequential hash-chained event; no event can be silently deleted or reordered without breaking that chain. However, a valid earlier journal prefix is still valid on its own. The caller MUST maintain an **independent** trusted head and monotonic revision and reject rollback; this pure implementation neither provides that store nor provides atomic durability.

## UI and queued messages

Every identity-change event yields an ordered, retained notification descriptor, with its prior verification status, classification, new subject and message key. All notifications MUST be surfaced accessibly and without disguising verified-to-unverified changes. The caller MUST durably commit change, acknowledgment and fresh-comparison state, and its independent anchor *before* displaying trusted status or permitting send. Concurrent reads, sends, accepted identity updates and recovery MUST be serialized by the host, or independently proven to have equivalent ordering.

Queued protected messages MUST be bound to recipient subject and journal revision. After **any** intervening subject-change event, including A→B→A, old queued content MUST NOT silently be encrypted or sent to the new subject; obtain a new explicit authorization, regenerate the recipient binding, and requeue. Queue checks do not constitute real network delivery protection without integration at the final encryption/dispatch boundary.

Reference evaluator: \`scripts/key_change_state_machine.py\`. Regression tests: \`tests/test_key_change_state_machine.py\`. It does not prove out-of-band comparison actually occurred, evidence references are authentic, accessibility is implemented, or an endpoint persists the journal safely. These remain distinct adoption and assurance requirements.
