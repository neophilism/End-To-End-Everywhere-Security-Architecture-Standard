# Authenticated hardware recovery attempt budgets (AUD-11)

**Status:** Normative policy and reference consistency checks; not proof of an HSM guarantee.

## Budget and exhaustion model

The hardware-assisted recovery profile **MUST** bind every recovery attempt to an explicit policy, cryptographic identity, hardware identity, approved executable measurement, approved release policy, authorized initiator and uniquely named shared budget. Failed candidate recovery secrets **MUST** consume a budget reservation **before** their validity is tested. A user-chosen low-entropy secret and a generated high-entropy secret **MUST NOT** be presented as having equivalent offline guessing resistance; the selected release policy **MUST** state its finite attempt count and exhaustion consequences.

An exhausted budget **MUST NOT** be replenished by restoring application snapshots, changing services, enrolling replicas, rebooting hardware, using an administrator interface, or bypassing the frontend. Unauthenticated requests MUST be rejected *before* consuming attempts, to limit denial-of-service by unauthorized services. An already authorized adversary may still exhaust the budget: the product MUST disclose this availability failure and provide only separately authenticated recovery alternatives if configured.

## Attestation and counter authority

Attestation **MUST** establish actual hardware identity, executable measurement, policy identity, key-use restrictions, and version/revocation information under a pinned trust policy. A boolean assertion, textual attestation reference, or a passing schema check is **not** this proof. The recovery back end MUST independently verify evidence, not rely on browser or mobile flags.

Every authorized replica **MUST** use the same non-rollbackable attempt budget and authenticated monotonic counter. A single-hardware-counter mode is valid only for a single isolated replica. A shared-replica mode requires a genuine strongly consistent trusted counter enforced at the hardware release boundary; a cloud database field without anti-rollback authority does not qualify. Additional replicas MAY be enrolled only under a new authenticated release-policy transition retaining the old remaining budget.

The operation that reserves an attempt **MUST** atomically advance hardware counter state and an independently trusted checkpoint *before* unwrapping or testing a candidate recovery secret. On uncertainty or failure to commit, the release path MUST fail closed. Restoring an old but otherwise well-formed signed budget state must not restore attempts.

## Authorized reset

A reset of an exhausted budget **MUST** use separately authenticated authority, new policy epoch, and monotonically increasing global counter, without treating support staff, the storage provider or elapsed time as silent recovery authority. Reset policy MAY forbid resets altogether. Original ciphertext and retained key copies remain subject to their own security assumptions.

## Evidence limits

The reference model \`scripts/recovery_attempt_budget.py\` verifies internally consistent declarations, reservations and monotonic checkpoint digests. It deliberately returns \`may_release_secret=false\` even for policy-consistent reservations. It does not verify an actual attestation chain, independent counter signature, HSM API, replicated consensus system, or durable transaction. A caller MUST independently authenticate each receipt and initiator reference, verify current revocation and hardware policies, and commit the proposed state before release.

Regression cases in \`tests/test_recovery_attempt_budget.py\` cover exhaustion, stale snapshots, changed measurements, unauthorized frontend bypass, rogue replicas, missing attestation and distinct reset authority. Production compliance remains pending actual hardware qualification, cross-replica concurrency/rollback testing, and security review.
