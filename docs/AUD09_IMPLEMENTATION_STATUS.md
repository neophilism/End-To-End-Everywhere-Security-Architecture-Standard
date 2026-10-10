# AUD-09 implementation slices

Parent: AUD-09 in [the approved remediation plan](AUDIT_REMEDIATION_PLAN.md).
Dependency: AUD-08 development implementation, merged in PR62. Independent
protocol review remains a separate, unsatisfied release gate.

## AUD-09.1: persisted verification invalidation

This change implements the first, narrowly scoped AUD-09 invariant: an explicitly
invalidated manual-verification record does not become verified merely because
its old subject digest matches the current snapshot again. The status evaluator
requires a fresh explicit out-of-band comparison before verified trust is restored.
The existing account-root and device-set verification profiles are both covered.

The evaluator is pure: the caller owns durable, atomic persistence of the accepted
invalidation before any send or display decision. Calling the evaluator without
persisting an observed subject change is not a durable key-change state machine.
A caller cannot restore trust by editing the old record's status field; it must
create and preserve a new comparison record through the existing confirmation path.
The returned status is not proof that a UI displayed a warning or that a person
actually performed an independent comparison.

Regression coverage includes persisted invalidation, a subject changing away and
back, fresh explicit comparison, rejected silent comparison, malformed records,
and authorized subordinate-device changes under an unchanged account root.
The PR and CI record merge/test status; this document does not claim a deployment.

## Remaining AUD-09 work

AUD-09 remains incomplete after this slice. Subsequent coherent PRs must implement
and test the selected acknowledgement versus stricter re-verification send policies,
verified and unverified subject-change notices, routine-change versus replacement
classification, durable ordered notice history, accessible presentation contracts,
and queued-message handling that never silently re-encrypts to a changed recipient.
Actual endpoint integration, persistence/race behavior, accessibility and independent
security review require their own evidence. No production or conformance claim is
created by this reference-engine correction.
