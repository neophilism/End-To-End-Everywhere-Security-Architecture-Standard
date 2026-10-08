# Certification Lifecycle

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 29.

This document defines the event-sourced certification lifecycle consumed by Open E2EE Verified.

A certification state is never edited directly. It is derived by replaying validated lifecycle events in order.

## 1. States

The initial lifecycle states are:

- `draft`
- `submitted`
- `intake-review`
- `evaluation`
- `remediation`
- `decision-review`
- `certified`
- `surveillance-review`
- `corrective-action`
- `renewal-review`
- `suspended`
- `revoked`
- `denied`
- `appeal-review`
- `expired`
- `withdrawn`
- `closed`

A terminal or adverse state MUST NOT be bypassed by editing a record. Any later change must be represented by an allowed transition event.

## 2. Core lifecycle

The normal first-certification path is:

`draft → submitted → intake-review → evaluation → decision-review → certified`

Evaluation MAY require remediation before decision review:

`evaluation → remediation → evaluation`

A denied application MAY enter appeal review.

## 3. Surveillance and corrective action

A certified product MAY enter `surveillance-review`.

Surveillance can:

- return to `certified`;
- require `corrective-action`;
- suspend the certification;
- revoke the certification; or
- determine that the certification has expired.

Corrective action returns to surveillance review for re-evaluation; it does not directly restore certification.

## 4. Renewal

A certified product MAY enter `renewal-review` before expiry.

Renewal can:

- renew to `certified` with a new evidence bundle and validity window;
- require corrective action;
- suspend;
- revoke; or
- expire.

A renewal MUST bind a current certification evidence bundle.

## 5. Suspension

Suspension temporarily removes active certification status.

Reinstatement from suspension requires:

- current evidence;
- a permitted reinstatement actor;
- a reason;
- a fresh surveillance due date; and
- a certificate expiry date that remains in the future.

Suspension MUST NOT be represented as continued active certification.

## 6. Revocation

Revocation removes certification.

A revoked certification MUST NOT be reinstated through an ordinary lifecycle transition.

A successful appeal MAY remand the case to `decision-review`, but a new positive decision is required before any later certification.

## 7. Expiration

Expiration occurs when the certificate validity window ends without a valid renewal.

An `expire` event MUST NOT occur before the current certificate expiry time.

A lifecycle record in active `certified` state whose validity date has already passed is invalid as of that evaluation time.

## 8. Surveillance due dates

Certification and renewal events set a surveillance due date.

If the case is still `certified` after the surveillance due date without entering a surveillance or renewal process, the lifecycle is overdue and MUST NOT be represented as fully current certification.

The engine reports overdue surveillance as a validation failure when validating the lifecycle as of a time after the due date.

## 9. Evidence bundle binding

The following events require an exact certification evidence bundle digest:

- `submit`
- `remediation-submitted`
- `advance-to-decision`
- `approve`
- `begin-surveillance`
- `corrective-action-submitted`
- `begin-renewal`
- `renew`
- `reinstate`

A decision MUST NOT approve a bundle other than the exact bundle advanced to decision review.

A later remediation, surveillance or renewal cycle MAY replace the current evidence bundle, but the transition event must identify the new digest explicitly.

## 10. Separation of duties

At minimum:

- an applicant submits;
- evaluators evaluate evidence;
- a certification decision-maker approves or denies;
- surveillance reviewers perform surveillance decisions;
- appeal reviewers decide appeals.

A certification decision-maker MUST NOT be an applicant actor for the same case.

A certification decision-maker MUST NOT be an evaluator who participated in that decision cycle.

An appeal reviewer MUST NOT be the actor whose adverse decision is under appeal.

Later certification policy MAY impose stronger organizational-independence rules.

## 11. Adverse-action reasons

The following events require a non-empty reason:

- `deny`
- `require-remediation`
- `require-corrective-action`
- `suspend`
- `revoke`
- `expire`
- `withdraw`
- `appeal-upheld`
- `appeal-remanded`

The reason is part of the audit history and MUST NOT be deleted from the event log.

## 12. Appeals

An appeal may be opened from:

- `denied`
- `suspended`
- `revoked`

The engine records the adverse origin state.

An appeal may be:

- upheld, returning to the same adverse origin state; or
- remanded to `decision-review`.

A remand is not a certification. A new independent certification decision is still required.

## 13. Event ordering and immutability

Event IDs MUST be unique.

Event timestamps MUST be monotonic non-decreasing.

Every event MUST declare the state it expects before and after the transition.

The declared `from_state` MUST equal the state produced by prior events.

The event type, from-state and to-state MUST exactly match a registered transition.

## 14. Decision-cycle independence

The lifecycle engine tracks evaluator actors since the most recent entry into `evaluation`.

An `approve` or `deny` event actor MUST NOT appear in that evaluator set.

When a case enters a fresh evaluation cycle after remediation or appeal remand, evaluator tracking begins again for that decision cycle.

## 15. Validity windows

`approve`, `renew`, and `reinstate` require:

- `certificate_expires_at`; and
- `surveillance_due_at`.

Both MUST be later than the event time.

The surveillance due date MUST NOT be later than certificate expiry.

## 16. Lifecycle validation time

A lifecycle may be validated `as_of` a supplied UTC time.

If `as_of` is after certificate expiry while the derived state is `certified`, validation fails.

If `as_of` is after surveillance due while the derived state remains `certified`, validation fails.

This prevents stale event logs from being treated as current certification.

## 17. Fail-closed behavior

Validation fails on:

- unknown states or event types;
- illegal transitions;
- event-state mismatch;
- duplicate event IDs;
- decreasing timestamps;
- wrong actor role;
- missing reasons for adverse events;
- missing or malformed evidence bundle digests;
- approval of a bundle different from the bundle advanced to decision;
- decision-maker participation as applicant/evaluator;
- appeal reviewer conflict;
- invalid validity windows;
- premature expiration;
- stale active certification; or
- reinstatement from revocation.

## 18. Attestation boundary

PR 29 determines lifecycle state.

PR 30 signs the machine-readable certification attestation corresponding to an approved, current lifecycle state.
