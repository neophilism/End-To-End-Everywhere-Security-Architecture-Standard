# ADR-0029: Certification lifecycle is event sourced

- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision class:** Invariant
- **Affected components:** certification, surveillance, renewal, suspension, revocation, appeals
- **Security properties affected:** integrity and auditability of certification status

## Context

A mutable `status` field cannot explain how a certification reached its current state, who made each decision, which evidence was reviewed, or whether separation-of-duties rules were obeyed.

## Serious alternatives considered

### Mutable status plus audit log

Rejected as the canonical model because status and log can diverge.

### Event-sourced lifecycle

Accepted. State is derived exclusively by replaying validated transitions.

## Decision

Certification lifecycle state is event sourced.

Transitions are registry-defined and actor-role constrained.

Positive decisions bind exact evidence bundles and validity windows.

Decision makers cannot be applicants or evaluators in the same decision cycle.

Appeal reviewers cannot be the adverse decision actor.

## Security consequences

The lifecycle is reconstructable and tamper-evident when the event record is protected and later attested.

Invalid direct state changes are structurally impossible in the canonical record.

## Compatibility constraints

Revocation cannot be directly reinstated.

Expired certificates cannot remain current by omission of an expiry event; validation as-of time catches stale active records.

PR 30 attestations may be issued only from a current validated certified state.

## Evidence and references

The model implements the application/evaluation/remediation/decision/surveillance/renewal/suspension/revocation flow established by the E2EESA development plan.

## Reconsideration triggers

Re-open if an external conformity-assessment standard requires a materially different state or actor-separation model.
