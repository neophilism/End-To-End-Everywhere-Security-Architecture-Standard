# Research → Production Promotion Gates

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 38. **Decision class:** ⚖️ multi-option.

PR 38 is the sole E2EESA 0.1 path for promoting PR 37 research toward production status.

The lifecycle is:

`Experimental → Candidate → Recommended → Required`

Promotion is evidence-driven, sequential, append-only, and independently reviewable. No research entry can promote itself merely by changing a status field.

## 1. State semantics

### Experimental

The authoritative object is a valid PR 37 research entry.

It remains:

- `lifecycle_status = experimental`;
- `production_selectable = false`.

### Candidate

A Candidate has passed the Candidate gate and may enter the production profile catalog only as:

- profile status `provisional`; and
- non-experimental decision class.

The existing profile resolver therefore requires explicit opt-in before Candidate use.

Candidate is not the E2EESA default.

### Recommended

A Recommended promotion has passed a selected Recommended evidence path.

Its production catalog profile has status `recommended`.

### Required

A Required promotion has passed a selected Required evidence path.

The production catalog profile remains `recommended`; E2EESA records the stronger `required` lifecycle state separately rather than overloading profile status.

PR 40 Conformance Engine consumes Required-state records and enforces them when the corresponding family is in scope.

## 2. Sequential promotion

Allowed transitions are only:

- `experimental → candidate`;
- `candidate → recommended`;
- `recommended → required`.

Skipping a state is prohibited.

A later deprecation, emergency retirement, or migration is governed by PR 39, not by reversing PR 38 promotion.

## 3. Common invariants

Every promotion request MUST:

- bind one exact PR 37 entry ID/version/digest;
- validate that PR 37 entry against the current research registry;
- bind the exact predecessor promotion record when the source state is Candidate or Recommended;
- bind one proposed production profile;
- make the proposed profile target match the research target family/profile/version;
- reconcile every surviving `EXP-TM-*`, `EXP-SP-*`, and `EXP-COMP-*` identifier;
- preserve negative, refuted, inconclusive, and error research results rather than deleting them;
- contain no unresolved blocker or critical finding;
- contain no unresolved promotion-critical hypothesis;
- provide immutable promotion evidence;
- satisfy one registered gate profile for the target state;
- satisfy decision quorum/independence requirements; and
- produce a deterministic promotion-record digest.

## 4. Experimental identifier reconciliation

Every experimental threat/property/component from the source research entry MUST have one reconciliation disposition:

- `promoted` — mapped to an exact production registry ID;
- `retired` — no longer used by the proposed production profile, with rationale; or
- `superseded` — replaced by an exact production registry ID, with rationale.

A disposition may not map an experimental concept to an unknown production ID.

No `EXP-*` identifier may appear in a Candidate/Recommended/Required production profile.

If the research depends materially on an experimental concept that has not been reconciled, promotion fails.

## 5. Promotion-critical hypotheses

The request declares every source hypothesis as:

- `promotion-critical`; or
- `non-blocking`.

Every promotion-critical hypothesis MUST have at least one latest applicable experiment outcome of `supported`.

A `refuted`, `inconclusive`, or `error` latest outcome blocks promotion-critical status.

A non-blocking unresolved hypothesis requires an explicit rationale explaining why the proposed production security claims do not depend on it.

## 6. Findings

Promotion findings are:

- `blocker`;
- `critical`;
- `high`;
- `medium`;
- `low`; or
- `informational`.

Statuses are:

- `open`;
- `resolved`; and
- `accepted`.

Open blocker/critical findings always block promotion.

A blocker finding may never be risk-accepted.

Critical findings may be accepted only if the selected gate profile explicitly permits critical risk acceptance; E2EESA 0.1 built-in promotion profiles do not.

Open/accepted high findings are governed by the selected gate profile.

Every resolved or accepted finding binds immutable resolution/acceptance evidence.

## 7. Evidence model

Promotion evidence records are content-addressed and typed.

Supported evidence types include:

- `implementation-provenance`;
- `independent-security-review`;
- `independent-replication`;
- `interoperability`;
- `formal-verification`;
- `test-vector-verification`;
- `operational-deployment`;
- `public-review`;
- `recognized-external-standard`; and
- `benchmark-evaluation`.

Every evidence item records:

- evidence ID/type;
- evidence digest;
- reference;
- producer organization ID;
- whether producer is independent of the submitter;
- creation time; and
- typed evidence details.

Independence is counted by distinct external organization ID, not raw evidence-item count.

## 8. Candidate gate

E2EESA has one Candidate baseline because the purpose of Candidate is controlled production evaluation, not default recommendation.

Candidate requires, at minimum:

- all common invariants;
- one non-concept implementation;
- independently verified test-vector evidence;
- one independent security review;
- one independent external organization represented in promotion evidence;
- no open high-or-worse finding;
- no promotion-critical unresolved hypothesis;
- at least two approvers;
- at least one approver organization independent of the submitter.

Candidate produces a `provisional` catalog profile.

## 9. Recommended evidence paths

There is legitimate expert disagreement over how much weight should be placed on implementation diversity, formal analysis, or an already-completed external standards process.

E2EESA therefore implements all three serious Recommended paths.

### Implementation-led

Requires:

- at least two non-concept implementations;
- at least two distinct implementation organizations;
- at least two independent security reviews;
- at least one independent replication;
- at least one interoperability evidence item;
- at least one operational-deployment evidence item;
- independently verified test vectors;
- at least 30 calendar days of public review with disposition evidence;
- three approvers from at least two independent organizations.

### Formal-assurance-led

Requires:

- at least two non-concept implementations;
- at least two distinct implementation organizations;
- at least one independent security review;
- at least one independent replication;
- at least one interoperability evidence item;
- at least one formal-verification evidence item covering every declared critical property/claim;
- independently verified test vectors;
- at least 30 calendar days of public review;
- three approvers from at least two independent organizations.

Formal verification supplements rather than replaces implementation/interoperability evidence.

### External-standard-led

Requires:

- a final recognized external standard tied to the same design/profile semantics;
- at least two non-concept implementations;
- at least two distinct implementation organizations;
- at least one independent security review;
- at least one interoperability evidence item;
- independently verified test vectors;
- three approvers from at least two independent organizations.

The external-standard evidence must identify the standards body, final designation/version, immutable specification digest, and reference.

## 10. Required evidence paths

Required means E2EESA intends the profile to become mandatory when its family is in scope. This bar is deliberately higher.

### Operational-maturity

Requires:

- prior Recommended state for at least 180 days;
- at least three non-concept implementations from three distinct organizations;
- at least two independent security reviews;
- at least two independent replications;
- at least two interoperability evidence items;
- at least three operational deployments from three distinct organizations;
- independently verified test vectors;
- four approvers from at least three independent organizations.

### Standards-and-deployment

Requires:

- prior Recommended state for at least 90 days;
- a final recognized external standard;
- at least three non-concept implementations from three distinct organizations;
- at least two independent security reviews;
- at least two interoperability evidence items;
- at least two operational deployments from two distinct organizations;
- independently verified test vectors;
- four approvers from at least three independent organizations.

Neither Required path allows open or accepted high-or-worse findings.

## 11. Public review evidence

Public-review evidence records:

- review start;
- review end;
- public review reference;
- comment/disposition digest; and
- disposition reference.

Duration is calculated in calendar days from the recorded UTC timestamps.

A public review with no immutable disposition record does not satisfy a gate.

## 12. Implementations and organization independence

Implementation evidence is derived from the PR 37 implementation registry plus promotion evidence.

A distinct implementation organization must be identifiable.

Two forks built by the same organization do not satisfy a two-independent-organization gate.

A research implementation with `production_use_prohibited=true` does not itself become production-approved; promotion produces a separate production profile decision.

## 13. Decision and approval

A promotion decision is:

- `pending`;
- `approved`; or
- `rejected`.

An approved decision records:

- approver ID;
- organization ID;
- role;
- approval time;
- detached approval/signature evidence digest; and
- reference.

The engine validates quorum and organization independence.

Cryptographic signature verification itself is delegated to an external verifier; PR 38 validates the immutable approval evidence record.

A request that does not satisfy its selected gate cannot be approved.

## 14. Catalog projection

A successful Candidate or Recommended/Required promotion produces a deterministic catalog profile projection.

Candidate projection:

- profile status `provisional`.

Recommended/Required projection:

- profile status `recommended`.

The projected profile MUST pass the existing production catalog validator when applied to the target catalog.

A new family may be proposed only by including a complete family definition that passes the production catalog constraints.

## 15. Promotion state registry

The promotion state registry is separate from the profile catalog and records:

- exact production profile ref;
- research entry digest;
- current lifecycle state;
- current promotion record digest;
- effective time; and
- selected gate profile.

This preserves the stronger `required` state without changing existing profile-status semantics.

## 16. Fail-closed behavior

Validation fails on:

- invalid or substituted research-entry digest;
- skipped lifecycle state;
- wrong predecessor promotion record;
- target profile/family/version mismatch;
- unreconciled experimental identifiers;
- promotion-critical hypothesis lacking supported evidence;
- missing/forged evidence links;
- same-organization evidence counted as independent;
- unmet selected gate thresholds;
- unresolved blocker/critical findings;
- disallowed high findings;
- inadequate public-review duration/disposition;
- incorrect final-standard evidence;
- insufficient approver quorum/independence;
- wrong catalog profile status for lifecycle state;
- catalog projection that violates existing profile constraints;
- promotion-record digest mismatch; or
- promotion-state registry mismatch.

## 17. Standards/process grounding

E2EESA follows the mature-process principles that production standards should be stable, technically competent, independently reviewed, interoperably implemented, and informed by operational experience.

The built-in gate profiles intentionally preserve multiple serious evidence paths rather than asserting that implementation count, formal analysis, and external standardization are interchangeable.

## 18. References

- PR 37 Research Profile Registry.
- RFC 2026 Internet Standards Process principles.
- NIST public cryptographic-evaluation/standardization process.
- PR 25 Security Verification Framework.
- PR 26 Formal Verification Profiles.
- PR 34 Observatory Evidence Model.
- PR 40 Conformance Engine (consumer of Required state).
