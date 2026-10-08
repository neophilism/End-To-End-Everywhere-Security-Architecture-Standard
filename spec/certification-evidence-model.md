# Certification Evidence Model

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 28.

This document defines the evidence bundle that a later Open E2EE Verified certification decision consumes.

The bundle is content-addressed, exact-scope, and evidence-oriented. It does not itself issue a certificate.

## 1. Exact certification subject

Every certification evidence bundle MUST bind:

- product ID;
- product version;
- platform;
- exact E2EESA configuration digest;
- exact resolved profile set;
- exact assurance-plan digest;
- exact source digest;
- exact assessed artifact digest; and
- bundle observation time.

A certification bundle for one product version/platform/configuration MUST NOT be silently reused for another.

## 2. Evidence manifest

Every evidence item has:

- unique evidence-item ID;
- evidence type;
- immutable SHA-256 digest;
- issuer ID and issuer role;
- assessor IDs when applicable;
- exact profile references in scope;
- property IDs in scope;
- threat IDs in scope;
- observed-at timestamp;
- report/reference locator; and
- disclosure/limitation text.

The evidence manifest is an index of evidence artifacts. A digest proves identity of the referenced bytes; it does not prove the truth of the artifact's claims.

## 3. Evidence types

The initial evidence-type registry includes:

- `architecture-configuration`;
- `security-claims`;
- `verification-policy`;
- `verification-evidence`;
- `formal-policy`;
- `formal-evidence`;
- `secure-development-policy`;
- `secure-development-evidence`;
- `supply-chain-policy`;
- `supply-chain-evidence`;
- `sbom`;
- `build-provenance`;
- `source-review-report`;
- `independent-audit-report`;
- `cryptographic-profile-report`;
- `threat-model-report`; and
- `exception-record`.

Later versions MAY add types without changing prior bundle semantics.

## 4. Assurance-level evidence floors

The bundle validator derives evidence floors from the PR 27 assurance level.

### A1

Requires:

- architecture configuration;
- security claims;
- verification policy;
- verification evidence;
- independent audit report;
- cryptographic profile report; and
- threat model report.

### A2 and above

Adds:

- secure-development policy/evidence;
- supply-chain policy/evidence;
- SBOM;
- build provenance; and
- source-review report.

A2+ requires non-`none` source access for the independent source-review scope.

### A3 and above

Adds formal policy/evidence for each derived symbolic formal requirement.

### A4 and above

Adds formal policy/evidence for each derived code/refinement requirement.

### A5

Adds formal policy/evidence for each derived computational requirement not explicitly exempted by the assurance plan.

These are minimum evidence categories. Certification policy MAY require more.

## 5. Source-access declaration

The bundle MUST declare one of:

- `full-source`;
- `restricted-review`;
- `escrowed-source`; or
- `none`.

A1 MAY use `none`.

A2–A5 MUST use a source-access mode other than `none` and MUST include source-review evidence.

Source access is evidence access, not an open-source requirement.

## 6. Claim-to-evidence matrix

Every claimed security property MUST have at least one claim-evidence record.

Each claim-evidence record binds:

- property ID;
- threat IDs;
- evidence-item IDs;
- limitations; and
- status.

Allowed statuses are:

- `supported`;
- `conditional`; and
- `not-supported`.

A claimed property in the assurance plan MUST NOT be represented only by `not-supported` records.

Evidence for one property MUST NOT be silently used as evidence for another property.

## 7. Independent assessor coverage

All independent assessor IDs named by the assurance plan MUST appear in at least one independent evidence item.

Evidence types `verification-evidence`, `formal-evidence`, `source-review-report`, and `independent-audit-report` that are used to satisfy independent assessment requirements MUST be issued by `independent-assessor`.

A vendor-authored artifact MAY be included as evidence but MUST NOT count as independent assessment.

## 8. Formal evidence linkage

For every formal requirement derived by PR 27, the bundle MUST contain:

- a `formal-policy` evidence item; and
- a `formal-evidence` evidence item

whose profile references cover the corresponding formal profile.

A single evidence artifact MAY cover multiple formal requirements when its scope genuinely covers all required properties and threats.

## 9. Artifact and source identity

All security-critical evidence that makes claims about implementation behavior MUST identify the assessed source and/or artifact scope.

The bundle-level source and artifact digests define the certification subject.

Evidence referencing a materially different source or artifact MUST NOT satisfy the bundle unless explicitly identified as supporting background evidence rather than assessed-subject evidence.

## 10. Exceptions

PR 28 does not permit a waiver of E2EESA `MUST` or `MUST NOT` requirements.

Exception records are limited to:

- documented deviations from `SHOULD` or `SHOULD NOT` requirements; or
- profile limitations that narrow the certification claim.

Every exception MUST include:

- exception ID;
- class;
- requirement/profile reference;
- rationale;
- security consequence;
- approving authority;
- issue date;
- expiration date; and
- remediation/migration plan.

The exception MUST expire. An expired exception invalidates the bundle until removed, renewed under later policy, or remediated.

## 11. Evidence freshness

Evidence items MUST NOT be dated after the bundle observation time.

Certification lifecycle policy may impose stricter maximum ages. PR 28 validates chronology and exact scope; PR 29 defines lifecycle surveillance and renewal.

## 12. Evidence completeness versus truth

Schema and semantic validation establish that required evidence exists and is consistently scoped.

They do not establish that:

- an audit was competently performed;
- a claimed proof is mathematically sound beyond the trusted checker;
- an assessor is actually independent;
- a source review inspected every relevant path; or
- no vulnerability exists.

Those are assurance and certification-review judgments.

## 13. Fail-closed semantics

The bundle validator MUST fail on:

- product/version/platform mismatch with the assurance plan;
- assurance-plan digest mismatch;
- configuration digest mismatch;
- effective-profile mismatch;
- source/artifact digest malformation;
- duplicate evidence IDs;
- unknown evidence types;
- missing assurance-level evidence categories;
- missing formal proof linkage;
- missing independent assessor coverage;
- source-access level below the assurance floor;
- claim-evidence gaps;
- claim references to unknown evidence items;
- invalid or expired exception records; or
- future-dated evidence.

## 14. Certification boundary

PR 28 creates an evidence package suitable for review.

PR 29 defines application, remediation, decision, surveillance, renewal, suspension and revocation.

PR 30 defines signed machine-readable certification attestations.
