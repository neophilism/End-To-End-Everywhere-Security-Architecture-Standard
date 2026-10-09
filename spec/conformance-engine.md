# Conformance Engine

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 40. **Decision class:** ⚖️ multi-option claim scope.

PR 40 composes the previously independent E2EESA validators into one deterministic product/configuration conformance decision.

A profile resolver success alone is not a conformance claim.

A conformance evaluation binds the exact product, platform, configuration, source, artifact, assurance plan, certification evidence bundle, standards registries, scope declaration, and—when applicable—research-promotion or migration state used to reach the verdict.

## 1. Verdicts

The engine produces exactly one verdict:

- `pass`;
- `fail`; or
- `indeterminate`.

### Pass

Every requirement for the selected conformance policy is satisfied and all required security-property claims are supported.

### Fail

At least one normative conformance requirement is violated, required evidence is invalid/missing, a required claim is explicitly not supported, or an input binding is inconsistent.

### Indeterminate

The evaluation inputs are structurally valid and no explicit failure is established, but one or more required security-property claims are conditional.

Indeterminate MUST NOT be represented as conformance.

## 2. Claim scopes

There is no single honest claim label for normal production, Candidate evaluation and retirement/migration activity. E2EESA therefore supports three explicit policies.

### Production conformance

`conformance-production@0.1.0`

- allowed profile statuses: `recommended`, `allowed`;
- configuration must not accept non-default lifecycle statuses;
- PR 38 Required profiles are enforced when their family is in scope;
- full in-scope security-property evidence is required;
- migration context is prohibited;
- a passing result is eligible to support a production conformance/certification claim.

### Candidate evaluation

`conformance-candidate-evaluation@0.1.0`

- allowed profile statuses: `recommended`, `allowed`, `provisional`;
- configuration may accept only `provisional`;
- every effective provisional profile must be an exact PR 38 Candidate profile;
- PR 38 Required profiles are still enforced when their family is in scope;
- full in-scope security-property evidence is required;
- migration context is prohibited;
- a passing result means only that the Candidate evaluation configuration meets its declared evaluation requirements;
- it is **not** eligible to be labeled production conformance.

### Migration-only conformance

`conformance-migration-only@0.1.0`

- allowed profile statuses: `recommended`, `allowed`, `legacy`, `deprecated`;
- configuration may accept only `legacy` and/or `deprecated`;
- an exact PR 39 migration plan and case are mandatory;
- the request binds the product's affected-asset usage evidence;
- the requested operation must be permitted by PR 39 at the evaluation time;
- only `historical-read-verify` or `migration-transform` operations are allowed;
- a passing result is a migration/archival-operation result, not a production conformance claim.

Experimental and prohibited profiles can never receive a PR 40 passing verdict.

## 3. Exact evaluation basis

Every request binds canonical SHA-256 digests for:

- profile catalog;
- cryptographic algorithm/suite registry;
- security-property registry;
- threat-model registry;
- assurance-level registry;
- certification-evidence registry;
- research-promotion registry;
- deprecation/migration registry;
- assurance plan; and
- certification evidence bundle.

The engine recomputes every supplied digest.

An evaluator can therefore reproduce which standards universe and which product evidence was evaluated.

## 4. Product/configuration identity

The request product ID, version and platform MUST exactly match:

- the assurance plan; and
- the certification evidence bundle.

The request source/artifact digests MUST exactly match the certification bundle.

The request configuration digest MUST equal the canonical digest of the assurance plan's configuration and the certification bundle's configuration digest.

The certification bundle must bind the exact assurance-plan digest.

## 5. Family scope declaration

Every catalog family MUST appear exactly once in `family_scope` as:

- `in-scope`; or
- `not-applicable`.

A not-applicable family requires a rationale.

The declaration is complete, so an evaluator cannot hide an inconvenient family by omitting it.

The following rules apply:

- every `exactly-one` family is in scope;
- every family represented by an effective profile is in scope;
- every in-scope family has at least one effective profile;
- an effective profile in a not-applicable family is a failure.

A product may legitimately mark a capability family not applicable when the product does not implement that capability, but the rationale remains part of the audit record.

## 6. Effective profile set

The engine resolves the assurance-plan configuration using the existing PR 2 profile resolver.

It then requires:

- exact equality between resolved profiles and the certification bundle's effective profiles;
- no effective profile with a status outside the selected conformance policy;
- no prohibited profile under any policy;
- no experimental profile under any policy.

Production conformance rejects even explicitly accepted provisional/legacy/deprecated statuses.

## 7. Required promoted profiles

PR 38 records Required lifecycle state separately from profile status.

For every `required` promoted profile:

1. the profile reference must exist in the evaluated catalog;
2. the promotion-state family is determined from that exact profile; and
3. if the family is in scope, that exact required profile MUST appear in the effective configuration.

A family marked not applicable is not forced into scope merely because it has a Required profile.

If two Required profiles make an at-most-one/exactly-one family impossible to satisfy, conformance fails rather than choosing one silently.

## 8. Candidate binding

Under Candidate evaluation, every effective `provisional` profile MUST have a PR 38 promotion-state record with:

- the same exact profile ref; and
- lifecycle state `candidate`.

A generic provisional profile that did not pass PR 38 Candidate gates cannot use the Candidate conformance policy.

A PR 38 Recommended/Required profile should already be represented in the production catalog as `recommended`; a provisional status mismatch fails.

## 9. Full property coverage

PR 40 distinguishes evidence/assurance mechanism families from architecture/control families.

Evidence-only families are declared in the conformance registry.

Required security properties are the union of `security_properties` from every effective in-scope profile whose family is not evidence-only.

Every required property MUST:

- appear in the assurance plan's `claimed_property_ids`;
- have valid certification evidence under the existing PR 28 validator; and
- have at least one claim-evidence record.

For a production or Candidate pass, each required property must have at least one `supported` claim and no `conditional` or `not-supported` claim.

A conditional required property yields `indeterminate`.

A not-supported required property yields `fail`.

This prevents conformance to a profile while evaluating only a convenient subset of the profile's promised properties.

## 10. Existing assurance/certification validation is authoritative

PR 40 composes, rather than reimplements:

- PR 2 profile configuration resolution;
- PR 27 assurance-level plan evaluation;
- PR 28 certification-evidence bundle validation;
- PR 25/26 verification/formal-evidence requirements as reached through assurance/certification.

Any error from an underlying validator is a conformance failure.

PR 40 additionally verifies scope, lifecycle and complete-claim semantics above those lower-level validators.

## 11. Evidence time

The certification bundle observation time MUST NOT be after the conformance evaluation time.

Subsystem-specific evidence freshness rules remain authoritative.

PR 40 does not invent one universal maximum evidence age that would be inappropriate across all assurance methods.

## 12. Migration-only binding

A migration-only request binds:

- exact PR 39 plan digest;
- exact PR 39 case digest;
- requested operation;
- historical material creation time when required;
- immutable evidence that this product/configuration actually uses the affected asset; and
- usage reference.

The PR 39 plan and case must validate at the conformance evaluation time.

The operation must return allowed from the PR 39 operation decision.

A migration-only pass cannot be converted into a normal production conformance claim.

## 13. Exceptions

PR 28 exceptions remain restricted to SHOULD/SHOULD-NOT/profile-limitation requirements.

PR 40 never uses an exception to waive:

- profile resolver errors;
- Required-profile enforcement;
- prohibited/experimental lifecycle state;
- exact evidence/digest binding;
- missing in-scope family selection;
- required property coverage;
- PR 39 migration-operation restrictions; or
- any MUST/MUST-NOT rule.

## 14. Deterministic result

The result records:

- assessment ID;
- policy/claim scope;
- verdict;
- production-certification eligibility;
- evaluated product identity;
- evaluation time;
- effective profile refs;
- in-scope family IDs;
- Required profile refs applied;
- required security-property IDs;
- conditional/not-supported property IDs;
- exact input digests;
- normalized reason records; and
- result digest.

For identical request and evaluation inputs, the logical result is deterministic.

## 15. Fail-closed conditions

Conformance fails on, among other things:

- mismatched product/version/platform;
- mismatched source/artifact/configuration;
- stale/future bundle observation;
- changed registry/input digest;
- incomplete family scope;
- selected profile in a not-applicable family;
- in-scope family with no effective profile;
- disallowed lifecycle status;
- Candidate profile without Candidate promotion state;
- missing Required promoted profile;
- invalid assurance plan;
- invalid certification bundle;
- missing promised property claim;
- explicitly unsupported promised property;
- invalid migration context/operation; or
- output digest mismatch during result verification.

Conditional promised properties yield indeterminate, never pass.

## 16. References

PR 40 composes the E2EESA profile, assurance, certification, research-promotion and deprecation/migration layers established by PRs 2, 27–28 and 38–39.

## Active component inventories

Active `0.2` assessments MUST classify components and data flows using `registry/product-classes.json`, with source/build-bound observations and completeness evidence appropriate to the assessment tier. The inventory is an assessment input, not its own completeness proof. A mandatory family cannot be waived by a rationale or an empty inventory contradicted by observed protected flows. Unknown classes or capabilities do not receive exemptions. A public website, endpoint, relay, and intentionally authorized processor may be separate components in one product.

A reusable protected-content component MAY declare explicit host obligations for the exact consuming flow; an unrelated service profile cannot discharge them. Offline vaults do not require a network solely to earn component conformance. Declared inventories without trusted assessment evidence remain unqualified for product claims.
