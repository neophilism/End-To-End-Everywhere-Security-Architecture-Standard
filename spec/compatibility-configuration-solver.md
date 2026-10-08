# Compatibility and Configuration Solver

**Status:** Normative solver contract. **Version:** 0.1.0. **Milestone:** PR 42. **Decision class:** ⚖️ multi-option.

PR 42 proposes profile configurations that are internally compatible with the E2EESA profile catalog and caller-declared requirements.

A solver result is **not** a conformance result.

PR 40 remains authoritative for final conformance evaluation.

## 1. Purpose

The standard intentionally preserves multiple serious architecture options where expert practice does not justify collapsing them into one universal choice.

The solver therefore exists to answer:

> Which exact profile configurations satisfy these explicit requirements without violating E2EESA dependencies, incompatibilities, lifecycle rules, family cardinality, Required promotion state, or requested security-property coverage?

It does not answer:

> Which architecture is universally best?

## 2. Solver modes

Three lifecycle modes are supported.

### Production

`production`

Eligible profile statuses:

- `recommended`;
- `allowed`.

No non-default lifecycle opt-in is emitted.

### Candidate

`candidate`

Eligible statuses:

- `recommended`;
- `allowed`;
- `provisional`.

A provisional profile is eligible only when the exact profile ref has PR 38 lifecycle state `candidate`.

The emitted configuration accepts only `provisional`.

### Migration

`migration`

Eligible statuses:

- `recommended`;
- `allowed`;
- `legacy`;
- `deprecated`.

The emitted configuration accepts `legacy` and `deprecated`.

A migration-mode proposal still requires PR 39 migration context before PR 40 migration-only conformance can pass.

Experimental and prohibited profiles are never solver-eligible.

## 3. Solver request

A request declares:

- solver request ID;
- standard version;
- mode;
- required family IDs;
- forbidden family IDs;
- desired security-property IDs;
- exact pinned profile refs;
- exact excluded profile refs;
- maximum returned solutions; and
- whether PR 38 Required profiles must be enforced.

The request does not contain subjective weights or a hidden score.

## 4. Mandatory families

Every `exactly-one` family is automatically required because any PR 40 family scope must keep such a family in scope.

Caller-required families are added to that set.

Pinned profiles also bring their families into scope.

Dependencies may bring additional families into the effective configuration.

## 5. Family selection

For an in-scope family:

- `exactly-one` → exactly one effective profile;
- `at-most-one` → exactly one when the caller requires the family;
- `one-or-more` → at least one;
- `many` → at least one.

For `many` and `one-or-more`, the solver may return multiple selected profiles when compatible.

The existing PR 2 resolver remains authoritative after every proposed selection.

## 6. Dependencies

A proposed selected set is always resolved through PR 2.

Dependencies are auto-added by the existing resolver.

The solver records:

- requested selections;
- effective selections;
- auto-added profile refs; and
- auto-added family IDs.

A forbidden family reached through a dependency makes that candidate invalid.

## 7. Incompatibilities and versions

The existing profile resolver remains authoritative for:

- exact version pinning;
- profile dependency expansion;
- profile incompatibility;
- same-profile multi-version rejection; and
- family cardinality.

PR 42 does not reimplement different compatibility semantics.

## 8. Required promotions

When `enforce_required_promotions=true`, every PR 38 `required` profile whose family becomes in scope must be effective.

The solver MAY auto-add that exact required profile.

If Required state creates an unsatisfiable cardinality or incompatibility conflict, the solver reports no valid solution for that branch rather than choosing a different profile.

## 9. Candidate promotion binding

In Candidate mode, every provisional profile must have exact PR 38 Candidate state.

A generic provisional catalog entry that has never passed Candidate gates is excluded.

Recommended/Required promoted profiles are expected to appear in the production catalog as `recommended` and are handled by their catalog status.

## 10. Desired security properties

Desired property IDs must exist in the security-property registry.

A solution satisfies a desired property only when an effective profile from a non-evidence-only family declares that property.

Evidence-only families are inherited from PR 40:

- assurance-level;
- security-verification;
- formal-verification.

Selecting proof/assurance machinery cannot manufacture an architecture property.

## 11. Pinning and exclusion

A pinned profile:

- must exist;
- must be lifecycle-eligible for the solver mode;
- must not be excluded;
- brings its family into scope.

An excluded profile can never be selected or auto-added.

If a dependency or Required promotion needs an excluded profile, that candidate is invalid.

## 12. Forbidden families

A forbidden family cannot appear in the effective configuration.

If a required profile, pinned profile, or dependency needs a forbidden family, the request is unsatisfiable.

Exactly-one families cannot be forbidden.

## 13. Enumeration

The reference solver enumerates compatible configurations deterministically.

It does not assign a security score.

Solutions are deduplicated by exact effective-profile set and sorted lexicographically by their exact profile refs.

This means two different requested selections that resolve to the same effective architecture are one logical solution.

## 14. Returned-solution limit

The request may limit the number of returned solutions.

The engine still counts the complete solution set within its search budget before slicing the returned list.

The result records:

- total solution count;
- returned solution count;
- whether the returned list is truncated;
- whether the search was exhaustive; and
- search states examined.

The solver MUST NOT label a partial search exhaustive.

## 15. Search budget

The registry defines a hard maximum number of search states for the reference solver.

If the budget is exceeded:

- `search_exhaustive=false`;
- the result status is `search-limit`; and
- any partial solutions are explicitly marked partial.

A search-limit result is not proof that no other compatible configuration exists.

## 16. Solution configuration

Each solution contains a ready-to-resolve configuration object:

- exact selected profile refs;
- standard version;
- accepted non-default statuses dictated by solver mode.

It also records:

- effective profiles;
- auto-added profiles;
- effective architecture property IDs;
- family scope implied by the effective profile set;
- auto-added family IDs; and
- solution digest.

A caller may turn the implied family scope into a complete PR 40 family-scope declaration by marking all remaining non-mandatory families not applicable with an appropriate product-specific rationale.

## 17. Diagnostics

Before combinatorial search, the solver reports deterministic request errors such as:

- unknown family/property/profile;
- pin/exclusion collision;
- prohibited or experimental pin;
- mode-ineligible pin;
- forbidden exactly-one family;
- required family with no eligible profiles;
- requested property unavailable from any eligible architecture profile.

When search is exhaustive but no solution exists, result status is `unsatisfiable`.

The solver may include normalized sample rejection reasons, but these are diagnostic only.

## 18. Result statuses

Result status is one of:

- `solutions`;
- `unsatisfiable`;
- `invalid-request`;
- `search-limit`.

Only `solutions` contains one or more compatible proposals.

## 19. No conformance inflation

A PR 42 solution MUST NOT be labeled:

- conformant;
- certified;
- certification-eligible; or
- secure merely because the solver found it.

The solution has only passed compatibility/configuration constraints.

The caller still needs PR 40 evidence, complete scope, property claims, and—where relevant—migration context.

## 20. Determinism

For the same:

- request;
- profile catalog;
- security-property registry;
- promotion registry; and
- conformance registry,

the logical result is deterministic.

The request and result are content-addressed by canonical SHA-256 digests.

## 21. References

PR 42 composes:

- PR 2 Profile and Configuration Model;
- PR 38 Required/Candidate promotion state;
- PR 40 evidence-only family semantics and final conformance boundary.
