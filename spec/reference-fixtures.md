# Reference Fixtures

**Status:** Normative coverage contract with informative generated examples. **Version:** 0.1.0. **Milestone:** PR 43.

PR 43 turns every profile in the E2EESA catalog into an executable reference case.

A fixture demonstrates lifecycle/configuration behavior. It is not, by itself, a security proof or certification.

## 1. Complete catalog coverage

The reference-fixture manifest MUST contain exactly one entry for every exact profile reference in the profile catalog.

Adding or removing a catalog profile therefore requires an intentional fixture-manifest update.

The manifest records:

- fixture ID;
- exact profile ref;
- family ID;
- current catalog lifecycle status;
- expected fixture disposition;
- solver mode; and
- expected PR 42 solver result status.

## 2. Positive fixture classes

### Production-positive

Every `recommended` and `allowed` profile receives a production-positive fixture.

The fixture pins the exact target profile in PR 42 production mode.

A valid fixture MUST:

- produce at least one solution;
- complete an exhaustive search within the reference search budget;
- contain the target profile in every returned/effective solution;
- re-resolve through PR 2; and
- preserve PR 42's no-ranking semantics.

### Candidate-positive

A `provisional` profile receives a Candidate-positive fixture only when the exact profile ref currently has PR 38 lifecycle state `candidate`.

The fixture runs in Candidate mode and must produce a solution containing the exact target.

### Migration-positive

A `legacy` or `deprecated` profile receives a migration-positive compatibility fixture.

This proves only that PR 42 can form a migration-mode configuration. It does not replace the PR 39 plan/case required for PR 40 migration-only conformance.

## 3. Negative lifecycle fixture classes

Profiles that must not be selectable for the corresponding ordinary use are represented explicitly.

### Unpromoted provisional

A provisional profile without exact PR 38 Candidate state MUST produce PR 42 `invalid-request` when pinned in Candidate mode.

### Experimental

An experimental profile MUST produce `invalid-request` when pinned by the reference solver.

Its presence in the standard remains research-only.

### Prohibited

A prohibited profile MUST produce `invalid-request` even in migration solver mode.

Historical processing of a prohibited cryptographic asset, where permitted, is governed by PR 39 and does not make a prohibited profile selectable.

## 4. Fixture request construction

Reference requests are deterministic.

Each request:

- pins exactly the target profile;
- uses no hidden preference or score;
- requests no unrelated security property;
- forbids no family;
- excludes no profile;
- enforces PR 38 Required promotions;
- uses the current catalog standard version; and
- permits up to the PR 42 maximum returned-solution count.

Exactly-one families and dependencies are supplied by the existing PR 42/PR 2 machinery.

## 5. Generated positive case

For a positive manifest entry, the reference generator selects the lexicographically first PR 42 solution after the solver has exhaustively enumerated and sorted all logical solutions.

"First" is a deterministic serialization choice only. It MUST NOT be described as safer, preferred or better than the other valid solutions.

The generated case records:

- manifest entry;
- canonical solver request;
- complete solver-result digest;
- selected reference solution; and
- case digest.

## 6. Generated negative case

For a negative manifest entry, the generated case records:

- manifest entry;
- canonical solver request;
- expected invalid-request result; and
- case digest.

A negative fixture passing means the prohibited/unpromoted lifecycle boundary was correctly enforced.

## 7. Coverage report

The reference-fixture validator emits a deterministic coverage report containing:

- catalog profile count;
- manifest entry count;
- production-positive count;
- Candidate-positive count;
- migration-positive count;
- negative lifecycle count;
- family coverage count;
- passed case count;
- failed case count;
- normalized errors; and
- report digest.

A complete PR 43 repository has zero failed cases.

## 8. Family coverage

Every catalog family that contains a production-eligible profile MUST have at least one positive fixture.

A family containing only non-production lifecycle states remains covered by its negative fixture(s).

## 9. Profile dependencies and incompatibilities

Fixtures do not hard-code dependency expansion.

PR 42 invokes the PR 2 resolver, which remains authoritative for:

- required-profile expansion;
- incompatibilities;
- exact version pinning;
- family cardinality; and
- lifecycle opt-in.

This ensures fixture behavior cannot drift from the standard resolver.

## 10. Required promotions

Reference requests set `enforce_required_promotions=true`.

If a future Required profile makes another profile's reference case impossible, the fixture fails and forces an intentional standards decision instead of silently dropping the Required state.

## 11. No hidden conformance claim

A positive reference fixture establishes only that a catalog option can participate in at least one compatible configuration under its lifecycle mode.

It does not establish:

- PR 40 production conformance;
- complete product scope;
- independent assurance;
- certification; or
- a recommendation among competing profiles.

## 12. Determinism and integrity

Manifest validation and case generation are deterministic for the exact:

- profile catalog;
- security-property registry;
- PR 38 promotion registry;
- PR 40 conformance registry; and
- PR 42 solver registry.

Generated cases and reports are content-addressed with canonical SHA-256 digests.

## 13. Fail-closed conditions

PR 43 fails on:

- catalog profile missing from manifest;
- extra/stale manifest profile;
- duplicate fixture/profile entry;
- manifest family/status mismatch;
- lifecycle disposition mismatch;
- positive fixture with no solution;
- positive target absent from a returned solution;
- positive search-limit result;
- negative fixture unexpectedly becoming selectable;
- generated solution failing PR 2 re-resolution;
- production-eligible family lacking positive fixture; or
- case/report digest mismatch.

## 14. References

PR 43 composes:

- PR 2 Profile and Configuration Model;
- PR 38 Candidate/Required lifecycle state;
- PR 42 Compatibility and Configuration Solver.

PR 44 uses these fixtures as the corpus for cross-profile interoperability testing.
