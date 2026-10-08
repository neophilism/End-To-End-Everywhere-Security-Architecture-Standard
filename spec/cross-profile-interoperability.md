# Cross-Profile Interoperability Suite

**Status:** Normative test contract. **Version:** 0.1.0. **Milestone:** PR 44.

PR 44 verifies cross-profile compatibility boundaries across the PR 43 production fixture corpus.

It uses "interoperability" narrowly and explicitly.

A pair that can coexist in one E2EESA configuration is **co-configurable**. That does not automatically mean two independently implemented endpoints using different profiles speak the same wire protocol.

Wire interoperability MUST be declared by the profile specifications or a dedicated interface contract; it is never inferred from configuration compatibility.

## 1. Corpus

The suite consumes every PR 43 `production-positive` profile.

With the current catalog this is 63 profiles.

Every unordered pair is evaluated exactly once, giving `n(n-1)/2` pair cases.

Lifecycle-negative PR 43 fixtures are not treated as production interoperability candidates.

## 2. Pair evaluation

For a pair `A, B`, the suite builds a PR 42 production-mode request that pins both exact profile refs and enforces PR 38 Required promotions.

The pair solver result is the authoritative configuration-compatibility observation.

A pair is co-configurable only when PR 42 returns at least one exhaustive solution containing both exact refs.

Search-limit results fail the interoperability suite; they are not interpreted as incompatibility.

## 3. Relationship classes

### Co-configurable

The two exact profiles can participate in at least one common valid production configuration.

### Exclusive alternative

The profiles occupy the same `exactly-one` or `at-most-one` family.

Distinct alternatives in such a family MUST NOT be co-configurable.

This says nothing by itself about whether separate endpoints could negotiate between them.

### Explicitly incompatible

One profile directly lists the other in `incompatible_profile_refs`.

The pair MUST NOT be co-configurable.

### Dependency-compatible

One profile directly requires the other.

The pair MUST be co-configurable.

A production-positive consumer that cannot compose with its own declared dependency is a standards defect.

### Contextually incompatible

The pair has no direct incompatibility declaration and is not an exclusive-family pair, but no common configuration exists after transitive dependencies, family cardinality and other constraints are applied.

This result is recorded rather than rewritten as a fake direct incompatibility.

## 4. Declared dependency contracts

PR 44 maintains a static dependency-contract manifest for every direct production-to-production `requires_profile_refs` edge.

Each contract records:

- contract ID;
- consumer exact profile ref;
- provider exact profile ref;
- interface kind; and
- expected relationship `co-configurable`.

The manifest intentionally snapshots the catalog. Adding/removing a direct dependency requires an explicit interoperability-contract update.

## 5. Interface kinds

### Runtime profile composition

A runtime protocol/profile directly consumes another profile.

The current example is SFrame media using the MLS group profile for key management.

### Assurance/evidence composition

An assurance profile composes verification, secure-development, supply-chain or formal-verification profiles.

This is an evidence/assurance interface, not a network protocol.

### Resolver composition

A profile dependency exists primarily to exercise or specify configuration composition.

## 6. Wire interoperability

The suite MUST NOT claim wire interoperability merely because:

- two profiles are co-configurable;
- two profiles share security properties;
- two profiles are in the same family;
- one profile requires another; or
- both reference the same primitive.

A future explicit wire contract must identify:

- protocol/specification;
- exact sending profile(s);
- exact receiving profile(s);
- version/negotiation rules;
- required test vectors or implementation evidence; and
- expected success/failure cases.

PR 44 has no blanket wire-interoperability inference.

## 7. Pair invariants

The suite fails if:

- an exclusive-alternative pair becomes co-configurable;
- an explicitly incompatible pair becomes co-configurable;
- a direct dependency pair is not co-configurable;
- a co-configurable solution omits either target;
- a co-configurable solution fails PR 2 re-resolution;
- a pair search is non-exhaustive;
- pair classification is not symmetric;
- a production-positive profile is missing from the corpus;
- a direct dependency is missing from the static contract manifest; or
- the manifest contains a stale dependency contract.

## 8. Full matrix report

The suite emits a deterministic content-addressed report containing:

- production profile count;
- unordered pair count;
- co-configurable count;
- exclusive-alternative count;
- explicitly-incompatible count;
- dependency-compatible count;
- contextually-incompatible count;
- declared dependency-contract count;
- search states examined;
- per-pair records/digests;
- normalized errors; and
- report digest.

Relationship counts use one primary classification per pair with priority:

1. explicit incompatibility;
2. exclusive alternative;
3. direct dependency;
4. co-configurable;
5. contextual incompatibility.

The raw pair record also retains all applicable structural flags.

## 9. No "best profile" inference

Interoperability results do not rank alternatives.

A pair being co-configurable does not make either profile preferable.

An exclusive pair remains a caller-visible architecture choice under PR 42.

## 10. PR 43 integration

PR 44 consumes the PR 43 manifest rather than independently deciding which lifecycle states are production-supported.

A catalog lifecycle change therefore flows through PR 43 coverage first and then into PR 44.

## 11. Fail closed on basis drift

The suite binds exact digests for:

- profile catalog;
- PR 43 fixture manifest;
- PR 42 solver registry;
- security-property registry;
- PR 38 promotion registry; and
- PR 40 conformance registry.

Changed basis produces a different report digest.

## 12. References

PR 44 composes:

- PR 2 profile/configuration resolution;
- PR 42 compatibility solving;
- PR 43 reference-fixture lifecycle corpus.

PR 45 defines downstream six-project integration contracts; those are separate from profile-to-profile compatibility.
