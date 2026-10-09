# Profile and Configuration Model

**Status:** Normative

This document defines how E2EESA represents, selects, composes, and validates alternative security architectures.

The purpose of the profile system is to support multiple serious implementation approaches without turning security into an unrestricted collection of feature flags.

## 1. Core rule

A conformant E2EESA configuration is the resolved result of:

1. an exact E2EESA standard version;
2. an exact profile catalog associated with that standard version;
3. an explicit set of requested, version-pinned profiles;
4. deterministic dependency expansion;
5. lifecycle-status policy; and
6. compatibility and cardinality validation.

A configuration MUST NOT be considered conformant merely because every selected component is individually recognized.

## 2. Exact profile references

Profiles are referenced as:

`profile-id@major.minor.patch`

Profile version ranges, floating tags, "latest", branch names, and implicit upgrades MUST NOT be used in a conformance configuration.

A change to a selected profile version is a configuration change and MUST be re-resolved and re-evaluated.

## 3. Profile families

Every profile belongs to exactly one profile family.

A family represents one architectural decision domain or independently selectable capability domain.

Each family declares one of four cardinalities:

- **exactly-one** — exactly one profile in the family MUST be present in the effective configuration;
- **at-most-one** — zero or one profile in the family MAY be present;
- **one-or-more** — at least one profile in the family MUST be present;
- **many** — zero or more profiles in the family MAY be present.

Profiles from different families MAY coexist unless a dependency or incompatibility rule says otherwise.

## 4. Requested and effective profiles

The **requested profile set** is the exact set named by the configuration author.

The **effective profile set** is the requested set plus all recursively required profiles.

Dependency expansion MUST be deterministic.

Any automatically added dependency MUST be visible in resolution output. Hidden dependency selection is prohibited.

## 5. Dependencies

A profile MAY require one or more exact profile references.

When a selected profile requires another profile, the resolver MUST include that required profile in the effective set.

A missing required profile is a resolution failure.

Dependency cycles MAY exist only when every member of the cycle is mutually satisfiable and exact-version pinned. The resolver MUST terminate safely and MUST NOT duplicate profiles.

## 6. Incompatibilities

A profile MAY declare exact profile references with which it is incompatible.

Incompatibility is semantically symmetric: if either selected profile declares the other incompatible, the pair MUST NOT coexist in the effective configuration.

The catalog is not required to duplicate the declaration in both directions.

## 7. Lifecycle status

Profile lifecycle statuses have the following configuration semantics in this PR:

- **recommended** — permitted by default for new configurations;
- **allowed** — permitted by default;
- **provisional** — requires explicit opt-in;
- **experimental** — requires explicit opt-in and MUST NOT be represented as production-recommended;
- **legacy** — requires explicit opt-in and exists only for compatibility or migration;
- **deprecated** — requires explicit opt-in and SHOULD trigger a migration warning;
- **prohibited** — MUST NOT appear in an effective conformant configuration under any opt-in.

A configuration MAY explicitly accept any subset of `provisional`, `experimental`, `legacy`, and `deprecated`.

A configuration MUST NOT be able to opt into `prohibited`.

## 8. Security properties

Each profile declares the registered security properties that it is designed to provide or participate in providing.

The union of profile property IDs in the effective set is informational at this stage. It MUST NOT by itself be interpreted as proof that the resolved product provides those properties.

Security-property claims remain subject to the scoped claim model and later assurance requirements.

## 9. Closed-world resolution

Resolution is closed-world.

Every requested profile, dependency, incompatibility reference, property reference, and family reference MUST exist in the catalog used for resolution.

Unknown references MUST fail closed.

## 10. Family cardinality

Cardinality is evaluated after dependency expansion.

A dependency MAY cause a family to become populated.

If the effective set violates a family cardinality, resolution MUST fail.

This means a required `exactly-one` family cannot be satisfied by omitting the decision, and an `at-most-one` family cannot be satisfied by selecting two alternatives.

## 11. Multiple versions of one profile

The effective configuration MUST NOT contain more than one version of the same `profile_id`.

If dependencies require conflicting exact versions of the same profile, resolution MUST fail rather than choosing one.

## 12. Configuration immutability

A configuration suitable for conformance evaluation MUST identify its standard version and exact requested profile references.

Resolution output SHOULD be retained with the evaluated artifact so the exact effective profile set can be reconstructed.

## 13. Determinism

Given identical:

- standard version;
- catalog contents; and
- configuration contents,

a conforming resolver MUST produce the same effective profile set, warnings, and validation outcome.

Effective profile references MUST be emitted in stable lexical order when serialized by the reference resolver.

## 14. Fail-closed behavior

The resolver MUST fail on:

- unknown profiles;
- unknown families;
- unknown security properties;
- malformed or non-exact profile references;
- mismatched standard versions;
- prohibited profiles;
- nondefault lifecycle statuses lacking explicit opt-in;
- unresolved dependencies;
- incompatible effective profiles;
- conflicting versions of the same profile;
- family-cardinality violations; or
- malformed configuration fields.

The resolver MUST NOT silently repair an invalid configuration by selecting a different architecture.

## 15. Multi-option architecture rule

Where E2EESA later recognizes multiple serious approaches to a disputed architectural question, those approaches SHOULD normally be represented as distinct profiles in a common family.

The resolver provides the mechanism to select among them safely.

It does not establish that every conceivable implementation is acceptable, and it does not permit a configuration author to disable E2EESA invariants.

## Typed and scoped dependency contracts

Production profiles MAY declare `dependency_rules`. Each rule binds a requirement identifier, `same-component` or `same-flow` scope, and a typed `all_of` / `any_of` tree of exact `profile_ref` or `family_id` leaves. These rules are authoritative. A prose drift check is supplementary. The resolver rejects missing alternatives; the solver enumerates them without silently selecting a weaker replacement. Family cardinality is unchanged and applies within the component scope.

Active assessments MUST check each consuming flow. Profiles in an unrelated component or flow cannot satisfy a key-delivery dependency. A reusable library's host obligation names the exact consuming flow, host component/flow, requirement, and source/build-bound integration evidence. Recipient and key-authority boundaries must agree; declaration validity alone does not establish runtime integration.
