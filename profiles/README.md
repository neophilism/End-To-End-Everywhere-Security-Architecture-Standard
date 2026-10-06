# Profiles

Profiles represent named, versioned implementation choices that satisfy E2EESA security invariants.

A profile is not an arbitrary bag of switches. A profile:

- has a stable identifier and exact version;
- belongs to exactly one profile family;
- declares its lifecycle status;
- declares the registered security properties it participates in providing;
- declares exact-version dependencies and incompatibilities; and
- may be selected only when the complete resolved configuration is valid.

Profile references use the form `profile-id@major.minor.patch`.

## Families

A family defines the cardinality of an architectural decision domain:

- `exactly-one`
- `at-most-one`
- `one-or-more`
- `many`

This is the mechanism used later to represent multiple serious solutions to disputed architecture questions.

## Lifecycle statuses

- `recommended` — allowed by default for new configurations
- `allowed` — allowed by default
- `provisional` — explicit opt-in required
- `experimental` — explicit opt-in required and not production-recommended
- `legacy` — explicit opt-in required for compatibility/migration
- `deprecated` — explicit opt-in required and migration warning expected
- `prohibited` — never selectable by a conformant configuration

## Resolution

The profile engine expands exact dependencies, reports auto-added profiles, rejects unknown references, checks incompatible pairs, prevents multiple versions of the same profile, enforces family cardinality, and rejects lifecycle states that are not permitted by the configuration.

See `spec/profile-configuration.md` for normative rules.
