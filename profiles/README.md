# Profiles

Profiles represent named, versioned implementation choices that satisfy E2EESA security invariants.

A profile is not an arbitrary bag of switches. A profile:

- has a stable identifier and explicit version;
- declares its lifecycle status;
- declares the security properties it provides;
- declares compatibility and incompatibility constraints;
- references mechanisms through registries rather than embedding undocumented magic values; and
- may be selected only when all required invariants remain satisfied.

Lifecycle statuses are initially:

- `recommended`
- `allowed`
- `legacy`
- `deprecated`
- `prohibited`
- `provisional`
- `experimental`

The exact normative semantics of these statuses will be defined in later PRs.
