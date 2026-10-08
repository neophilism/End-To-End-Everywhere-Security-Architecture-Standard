# End To End Everywhere Security Architecture Standard (E2EESA)

E2EESA is the upstream, implementation-neutral security architecture standard for End To End Everywhere technical projects.

The standard separates:

- **security invariants** that compliant implementations cannot disable;
- **versioned profiles** for areas where multiple serious architectures are defensible;
- **capabilities** that apply only to some product classes; and
- **experimental profiles** that are not production recommendations.

## Repository layout

- `spec/` — normative and informative specification material
- `schemas/` — machine-readable configuration/evidence schemas
- `registry/` — machine-readable standard terminology and future registries
- `profiles/` — versioned standard profiles
- `fixtures/` — valid and invalid conformance examples
- `adr/` — architecture decision records
- `scripts/` — repository validation tooling
- `tests/` — validation tests

## Normative foundation

E2EESA defines its requirement language in `spec/normative-language.md` and its core vocabulary in `spec/terminology.md`. Implementations and later profiles must use those definitions consistently rather than silently redefining security terms.

## Development rule

Security-sensitive changes are made through reviewed pull requests. Controversial choices are represented as explicit profiles rather than hidden implementation defaults.

## Current status

E2EESA 0.9 release candidate (`0.9.0-rc.1`). The candidate is frozen for independent expert review before the 1.0 decision. No profile in this repository should yet be interpreted as an End To End Everywhere certification claim.
