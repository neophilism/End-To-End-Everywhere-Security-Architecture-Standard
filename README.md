# End To End Everywhere Security Architecture Standard (E2EESA)

**Original 50-milestone development plan:** [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md). **Separate corrected audit remediation:** [docs/AUDIT_REMEDIATION_PLAN.md](docs/AUDIT_REMEDIATION_PLAN.md).

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

Development toward `0.9.0-rc.2` is addressing Audit v2. The original `0.9.0-rc.1` bytes and manifest remain archived and verified on every check. The current development tree is not a frozen candidate or a production certification basis. Legacy evaluator passes establish configuration consistency only. Independent expert review and the 1.0 decision remain separate gates.

The ordered work and evidence states are in `registry/audit-remediation.json`. Downstream adoption follows the corrected component and data-flow contracts.
