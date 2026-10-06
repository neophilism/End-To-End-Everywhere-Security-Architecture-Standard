# Contributing

E2EESA is a security standard. Changes must be reviewable, attributable, and explicit about security consequences.

## Pull requests

Every substantive pull request must:

1. state the security property or repository concern it changes;
2. identify affected profiles, schemas, fixtures, or normative text;
3. add or update validation/tests where behavior changes;
4. document disputed architectural choices in an ADR;
5. avoid introducing unreviewed cryptographic primitives.

## Normative language

The specification will use RFC 2119 / RFC 8174 style terms (`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, `MAY`) only when the requirement is intended to be normative.

## Multi-option decisions

When credible expert approaches differ, the repository should model each supported approach as a named, versioned profile or capability. Arbitrary combinations are not automatically valid; compatibility constraints must be explicit.

## Security changes

Do not weaken an invariant merely to preserve compatibility. If compatibility requires a weaker mode, it must be separately named and its assurance consequences documented.
