# ADR-0044: Configuration interoperability does not imply wire interoperability

- **Status:** Accepted
- **Date:** 2026-10-08
- **Decision class:** Invariant
- **Affected components:** profile compatibility, interoperability testing, downstream integration
- **Security properties affected:** none directly; prevents misleading interoperability claims

## Context

Profiles can interact in several different senses.

Two profiles may coexist in one product configuration. One may require another. Two same-family profiles may be alternative architectures. Separately implemented endpoints may or may not be able to communicate over the same wire protocol.

Treating all of these as one "interoperable" boolean would overstate what the standard proves.

## Decision

PR 44 separates:

- configuration co-existence;
- exclusive-alternative boundaries;
- explicit incompatibility;
- dependency composition; and
- wire interoperability.

The complete PR 43 production-positive corpus is tested pairwise through PR 42.

Direct dependency edges are snapshotted as explicit composition contracts.

Wire interoperability is never inferred from co-configuration and requires a separately declared testable contract.

## Consequences

The suite can catch cross-profile configuration regressions without making unsupported protocol claims.

Transitive/contextual incompatibilities remain visible rather than being misrepresented as direct declarations.

The pair matrix is larger, but deterministic and machine-verifiable.

## Reconsideration triggers

Re-open if future profile metadata gains explicit standardized wire-interface identifiers sufficient to generate wire interoperability tests safely.
