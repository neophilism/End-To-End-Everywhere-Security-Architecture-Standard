# ADR-0001: Profile resolution and exact version pinning

- **Status:** Accepted
- **Date:** 2026-10-06
- **Decision class:** Profile choice infrastructure
- **Affected components:** profiles, configuration, resolver, conformance tooling
- **Security properties affected:** downgrade resistance, configuration integrity, reproducibility of claims

## Context

E2EESA must support multiple serious architectures in disputed areas without allowing arbitrary combinations to silently weaken security.

The configuration mechanism therefore needs to balance flexibility with reproducibility and fail-closed behavior.

## Serious alternatives considered

### Free-form feature flags

Rejected. Independent booleans make it too easy to create combinations that were never analyzed together and are difficult to name, audit, reproduce, or certify.

### Floating profile references

Examples include "latest", branch names, or semantic-version ranges. Rejected for conformance configurations because identical configuration text could resolve to different security architecture at different times.

### Exact profile references with dependency resolution

Selected. The user chooses named, versioned architectures. Dependencies may be auto-added only when exact and declared, and the resolver reports every auto-added profile.

### One hard-coded architecture

Rejected as the general E2EESA model because serious expert disagreement exists in multiple domains. A specific downstream product may still intentionally select one profile.

## Decision

E2EESA configurations use exact profile references in the form `profile-id@version`.

Profiles belong to cardinality-constrained families.

The resolver recursively expands exact dependencies, rejects incompatibilities and version conflicts, validates lifecycle status, and emits the complete effective profile set.

Prohibited profiles cannot be enabled by configuration.

## Security consequences

Benefits:

- reproducible security architecture;
- explicit alternative selection;
- no silent upgrades;
- deterministic dependency expansion;
- machine-checkable incompatible combinations;
- clear certification scope.

Costs:

- upgrades require explicit configuration changes;
- catalogs must maintain precise dependency metadata;
- users cannot rely on convenient floating "latest secure" aliases for a conformance artifact.

## Compatibility constraints

A configuration is invalid if exact dependencies cannot be satisfied, more than one version of one profile is required, family cardinality is violated, or an incompatibility exists in the effective set.

## Evidence and references

This is an E2EESA architectural decision derived from the project's requirement to support multiple defensible architectures while preventing arbitrary insecure combinations. Later standards crosswalk work will attach external configuration and assurance references where applicable.

## Reconsideration triggers

Reconsider if:

- a later conformance model introduces cryptographically bound catalog manifests with safe immutable aliases;
- exact pinning prevents a necessary emergency-deprecation mechanism that cannot be handled by policy; or
- independent security review identifies a safer composition model.
