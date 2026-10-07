# ADR-0017: Ciphertext-only infrastructure is a common invariant

- **Status:** Accepted for pre-1.0 development
- **Date:** 2026-10-07
- **Decision class:** Invariant
- **Affected components:** server trust policy, inventory and retention evidence
- **Security properties affected:** SP-CONFIDENTIALITY, SP-AUTHORIZATION-INTEGRITY, SP-METADATA-MINIMIZATION

## Context

Server disk encryption and a service KMS can otherwise be confused with E2EE.
The architecture needs an explicit boundary across all storage/processing paths.

## Serious alternatives considered

Server-side disk/KMS encryption protects some storage threats but permits operator
decryption. Confidential computing can reduce operator access while still
terminating content inside a service. Endpoint-only application encryption keeps
the service outside the content trust boundary.

## Decision

Require ciphertext-only infrastructure, separate service and E2EE keys,
exhaustive inventory, client-authorized recipients and bounded retention. A
plaintext-processing service must be separately authorized as an endpoint rather
than offered as a weaker option under the same invariant.

## Security consequences

Service credential compromise cannot recover E2EE content under the declared
boundary. Routing metadata, traffic analysis, malicious delivery and endpoint
compromise require separate controls. Purge does not mean recipient recall.

## Compatibility constraints

Composes with all supported pairwise/group/media architectures. Application keys
cannot be shared with service TLS, metadata storage or abuse-control purposes.

## Evidence and references

The normative specification references the repository's already established
identity, backup, attachment, storage, transport and client-security layers.
Fixtures include server key access, extra recipients and unpurged expired objects.

## Reconsideration triggers

New product classes, demonstrated key-access paths, or a need for a separately
versioned long-term encrypted archive retention policy.
