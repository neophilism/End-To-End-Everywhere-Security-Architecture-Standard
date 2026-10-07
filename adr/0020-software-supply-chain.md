# ADR-0020: Artifact expectations and independent reproduction

- **Status:** Accepted for pre-1.0 development
- **Date:** 2026-10-07
- **Decision class:** Invariant
- **Affected components:** supply-chain profiles, evidence and reference release builder
- **Security properties affected:** SP-SOFTWARE-INTEGRITY, SP-BUILD-PROVENANCE

## Context

Signed code can still be built from the wrong source or compromised dependencies.
Provenance must be checked against independent expectations and actual artifacts.

## Serious alternatives considered

Signing alone authenticates a signer without explaining inputs. SBOMs document
components without authenticating the build. SLSA provenance with expected-source
checking and independent reproduction combines distinct useful controls. SPDX
and CycloneDX remain supported interchange alternatives for equivalent inventories.

## Decision

Require complete immutable inputs, a validated artifact-bound SBOM, authenticated
SLSA Build provenance and independent byte reproduction. Add an actual offline
source-release builder and pin CI action revisions, while keeping cryptographic
signature and full format validation in authenticated assessor reports.

## Security consequences

Wrong-source, wrong-builder and wrong-subject records cannot satisfy the profile.
Reproduction detects differing builds but does not prove benign source. Signing
trust, builder assurance and Source/Build SLSA levels remain separate claims.

## Compatibility constraints

The provenance statement subset and local build type are exactly versioned.
Additional parameters/formats require review. A source-only SBOM does not cover
runtime/CI dependencies by implication. PR 20 update trust and PR 23 development
controls remain separately applicable.

## Evidence and references

SLSA 1.2, in-toto Statement v1, DSSE, SPDX 2.3 and CycloneDX 1.6. Fixtures model
their assessment contracts; reproduction tests exercise actual archive bytes.

## Reconsideration triggers

New approved provenance/format revisions, builder findings, or unsupported source
layouts/toolchains requiring a new deterministic-build contract.
