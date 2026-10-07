# ADR-0016: Make client execution trust an explicit profile choice

- **Status:** Accepted for pre-1.0 development
- **Date:** 2026-10-07
- **Decision class:** Profile choice
- **Affected components:** client-security profiles, schemas and validator
- **Security properties affected:** SP-SOFTWARE-INTEGRITY, SP-DOWNGRADE-RESISTANCE

## Context

Encryption depends on the code running at its endpoints. Signed native releases,
ordinary web delivery and independently verified browser execution have different
trust boundaries that CSP or TLS cannot erase.

## Serious alternatives considered

Signed installed clients provide an artifact-bound execution root. Hardened web
delivery provides accessibility while retaining origin trust. An independently
installed verifier can gate browser execution against authenticated releases.
Excluding all browser clients would discard a useful architecture; treating them
all as equally server independent would overstate assurance.

## Decision

Register all three architectures, require complete release manifests, independent
transparency and rollback/freeze checks, and reject claims inconsistent with the
selected execution boundary. Add strict standard-library schema/evidence helpers
instead of repeating permissive dictionary validation in each assurance engine.

## Security consequences

Ordinary browser transparency detects inconsistent releases but does not stop a
malicious origin from bypassing its own verifier. The verified-bootstrap profile
requires an independent installation trust root and complete execution coverage.
External reports remain untrusted until authenticated by the assessment process.

## Compatibility constraints

One profile applies per assessed product version/platform. PR 18 storage and PR
19 transport must be assessed separately. No profile claims compromised-endpoint
protection or substitutes for production cryptographic verification.

## Evidence and references

See the version-pinned TUF, CSP and SRI references in the normative specification.
Positive and adversarial fixtures exercise each trust boundary.

## Reconsideration triggers

New browser code-integrity mechanisms, CSP draft changes, TUF security revisions,
or evidence of bypasses in supported loader/update architectures.
