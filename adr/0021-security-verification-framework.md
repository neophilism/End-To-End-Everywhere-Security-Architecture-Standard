# ADR-0021: Preserve assessment method and scope differences

- **Status:** Accepted for pre-1.0 development
- **Date:** 2026-10-07
- **Decision class:** Profile choice
- **Affected components:** verification profile registry, coverage engine and reference runner
- **Security properties affected:** SP-SOFTWARE-INTEGRITY and assessed architecture properties

## Context

Black-box behavior, source inspection and bounded protocol models expose different
failure classes. A generic passing test badge does not identify their scope.

## Serious alternatives considered

External-only testing works when source access is absent but cannot establish
key erasure or build provenance. Internal review/modeling sees code/state with
different deployment assumptions. Combined assessment covers both at higher cost.

## Decision

Register all three approaches with explicit mandatory methods and claim limits.
Bind coverage to every resolved architecture, product/version/platform and exact
source/artifact. Preserve independent review, corpus identity and counterexamples.
Add real bounded reference mutation/property checks without calling them formal
proof or an independent product audit.

## Security consequences

Missing options, mismatched source, untested properties/threats and flaky/failed
results cannot silently satisfy assessment. Actual report authentication and
substantive quality remain essential external responsibilities.

## Compatibility constraints

The selected configuration resolves under existing family/lifecycle rules.
Illustrative resolver profiles are excluded from targets. Formal techniques and
assurance tiers remain PRs 26–27; certification remains later milestones.

## Evidence and references

NIST SP 800-115; LLVM libFuzzer documentation; existing E2EESA profile/threat/
property registries. Fixtures show complete and deliberately incomplete coverage.

## Reconsideration triggers

New formal methods, production fuzzing evidence, platform limitations or expert
review requiring stronger per-option assessment conditions.
