# ADR-0019: An evidence-bound secure-development baseline

- **Status:** Accepted for pre-1.0 development
- **Date:** 2026-10-07
- **Decision class:** Invariant
- **Affected components:** development control registry, policy and release evidence
- **Security properties affected:** SP-SOFTWARE-INTEGRITY, SP-BUILD-PROVENANCE

## Context

Protocol correctness alone cannot protect products from unsafe changes, build
compromise or ignored vulnerabilities. Process claims need explicit release scope.

## Serious alternatives considered

Prose-only checklists are easy to claim without evidence. Tool-specific mandates
would bind an implementation-neutral standard to one vendor. Outcome/evidence
controls allow multiple tools while preserving mandatory review and release gates.

## Decision

Map the baseline to all 19 final SSDF 1.1 practice areas, require independent
exact-source review and six executable gates, and distinguish verified remediation
from limited expiring noncritical risk acceptance. No high/critical waiver is
accepted. Draft SSDF updates require an intentional profile revision.

## Security consequences

Unreviewed, stale or incorrectly scoped results cannot satisfy the release record.
Authenticity and quality of external reports still require the assessment layer.
Two-person release authorization adds process integrity but is not a cryptographic
proof that the product has no defects.

## Compatibility constraints

All product classes retain the baseline controls. Language/tool choices remain
free when they produce equivalent assessed evidence. PRs 24–25 deepen build and
verification requirements; PR 46 expands the external crosswalk.

## Evidence and references

NIST SP 800-218 SSDF 1.1 (2022 final); local practice/control registry and
source-bound positive/adversarial fixtures.

## Reconsideration triggers

A finalized SSDF revision, new supply-chain findings or evidence that gate
coverage/review separation needs stronger requirements.
