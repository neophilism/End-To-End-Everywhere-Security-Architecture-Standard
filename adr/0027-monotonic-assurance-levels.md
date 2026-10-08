# ADR-0027: Monotonic assurance levels

- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision class:** Profile choice
- **Affected components:** assurance, verification, formal verification, certification
- **Security properties affected:** assurance evidence for all claimed properties

## Context

E2EESA needs a way to communicate and machine-enforce different depths of security evidence without pretending that every product has identical assurance or that a single binary badge captures all confidence levels.

## Serious alternatives considered

### One binary assurance state

Rejected. It hides major differences between external testing, source review and machine-checked formal evidence.

### Independent non-monotonic labels

Rejected. Users could not reliably infer whether one label includes another label's evidence.

### Monotonic evidence tiers

Accepted. Each tier includes the evidence floor of lower tiers and adds explicit requirements.

## Decision

E2EESA defines A1 through A5 assurance profiles. Higher ordinals MUST preserve lower-level profile requirements and formal-property obligations.

A2 is the recommended general-purpose assurance baseline in E2EESA 0.1. Certification policy remains separate.

A5 requires explicit treatment of computational-proof candidates: either product-specific proof scope or a documented standardized-construction exemption.

## Security consequences

The model makes assurance comparisons deterministic and prevents a higher badge-like label from silently dropping lower-level controls.

The tradeoff is that higher assurance can be expensive and may be inappropriate for low-risk products. E2EESA therefore permits lower levels and leaves certification thresholds to later policy.

## Compatibility constraints

Only one assurance-level profile may be selected for an exact configuration.

Assurance profiles are evidence profiles; they do not create underlying architecture security properties.

## Evidence and references

The tier model composes E2EESA PR 23–26 secure-development, supply-chain, verification and formal-verification evidence rather than introducing new cryptographic primitives or protocol requirements.

## Reconsideration triggers

Re-open if independent review finds a non-monotonic assurance dimension that cannot be represented as an orthogonal capability, or if certification practice requires a materially different tier taxonomy.
