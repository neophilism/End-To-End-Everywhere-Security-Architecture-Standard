# ADR-0036: Keep confidence semantics explicit and make human/AI resolution selectable

- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision class:** ⚖️ Multi-option
- **Affected components:** Observatory classification, analytic confidence, automated classifiers
- **Security properties affected:** analytic transparency, provenance, auditability

## Context

Confidence is represented differently across serious analytic and cyber-threat practices.

STIX provides a 0–100 confidence scale. Analytic workflows often use low/moderate/high confidence supported by source and uncertainty reasoning. Automated classifiers may produce calibrated probabilities, but raw model scores are not automatically calibrated probabilities.

There is also no universal best rule for combining human and automated judgment.

## Serious alternatives considered

### One universal confidence number

Rejected. It would conflate analytic judgment, interoperable confidence scales and calibrated probability.

### Always trust the automated classifier

Rejected as a universal model.

### Always require a human final decision

Supported as one serious mode, but not required for low-risk or high-volume machine classification.

### Silent human/model averaging

Rejected. It hides policy choices and can combine non-comparable quantities.

### Explicit confidence models and explicit mixed-resolution strategies

Accepted.

## Decision

E2EESA supports:

- dimensional ordinal confidence;
- STIX 0–100 confidence; and
- calibrated probability with empirical calibration evidence.

Classification supports:

- human-reviewed;
- automated; and
- mixed.

Mixed mode supports:

- human-final;
- consensus with escalation; and
- declared weighted confidence where both inputs use the same STIX 0–100 semantics.

No implicit conversion between confidence models is permitted.

## Security consequences

Consumers can tell whether “confidence” is judgment, interoperability metadata, or a calibrated probability.

Human/model disagreements remain visible.

Weighted blending is possible where an organization deliberately selects it, but the weights and arithmetic are auditable.

## Compatibility constraints

Automated and mixed results bind exact model/configuration identities.

Calibrated probability is prohibited for human-only assessments.

PR 37 research records may use these confidence semantics for experimental results without automatically promoting them to production recommendations.

## References

- OASIS STIX 2.1 confidence scale.
- ODNI analytic confidence guidance.
- NIST AI RMF.
- NIST AI 700-1 Brier-score evaluation.

## Reconsideration triggers

Re-open if a broadly adopted machine-readable confidence/calibration standard supersedes these representations or independent review identifies a materially better human/automation resolution model.
