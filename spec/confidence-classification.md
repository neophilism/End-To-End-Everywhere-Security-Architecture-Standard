# Confidence and Classification Model

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 36. **Decision class:** ⚖️ multi-option.

PR 36 defines how Observatory evidence is classified and how confidence in a classification is represented without hiding provenance, human judgment, model output, disagreement, or uncertainty.

Classification is an assertion about PR 34 evidence. It is not a replacement for the underlying evidence or citation graph.

## 1. Classification modes

E2EESA supports three modes:

### Human-reviewed

A human reviewer assigns the labels and confidence.

The reviewer MUST be represented by a PR 34 `person` agent.

### Automated

A software/service classifier assigns the labels and confidence.

The classifier MUST record:

- software/service agent;
- model/system ID;
- version;
- immutable model/artifact digest;
- configuration digest; and
- exact assessment time.

An automated result MUST NOT be described as human-reviewed.

### Mixed

Human and automated assessments are retained independently.

The final result is resolved through one of the explicit mixed-resolution strategies in section 5.

The source assessments MUST NOT be deleted after resolution.

## 2. Taxonomy binding

Every classification binds an exact taxonomy:

- taxonomy ID;
- taxonomy version; and
- taxonomy reference.

Labels are opaque taxonomy-defined identifiers.

E2EESA does not impose a universal Observatory taxonomy in PR 36.

Changing taxonomy version creates a new classification revision.

## 3. Evidence and provenance binding

Every classification record MUST bind:

- one exact PR 34 source bundle digest;
- one target entity or event in that bundle;
- at least one citation from that same evidence bundle;
- classification mode;
- exact taxonomy;
- source human/automated assessments;
- final resolution when available; and
- classification record digest.

Confidence without supporting citations is invalid.

A classification does not rewrite the source bundle.

## 4. Confidence models

There is no single universally best confidence representation. E2EESA supports three serious models.

### Dimensional ordinal confidence

`dimensional-ordinal`

Records an ordinal level:

- `unknown`;
- `low`;
- `moderate`; or
- `high`.

It also records separate dimensions:

- source reliability;
- evidence directness;
- corroboration;
- freshness; and
- conflicting evidence.

No hidden formula converts those dimensions into the ordinal level.

The assessor MUST provide a rationale connecting the evidence dimensions to the final level.

This model is appropriate where confidence remains an analytic judgment rather than a calibrated probability.

### STIX 0–100 confidence

`stix-0-100`

Records an integer from 0 through 100 consistent with the STIX confidence scale.

The score expresses confidence in the correctness of the content/classification. It MUST NOT be described as a probability unless independent calibration evidence justifies a probabilistic interpretation.

A rationale is required.

### Calibrated probability

`calibrated-probability`

Records an integer probability in basis points from 0 through 10,000, representing estimated probability that the automated classification is correct.

This model is allowed only for automated assessments and automated components of mixed assessments.

It requires calibration evidence:

- classifier model digest;
- evaluation dataset digest;
- sample count;
- evaluation time;
- calibration method;
- Brier score in millionths; and
- expected calibration error in basis points when available.

A policy using calibrated probability MUST declare the maximum permitted age of calibration evidence.

A raw model softmax/logit/score MUST NOT be labeled calibrated probability merely because it falls between 0 and 1.

## 5. Mixed human/automated resolution

E2EESA supports three serious resolution strategies.

### Human final

`human-final`

The final labels and final confidence are the human assessment.

If the human labels differ from the automated labels, an override/disagreement rationale is required.

This treats automation as decision support.

### Consensus with escalation

`consensus`

Human and automated labels MUST match for a final classification.

If they differ, the classification status is `needs-review`; no final labels or final confidence may be published.

When they agree, policy MUST declare whether final confidence comes from the human or automated assessment. The selected assessment is copied exactly; no implicit averaging occurs.

### Declared weighted confidence

`declared-weighted`

Human and automated labels MUST match.

Both assessments MUST use the STIX 0–100 confidence model.

The policy declares integer human and automated weights that sum to 100.

Final confidence is the deterministic round-half-up weighted value:

`floor((human_score * human_weight + automated_score * automated_weight + 50) / 100)`

If the labels differ, status is `needs-review`.

The weights, scores and resulting value are all retained.

This strategy is permitted but not recommended as a universal default; weighting human judgment and model output is domain-dependent.

## 6. Classification status

Allowed statuses are:

- `classified`; and
- `needs-review`.

A `classified` record MUST have at least one final label and final confidence.

A `needs-review` record MUST have no final labels and no final confidence.

Human-reviewed and automated modes normally resolve to `classified`.

Mixed consensus/weighted disagreement MUST resolve to `needs-review`.

## 7. Human and automated assessment provenance

A human assessment records:

- human agent ID;
- labels;
- confidence;
- rationale; and
- assessment time.

An automated assessment records:

- software/service agent ID;
- labels;
- confidence;
- classifier model/system metadata; and
- assessment time.

A human-only assessment MUST NOT use `calibrated-probability`.

An automated assessment MAY use any permitted confidence model, but `calibrated-probability` must satisfy section 4.

## 8. Model calibration freshness

When policy selects a maximum calibration age, the automated assessment time MUST be no later than that many calendar days after the calibration evaluation time.

Calibration evaluation time MUST NOT be after the classification assessment time.

Calibration evidence is scoped to the exact model digest.

A new model digest requires its own calibration evidence.

## 9. Revisions

Classification records are append-only.

Revision 1 has no predecessor.

Every later revision MUST:

- increment revision by exactly one;
- identify the previous classification digest;
- preserve source bundle, target and taxonomy identity unless the policy treats the change as a new classification series.

A changed label, confidence, reviewer, model, or rationale produces a new revision rather than mutating the previous record.

## 10. Confidence versus probability

E2EESA deliberately separates:

- confidence as analytic/editorial judgment;
- confidence as the STIX interoperable 0–100 scale; and
- empirically calibrated probability.

These representations are not automatically convertible.

A STIX confidence score of 85 MUST NOT be silently converted into 85% probability.

A human `high` confidence judgment MUST NOT be assigned an arbitrary numeric score unless the policy explicitly selects and documents a mapping.

## 11. Automated-classifier governance

An automated or mixed classifier policy MUST make it possible to reconstruct:

- which model/configuration produced the assessment;
- what evidence bundle and citations were input;
- when classification occurred;
- whether human review occurred;
- how disagreement was resolved; and
- whether any probabilistic confidence was calibrated.

PR 36 does not require public release of proprietary model weights. It requires immutable identity/provenance sufficient to distinguish one model/configuration from another.

## 12. Fail-closed behavior

Validation fails on:

- unknown target/citation/agent;
- wrong human/software agent type;
- missing model/configuration identity;
- unsupported confidence model;
- human use of calibrated probability;
- stale/mismatched calibration evidence;
- classification taxonomy mismatch with policy;
- classification mode mismatch with policy;
- hidden mixed-mode disagreement;
- final labels/confidence inconsistent with the selected resolution strategy;
- mixed weighted scores using different confidence semantics;
- weights not summing to 100;
- incorrect weighted result;
- `classified` without final result;
- `needs-review` with a published final result;
- digest mismatch; or
- invalid revision chain.

## 13. Standards and practice alignment

- STIX 2.1 defines an integer 0–100 confidence property and mappings to several established confidence scales.
- Analytic tradecraft distinguishes confidence from likelihood and requires uncertainty/information gaps to be explained.
- NIST evaluation work uses Brier score for probabilistic predictions and emphasizes testing/evaluation of AI systems.
- NIST AI RMF emphasizes transparent, measured, governed AI lifecycle practice.

## 14. References

- OASIS STIX 2.1.
- ODNI ICD 203 analytic standards and associated confidence guidance.
- NIST AI Risk Management Framework.
- NIST AI 700-1.
- E2EESA PR 34 Observatory Evidence Model.
- E2EESA PR 35 Observatory Data Architecture.
