# Security Rationale Corpus

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 47.

PR 47 provides an auditable security rationale record for every normative E2EESA requirement identified by PR 46.

## 1. Completeness

Every PR 46 requirement ID MUST have exactly one rationale record.

The corpus MUST remain at 100% coverage.

A newly added normative paragraph therefore fails repository validation until the rationale corpus can explain why it exists.

## 2. Rationale record

Every rationale record binds:

- exact PR 46 requirement ID;
- source document and text digest;
- normalized normative text;
- document security rationale;
- registered threat IDs;
- registered composite-scenario IDs where applicable;
- registered security-property IDs;
- one or more expected evidence classes;
- PR 46 external-standard relationships or explicit no-direct-analog rationale; and
- rationale-record digest.

The corpus report is content-addressed.

## 3. Threat and property integrity

Threat IDs MUST exist in `registry/threat-model.json`.

Security-property IDs MUST exist in `registry/security-properties.json`.

Unknown IDs fail closed.

The corpus does not assert that every requirement mitigates every listed threat by itself. Threat/property linkage identifies the security context in which the requirement exists.

## 4. Evidence expectations

Evidence expectations describe what an evaluator should look for to determine whether the requirement is actually implemented.

Examples include:

- protocol transcript evidence;
- configuration/resolver evidence;
- test-vector evidence;
- lifecycle/status evidence;
- provenance/digest evidence;
- security review evidence;
- reproducible-build evidence;
- interoperability evidence; and
- formal-proof evidence.

Every rationale record MUST contain at least one evidence expectation.

An evidence class is not itself proof of conformance; PR 40 remains the conformance decision engine.

## 5. External references

PR 47 inherits the exact PR 46 external-standard relations for the same requirement ID.

It MUST NOT add a stronger external-equivalence claim than PR 46.

Requirements classified by PR 46 as `no-direct-analog` preserve that rationale.

## 6. Rationale scope

Document rules provide the baseline security reason shared by normative requirements in that specification area.

The generated requirement record also preserves the exact normative text, so reviewers can assess whether the inherited rationale, threats, properties, and evidence remain appropriate.

PR 49 independent expert review may refine individual or document-level rationale records.

## 7. Drift detection

Validation fails if:

- any PR 46 requirement lacks a rationale record;
- a rationale rule references a missing spec document;
- a current spec document lacks a rationale rule;
- a threat/property/scenario ID is unknown;
- evidence expectations are empty;
- PR 46 relation data is changed or dropped;
- duplicate requirement IDs occur; or
- the generated rationale corpus is not deterministic.

## 8. Output

`scripts/security_rationale.py` generates the complete corpus as JSON.

The report includes:

- requirement count;
- rationale count;
- coverage percentage;
- per-document counts;
- per-threat counts;
- per-property counts;
- per-evidence-class counts; and
- every content-addressed rationale record.

## 9. Interpretation

The corpus explains the security purpose and expected evidence of E2EESA requirements.

It does not replace:

- the normative requirement text;
- the threat model;
- conformance testing;
- external standards;
- independent cryptographic review; or
- implementation-specific security analysis.

## 10. Authoritative files

- `registry/security-rationale-rules.json`
- `schemas/security-rationale-rules.schema.json`
- `scripts/security_rationale.py`
- `tests/test_security_rationale.py`
