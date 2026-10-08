# Complete Standards Crosswalk

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 46.

PR 46 provides a complete, reproducible requirement-by-requirement crosswalk between the E2EESA normative corpus and relevant external standards.

## 1. Completeness rule

Every normative paragraph containing a BCP 14 keyword — `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, or `MAY` — MUST produce exactly one crosswalk record.

A requirement is never silently omitted.

Each record is either:

- externally related to one or more registered standards; or
- explicitly classified `no-direct-analog` with a rationale.

## 2. Requirement identity

Requirement IDs are content-addressed.

The extractor:

1. ignores fenced code blocks;
2. groups prose into Markdown paragraphs;
3. normalizes internal whitespace;
4. detects BCP 14 keywords;
5. hashes the document path plus normalized paragraph text; and
6. prefixes the digest with `REQ-`.

This makes the crosswalk resilient to unrelated line-number movement while still changing identity when normative text changes.

## 3. Relationship semantics

An external relationship is one of:

- `direct` — the external standard directly specifies the referenced mechanism, format, process, or semantic rule;
- `contextual` — the external standard provides aligned controls, process guidance, or security context but is not asserted to be textually/normatively equivalent.

PR 46 deliberately does not claim that broad management/control standards are identical to protocol-specific E2EESA requirements.

## 4. No-direct-analog semantics

`no-direct-analog` does not mean the requirement is unsupported.

It means E2EESA is defining project-specific composition, lifecycle, tooling, evidence, or integration behavior for which no single external standard is represented as an equivalent.

The rationale MUST be explicit.

## 5. Standards catalog

The machine-readable catalog includes current relevant standards from:

- IETF;
- NIST;
- ISO/IEC;
- OASIS;
- W3C;
- OpenSSF/SLSA;
- SPDX; and
- CycloneDX.

The catalog records designation, title, status, organization, and canonical reference URI.

## 6. Mapping rules

Mapping rules are document-scoped defaults.

They do not rewrite E2EESA requirements.

Every generated requirement record preserves:

- requirement ID;
- source document;
- normative keywords;
- normalized text;
- text digest;
- relationship list; and
- no-direct-analog rationale when applicable.

Document-scoped mappings use `contextual` unless a relationship is known to be directly composed by E2EESA.

## 7. Coverage validation

Validation fails if:

- a normative paragraph lacks a rule;
- a rule references an unknown external standard;
- a requirement has neither an external relationship nor a no-direct-analog rationale;
- a requirement has both external mappings and a no-direct-analog rationale;
- duplicate requirement IDs occur;
- a current normative spec document lacks a rule;
- a rule references a missing spec document; or
- generated coverage is below 100%.

## 8. Drift detection

Changing a normative requirement changes its content-addressed requirement ID.

Adding a new normative paragraph automatically creates an unmapped requirement unless the document is already governed by a valid rule.

Adding a new normative spec document fails closed until a crosswalk rule is added.

## 9. Output

`scripts/standards_crosswalk.py` can produce a deterministic JSON report containing:

- standard catalog digest;
- rule-set digest;
- requirement count;
- mapped requirement count;
- no-direct-analog count;
- per-document counts;
- per-organization relation counts; and
- every requirement record.

The report digest covers the complete report excluding its own digest.

## 10. Interpretation

The crosswalk is explanatory and interoperability-oriented.

It MUST NOT be used to claim:

- certification to an external standard;
- that E2EESA conformance implies ISO/NIST/OASIS certification;
- that a contextual mapping is normative equivalence; or
- that an external standard endorses E2EESA.

## 11. Authoritative files

- `registry/external-standards.json`
- `registry/standards-crosswalk-rules.json`
- `schemas/external-standards.schema.json`
- `schemas/standards-crosswalk-rules.schema.json`
- `scripts/standards_crosswalk.py`
- `tests/test_standards_crosswalk.py`
