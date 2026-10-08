# Advisory Interoperability

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 33.

PR 33 defines a normalized E2EESA security-advisory record and interoperable CSAF exports.

The normalized record preserves vulnerability identity, product/version status, remediation, technical severity, exploitation probability, known exploitation and organization-specific response context as distinct data.

## 1. Supported output profiles

E2EESA supports two CSAF interoperability profiles.

### Stable ISO profile

`advisory-csaf-2-0-iso20153@0.1.0`

- CSAF 2.0 Security Advisory profile;
- standardized as ISO/IEC 20153:2025;
- production-stable compatibility target;
- does not natively represent all modern E2EESA signals such as CVSS v4, EPSS v5 or SSVC v2.

### Current CSAF 2.1 draft profile

`advisory-csaf-2-1-csd03@0.1.0`

- CSAF 2.1 Committee Specification Draft 03, 11 September 2026;
- provisional profile because CSAF 2.1 is not yet a final OASIS Standard;
- supports native CVSS v4, EPSS and SSVC v2 metrics;
- supports first-known-exploitation dates.

Both profiles may be emitted from one normalized advisory.

## 2. Normalized advisory record

A normalized E2EESA advisory binds:

- advisory ID and title;
- publisher identity and namespace;
- initial/current release timestamps and revision;
- source PR 32 handling-case ID and digest;
- one or more exact products/versions;
- one or more vulnerabilities;
- CVE IDs when assigned;
- CWE IDs when known;
- description and references;
- product status;
- remediation statements;
- technical severity;
- EPSS;
- KEV status;
- contextual prioritization/risk;
- exploitation status and first-known-exploitation date when known.

The normalized record is not itself a CVE Record or CSAF document.

## 3. CVE Record compatibility

Assigned CVE IDs MUST match the CVE identifier syntax.

When CVE-source metadata is included, E2EESA records the CVE Record Format version used by the source.

The current production CVE Record Format is 5.2.0.

PR 33 does not authorize a vendor to act as a CVE Numbering Authority and does not synthesize official CVE Records.

## 4. CWE

CWE identifiers MUST use the form `CWE-<positive integer>`.

CWE is a weakness classification and MUST NOT be treated as a vulnerability identifier.

Multiple CWE values MAY apply when a vulnerability spans more than one weakness class.

## 5. CVSS v4

When a CVSS v4 score is published, the record MUST include:

- `version = 4.0`;
- full `vectorString`;
- numeric `baseScore`; and
- `baseSeverity`.

The vector MUST begin with `CVSS:4.0/`.

Technical severity is not response priority.

## 6. EPSS

EPSS is represented independently from CVSS.

The record includes:

- probability in [0,1];
- percentile in [0,1];
- observation timestamp;
- model identifier;
- source URI.

For records using the current model after 15 June 2026, `model = EPSS-v5`.

EPSS is an exploitation-probability estimate, not evidence that exploitation has occurred.

## 7. CISA KEV

CISA Known Exploited Vulnerabilities status is represented separately as:

- `listed`;
- `not-listed`; or
- `unknown`.

Every KEV observation MUST record:

- CISA KEV source URI; and
- checked-at timestamp.

A `listed` observation additionally requires the catalog `date_added`. If a due date or known-ransomware-campaign-use value is available it is retained.

KEV listing is evidence of known exploitation as defined by the catalog; absence from KEV MUST NOT be interpreted as proof that exploitation is not occurring.

## 8. Contextual risk / prioritization

Organization-specific response priority remains separate from CVSS, EPSS and KEV.

The record binds:

- prioritization profile;
- decision;
- rationale;
- observation time; and
- input factors.

PR 32 CVSS+threat and SSVC decisions can be projected directly.

A single synthetic `combined_score`, `overall_score` or equivalent field that numerically merges CVSS, EPSS, KEV and contextual risk is prohibited.

## 9. Known exploitation

Known exploitation is represented separately from EPSS.

Allowed normalized states are:

- `none-known`;
- `proof-of-concept`;
- `active`;
- `unknown`.

When an actual exploitation date is known, it is recorded separately.

An active PR 32 exploitation finding MAY coexist with KEV `not-listed` or `unknown`; those signals come from different sources and MUST NOT be forced to agree.

## 10. Products and status

Each normalized product is an exact product/version identity.

At minimum it contains:

- product ID;
- product-line ID, which groups exact versions of the same product for affected/fixed lineage checks;
- vendor;
- product name;
- version.

PURL and CPE MAY be included.

For each vulnerability, products may be:

- known affected;
- fixed;
- known not affected; or
- under investigation.

A product ID MUST NOT appear in mutually incompatible status sets for the same vulnerability.

Every fixed product MUST have a corresponding affected product in the same release/product scope.

## 11. Remediations

Remediation categories are:

- vendor fix;
- mitigation;
- workaround;
- no fix planned; and
- none available.

Every remediation MUST identify the product IDs to which it applies and provide details.

A vendor-fix remediation SHOULD provide a URL or immutable artifact reference.

## 12. CSAF 2.1 mapping

The CSAF 2.1 export uses:

- schema URI `https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json`;
- document category `csaf_security_advisory`;
- product tree full product names;
- vulnerability CVE/CWE/notes/product status/remediations/references;
- native `cvss_v4` metric;
- native `epss` metric;
- native `ssvc_v2` when the source priority can be represented by the referenced SSVC schema;
- `first_known_exploitation_dates` for known active exploitation dates.

KEV and non-SSVC contextual risk are not forced into nonstandard extension fields.

They MAY be represented in human-readable threat/reference content, while the normalized E2EESA record remains the authoritative machine-readable source for those signals.

## 13. CSAF 2.0 / ISO 20153 mapping

The CSAF 2.0 export uses:

- CSAF 2.0 schema;
- `csaf_security_advisory`;
- product tree;
- vulnerabilities;
- CVE;
- notes;
- product status;
- remediation and references.

CSAF 2.0 lacks native CVSS v4 and EPSS fields.

E2EESA MUST NOT down-convert CVSS v4 to CVSS v3 merely to populate a CSAF 2.0 score.

Modern metrics remain present in the normalized E2EESA advisory and MAY be summarized in human-readable notes/references in the CSAF 2.0 document.

## 14. Full CSAF validation

The E2EESA reference exporter produces a deliberately constrained CSAF structure.

A document MUST NOT be labeled `csaf_validated=true` solely because the E2EESA semantic exporter accepted it.

A conformance claim requires an external CSAF validator result containing:

- CSAF version;
- validator identity/version;
- document digest;
- validation timestamp; and
- zero errors.

Warnings MUST be preserved.

This avoids reimplementing the full CSAF standard and its mandatory tests inside E2EESA.

## 15. Revision consistency

An advisory update MUST:

- increment the normalized revision;
- update current release time;
- preserve initial release time;
- preserve advisory ID;
- preserve revision history in the CSAF output.

EPSS/KEV/contextual-risk observations are time-varying and SHOULD be refreshed without rewriting their historical provenance.

## 16. Fail-closed behavior

Validation fails on:

- invalid CVE/CWE syntax;
- malformed CVSS v4 data;
- EPSS values outside [0,1];
- EPSS v5 observations with missing provenance;
- KEV status without source/check time;
- listed KEV record without date added;
- combined/synthetic risk score fields;
- product status conflicts;
- fixed products with no affected lineage;
- remediation references to unknown products;
- output/profile version mismatch;
- CSAF export scope differing from the normalized advisory;
- a `csaf_validated` claim lacking a matching successful external validator result.

## 17. References

- OASIS CSAF 2.0.
- ISO/IEC 20153:2025 — OASIS CSAF 2.0.
- OASIS CSAF 2.1 Committee Specification Draft 03.
- CVE Record Format 5.2.0.
- FIRST CVSS v4.0.
- FIRST EPSS v5.
- CISA Known Exploited Vulnerabilities Catalog.
- CWE.
