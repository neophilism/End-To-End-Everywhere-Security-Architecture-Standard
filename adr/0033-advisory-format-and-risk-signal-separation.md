# ADR-0033: Support CSAF 2.0/ISO 20153 and provisional CSAF 2.1 while keeping risk signals separate

- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision class:** Profile choice
- **Affected components:** vulnerability advisory generation and exchange
- **Security properties affected:** vulnerability-information integrity and interoperability

## Context

ISO/IEC 20153:2025 standardizes CSAF 2.0, while CSAF 2.1 Committee Specification Draft 03 adds modern fields such as CVSS v4, EPSS, SSVC and first-known-exploitation dates.

Organizations therefore face a legitimate stability-versus-capability tradeoff.

Separately, CVSS, EPSS, KEV and organization-specific priority measure different things and should not be collapsed into a synthetic score.

## Serious alternatives considered

### CSAF 2.0 only

Rejected as the only option because it cannot natively encode several current vulnerability metrics.

### CSAF 2.1 only

Rejected while 2.1 remains a committee specification draft and ISO 20153 still maps to 2.0.

### Support both

Accepted.

### Merge CVSS/EPSS/KEV into one risk number

Rejected. Technical impact, predicted exploitation probability, confirmed catalog exploitation and organizational response context are not commensurate measurements.

## Decision

E2EESA supports:

- stable `advisory-csaf-2-0-iso20153@0.1.0`; and
- provisional `advisory-csaf-2-1-csd03@0.1.0`.

The normalized advisory retains CVSS, EPSS, KEV, exploitation and contextual-priority data independently.

Full CSAF conformance claims require an external CSAF validator result.

## Security consequences

Consumers retain provenance and avoid misleading synthetic risk arithmetic.

The cost is that CSAF 2.0 output cannot carry all modern fields natively and a publisher may need both the normalized E2EESA record and CSAF output.

## Compatibility constraints

Multiple CSAF outputs may be generated from the same normalized advisory.

No output may widen affected-product scope or omit a remediation that the normalized record declares applicable to a known-affected product.

## References

- OASIS CSAF 2.0.
- ISO/IEC 20153:2025.
- OASIS CSAF 2.1 CSD03.
- FIRST CVSS v4.0.
- FIRST EPSS v5.
- CISA KEV.
- CVE Record Format 5.2.0.

## Reconsideration triggers

Re-open when CSAF 2.1 reaches final OASIS Standard status, when ISO publishes a successor to ISO/IEC 20153 covering CSAF 2.1+, or if a newer CSAF release changes the signal model.
