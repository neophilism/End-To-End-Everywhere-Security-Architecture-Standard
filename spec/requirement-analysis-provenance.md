# Requirement-specific security analysis and independent review provenance (AUD-21)

**Status:** Normative reference governance. Current per-requirement authored and externally reviewed coverage begins at zero.

## Analysis identity and provenance

Every individually authored E2EESA analysis **MUST** have a stable, manually assigned logical requirement ID distinct from its current content-derived normative paragraph ID. It MUST bind the exact current requirement text digest, source document, author identity, requirement-specific rationale, applicable threat and security property IDs, evidence classes, applicable external standards and typed dependencies. A document-level inherited rationale or a mechanically generated rephrasing MUST NOT be classified as authored requirement-specific analysis.

An analysis **MUST** be invalidated or flagged stale after a normative paragraph changes, after any normative dependency's source version changes, or after a supporting threat/property/external-standard registry changes. Typed dependencies MUST point to registered, resolvable logical IDs and express an explicit relation; prose regular expressions or citation matching are supplemental discovery aids, not authoritative dependency validation. Orphaned or conflicting requirement overrides MUST fail validation.

## Independent review

An individually authored analysis is not an independently reviewed analysis. A review **MUST** bind the exact authored content/context digest, reviewer and organization identity, and evidence of independent authentication. The review MUST NOT be counted as externally authenticated merely because a JSON record, signature string or AI-generated review text claims approval. An authentic verifier outside the evaluated code path MUST verify the review evidence, applicable reviewer independence and accepted content digest. Changed source context automatically invalidates old review acceptance.

## Reporting

Coverage MUST distinguish at least: generated/document-level projections, individually authored current analysis, recorded but unauthenticated review provenance, and externally authenticated current review. A 100% projected coverage value does not imply any authored or reviewed requirements. Each reported numerator and denominator MUST identify its exact frozen source and support-registry basis.

Reference implementation: \`scripts/requirement_analysis.py\`. Source registry: \`registry/requirement-analyses.json\`. Tests: \`tests/test_requirement_analysis.py\`. The initial empty registry honestly reports zero individually authored and zero independently authenticated reviewed analyses. A structural validator does not substitute for the costly real analysis/review work.
