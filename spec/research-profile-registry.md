# Research Profile Registry

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 37.

The Research Profile Registry provides a durable, machine-readable home for experimental protocol/profile research before any production recommendation is possible.

Registration means **the research exists and is reproducibly described**. It does not mean the research is secure, mature, recommended, conformant, or production-ready.

## 1. Hard research/production boundary

Every PR 37 research entry MUST have:

- lifecycle status `experimental`;
- `production_selectable = false`; and
- an immutable entry digest.

The production profile resolver MUST NOT treat a PR 37 research entry as an ordinary selectable architecture profile.

PR 38 is the only E2EESA 0.1 mechanism that can promote research through Candidate, Recommended and Required lifecycle states.

## 2. Research entry identity

Every entry binds:

- entry ID;
- semantic entry version;
- revision;
- previous entry digest for later revisions;
- title and summary;
- research kind;
- target family/profile identity;
- lifecycle status;
- creation/update time;
- provenance evidence;
- threat model;
- target security properties;
- algorithm/component references;
- design artifact;
- hypotheses;
- experiments/results;
- test vectors;
- implementations;
- review/formal evidence;
- limitations/open questions;
- reproducibility instructions; and
- entry digest.

Changing any of these creates a new revision/digest.

## 3. Research kinds

Initial research kinds are:

- `protocol-profile`;
- `algorithm-composition`;
- `implementation-technique`;
- `evidence-study`; and
- `verification-method`.

A research kind describes what is being evaluated, not its maturity.

## 4. Target identity

A research entry identifies the production namespace it might eventually affect:

- target family ID;
- target profile ID; and
- intended profile version.

The target profile need not yet exist in the production catalog.

If the target family already exists, its exact family ID SHOULD be used.

A target identity is not a reservation or guarantee of future inclusion.

## 5. Provenance

Research provenance MUST include at least one content-addressed PR 34 Observatory evidence bundle digest.

Additional specification, paper, dataset and repository references MAY be included, but mutable URLs are not sufficient as the sole provenance record.

The entry records the exact design-specification digest and reference.

## 6. Threat model

A research entry declares:

- registered PR 3 threat IDs that apply;
- registered composite-scenario IDs when applicable; and
- any experimental threats not yet present in the standard registry.

Experimental threat IDs use the prefix `EXP-TM-`.

Every experimental threat includes a name, description and adversary capabilities.

PR 38 promotion requires any experimental threat that remains material to be reconciled with the production threat registry.

## 7. Security properties

A research entry declares:

- existing PR 3 security-property IDs it studies; and
- optional experimental properties using prefix `EXP-SP-`.

An experimental property includes a name and definition.

A research result does not establish that the property is achieved in production.

## 8. Cryptographic and technical components

Registered cryptographic algorithms MUST use exact PR 6 algorithm IDs.

Research MAY additionally identify experimental components using `EXP-COMP-` IDs.

Each experimental component must provide:

- name;
- category;
- specification digest; and
- specification/reference locator.

An experimental component is not added to the production cryptographic registry by PR 37.

## 9. Hypotheses

Each hypothesis contains:

- hypothesis ID;
- statement;
- falsification/acceptance criterion; and
- target property IDs.

Hypothesis IDs are local to the research entry and immutable within a revision.

A hypothesis MUST be testable or reviewable through the registered evidence path.

## 10. Experiments and results

Every experiment records:

- experiment ID;
- hypothesis IDs;
- methodology digest/reference;
- input/test-vector IDs;
- implementation IDs when code is exercised;
- execution environment digest/reference;
- result outcome;
- result digest/reference;
- execution time; and
- replication status.

Allowed outcomes are:

- `supported`;
- `refuted`;
- `inconclusive`; and
- `error`.

These labels describe the experiment relative to its hypothesis. They are not production security statuses.

Replication statuses are:

- `none`;
- `internal`; and
- `independent`.

Independent replication requires distinct replication evidence.

## 11. Test vectors

Test vectors are content-addressed artifacts.

Each vector records:

- vector ID;
- purpose;
- format/media type;
- artifact digest;
- artifact reference; and
- verification status.

Verification status is:

- `generated`;
- `internally-verified`; or
- `independently-verified`.

An independently verified vector must record independent verification evidence.

## 12. Implementations

Implementation records describe research code.

Implementation maturity is one of:

- `concept`;
- `prototype`;
- `reference`; or
- `independent`.

Every code-bearing implementation records:

- source reference;
- exact source/commit digest;
- language/runtime;
- build/reproduction reference; and
- known limitations.

All PR 37 implementations MUST have `production_use_prohibited = true`.

A reference implementation in the research registry is a research artifact, not a production approval.

## 13. Review and formal evidence

A research entry may bind:

- review evidence digests;
- formal-verification evidence digests;
- interoperability evidence digests; and
- benchmark/evaluation evidence digests.

PR 37 validates that such evidence is content-addressed and identified. It does not convert the evidence into a promotion decision.

PR 38 defines which evidence is sufficient for each lifecycle promotion.

## 14. Limitations and open questions

Every entry MUST contain at least one limitations record and an open-questions array.

A limitation may later be resolved, but the historical revision remains immutable.

An entry with no known limitations is not treated as proof that no limitations exist.

## 15. Reproducibility

Every entry must provide a reproduction reference describing how to reproduce or inspect the registered evidence.

Experiments that rely on unavailable proprietary infrastructure must declare that dependency explicitly in limitations.

A result that cannot presently be independently reproduced may still be registered, but its replication status must remain accurate.

## 16. Registry index

The registry index contains only compact entry metadata:

- entry ID/version;
- entry digest;
- lifecycle status;
- research kind;
- target family/profile;
- update time; and
- production-selectable flag.

The full research entry remains the authoritative record.

An index record is invalid if its digest/metadata differs from the corresponding entry.

## 17. Revisions

Revision 1 has no predecessor digest.

Every later revision MUST:

- increment revision by exactly one;
- identify the prior entry digest;
- preserve entry ID; and
- preserve target identity unless a new research entry ID is created.

A changed result, vector, implementation, limitation or evidence reference requires a new revision.

## 18. Fail-closed behavior

Validation fails on:

- non-experimental lifecycle state;
- `production_selectable=true`;
- unknown registered threat/scenario/property/algorithm references;
- malformed experimental IDs;
- hypothesis/result references to unknown IDs;
- experiment inputs referencing unknown vectors/implementations;
- independent replication without evidence;
- independent vector verification without evidence;
- missing model/design/result/source digests;
- implementation not marked production-prohibited;
- missing limitations;
- digest mismatch;
- index/entry mismatch; or
- invalid revision chain.

## 19. References

PR 37 composes:

- PR 3 threat/security-property registries;
- PR 6 cryptographic algorithm registry;
- PR 25–26 verification/formal-evidence concepts;
- PR 34 immutable evidence/provenance.

PR 38 defines Research → Production Promotion Gates.
