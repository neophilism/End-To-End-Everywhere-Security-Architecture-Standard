# Six-Project Integration Contracts

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 45.

This document defines stable machine-readable integration contracts between E2EESA and the six downstream End To End Everywhere systems:

1. SDK
2. Verified
3. Security Lab
4. Incident Exchange
5. Observatory
6. Research Lab

The purpose is to keep E2EESA reusable as a standard and architecture layer rather than coupling it to one product implementation.

## 1. Contract model

Each downstream system has one versioned contract.

A contract declares:

- contract ID and semantic version;
- system ID;
- artifact types it may consume;
- artifact types it may emit;
- the authoritative E2EESA schema or registry path for each artifact type;
- required identity/binding fields that MUST survive the handoff;
- whether an artifact is normative, evidence, state, request, result, or projection;
- whether the downstream system may modify the artifact or must preserve it byte-for-byte.

The registry is closed-world. Unknown artifact types are invalid.

## 2. Common exchange envelope

Artifacts exchanged under a PR 45 contract use the integration envelope.

The envelope binds:

- envelope schema version;
- contract ID/version;
- producer system;
- consumer system;
- artifact type;
- E2EESA standard version;
- authoritative schema/registry path;
- canonical payload SHA-256 digest;
- production timestamp;
- optional correlation ID; and
- payload.

The envelope digest is calculated over the envelope excluding its own `envelope_digest`.

A consumer MUST reject:

- a contract/version mismatch;
- an artifact type not permitted by that contract direction;
- a schema path different from the registry definition;
- a payload digest mismatch;
- an envelope digest mismatch; or
- a missing required binding field.

## 3. Canonical digest rule

PR 45 uses E2EESA canonical JSON:

- UTF-8;
- object keys sorted lexically;
- no insignificant whitespace;
- no NaN/Infinity values.

`payload_digest = SHA-256(canonical(payload))`.

`envelope_digest = SHA-256(canonical(envelope_without_envelope_digest))`.

This is transport-independent. A downstream implementation may use HTTP, files, queues, local process calls, or another transport without changing the artifact contract.

## 4. SDK contract

The SDK contract is the client/developer integration surface.

### Consumes

- profile catalog;
- cryptographic registry;
- configuration;
- conformance request.

### Emits

- configuration;
- conformance request.

### Required bindings

Configuration/request handoffs preserve:

- `standard_version`;
- exact selected profile refs;
- accepted nondefault statuses;
- exact product/configuration identity where the request defines it.

The SDK MUST NOT invent unregistered profile or algorithm identifiers.

## 5. Verified contract

Verified is the certification/trustmark integration surface.

### Consumes

- conformance result;
- certification evidence bundle;
- certification lifecycle case;
- signed certification attestation/status statement.

### Emits

- certification lifecycle case;
- signed certification attestation;
- certification status statement.

### Required bindings

Certification artifacts preserve exact:

- product/configuration identity;
- standard version;
- conformance result/evidence digests;
- certification scope;
- profile/configuration basis;
- attestation/status identifiers and lifecycle state.

Verified MUST NOT convert a failed conformance result into a passing certification claim.

## 6. Security Lab contract

Security Lab is the verification/evaluation integration surface.

### Consumes

- verification policy;
- profile catalog;
- threat model registry;
- security property registry.

### Emits

- verification evidence;
- formal verification evidence.

### Required bindings

Verification evidence preserves exact:

- target artifact/configuration identity;
- profile refs;
- threat/property coverage;
- method/tool/model identity;
- source/build digest where applicable;
- result/evidence digest.

A downstream lab may add evidence, but MUST NOT rewrite the underlying E2EESA target identity.

## 7. Incident Exchange contract

Incident Exchange is the vulnerability/advisory integration surface.

### Consumes

- vulnerability handling case;
- normalized advisory;
- advisory interoperability registry.

### Emits

- vulnerability handling case;
- normalized advisory.

### Required bindings

Incident artifacts preserve:

- vulnerability/case/advisory identity;
- affected product/configuration/profile identity;
- severity/risk provenance;
- remediation and disclosure state;
- evidence references/digests;
- advisory revision lineage.

The exchange MUST preserve whether information is confirmed, provisional, disputed, or remediated when that distinction exists in the source artifact.

## 8. Observatory contract

Observatory is the evidence/classification integration surface.

### Consumes

- Observatory evidence bundle;
- confidence/classification policy.

### Emits

- Observatory evidence bundle;
- classification record;
- Observatory projection manifest.

### Required bindings

Observatory handoffs preserve:

- immutable source-bundle digest;
- entity/event/citation IDs;
- provenance activity/agent identity;
- classification taxonomy/version;
- human/model provenance;
- classification confidence semantics;
- revision lineage.

A projection is derived data and MUST remain bound to its canonical source evidence.

## 9. Research Lab contract

Research Lab is the experimental-profile and promotion integration surface.

### Consumes

- Observatory evidence bundle;
- research profile registry;
- research promotion registry.

### Emits

- research profile entry;
- research promotion record.

### Required bindings

Research handoffs preserve:

- exact research entry ID/version/digest;
- experimental lifecycle boundary;
- threat/property/algorithm references;
- hypothesis/experiment/vector/implementation identity;
- evidence and limitations;
- promotion predecessor/state/gate bindings.

A PR 37 research artifact cannot become production-selectable through the PR 45 transport layer.

## 10. Producer/consumer rules

The six project IDs are:

- `sdk`;
- `verified`;
- `security-lab`;
- `incident-exchange`;
- `observatory`;
- `research-lab`.

The E2EESA standard implementation itself uses producer/consumer ID `e2eesa`.

A downstream system may only emit artifact types listed under its contract's `emits`.

A downstream system may only consume artifact types listed under its contract's `consumes`.

For a downstream-to-E2EESA envelope, the producer must be the contract system and the consumer must be `e2eesa`.

For an E2EESA-to-downstream envelope, producer and consumer are reversed.

## 11. Mutability

Artifact contracts use one of three mutability modes:

- `preserve` — payload is immutable and must be forwarded unchanged;
- `produce-new` — the system creates a new artifact conforming to the authoritative schema;
- `derive` — the system may produce a projection/derived artifact that remains digest-bound to its source.

A system MUST NOT treat `preserve` as permission to normalize away identifiers, evidence, failure states, or signatures.

## 12. Versioning

Contract versions are independently versioned from the E2EESA standard.

A breaking change includes:

- removing an artifact type;
- changing an authoritative schema path;
- removing a required binding field;
- changing digest semantics;
- changing a direction from consume/emit; or
- changing producer/consumer identity semantics.

Breaking changes require a new major contract version.

Additive artifact types or binding fields require at least a minor version.

## 13. No transport lock-in

PR 45 intentionally does not standardize:

- HTTP endpoints;
- message broker products;
- authentication infrastructure;
- cloud providers;
- programming languages; or
- database engines.

Those are implementation choices of the six downstream codebases.

The stable boundary is the content-addressed artifact contract.

## 14. Fail-closed behavior

Validation fails on:

- unknown contract;
- wrong contract version;
- unknown system;
- direction violation;
- unknown artifact type;
- wrong authoritative schema/registry path;
- payload digest mismatch;
- envelope digest mismatch;
- missing required binding field;
- prohibited payload mutation;
- standard-version mismatch when the artifact carries one; or
- research/certification/conformance state escalation through transport.

## 15. Reference files

- `registry/integration-contracts.json`
- `schemas/integration-contract-registry.schema.json`
- `schemas/integration-envelope.schema.json`
- `scripts/integration_contracts.py`
- `tests/test_integration_contracts.py`
