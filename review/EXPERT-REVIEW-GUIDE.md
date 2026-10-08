# E2EESA 0.9 Independent Expert Review Guide

This guide is the primary handoff document for external reviewers of E2EESA 0.9.0-rc.1.

## Candidate identity

Review exactly this candidate:

- Release: `0.9.0-rc.1`
- Frozen files: **645**
- Candidate tree digest: `sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c551083f5f5189491370ce2a2`
- Frozen internal artifact basis: `0.1.0-dev`

Do not silently substitute a later branch or a different tree. If the candidate digest changes, the review package must identify the new digest and explain why.

## What E2EESA is

E2EESA is an implementation-neutral security architecture standard for end-to-end encrypted systems.

It deliberately separates:

- security invariants;
- versioned architecture profiles;
- product-class capabilities;
- experimental research profiles;
- conformance/certification evidence;
- lifecycle/deprecation/migration rules;
- observability/research systems that must not silently become production approval.

The review is therefore broader than a conventional source-code audit.

## Required review domains

The final review package must cover all five domains:

1. **Cryptography and protocols**
2. **Implementation security**
3. **Software supply chain and secure development**
4. **Privacy, metadata, backup, and recovery**
5. **Conformance, certification, and standards semantics**

At least one independent reviewer must cover cryptography/protocols. The final package requires at least three independent reviewers from at least two independent organizations.

## Recommended reading order

1. `README.md`
2. `spec/normative-language.md`
3. `spec/terminology.md`
4. `spec/threat-model.md`
5. `spec/security-properties.md`
6. `profiles/catalog.json`
7. `registry/cryptographic-algorithms.json`
8. protocol/profile specifications relevant to the reviewer domain
9. `spec/security-verification-framework.md`
10. `spec/conformance-engine.md`
11. `spec/standards-crosswalk.md`
12. `spec/security-rationale-corpus.md`
13. `spec/release-candidate.md`

Reviewers should then inspect the associated schemas, ADRs, fixtures, and tests for the portions they evaluate.

## High-priority architecture areas

### Cryptography and protocols

Review:

- algorithm lifecycle and agility;
- authenticated negotiation and downgrade resistance;
- pairwise and group E2EE composition;
- forward secrecy and post-compromise security;
- hybrid/post-quantum security claims;
- device identity and authorization;
- key verification and transparency;
- replay/rollback behavior;
- real-time media;
- attachment/file encryption;
- randomness and state requirements.

Look specifically for places where a sound primitive is composed unsafely or where the standard claims more than the referenced construction establishes.

### Recovery, backup, and multi-device

Review whether backup/recovery/device enrollment creates a weaker alternate decryption path.

Check:

- user-controlled versus hardware-assisted recovery assumptions;
- rollback of backup/recovery state;
- stolen credentials;
- compromised recovery services/HSM assumptions;
- new-device authorization;
- revocation and stale devices;
- recovery confidentiality and authorization integrity.

### Metadata and privacy

Review what content encryption does **not** hide.

Check:

- routing and service metadata;
- contact discovery;
- telemetry;
- retention;
- linkability;
- client/server trust boundaries;
- whether privacy properties are accurately scoped.

### Client, update, and supply-chain security

Review whether a malicious update, web bootstrap, dependency compromise, signing-key compromise, or rollback can defeat otherwise-correct E2EE.

Check:

- native/web client assumptions;
- build provenance;
- artifact signing;
- transparency;
- SBOM/provenance semantics;
- downgrade and rollback of released clients;
- evidence linking source, build, and release.

### Conformance and certification

Try to construct false-positive conformance claims.

Look for cases where:

- a product can pass with missing evidence;
- an experimental/provisional profile becomes production-selectable;
- profile dependencies are omitted;
- deprecated/legacy states are accepted outside migration;
- a certification survives a materially changed implementation;
- a trustmark says more than the evaluated scope;
- evidence digests can be swapped or replayed;
- a broad external-standard mapping is presented as certification/equivalence.

## Review methodology

Use whichever methods are appropriate to your expertise. Useful methods include:

- normative text review;
- threat-model challenge;
- protocol composition review;
- test-vector inspection;
- negative/adversarial test design;
- state-machine review;
- property-based/fuzz test proposals;
- formal-model critique;
- implementation-reference inspection;
- schema/evidence-model review;
- supply-chain analysis;
- conformance false-positive attempts;
- standards-crosswalk verification.

A review is not expected to prove the entire standard correct. It must clearly state the scope actually reviewed and the limits of the conclusions.

## Running the candidate checks

From the repository root:

`python scripts/validate_repo.py`

`python scripts/release_candidate.py`

`python -m unittest discover -s tests -v`

`python scripts/run_reference_security_checks.py --seed 20261007 --iterations 1000`

The review workspace itself can be checked with:

`python review/validate_review.py`

When the final evidence is assembled:

`python review/validate_review.py --require-complete`

The final command is expected to fail until genuine external reviewer attestations and finding dispositions have been added.

## Finding expectations

Every substantive finding should contain:

- finding ID;
- reviewer ID;
- severity;
- affected requirement IDs when applicable;
- affected repository paths;
- technical analysis;
- concrete failure/exploit scenario when applicable;
- recommendation;
- final disposition;
- fix reference if fixed; and
- reviewer acceptance of the disposition.

Use `review/finding-template.json` as the starting point.

## Severity guidance

**Blocker** — the candidate should not proceed to 1.0 under any circumstances until fixed.

**Critical** — a practical or fundamental failure capable of defeating major stated security properties.

**High** — a serious failure of a material security property, lifecycle rule, or evidence/conformance boundary.

**Medium** — meaningful security or assurance weakness that requires disposition before 1.0, but may be deferrable only when it does not invalidate a claimed property.

**Low** — limited-impact weakness, ambiguity, or defense-in-depth improvement.

**Informational** — observation, clarification, or non-security editorial recommendation.

## Reviewer attestation

Each reviewer should provide a content-addressed attestation using `review/reviewer-attestation-template.json`.

The attestation should identify:

- reviewer and organization;
- independence from maintainers;
- areas of expertise;
- review domains covered;
- exact candidate digest reviewed;
- dates;
- methods used;
- files/areas emphasized;
- explicit scope limitations;
- finding IDs submitted; and
- attestation digest/reference.

## Independence

For this gate, “independent” means the reviewer is not acting as a maintainer or author of the candidate and is able to provide an objective technical assessment.

Any financial, employment, authorship, or other relationship that could reasonably affect independence should be disclosed in the attestation.

## Completion

PR 49 may be considered complete only when:

- at least three independent reviewers are recorded;
- at least two independent organizations are represented;
- all five required domains are covered;
- independent cryptography/protocol review is represented;
- every blocker/critical/high finding is fixed and reviewer-accepted;
- every medium finding has a reviewer-accepted disposition;
- the review summary is content-addressed;
- the live package says `ready-for-1.0`; and
- `python review/validate_review.py --require-complete` passes.

Until then, development may continue, but the repository should describe 1.0 as **independent review pending** rather than complete.


## Final fixed-tree acceptance

After all review-driven fixes are applied, compute the exact fixed standard-tree identity with:

`python review/final_review_tree.py`

Every reviewer's final acceptance must reference that same tree digest. The combined completion record must use it as `final_reviewed_tree_digest`.


## Validation after review fixes

Once a reviewer finding causes a frozen candidate file to change, the original rc.1 manifest is expected to differ. Do **not** rewrite the historical rc.1 manifest merely to hide that difference.

Validate the fixed tree with:

`python review/validate_post_fix_tree.py`

This permits only the exact expected rc.1 manifest-drift condition and still requires every other repository invariant to pass. Then compute the fixed-tree identity with:

`python review/final_review_tree.py`
