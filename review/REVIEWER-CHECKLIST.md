# Independent Reviewer Checklist

Use this checklist as a working aid. It does not replace the signed/content-addressed reviewer attestation.

## Candidate integrity

- [ ] I reviewed E2EESA `0.9.0-rc.1`.
- [ ] I verified the candidate tree digest is `sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c551083f5f5189491370ce2a2`.
- [ ] I did not silently review a different branch/tree.
- [ ] I ran or independently inspected the repository validation results.

## Scope and independence

- [ ] My identity/organization are recorded.
- [ ] My relevant expertise is described.
- [ ] My relationship to the maintainers/project is disclosed.
- [ ] I can attest that my technical conclusions are independent.
- [ ] I identified the review domains I actually covered.
- [ ] I documented material areas I did not review.

## Security architecture

- [ ] Threat-model assumptions are explicit and internally consistent.
- [ ] Security-property claims do not exceed the threat model.
- [ ] Required profile dependencies are complete.
- [ ] Serious alternative architectures are not hidden as defaults.
- [ ] Experimental/research options cannot silently become production defaults.
- [ ] Lifecycle/deprecation/migration states fail closed.

## Cryptography/protocols, when in scope

- [ ] No custom cryptographic primitive is being treated as production-ready without appropriate external analysis.
- [ ] Algorithm use matches the referenced construction/standard.
- [ ] Negotiation is downgrade resistant.
- [ ] Identity and device authorization are bound to protocol state.
- [ ] Forward secrecy claims are justified.
- [ ] Post-compromise-security claims are justified.
- [ ] Post-quantum claims are correctly scoped.
- [ ] Replay/rollback cases are handled.
- [ ] Group membership/rekey behavior is sound.
- [ ] Media/file/attachment encryption does not create weaker side paths.

## Recovery/privacy/client security, when in scope

- [ ] Recovery/backup cannot bypass intended E2EE assumptions without an explicit profile.
- [ ] Multi-device enrollment/revocation semantics are sound.
- [ ] Metadata/privacy claims accurately describe what is and is not hidden.
- [ ] Telemetry cannot silently disclose protected content/state.
- [ ] Client update/bootstrap assumptions are explicit.
- [ ] A malicious/stale client update cannot be ignored by the threat model.
- [ ] Supply-chain evidence is linked to exact artifacts.

## Conformance/certification, when in scope

- [ ] I attempted to construct false-positive conformance cases.
- [ ] Candidate/experimental/legacy/deprecated states cannot pass production conformance improperly.
- [ ] Evidence is scope-bound and digest-bound.
- [ ] Certification lifecycle includes expiry/suspension/revocation/change handling.
- [ ] Crosswalk relationships do not falsely imply external certification or equivalence.
- [ ] The rationale corpus does not hide unsupported claims behind generic rationale.

## Findings and completion

- [ ] Every substantive concern has a finding ID.
- [ ] Finding severity reflects security impact.
- [ ] Affected requirement IDs/paths are included where possible.
- [ ] Recommendations are concrete enough to implement.
- [ ] Fixed findings were re-reviewed.
- [ ] I explicitly accepted or rejected the final disposition of my findings.
- [ ] My final attestation names every finding I submitted.


## Validation after review fixes

Once a reviewer finding causes a frozen candidate file to change, the original rc.1 manifest is expected to differ. Do **not** rewrite the historical rc.1 manifest merely to hide that difference.

Validate the fixed tree with:

`python review/validate_post_fix_tree.py`

This permits only the exact expected rc.1 manifest-drift condition and still requires every other repository invariant to pass. Then compute the fixed-tree identity with:

`python review/final_review_tree.py`


## Reproducible automated evidence

- [ ] I ran `python review/run_expert_review_suite.py --reviewer-id <id> --organization-id <org> --output review/evidence/<id>-automated-evidence.json`, or I documented why an equivalent/manual procedure was used.
- [ ] I preserved the generated report digest and referenced the evidence artifact in my attestation.
- [ ] I understand that a passing automated report does not substitute for my human technical review.
