# External Review Handoff

If you are an independent expert receiving the E2EESA candidate, start here.

## What to review

Candidate: **E2EESA 0.9.0-rc.1**

Frozen tree digest:

`sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c551083f5f5189491370ce2a2`

Frozen files: **645**

## What to read first

1. `review/EXPERT-REVIEW-GUIDE.md`
2. `review/REVIEWER-CHECKLIST.md`
3. `review/independent-review-request.md`
4. repository `README.md`
5. `spec/threat-model.md`
6. `spec/security-properties.md`
7. the specification areas matching your expertise.

## What to return

Please return:

1. a completed reviewer attestation based on `review/reviewer-attestation-template.json`;
2. each substantive finding using `review/finding-template.json` or equivalent structured content;
3. any supplemental analysis, proofs, test cases, traces, or references;
4. after fixes, your acceptance/rejection of each finding disposition.

The project will normalize the returned material into `review/independent-review.json`.

## Commands

### Recommended one-command evidence run

From the repository root:

`python review/run_expert_review_suite.py --reviewer-id <reviewer-id> --organization-id <organization-id> --output review/evidence/<reviewer-id>-automated-evidence.json`

This verifies the frozen candidate, runs the complete unit suite and seeded adversarial checks, validates the review package structure, and produces a content-addressed evidence report. It is supporting evidence only; the expert's human analysis, findings, limitations, and attestation remain required.

Preview the exact command plan without running it:

`python review/run_expert_review_suite.py --plan`

### Individual commands

Candidate validation:

`python scripts/validate_repo.py`

`python scripts/release_candidate.py`

`python -m unittest discover -s tests -v`

`python scripts/run_reference_security_checks.py --seed 20261007 --iterations 1000`

Review-package validation:

`python review/validate_review.py`

Final review gate:

`python review/validate_review.py --require-complete`

The final gate is intentionally expected to fail until the independent review has actually been completed.


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


## Normalizing submitted review artifacts

Standalone reviewer files are the source artifacts. Do not manually copy their hashes into the combined package.

After adding or updating files under `review/attestations/` or `review/findings/`, run:

`python review/ingest_review.py --write`

Then verify deterministic normalization with:

`python review/ingest_review.py`

The ingest tool computes SHA-256 identities and stable repository references automatically, checks reviewer/finding relationships, preserves the full finding failure scenario and references, and updates `review/independent-review.json`. The combined package never asks a source artifact to contain its own hash.
