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
