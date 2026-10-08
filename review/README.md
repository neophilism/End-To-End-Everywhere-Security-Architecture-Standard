# E2EESA 0.9 Independent Expert Review

This directory is intentionally **outside the frozen 0.9 candidate surface**.

The frozen candidate under review is:

- release: `0.9.0-rc.1`
- frozen files: 645
- candidate tree digest: `sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c551083f5f5189491370ce2a2`

PR 49 cannot be declared complete merely because repository tests pass. It requires actual review evidence from reviewers independent of the maintainers.

## Review domains

The review package requires coverage of:

- cryptography and protocol design;
- application/client/server implementation security;
- software supply chain and secure development;
- privacy, metadata, and recovery architecture;
- conformance, certification, and standards semantics.

One reviewer may cover multiple domains only when the review package records the relevant expertise. At least two distinct independent organizations must be represented, and cryptography/protocol review must include at least one independent reviewer.

## Finding severities

- blocker
- critical
- high
- medium
- low
- informational

Blocker, critical, and high findings must be resolved before PR 49 can be considered complete.

Medium findings may be resolved, deferred to a documented post-1.0 issue only if they do not invalidate a security claim, or rejected with documented technical rationale and reviewer disposition.

## Review artifacts

- `independent-review-request.md` — scope and instructions for reviewers.
- `review-package.schema.json` — machine-readable review package format.
- `independent-review.json` — live package; currently awaiting external review.
- `validate_review.py` — validates reviewer independence, domain coverage, findings, and completion state.

The live package begins in `awaiting-review` state. Do not replace that state with `complete` until the corresponding external attestations and finding dispositions actually exist.
