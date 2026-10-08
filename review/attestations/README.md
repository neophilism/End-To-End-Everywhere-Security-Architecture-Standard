# Reviewer Attestations

Place completed independent reviewer attestations in this directory.

Recommended filename:

`<reviewer-id>.json`

Each attestation should conform to:

`review/reviewer-attestation.schema.json`

Start from:

`review/reviewer-attestation-template.json`

The initial attestation identifies the exact 0.9.0-rc.1 candidate reviewed. After review-driven fixes are complete, update the final-acceptance fields so they bind to the digest reported by:

`python review/final_review_tree.py`

The final acceptance digest/reference should identify the reviewer's post-fix acceptance artifact. Do not invent these values before the reviewer has actually accepted the fixed tree.
