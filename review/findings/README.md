# Independent Review Findings

Place one structured JSON file per substantive independent-review finding in this directory.

Recommended filename:

`<finding-id>.json`

Each finding should conform to:

`review/finding.schema.json`

Start from:

`review/finding-template.json`

Keep the finding record through its full lifecycle. When fixed or otherwise dispositioned, update:

- `status`;
- `disposition_rationale`;
- `fix_reference`; and
- `reviewer_acceptance`.

Blocker, critical, and high findings must end in `fixed` with reviewer acceptance before PR 49 can complete. Medium findings must have a reviewer-accepted disposition.


## Content address

After the reviewer has finalized the standalone finding file, compute its digest with:

`python review/hash_artifact.py review/findings/<finding-id>.json`

When the finding is normalized into `review/independent-review.json`, record:

- `source_finding_digest` — the SHA-256 output above; and
- `source_finding_reference` — the repository path or another stable reference to the exact source finding.

This keeps the compact combined review package bound to the full reviewer-submitted finding.
