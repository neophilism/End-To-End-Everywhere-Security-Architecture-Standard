# Conformance CLI

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 41.

PR 41 exposes the PR 40 Conformance Engine through a deterministic command-line interface suitable for local evaluation and CI/CD.

The CLI is a thin adapter. It MUST NOT implement different conformance semantics from PR 40.

## 1. Entry point

Reference invocation:

`python3 scripts/e2eesa_conformance.py <command> ...`

The reference CLI has no third-party runtime dependencies.

## 2. Commands

### `basis`

Emits the exact standard-version and canonical registry/catalog digests required in a conformance request.

This allows a request author to discover the evaluation basis without manually calculating hashes.

### `bind-request`

Reads:

- a conformance request/template;
- assurance plan; and
- certification evidence bundle.

It validates that product identity is consistent across the plan, bundle and request, then fills/replaces only mechanically derived binding fields:

- standard version;
- assurance-plan digest;
- certification-bundle digest;
- configuration digest;
- source digest;
- artifact digest;
- standards input digests; and
- request digest.

It does not alter:

- assessment ID;
- conformance policy;
- evaluation time;
- family scope; or
- migration intent/context.

A conflicting product identity fails rather than being silently rewritten.

### `evaluate`

Runs PR 40 with the supplied request, assurance plan and certification bundle.

Migration-only evaluation additionally requires both:

- `--migration-plan`; and
- `--migration-case`.

Output is the PR 40 conformance-result object or a human-readable rendering of that exact result.

### `verify-result`

Reevaluates PR 40 from the supplied inputs, verifies the saved result digest, and compares the saved logical result with deterministic reevaluation.

A mismatch uses dedicated exit code 4.

If the result is authentic/reproducible, the command exits according to the verified verdict.

### `explain`

Reads a saved PR 40 result, validates its self-digest, and renders the verdict/reasons without reevaluating the underlying evidence.

Because `explain` does not receive the original evaluation inputs, it verifies only self-integrity. Full reproducibility verification requires `verify-result`.

## 3. Input parsing

The CLI rejects:

- malformed JSON;
- top-level values that are not JSON objects; and
- duplicate JSON object keys.

Duplicate-key rejection prevents ambiguous requests whose meaning could differ across parsers.

## 4. Output modes

Supported modes:

- `json`; and
- `text`.

JSON output is stable-key, UTF-8, pretty-printed JSON.

Text output displays:

- verdict;
- claim scope;
- product/version/platform;
- production-certification eligibility;
- effective profile count;
- in-scope family count;
- required property count; and
- normalized reasons.

Text is presentation only. The JSON result remains the machine-readable authority.

## 5. Output files

`--output -` or no output path writes to stdout.

A file output is written atomically using a temporary file in the destination directory followed by replacement.

A partial write must not leave a result file that appears complete.

## 6. Exit codes

The exit-code contract is normative:

- `0 PASS` — evaluation/verified result verdict is pass; also successful non-verdict commands;
- `1 FAIL` — evaluation/verified result verdict is fail;
- `2 INDETERMINATE` — evaluation/verified result verdict is indeterminate;
- `3 INVALID_INPUT` — invalid CLI invocation, malformed/ambiguous JSON, missing required artifacts, or command-level input error;
- `4 RESULT_MISMATCH` — saved result self-digest or deterministic reevaluation verification failed.

CI MUST use the exit code, not text matching.

## 7. Repository-root selection

By default, the CLI resolves the repository root as the parent of the `scripts` directory containing the reference CLI.

`--root` may select another E2EESA checkout.

All registry/catalog inputs are loaded from that root.

This makes the checkout itself part of the evaluation basis; PR 40 still verifies the exact canonical digests against the request.

## 8. Security boundaries

The CLI:

- performs no network access;
- does not fetch missing evidence;
- does not repair a failing request during `evaluate`;
- does not downgrade `fail` to `indeterminate`;
- does not treat Candidate/migration passes as production conformance;
- does not suppress PR 40 reasons; and
- does not write an output result before evaluation completes.

## 9. Migration arguments

If the request uses `conformance-migration-only@0.1.0`, both migration artifacts are mandatory.

For non-migration policies, supplying migration artifacts is allowed to reach PR 40 only when both are present; PR 40 will then fail them as semantically inappropriate. Supplying exactly one is a CLI input error.

## 10. Reproducibility

A `verify-result` command with the same:

- request;
- plan;
- bundle;
- registries/catalog; and
- migration artifacts when applicable

must reproduce the same PR 40 logical result.

Changed repository inputs produce PR 40 evaluation-basis digest failures rather than silently verifying the old result.

## Legacy diagnostics after Audit v2

The legacy `0.1` request adapter emits a separately versioned `0.2` configuration diagnostic result, under `schemas/conformance-diagnostic-result.schema.json`. It preserves the selected legacy policy as `evaluation_policy_scope` while `claim_scope` is `configuration-diagnostic`, `result_class` is `configuration`, and certification eligibility is always false. The output digest uses its exact diagnostic record contract. These passes do not establish product conformance. Historical `0.1` results retain their original archived verifier and bytes. Active component/flow assessments use `scripts/scoped_assessment.py` and its own exact schema/contract identities.
