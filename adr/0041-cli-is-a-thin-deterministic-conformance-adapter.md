# ADR-0041: The conformance CLI is a thin deterministic adapter

- **Status:** Accepted
- **Date:** 2026-10-08
- **Decision class:** Invariant
- **Affected components:** conformance execution, CI/CD integration, result verification
- **Security properties affected:** conformance integrity and reproducibility

## Context

A CLI is useful for adopters and CI, but duplicating PR 40 logic in command handlers would create two conformance implementations that could drift.

Machine consumers also need stable exit semantics and protection against ambiguous JSON input.

## Decision

The CLI calls the PR 40 engine directly.

It provides:

- basis discovery;
- mechanical request binding;
- evaluation;
- saved-result deterministic verification; and
- result explanation.

JSON duplicate keys are rejected.

Result files are written atomically.

Exit codes distinguish pass, fail, indeterminate, invalid input and result mismatch.

## Security consequences

CLI behavior remains testable against the same engine as direct library use.

A saved result cannot verify merely because its internal digest was recomputed after tampering; `verify-result` compares it with deterministic reevaluation.

## Reconsideration triggers

Re-open if E2EESA adopts a packaged SDK/daemon whose stable API becomes a better canonical CLI integration boundary than direct Python engine invocation.
