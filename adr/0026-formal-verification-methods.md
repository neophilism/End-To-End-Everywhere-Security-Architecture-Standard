# ADR-0026: Formal verification methods are complementary, not interchangeable

- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision class:** Profile choice
- **Affected components:** formal verification, security verification, assurance, certification evidence
- **Security properties affected:** all properties for which formal evidence is claimed

## Context

No single formal method proves every relevant layer of an E2EE system. Symbolic protocol analysis, computational cryptographic proofs, and implementation/refinement proofs reason about different semantics and assumptions.

Treating one method as universally superior would either overclaim its scope or exclude other serious approaches.

## Serious alternatives considered

### Require one named prover

Rejected. Tool brand does not define the security semantics, and serious tools overlap without being identical.

### Treat all formal methods as equivalent

Rejected. A symbolic secrecy theorem, a computational reduction, and a source-to-specification refinement theorem answer different questions.

### Support complementary proof profiles

Accepted. E2EESA names the proof model, binds its assumptions/evidence, and allows one or more profiles to be selected. Later assurance tiers decide which combinations are mandatory.

## Decision

E2EESA defines three initial formal-verification profiles:

- `formal-symbolic-protocol@0.1.0`
- `formal-computational-proof@0.1.0`
- `formal-code-refinement@0.1.0`

They share a `many` family and may coexist.

Specific tools are examples, not normative dependencies.

## Security consequences

This avoids false equivalence between proof models and avoids a single-tool monoculture.

The tradeoff is that evidence validation must track proof scope, assumptions, model/implementation correspondence and trusted computing base explicitly.

## Compatibility constraints

Bounded PR 25 protocol-model evidence does not automatically satisfy PR 26 formal proof obligations.

Unbounded-session obligations can be satisfied only by evidence whose proof semantics cover unbounded sessions.

Artifact-correspondence obligations require implementation/refinement evidence that actually binds the deployed artifact.

## Evidence and references

Relevant serious approaches include symbolic protocol provers such as Tamarin and ProVerif, computational proof systems such as EasyCrypt, and verified-programming/refinement systems such as F*, hax-backed pipelines, Jasmin, Lean/Rocq/Coq, Verus, Dafny and Vale.

## Reconsideration triggers

Re-open if a later formal framework provides a mechanically justified end-to-end composition theorem spanning the currently separate proof layers, or if independent review finds a proof-model class missing from E2EESA.
