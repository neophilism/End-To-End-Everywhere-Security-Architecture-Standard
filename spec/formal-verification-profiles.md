# Formal Verification Profiles

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 26.

Formal verification is scoped evidence about a model, proof, specification or implementation. It is not a blanket statement that an entire product is mathematically proven secure.

E2EESA supports several serious formal methods because they answer different questions and rest on different assumptions. A product MAY select more than one formal-verification profile. Later assurance tiers define which combinations are mandatory for particular claims.

## 1. Formal verification profiles

| Exact profile | Proof model | Appropriate claims |
| --- | --- | --- |
| `formal-symbolic-protocol@0.1.0` | Symbolic protocol proof under an explicit adversary/equational model | Secrecy, authentication, key agreement, state-machine and trace/equivalence properties |
| `formal-computational-proof@0.1.0` | Machine-checked computational/game-based cryptographic proof | Reductions from a protocol/construction claim to stated hardness/security assumptions |
| `formal-code-refinement@0.1.0` | Machine-checked implementation/refinement proof | Functional correctness, memory-safe refinement, parser/serializer correctness, algorithm implementation equivalence, state-machine refinement |

These profiles are complementary. None is universally stronger than the others because they reason about different semantic layers.

A bounded model-checking result from PR 25 is not, by itself, evidence for one of these profiles.

## 2. Common formal-evidence requirements

Every formal proof record MUST bind:

- the exact product, platform and resolved E2EESA configuration;
- the exact source digest;
- the exact artifact digest when deployed-code claims are made;
- the exact formal specification/model digest;
- the exact proof artifact digest;
- proof kind;
- property IDs and threat IDs actually proven;
- assumptions and trusted axioms;
- limitations and excluded behavior;
- proof tool/checker identity, version and immutable digest;
- verification result;
- unresolved obligations;
- reproduction instructions or an immutable reproduction reference.

A passing proof MUST have zero unresolved proof obligations.

A proof that contains admitted lemmas, `sorry`/placeholder terms, unchecked axioms beyond explicitly declared cryptographic/environment assumptions, skipped obligations, or checker errors MUST NOT satisfy a required formal-verification obligation.

Machine-checking validates the proof artifact under the tool's logic and trusted computing base. It does not make the model complete or the assumptions true.

## 3. Symbolic protocol verification

The symbolic profile models protocol roles, state transitions, adversary capabilities and desired properties in a symbolic model.

Acceptable tools include systems with capabilities comparable to Tamarin or ProVerif; E2EESA does not mandate one vendor or prover.

Evidence MUST disclose:

- protocol roles and state represented by the model;
- adversary model and equations;
- property/lemma identifiers;
- whether the result concerns trace properties, observational equivalence, or another formal relation;
- session scope;
- restrictions introduced to obtain termination or automation;
- model/specification correspondence; and
- any manual proof steps.

A claim of `unbounded` symbolic verification MUST be produced by a proof whose semantics actually cover arbitrarily many protocol sessions under its stated model.

Finite-state exploration, bounded traces or a manually chosen session cap MUST be labeled `bounded` and do not satisfy an obligation requiring unbounded symbolic proof.

## 4. Computational cryptographic verification

The computational profile uses a computational model in which security goals and assumptions are represented through games, probabilistic programs, reductions or equivalent machine-checked formalisms.

Tools MAY include systems comparable to EasyCrypt or CryptoVerif.

Evidence MUST identify:

- the security experiment or game;
- adversary capabilities;
- cryptographic assumptions;
- reduction theorem(s);
- concrete or asymptotic advantage bounds where the proof provides them;
- security parameters;
- idealized primitives/oracles;
- composition assumptions; and
- the relation between the proved construction and the E2EESA protocol/profile being assessed.

A computational proof MUST NOT be reported as proving implementation correctness unless code/refinement correspondence is separately established.

## 5. Implementation and refinement verification

The code-refinement profile establishes a machine-checked relation between executable or extractable implementation code and a formal specification.

Tools MAY include F*, hax-backed proof pipelines, Lean/Rocq/Coq, Verus, Dafny, Jasmin/EasyCrypt, Vale or comparable systems. Tool choice is not normative.

Evidence MUST identify:

- source-language and target/extracted-language boundaries;
- the specification being refined;
- verified functions/modules;
- unverified foreign-function, runtime, compiler, assembly or hardware boundaries;
- memory-safety assumptions;
- arithmetic/overflow semantics;
- concurrency assumptions when applicable;
- serialization/parsing representation; and
- artifact correspondence when the final deployed binary is within the claim.

If verified source is transformed by an unverified compiler, generator or linker, the evidence MUST disclose that trusted boundary.

A source-level refinement proof MUST NOT be described as a proof of the deployed binary unless artifact correspondence is separately justified.

## 6. Property coverage

A formal proof satisfies an E2EESA formal obligation only when the proof record explicitly lists the required property ID and all required threat IDs for that obligation.

The existence of a proof for one security property MUST NOT be used as evidence for another property merely because the properties are related.

A symbolic secrecy lemma does not establish constant-time implementation behavior. A code refinement proof does not establish a computational security reduction unless that relation is separately proven. A computational reduction does not establish that production code implements the construction correctly.

## 7. Tool independence and reproducibility

The normative unit is the proof obligation and resulting evidence, not a specific prover brand.

Policies MUST NOT require a named tool when two or more sound tools can establish the same required semantics, unless an external certification or interoperability requirement makes the tool choice material.

Evidence MUST pin tool/checker versions and immutable digests so later tool changes cannot silently alter a completed assessment.

Proof artifacts SHOULD be reproducible in an isolated environment.

## 8. Trusted computing base

Every formal proof record MUST enumerate its trusted computing base to the extent material to the claim.

Examples include:

- prover kernel;
- SMT solver;
- proof extraction/transpilation path;
- compiler or linker;
- runtime;
- verified or unverified cryptographic primitive implementations;
- hardware semantics; and
- manually assumed lemmas.

Smaller trusted computing bases MAY support stronger assurance but are not automatically correct.

## 9. Assumptions, axioms and abstraction gaps

Declared cryptographic assumptions such as IND-CCA security of a standardized primitive are not unresolved proof obligations.

Undeclared assumptions, admitted theorems or abstraction gaps that could invalidate the requested claim MUST cause the obligation to fail.

The evidence MUST distinguish:

1. intentional model assumptions;
2. cryptographic hardness/security assumptions;
3. trusted toolchain assumptions;
4. implementation boundaries outside the proof; and
5. unresolved proof obligations.

## 10. Formal-verification policy

A formal-verification policy binds exact proof obligations to an exact product/configuration.

Each obligation declares:

- proof profile;
- property IDs;
- threat IDs;
- proof scope;
- whether machine checking is mandatory;
- whether unbounded-session coverage is mandatory;
- whether artifact-level correspondence is mandatory; and
- maximum evidence age.

An obligation MAY require more than one proof profile for the same property.

## 11. Failure semantics

An obligation is unsatisfied when:

- no matching proof exists;
- the proof status is not `passed`;
- the proof uses the wrong proof model;
- required properties/threats are missing;
- the proof is stale;
- source/configuration/artifact digests mismatch;
- unresolved obligations remain;
- machine checking is required but absent;
- unbounded coverage is required but only bounded evidence exists;
- artifact correspondence is required but unproven; or
- assumptions/limitations materially contradict the requested claim.

Validation MUST fail closed.

## 12. Assurance boundary

PR 26 defines formal-proof evidence and validation. It does not decide that every E2EE product must use every formal technique.

PR 27 defines assurance tiers and determines which proof profiles are required at each tier.

Formal verification complements, rather than replaces, the black-box, white-box, fuzzing, property-testing and adversarial methods defined by PR 25.

## 13. References

- Tamarin Prover — symbolic protocol verification with explicit protocol/adversary/property models.
- ProVerif — automated symbolic protocol verification.
- EasyCrypt — machine-checked computational cryptographic proofs.
- Project Everest / F* — formally verified cryptographic and communication software.
- hax — translation of security-critical Rust into multiple formal verification backends.
