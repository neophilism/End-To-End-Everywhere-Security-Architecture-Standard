# Security Verification Framework

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 25.

This layer defines assessment coverage and evidence. It composes with the
architecture profiles and PRs 23–24; it does not itself issue a certificate.

## 1. Assessment profiles

| Exact profile | Mandatory methods for each assessed architecture | Boundary |
| --- | --- | --- |
| `verification-blackbox@0.1.0` | External tests, properties, fuzzing, adversarial tests | External behavior; no internal key-lifecycle/software provenance proof |
| `verification-whitebox@0.1.0` | Internal/source review, properties, fuzzing, adversarial tests, protocol models | Source/state/model assessment; production black-box behavior remains separate |
| `verification-combined@0.1.0` | All six methods | Combined external and internal assessment; recommended |

Each product/version/platform MUST select the applicable profile explicitly.
Assessment MUST be independent from the source authors, authenticated and
complete for the declared exact configuration. Where a product supports several
mutually exclusive configurations, each configuration MUST have its own coverage;
testing one option does not certify its alternatives. The development resolver's
foundation/example profiles are synthetic scaffolding and never real assessment
targets or a source of production security claims.

## 2. Immutable assessment scope

Policy MUST resolve through the existing profile engine with exact versions,
dependencies, cardinality and lifecycle rules. Tested architecture references
MUST equal the resolved nonillustrative architecture set. Requested properties
MUST be registered and provided by those architecture profiles; requested threats
MUST be registered in the unified threat model.

Each suite MUST bind the exact source and artifact digests, method, affected
profile references, properties, threats, tool/corpus identity, assessor and report.
Unknown profiles, mismatched release scope, duplicate suite IDs, future/stale
results or missing independent assessor identities fail validation. Every target
profile MUST have every method required by its assessment profile; an unrelated
profile's test results cannot fill a gap. Required property coverage MUST also be
present for each applicable target, and the declared threat set MUST be covered.

Black-box-only assessment MUST NOT establish internal software-integrity,
build-provenance, forward-secrecy or post-compromise state-erasure claims. Such
properties require internal/protocol examination and appropriately qualified
review in addition to observable behavioral checks.

## 3. Method requirements

External tests MUST exercise real supported interfaces and hostile peer/service
behavior. Source/internal review MUST inspect trust boundaries, key lifecycle,
error paths, concurrency, persistence and platform-specific behavior. Property
testing MUST specify invariants before generating cases and cover boundary/state
transitions; this version requires at least 100 generated cases, with a higher
policy floor permitted.

Fuzz evidence MUST bind the parser/state-machine targets, input/corpus and tool
configuration, campaign duration and case counts. Policies require at least 1,000
inputs and an explicit time floor. Coverage-guided fuzzers and applicable memory,
undefined-behavior or concurrency instrumentation SHOULD be used for production
implementations; a case-count floor does not prove adequate coverage.

Adversarial suites MUST cover declared service/network/credential/endpoint
capabilities and negative transitions, including downgrade, replay, unauthorized
enrollment, removal/rekey, rollback, malformed messages and resource exhaustion
where applicable. Protocol-model reports MUST pin the model, specification,
bounded explored state space, assumptions and counterexamples. This milestone
accepts bounded-model coverage only; PR 26 defines separate formal-verification
profiles, techniques and stronger proof scopes.

Failed, skipped, cancelled, flaky or unresolved-counterexample results MUST NOT
count as passing coverage. Minimized counterexamples MUST be preserved as
regressions, remediated and retested on the assessed source. Repeated execution
until a flaky failure disappears is not remediation. Evidence MUST disclose
limits, excluded platforms/interfaces, bounded models, untested threat assumptions
and the quality/qualification of external assessors.

## 4. Executable reference checks

`python scripts/run_reference_security_checks.py --seed 20261007 --iterations 1000`
runs bounded seeded malformed-input mutations against the six new evidence
validators, plus semantic checks against actual server recipient authorization,
DP lifetime composition and attachment nonce helpers. It retains deterministic
seed/iteration identity, a hash of code/schema/fixture inputs and a small failure
summary. `--output /absolute/path/report.json` saves an unsigned reference report.
CI runs the same fixed-seed campaign after repository validation and unit tests.

The runner is deliberately scoped to reference tooling. It is not coverage-guided
wire-protocol fuzzing, cryptographic implementation testing, independent audit,
full model checking or a product certificate. Its reports identify
`independent_assessment: false`; they cannot automatically populate an independent
assessment record. No test success implies an absence of unknown vulnerabilities.

## 5. Evidence authentication and assurance limits

The engine validates shape, configuration resolution, scope, freshness and the
method/property/threat coverage matrix. Content-addressed reports still require
authentication and substantive independent assessment. Declared case counts,
proof checks and assessor identities are not made true by JSON validation.
Synthetic fixtures are examples of the evidence contract, not completed audits.

PR 26 adds formal techniques; PR 27 defines assurance tiers; PRs 28–30 govern
certification evidence and lifecycle; PR 49 requires independent expert review
before the 1.0 release. These dependencies MUST NOT be replaced with an assertion
of full formal verification or no unknown vulnerabilities.

## 6. References

- [NIST SP 800-115, 2008 final](https://csrc.nist.gov/pubs/sp/800/115/final) — assessment planning and method context.
- [LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html) — production coverage-guided fuzzing example, not a mandatory implementation vendor.
- Repository threat, property, profile-resolution and secure-development specifications.
