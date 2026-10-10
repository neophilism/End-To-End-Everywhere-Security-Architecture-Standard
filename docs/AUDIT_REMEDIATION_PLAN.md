# E2EESA Audit Remediation: Development Plan and PR Register - Version 2

Date: 9 October 2026

Status: Revised planning baseline after Audit v2. Preparing this revision did not open, merge, or modify any GitHub pull request, code, deployment, or standard release. AUD and ROLL identifiers remain planning identifiers.

## Basis and review scope

This revision reconciles the supplied 49-page **E2EESA 0.9.0-rc.1 Audit v2 (corrected after external review)**, dated 9 October 2026, with the preceding remediation plan. The audited standard basis remains commit `dea8f54cab9130da86a71f36de553766a978daf2`, release `0.9.0-rc.1`. It does not make a new claim about the current head of the repository.

The prior review inspected central conformance, catalog, schema, identity, pairwise, serialization, and release sources and recorded a focused reproduction of the Unicode digest discrepancy. This reconciliation rechecked the conformance and pairwise specifications at the exact audited commit and consulted the relevant official Signal and RFC sources. It did not rerun the full repository validation pipeline, all seven solver experiments, or a downstream implementation audit. The 834-test run and the audit's complete experiment set remain reviewer-reported until separately reproduced and recorded.

All fifteen finding areas remain remediation targets. Acceptance of those targets is not agreement with every subsidiary empirical assertion, universal security guarantee, or proposed policy number in the audit. The interpretations below distinguish agreed design decisions from remaining implementation requirements.

## Planning baseline

Retain **26 upstream work packages**, including the optional PQ-MLS research package AUD-16. Retain ROLL-01 through ROLL-08 as **eight provisional inventory/adoption/monitoring slots**, not audited downstream estimates or guaranteed one-PR changes. This is a register of 34 slots including optional AUD-16, or 33 without it; it is not a prediction of the actual total PR count or of all remaining portfolio development.

The audit endorses inventory-first downstream planning, not the specific per-repository tasks. Each downstream slot must therefore be confirmed, resized, split, or removed after its component/data-flow inventory. Preserve the original planning ID as a parent if a slot is split. No new upstream package is needed solely to incorporate the v2 clarifications.

## Reconciliation decisions

| Audit item | Disposition for this plan | Owning packages |
|---|---|---|
| Finding 2 clarification | Accept that the prose drift test was supplementary, not the authoritative dependency mechanism. Typed, scoped all-of/any-of rules remain authoritative. | AUD-06, AUD-21 |
| Finding 4 clarification | Accept the clarified replacement-identity intent. Server-supplied predecessor linkage establishes neither control of the old identity nor freshness. Recovery with retained authority, replacement, and no recovery remain distinct. | AUD-08, AUD-09 |
| Finding 9 clarification | Accept that provisional status is not production approval. Preserve the additional exact Candidate promotion-state gate: provisional plus opt-in alone is insufficient for Candidate conformance. | AUD-07, AUD-16 |
| Findings 1-3 | Adopt component/data-flow classification, protected-content claim scope, typed dependencies, and removal of illustrative production profiles. A self-declared inventory is an input to assessment, not independent proof of its completeness. | AUD-04 through AUD-07 |
| Findings 5-7 | Adopt the corrected export rule, visible key changes, recovery exhaustion protections, and authenticated backup-generation transitions. Preserve the retained-old-copy limitation. | AUD-08 through AUD-12 |
| Finding 8 | Adopt explicit bounds, complete protocol pins, exact strength declarations, and versioned binding changes. Scope the PQ KEM floor to profiles with that role, not the classical X3DH profile. Treat seven/thirty days as the selected E2EESA policy, not a Signal mandate. | AUD-13, AUD-14 |
| Findings 9-10 | Require applied updates and complete key-path claims; keep PQ-MLS maturity gates and measured metadata limitations. Resolve the wake-only prose versus encrypted-payload enumeration before implementing push policies. | AUD-15 through AUD-17 |
| Findings 11-12 | Use one byte contract and versioned digest/signature definitions; preserve ordered arrays and historical artifacts. | AUD-02, AUD-03, AUD-23, AUD-24 |
| Finding 13 | Separate projected, authored, and independently reviewed coverage; track stale analysis. Text difference alone is not substantive analysis. | AUD-21, AUD-22 |
| Findings 14-15 | Model the security of each exact hybrid construction separately from lifecycle policy; preserve concrete parser/transport requirements and scoped evidence. | AUD-18 through AUD-20 |
| Audit summary, pages 46-48 | Correct residual instructions to regenerate historical attestations, assign one class to a repository, or assume all real families have at-most-one cardinality. The revised detailed rules govern this plan. | AUD-01, AUD-06, AUD-24 through AUD-26 |

### Residual implementation decisions to resolve in the owning PRs

**Candidate gate.** At the audited commit, `spec/conformance-engine.md` section 8 explicitly requires an exact PR 38 record with lifecycle state `candidate` for every effective provisional profile. A registration entry, draft citation, or opt-in does not create that record or its evidence. Preserve both this gate and the production rejection of provisional profiles. If the old ADR trigger requires broad deployment, do not label it satisfied merely by the existence of a working-group document; add a separate evaluation trigger with a new decision record.

**Pairwise scope and exposure.** Audit v2 page 23 says "the four pairwise profiles" must select a PQ KEM, while the audited specification's Profile A is classical X3DH plus Double Ratchet. The floor applies when a PQ KEM role exists. A recommended seven-day lifetime and thirty-day maximum can be selected as a versioned policy; deletion grace, delayed delivery, stale bundles, and retained private-key copies must also be addressed before claiming a bounded exposure window. Bind the exact selected parameter set even when multiple sets meet the same floor.

**Evidence-backed applicability.** Associate inventories with the evaluated build/source, relevant interfaces and storage schemas, recipient/key authority, and assessment evidence appropriate to the assurance tier. An empty or inconsistent inventory must not turn a protected-content component into process-only. Maintain dependencies at the consuming component/flow and explicitly discharge host responsibilities for reusable libraries. Preserve each family's actual cardinality.

**Export and push wording.** Separate none, wake-only, and encrypted-payload push modes. In encrypted-payload mode, define which recipients hold keys, which outer fields remain observable, and how the mode composes with endpoint-export rules. Encryption to a provider-controlled key is not protection from that provider. Correctly encrypted outputs remain subject to the declared metadata-leakage model; the word ciphertext is not an unconditional exemption. For intentional disclosure, bind authorization to identified items and recipients. A finite user-selected set may be represented as per-item authorization, but this is an explicit design clarification to approve and test, not an excuse for background exports or automatic future-content access.

**Coverage and claims.** An override different from boilerplate is not necessarily useful analysis; require requirement-specific threat/evidence reasoning and keep independent review separate. Likewise, the mere presence of a correlation-analysis digest must not remove limitations: its scope, model, residual bounds, and review must support the exact claim.

**Historical artifacts.** Regenerate active development fixtures and new candidate artifacts as needed. Do not rewrite old signed attestations, identity histories, status statements, or the rc.1 release manifest. Regeneration is not a promise that fixtures change only once during a multi-PR development cycle; every PR must retain meaningful passing checks.

## Non-negotiable design decisions

1. Configuration validity, a component implementation, scoped product conformance, and independent certification are different results.
2. Classes and capability declarations are evidence-backed; they do not let an applicant waive required protected-data controls.
3. Claims are bound to data flows, endpoints, threats, operations, exact versions, and evidence. Public data and intentionally authorized business processing are not mislabeled private E2EE.
4. Multiple serious architecture options remain explicit. Unsupported or research-only options cannot silently become production defaults.
5. Account recovery cannot silently inherit old cryptographic trust. Replacement identity and identity continuity are different events.
6. The endpoint export invariant prohibits unauthorized information disclosure, not legitimate ciphertext or correctly scoped cryptographic messages.
7. Digest/signature/wire changes are versioned. Historical signed artifacts and identity chains are not overwritten.
8. Passing reference fixtures or schema checks is not proof of deployed hardware, interoperability, a real cryptographic provider, or independent review.

## Upstream PRs

Each PR includes the necessary normative text, schema/registry updates, implementation/reference changes, positive and negative tests, documentation, and evidence-state updates. An OPTIONS marker denotes an explicit multi-option decision. External expert approval is tracked separately from implementation merges.

### AUD-01: Audit register, claim containment, and next-candidate governance

Audit findings: 1-3, 11-15. Dependencies: None.

**Scope.** Record the audit, verified observations, open questions, and reproduction cases. Preserve the immutable rc.1 basis. Introduce explicit next-candidate development/release semantics, not a disabled freeze check. Immediately correct projected-versus-analysed coverage labels and prevent unfinished candidate work from being advertised as production certification.

**Acceptance.** The archived rc.1 remains verifiable against its original commit; main is clearly identified as development toward a new candidate. Regression inputs and their expected corrected outcomes are checked in. Candidate status cannot become production eligibility solely because a fixture validates.

**V2 clarification and acceptance additions.** Use Audit v2 as the current finding narrative while retaining v1 and the prior review as provenance. Record evidence origin per claim: reported by reviewer, source-inspected, independently reproduced, implemented, or externally reviewed. Correct summary-level contradictions before turning audit prose into requirements. Preserve rc.1 byte identity and do not treat this review exchange as completion of the independent expert-release gate.

### AUD-02: Single canonical serialization contract and implementation

Audit findings: 11. Dependencies: AUD-01.

**Scope.** Add spec/canonical-serialization.md and a shared, tested canonicalization module. Define an RFC 8785-based restricted data model, duplicate-key rejection at parse time, invalid-Unicode/nonfinite-number rejection, safe integer bounds, and exact decimal representations. Sort only explicitly set-valued fields before canonicalization; preserve ordered arrays. Migrate active call sites without rewriting legacy artifacts.

**Acceptance.** Non-ASCII, non-BMP key ordering, duplicate keys, integer boundaries, decimal precision, and ordered/set-valued arrays have golden vectors. Every active digest owner uses the shared contract. Historical encodings remain explicitly versioned and cannot be silently accepted as new encodings.

### AUD-03: Versioned digest and signature-input contracts

Audit findings: 12, 14e. Dependencies: AUD-02.

**Scope.** Specify domain separators, field inclusion/exclusion, schema versions, signature algorithms/contexts, and exact bytes for identity events/states and all content-addressed assessment objects. Add explicit serialization/digest scheme identities and migration rules.

**Acceptance.** Every construction has positive and negative vectors. Cross-context substitution fails. The same input produces identical bytes in independent implementations. Old identity histories and signatures are verified under their original scheme rather than regenerated.

### AUD-04: Separate production profiles from illustrative fixtures

Audit findings: 3. Dependencies: AUD-01.

**Scope.** Move illustrative families and profiles into an explicitly loaded development catalog. Exclude them from production property providers, profile counts, coverage denominators, and attestations. Inventory duplicate validators and remove a confirmed unused alternate implementation after checking real CLI/import entry points.

**Acceptance.** No illustrative profile can appear in a passing production assessment, including via dependencies. Production counts exclude examples. Removing obsolete code does not remove a supported entry point or its tests.

### AUD-05: Composable product classes, roles, and protected-data inventories [OPTIONS]

Audit findings: 1. Dependencies: AUD-04.

**Scope.** Add a versioned product-class registry plus component roles and data-flow declarations. Cover endpoints, ciphertext services, reusable components, public-data services, and process-only assessments. Derive mandatory requirements from roles, enabled capabilities, recipients, and data classification; allow mixed applications without classifying a whole repository as one messenger.

**Acceptance.** Mixed public/private applications and endpoint/service combinations have valid examples. A protected-content system cannot obtain an E2EE claim by declaring process-only. Unknown classes and unsupported capabilities yield explicit non-assessment or failure, never automatic exemption.

**V2 clarification and acceptance additions.** The inventory must be bound to the evaluated source/build and supported by relevant code/interface/storage/egress evidence; it is not proof merely because it is present in JSON. Add a negative test for an inventory that omits a demonstrated protected flow. A reusable library can declare explicit host obligations rather than pretending to implement a full endpoint or satisfying its dependencies through an unrelated service.

### AUD-06: Scope-aware exact, family, AND, and OR dependencies [OPTIONS]

Audit findings: 2. Dependencies: AUD-04, AUD-05.

**Scope.** Extend schemas, resolver, solver, and conformance logic with typed dependency rules and alternatives. Encode existing normative relationships using requirement IDs. Satisfy dependencies in the correct endpoint/service boundary, not with unrelated profiles elsewhere in a product. Preserve meaningful no-backup/offline/component cases.

**Acceptance.** All seven forbidden-family cases in the audit become unsatisfiable where their requirements apply. An authenticated pairwise OR group channel satisfies attachment delivery only in the correct scope. Missing dependencies are explained with rule provenance; no weaker choice is selected silently.

**V2 clarification and acceptance additions.** Preserve actual cardinalities including many-valued formal-verification and advisory families, with cardinality checked in the correct component scope. Reject cross-component dependency laundering. The optional prose drift test is explicitly supplemental; it never determines conformance or silently changes the dependency graph.

### AUD-07: Scoped security claims and production-conformance eligibility

Audit findings: 1-3, 9. Dependencies: AUD-03, AUD-05, AUD-06.

**Scope.** Bind each claim to component, operation/data flow, property, threats, time, profile, and evidence. Separate configuration validity, component conformance, process conformance, product conformance, and certification eligibility. Bind an approved standard basis and applicable assurance requirements. Keep mock/reference evidence distinct from real implementation evidence.

**Acceptance.** Empty/scaffolding-only and TLS-only configurations cannot earn an E2EE-content claim. Pairwise PQ evidence cannot certify group traffic. A component's success cannot certify its host product. Missing, mismatched, unsupported, or conditional evidence never becomes an unqualified pass.

**V2 clarification and acceptance additions.** Bind each provisional profile to its exact Candidate promotion record and required evidence before any Candidate pass. Add separate regressions for provisional-with-opt-in-but-no-Candidate-record, Candidate-with-incomplete-evidence, and provisional-under-production-policy. A content-family selection elsewhere in a product cannot establish protection for an unprotected flow.

### AUD-08: Identity loss, recovery authority, and replacement identities [OPTIONS]

Audit findings: 4. Dependencies: AUD-03, AUD-05, AUD-06.

**Scope.** Define total-loss behavior and distinguish recovery using previously authorized retained cryptographic authority from creation of a replacement, initially unverified identity. Include explicit no-recovery, retained high-entropy authority, and pre-authorized threshold-contact options, with implementation/review maturity gates. Treat delayed account-gated replacement as discontinuity, never inherited cryptographic authority.

**Acceptance.** Account takeover, support override, forged/stale reset events, missing trusted history, revoked recovery authority, and concurrent reset races cannot transfer old verified trust or group membership. Backup restoration remains a separate action after device authorization. No unsupported new cryptographic protocol is promoted by registry presence.

**V2 clarification and acceptance additions.** Treat any server-supplied historical link as untrusted until the selected retained-view/transparency mechanism establishes the claimed property. A delay is a disclosed replacement policy, not proof of identity. Test revocation propagation and offline peers explicitly; an account record update must not be reported as global cryptographic revocation or erasure. No previous group membership transfers automatically to a replacement identity.

### AUD-09: Key-change visibility and send/reverification state machine [OPTIONS]

Audit findings: 6. Dependencies: AUD-08.

**Scope.** Track and surface verification-subject changes for both verified and unverified peers. Distinguish routine authorized changes from identity replacement. Define explicit acknowledgement and stricter re-verification policies, queued-message handling, accessibility, and auditable notice history.

**Acceptance.** A previously verified subject change blocks sending according to the selected policy and clears verified status until re-verification. Queued content is not silently re-encrypted to a changed recipient. Notice presentation may be usable without losing or concealing security events.

### AUD-10: Endpoint export boundary and explicit disclosure paths

Audit findings: 5. Dependencies: AUD-05, AUD-07.

**Scope.** Make protected-content-derived disclosure to non-recipients a core security boundary. Cover classifiers, embeddings, content hashes, previews, search indexes, diagnostics, and provider integrations. Explicitly distinguish encrypted outputs and protocol metadata from plaintext-derived leakage. Declare recipients, allowed leakage, and intentional disclosure workflows; do not allow automatic recipient expansion by relabeling a service.

**Acceptance.** Egress inspection covers success, failure, crash, retry, analytics, and background paths. Undeclared content-derived exports fail. Legitimate ciphertext transport still works. Intentional reporting/publication has scoped authorization and cannot silently cover future unrelated content.

**V2 clarification and acceptance additions.** Scope ciphertext/tag exemptions to the selected cryptographic construction and authorized recipients, preserving metadata-leakage limits. Generalize recipient presentation to files and business workflows as well as conversations. Record the finite user-selected batch-disclosure interpretation as a design decision; prohibit background, policy-triggered, or future-content exports to undeclared recipients. Test rejected recipient relabeling and provider-key encryption attempts.

### AUD-11: Hardware recovery attempt budgets and attestation evidence [OPTIONS]

Audit findings: 7. Dependencies: AUD-08.

**Scope.** Replace boolean-only assurances with attempt budgets, enforcement boundary, replication/rollback policy, attested code identity, and release policy. Define guarantees for low-entropy and high-entropy recovery inputs separately. Model malicious exhaustion of the recovery budget as an availability threat.

**Acceptance.** Snapshot restore, added replicas, modified code, support intervention, and front-end bypass cannot reset a protected guess budget. Counter exhaustion behavior is tested, including denial-of-service exposure and separately authorized recovery alternatives. A true flag is never treated as hardware evidence.

**V2 clarification and acceptance additions.** Use explicit attempt-initiation authorization and exhaustion policy, including separately authorized alternatives. Test a malicious service bypassing its own front end as well as unauthenticated exhaustion. Hardware identity, code measurement, approved policy, replica authority, and persistent budget evidence are distinct inputs; booleans cannot stand in for them.

### AUD-12: Recovery credential rotation and retained-copy semantics

Audit findings: 7. Dependencies: AUD-03, AUD-11.

**Scope.** Require an authenticated generation transition and fresh backup data-encryption key for recovery credential rotation. Define how new snapshots are encrypted and how retained historical envelopes are handled. Separate server-hosted recoverable backups from local-only vault credential management where assumptions differ.

**Acceptance.** Old credentials cannot unlock newly generated backup state. The system makes no claim that changing credentials revokes already retained old ciphertext. Salt changes alone are not accepted as proof of key rotation or secret change.

**V2 clarification and acceptance additions.** Authenticate the credential-generation transition and test actual fresh backup-key generation and new-ciphertext behavior. Merely incrementing a manifest counter is not evidence that keys changed. Do not publish raw secret material in evidence.

### AUD-13: Pairwise operational bounds and explicit strength policies [OPTIONS]

Audit findings: 8. Dependencies: AUD-06.

**Scope.** Add signed/last-resort prekey lifetimes, deletion grace, stock policy, replay/exhaustion observations, and offline behavior. Make missing PQ material fail closed. Use an explicit recommended ML-KEM strength policy and separately labelled constrained/interoperability choices where justified, rather than presenting an approved lower parameter set as inherently broken.

**Acceptance.** Expired/exhausted/stripped bundles and missing PQ keys have negative cases. Retention and availability tradeoffs are visible. Strength claims match the selected parameter set. Any seven-day bound is a named policy choice, not an unsupported universal security theorem.

**V2 clarification and acceptance additions.** Apply the PQ KEM floor only to PQXDH-based profiles and other roles that actually use a PQ KEM; preserve the explicitly classical X3DH profile. Use seven days recommended and thirty days maximum as the proposed versioned recommended-policy values, with rationale and a separately bounded deletion-grace policy. Test expired public bundles, delayed messages, clock uncertainty, long-offline behavior, and inappropriate private-key retention. Record the exact selected KEM; do not silently tighten an old profile identifier.

### AUD-14: External protocol pins and PQXDH binding interoperability

Audit findings: 8. Dependencies: AUD-03, AUD-06.

**Scope.** Pin the ML-KEM Braid companion specification and its dependencies by exact revision/content identity. Verify the exact selected KEM's required PQXDH binding behavior. Add protocol vectors and mutation tests; any additional authenticated-data convention receives a new explicit binding/profile version rather than changing the meaning of an existing pin.

**Acceptance.** Wrong prekeys, ciphertext substitution, wrong protocol revision, and incompatible bindings fail. Independent endpoints interoperate on the exact accepted bytes. Existing external test-vector guarantees are not claimed to cover a modified construction without validation.

**V2 clarification and acceptance additions.** Retain the pinned PQXDH-required binding as an explicit supported convention. Any additional unconditional binding uses a separate convention/profile version with exact bytes, reviewed rationale, vectors, and a mixed-version rejection case. Absence of an extra convention must not be portrayed as a demonstrated flaw in correctly implemented current PQXDH.

### AUD-15: Group update cadence and flow-specific quantum/PCS claims [OPTIONS]

Audit findings: 9. Dependencies: AUD-07, AUD-13, AUD-14.

**Scope.** Define applied update/commit freshness, sender-state rotation, offline/stale-member handling, and actual healing conditions. Separate direct-message, group-message, media, attachment, and backup quantum claims. Assess conditional sender-key/fanout confidentiality only over all relevant distribution and recovery paths.

**Acceptance.** An uncommitted proposal or a timer reset does not establish healing. Stale group state loses unsupported claims. Classical group traffic cannot inherit a pairwise PQ label. Membership changes, compromise, and rejoin paths have adversarial cases.

### AUD-16: Optional research track: pinned PQ/hybrid MLS profiles [OPTIONS]

Audit findings: 9, 14a. Dependencies: AUD-14, AUD-15, AUD-18.

Optional research track; not a prerequisite for correcting existing conformance behavior.

**Scope.** Evaluate draft-ietf-mls-pq-ciphersuites-06 and its complete dependency chain, including KEM/signature identifiers and codepoint status. Define experimental or candidate-only profiles only after the appropriate lifecycle gates; preserve a separate promotion decision.

**Acceptance.** Presence of a working-group draft does not imply broad deployment or production approval. Unassigned identifiers are not invented as standards identifiers. Omitting this optional track does not block repair of existing production-scope claims.

**V2 clarification and acceptance additions.** Registering a provisional suite does not grant Candidate conformance: require the exact PR 38 Candidate lifecycle record and its entry evidence. When those gates are unmet, report research/registration status only. Revise or supplement the ADR evaluation trigger rather than asserting that draft publication demonstrates broad deployment. This remains a separately gated optional research package.

### AUD-17: Push-provider and response-correlation metadata models [OPTIONS]

Audit findings: 10. Dependencies: AUD-05, AUD-07, AUD-10.

**Scope.** Add push providers, timing, routing tokens, and automatic responses to observer/claim models. Specify wake-only and, where justified, opaque encrypted-payload modes. Keep response delay/batching/no-receipt options explicit and privacy-tested; do not advertise jitter as proof of anonymity.

**Acceptance.** Payload captures contain no undeclared content or plaintext relationship identifiers. Token cross-service reuse and timing correlation are tested. Documented observer limitations survive into conformance output and public claims.

**V2 clarification and acceptance additions.** Resolve the audit's push-mode contradiction: wake-only constrains payloads to wake/routing information; encrypted-payload is a separate mode with exact protected fields, intended endpoint recipients, key isolation from the provider, and observable outer metadata. Add a negative case for plaintext identifiers and provider-decryptable payloads under a provider-confidentiality claim. A response-correlation report must justify the resulting limited claim; its digest alone changes no privacy verdict.

### AUD-18: Algorithm, external-standard, and version identity registry repair [OPTIONS]

Audit findings: 14. Dependencies: AUD-03, AUD-14.

**Scope.** Add exact hybrid mechanism identifiers and composition assumptions; distinguish lifecycle policy from cryptographic robustness. Add selected SLH-DSA signing options only for specified roles/encodings with valid identifiers and vectors. Reconcile SPDX 2.3/3.0 and other external pins. Make release label, basis, schema, profile, and digest identities explicit. Review HKDF status and Argon2 parallelism rationale.

**Acceptance.** A robust hybrid's claim is not computed with a generic weakest-component rule. Unsupported signing encodings fail. SBOM output validates against the exact named specification. External PKI has explicit algorithm/trust requirements rather than an unbounded registry exemption.

**V2 clarification and acceptance additions.** The or-secure property belongs to a specific reviewed combiner, protocol context, assumptions, and threat/property claim. It is not inferred for an arbitrary pair of algorithms or for all properties of a hybrid deployment. Preserve independent lifecycle restrictions and explicit limits on authentication, compromise, and implementation assumptions.

### AUD-19: Parser isolation and client security boundary evidence [OPTIONS]

Audit findings: 15a. Dependencies: AUD-10.

**Scope.** Define native and web isolation mechanisms, least-privilege parser processes/sandboxes, validated IPC, keystore exclusion, network/egress restrictions, and crash behavior. Prefer memory-safe implementations where feasible. A memory-safe wrapper or a worker name does not by itself qualify as isolation.

**Acceptance.** Malicious media/document inputs cannot reach keys or unauthorized network outputs through the parser boundary. Supported platforms have concrete boundary tests and fuzzing. Unsupported isolation is reported as a limitation, not inferred from language choice.

### AUD-20: Transport, external PKI, CT, and ECH profiles [OPTIONS]

Audit findings: 15b-15d, 14c. Dependencies: AUD-17, AUD-18.

**Scope.** Separate certificate-path validation from RFC 9525 service-identity verification. Use the selected platform's supported CT policy/enforcement. Pin RFC 9849 ECH and model fallback plus residual DNS/IP/timing visibility. Retain the hybrid-only rule within the current hybrid TLS profile; any pure-PQ alternative is a separate reviewed choice.

**Acceptance.** Invalid paths, wrong identities, applicable CT failures, and ECH downgrade cases are tested. Private PKI is not forced into irrelevant public CT rules. Unsupported custom CT-log scraping is not introduced as a universal client requirement.

### AUD-21: Requirement-level traceability infrastructure

Audit findings: 13. Dependencies: AUD-01, AUD-03.

**Scope.** Add requirement-specific rationale/crosswalk overrides, stable logical identifiers with content versions, reviewer status, and distinct projected/authored/reviewed coverage. Add typed dependency references instead of treating prose regular expressions as the dependency source of truth.

**Acceptance.** Boilerplate projection never counts as individual analysis. Editing a requirement invalidates or flags its old analysis; orphaned overrides and unresolved normative dependency references fail validation.

**V2 clarification and acceptance additions.** Different text is only a duplicate-detection signal. Authored status requires the stated requirement-specific rationale, threat, evidence, and relation fields; independently reviewed status requires a separate attributable review record for the exact content and relevant dependency versions. Invalidate or flag reviews when their supporting context changes, not only when the requirement paragraph changes.

### AUD-22: Core requirement-by-requirement analysis

Audit findings: 13. Dependencies: AUD-21, AUD-07, AUD-08, AUD-10, AUD-12, AUD-15, AUD-18, AUD-20.

**Scope.** Author individual rationale, threat/property links, dependencies, external references, evidence expectations, and verification status for the thirteen core areas named in the audit. Recount the actual changed corpus rather than freezing the audit's historical counts.

**Acceptance.** Every current core requirement has substantive analysis; external reviewer approval is a separate state. Content coverage and review completion are reported independently. Open security questions remain explicit release gates.

### AUD-23: Cross-implementation corpus and adversarial composition tests

Audit findings: 1-3, 7-12. Dependencies: AUD-02, AUD-03, AUD-06, AUD-07, AUD-09, AUD-12, AUD-14, AUD-15, AUD-17, AUD-19, AUD-20.

**Scope.** Regenerate development fixtures under the new identities and build cross-language golden-byte tests, solver/resolver/conformance agreement cases, composed end-to-end flows, and malformed-input/property tests. Preserve historical real attestations and fixture provenance. Document that pairwise profile combinations alone do not prove full-system interoperability.

**Acceptance.** The audit's core regressions fail closed. At least two independent implementations agree on new canonical and signed bytes. Retained old artifacts are checked under old versions. Claimed integration tests exercise real providers or clearly declare mocks.

### AUD-24: SDK/integration contract and migration package

Audit findings: 11-12, rollout. Dependencies: AUD-07, AUD-18, AUD-23.

**Scope.** Update integration schemas and examples for SDK/evaluator consumers. Publish migration guidance for standard/profile locks, canonicalization, identity history, evidence, and claims. Pin exact manifests and document incompatible versions and supported legacy read/verify paths.

**Acceptance.** A downstream project can consume the new contract without reverse-engineering Python source. Mixed-version inputs fail clearly. No migration rewrites signed historical evidence or silently changes recipient authority.

**V2 clarification and acceptance additions.** Migration instructions must consistently say components and flows, not one class per repository, and regenerated development artifacts, not rewritten historical attestations. Publish machine-readable distinctions among claim result class, lifecycle, assurance, implementation, and deployment state.

### AUD-25: Source-backed public standards portal and assessor guidance

Audit findings: 1-3, 9, 13-15. Dependencies: AUD-21, AUD-24.

**Scope.** Generate product-class/role guidance, profile dependencies, limitations, scoped claims, coverage definitions, review status, and migration guidance from authoritative repository data. Present component/process/production scope clearly for nontechnical readers.

**Acceptance.** Portal statements match current registries and evidence. No generic green badge claims more than the evaluated boundary. Production and illustrative counts remain separate, and accessibility/navigation tests pass.

**V2 clarification and acceptance additions.** Render the scope and evidence state explicitly; do not substitute a single universal green status for component/process/protected-content claims. Recount many-valued families and production-only coverage from authoritative data rather than copying old audit counts.

### AUD-26: New candidate freeze and independent-review handoff

Audit findings: All accepted findings. Dependencies: AUD-22, AUD-23, AUD-24, AUD-25.

**Scope.** Create a new immutable candidate, expected to be 0.9.0-rc.2 subject to the approved versioning policy. Preserve rc.1 unchanged. Publish updated manifests, migration notes, test outputs, finding dispositions, open questions, and expert-review instructions. Exclude optional AUD-16 profiles unless their lifecycle requirements are satisfied.

**Acceptance.** Repository/schema validation, freeze verification, unit/integration/interoperability and adversarial tests pass on the exact candidate. Hardware/field/expert evidence is recorded separately. Candidate publication does not itself authorize 1.0 or product certification.

**V2 clarification and acceptance additions.** Freeze 0.9.0-rc.2 as a distinct immutable candidate after the applicable gates, keeping the original rc.1 and its historical verification rules intact. Include a v2 disposition checklist for the precise residual issues in this plan. All three core audit demonstrations must have recorded reproduction/regression outcomes before their remediation is marked verified.

## Provisional downstream and monitoring slots - inventory first

### ROLL-01: Engine-Room - Portfolio inventory and live scoped status

Dependencies: Inventory design can begin with AUD-05; finalized scoped-status publication requires AUD-07, AUD-24, AUD-25.

Inventory each project's roles, protected/public flows, pinned basis, implementation state, conformance result, review state, deployment state, and evidence freshness. Read authoritative artifacts rather than inferring security from README wording or merged PR totals. Not assessed, not applicable, stale, and failed remain distinct.

**V2 clarification and acceptance additions.** Start factual inventory collection before estimating ROLL-02 through ROLL-08; it need not wait for rc.2. Record component/flow-specific host obligations and uncertain boundaries. Formal claim publication still waits for the finalized assessment contracts and evidence. Do not infer implementation from an inherited standard lock, README statement, or merged-PR count.

### ROLL-02: End-To-End-Everywhere-Suite - New serialization, digest, profile, and evidence bindings

Dependencies: AUD-24, AUD-26.

Migrate active contracts and reference outputs with cross-language vectors while retaining explicit legacy verification/read paths. Prove that existing encrypted state is not silently rendered unreadable by a version change.

**V2 clarification and acceptance additions.** Before confirming this scope or estimating effort, complete the target repository's current component/data-flow inventory under ROLL-01 or an equivalent reviewed inventory. The task is a candidate integration, not a downstream audit finding. Split or remove it when the inventory warrants; preserve the parent planning ID and evidence of the decision.

### ROLL-03: End-To-End-Everywhere-Suite - Implement selected identity, recovery, and endpoint policies

Dependencies: ROLL-02, AUD-08, AUD-09, AUD-10, AUD-11, AUD-12, AUD-19.

Wire supported policies into actual client/key-store/recovery boundaries. Keep unimplemented alternatives disabled. Validate adversarial transitions and egress; mocks and policy declarations do not become implementation evidence.

**V2 clarification and acceptance additions.** Before confirming this scope or estimating effort, complete the target repository's current component/data-flow inventory under ROLL-01 or an equivalent reviewed inventory. The task is a candidate integration, not a downstream audit finding. Split or remove it when the inventory warrants; preserve the parent planning ID and evidence of the decision.

### ROLL-04: Distributed-Audio-Engine - Migrate encrypted-media/control contracts and scoped claims

Dependencies: AUD-24, AUD-26.

Update canonical/control/attachment bindings and the standard lock; test compatibility, replay, substitution, tenant separation, and actual component claim scope. Preserve intentional public metadata versus protected media distinctions.

**V2 clarification and acceptance additions.** Before confirming this scope or estimating effort, complete the target repository's current component/data-flow inventory under ROLL-01 or an equivalent reviewed inventory. The task is a candidate integration, not a downstream audit finding. Split or remove it when the inventory warrants; preserve the parent planning ID and evidence of the decision.

### ROLL-05: Distributed-Audio-Engine - Authenticated parent/key-channel vertical integration

Dependencies: ROLL-04, ROLL-02.

Integrate a selected real authenticated key-distribution channel with the endpoint codec, including enrollment/revocation and negative recipient tests. Scope this to a tested vertical slice; unsupported channels and native/hardware qualification remain explicit gaps.

**V2 clarification and acceptance additions.** Before confirming this scope or estimating effort, complete the target repository's current component/data-flow inventory under ROLL-01 or an equivalent reviewed inventory. The task is a candidate integration, not a downstream audit finding. Split or remove it when the inventory warrants; preserve the parent planning ID and evidence of the decision.

### ROLL-06: SceneSignal - Role/data-flow manifest and adoption gates

Dependencies: ROLL-04, AUD-26.

Map venue, participant, operator, location, permit, and media boundaries. Add the selected security contract and tests as application code develops. A policy-only manifest remains architecture-adopted, not implemented.

**V2 clarification and acceptance additions.** Before confirming this scope or estimating effort, complete the target repository's current component/data-flow inventory under ROLL-01 or an equivalent reviewed inventory. The task is a candidate integration, not a downstream audit finding. Split or remove it when the inventory warrants; preserve the parent planning ID and evidence of the decision.

### ROLL-07: Distributed-Radio-Engine - Role/data-flow manifest and adoption gates

Dependencies: ROLL-04, AUD-26.

Separate private programming/media, delivery, public station information, reward verification, and commerce facts. Define narrowly authorized processors without making them silent media recipients. Keep component and application claims separate.

**V2 clarification and acceptance additions.** Before confirming this scope or estimating effort, complete the target repository's current component/data-flow inventory under ROLL-01 or an equivalent reviewed inventory. The task is a candidate integration, not a downstream audit finding. Split or remove it when the inventory warrants; preserve the parent planning ID and evidence of the decision.

### ROLL-08: TrackZero - Client identity, reward/privacy, and adoption gates

Dependencies: ROLL-07, AUD-26.

Bind the consumer application to the radio engine's scoped contract, including actual endpoint authority, consent and reward-data disclosures. Until executable integrations and evidence exist, report pending rather than inherited conformance.

**V2 clarification and acceptance additions.** Before confirming this scope or estimating effort, complete the target repository's current component/data-flow inventory under ROLL-01 or an equivalent reviewed inventory. The task is a candidate integration, not a downstream audit finding. Split or remove it when the inventory warrants; preserve the parent planning ID and evidence of the decision.

## Sequencing and merge policy

Start with AUD-01 through AUD-07. After the common contracts stabilize, identity/recovery, mechanism hardening, endpoint/privacy, and traceability work can proceed in parallel on their stated dependencies. AUD-21 can start early after AUD-03; AUD-16 remains isolated. Conclude with AUD-22 through AUD-26. Update affected development fixtures with each change rather than leaving CI broken until the end; freeze the final release artifact only after the complete candidate passes.

Independent development unrelated to these interfaces can continue throughout. Downstream inventory and implementation work may begin against explicitly labelled development contracts, but must not advertise conformance to an unfinished candidate. The downstream dependencies above identify the baseline needed before final migration claims are accepted; a current inventory is an additional scope-confirmation gate for every downstream slot.

Use sequential or short stacked PR chains. Merge only when required checks and applicable review rules pass; do not bypass branch protections, unresolved conflicts, security review requirements, or missing material decisions. Update the finding register and Engine Room as evidence changes.

## Required regression outcomes

- The scaffolding-only product and unsupported scope exemptions cannot obtain production E2EE eligibility.
- The audit's seven dependency-omission cases fail in the applicable roles, while valid alternatives and component/offline cases remain possible.
- Unicode and exact-number data yield interoperable bytes, and malformed input is rejected before hashing.
- Account takeover cannot inherit verified identity; revoked devices and changed recipients cannot receive newly protected content silently.
- Hardware rollback/replica creation cannot refresh a guess budget; old credentials do not unlock new backup generations.
- Pairwise PQ protection cannot certify classical group traffic; update proposals without applied commits do not count as healing.
- Undeclared endpoint-derived exports and misleading metadata claims fail evaluation.
- The public portal and Engine Room distinguish implemented, assessed, reviewed, deployed, stale, failed, and not-applicable states.

## Evidence and release gates

For each finding, record disposition, affected requirements, PRs, regression tests, proof/measurement references where applicable, reviewer state, and remaining limitations. A new candidate requires all relevant repository, schema, resolver, conformance, interoperability, unit, integration, and adversarial checks on the exact manifest. Full core analysis coverage is a separate metric from reviewer completion. Independent cryptographic/protocol review, real hardware qualification, and production deployment evidence remain explicit gates where the selected claims require them.

## Source and evidence register

The prior plan is preserved unchanged as `E2EESA-Audit-Remediation-Development-Plan.md`. This file is its v2 planning successor; neither document modifies Claude's audit PDF.

| Reference | Locator and role |
|---|---|
| Audit v2 | `Untitled-1(1).pdf`, 49 pages, dated 9 October 2026; corrections on pp. 1-2, component scope pp. 6-8, dependencies p. 11, reset pp. 13-15, export p. 16, pairwise pp. 22-24, Candidate/group pp. 25-26, push p. 28, serialization pp. 30-32, coverage pp. 35-36, hybrid p. 36, rollout pp. 46-48. |
| Earlier plan | `E2EESA-Audit-Remediation-Development-Plan.md`; preserved planning identifiers and original source-review scope. |
| Pinned conformance specification | Repository `neophilism/End-To-End-Everywhere-Security-Architecture-Standard`, commit `dea8f54cab9130da86a71f36de553766a978daf2`, `spec/conformance-engine.md`, sections 2 and 8: Candidate policy and exact promotion-state binding. Rechecked in this reconciliation. |
| Pinned pairwise specification | Same repository/commit, `spec/pairwise-e2ee.md`, sections 7-10: classical Profile A versus three PQXDH-based profiles. Rechecked in this reconciliation. |
| Signal PQXDH | Revision 3, last updated 2024-01-23, sections 3.2-3.3: periodic prekeys, deletion grace, and associated-data construction. Consulted for the policy/binding distinction. |
| Signal ML-KEM Braid | Revision 1, 2025-02-21, last updated 2025-09-26. Official document consulted; any implementation pin must also preserve exact source identity. |
| RFC 9849 | TLS Encrypted Client Hello. Official RFC consulted; pin supports AUD-20 without establishing product implementation. |
| RFC 10024 | Post-Quantum Traditional Hybrid Key Agreement Mechanisms for TLS 1.3. Official RFC consulted for construction-specific hybrid security. |

### Local source identities

- Audit v2 PDF SHA-256: `74685298eace3e5b3752541a197f42bde029819033613739e0460d31643b1958`
- Preserved prior-plan SHA-256: `774ad5464722cadcf1fc45a10802026fe44cad2ba993c8fc8eda3a5907f3d834`

These identify the local source bytes used to prepare this plan; they are not certifications, external review signatures, or evidence that code was changed.