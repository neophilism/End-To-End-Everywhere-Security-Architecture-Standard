# Key Transparency

**Status:** Normative

This document defines E2EESA Key Transparency (KT) profiles for detecting inconsistent, unauthorized, or rolled-back views of cryptographic identity-directory state. E2EESA 0.1 does not invent a new transparency primitive. It pins the current IETF Key Transparency architecture and protocol drafts and adds E2EESA-specific binding to the canonical verification subject defined by PR #11.

## 1. Core invariant

A service that distributes cryptographic identity state **MUST NOT** be able to present long-lived inconsistent key-directory views to honest participants without detection under the assumptions of the selected Key Transparency deployment profile.

A successful KT lookup establishes consistency of the cryptographic directory value according to the selected KT threat model. It does not, by itself, prove a person's real-world identity.

## 2. Pinned protocol

E2EESA 0.1 pins:

- `draft-ietf-keytrans-protocol-05`, published July 2026; and
- `draft-ietf-keytrans-architecture-09`, published June 2026.

The E2EESA protocol identifier is `KEYTRANS-IETF-05`.

These are active Internet-Drafts. Their use here is therefore **provisional**. A future IETF draft or RFC that materially changes protocol semantics **MUST** receive a new E2EESA protocol identifier. An implementation **MUST NOT** silently treat a later draft as equivalent to `KEYTRANS-IETF-05`.

## 3. Cipher suites

E2EESA 0.1 recognizes the two cipher suites defined by the pinned protocol draft:

- `0x0001 KT_128_SHA256_P256` — allowed;
- `0x0002 KT_128_SHA256_Ed25519` — recommended.

The selected cipher suite **MUST** be fixed for the transparency log configuration and **MUST** be recorded in conformance evidence.

## 4. PR #11 verification-subject binding

The application value stored for an E2EESA cryptographic identity **MUST** commit to the exact `subject_digest_hex` produced by PR #11 for the identity/key subject being distributed.

A client accepting a lookup **MUST** verify that the value authenticated by KT corresponds to the exact currently expected PR #11 subject digest.

KT **MUST NOT** reinterpret or replace PR #11's canonical subject construction.

A successful KT result MAY be attached to a PR #11 verification record through its transparency-evidence reference, but it **MUST NOT** be represented as proof that a user manually compared a safety number or QR code.

## 5. Privacy mechanisms

The selected KT protocol profile **MUST** use the protocol's VRF mechanism to conceal labels in the authenticated tree and the protocol's commitment mechanism to hide application values from parties that do not possess the opening.

A conforming E2EESA KT deployment **MUST NOT** replace VRF label privacy with a plain unsalted hash of a user identifier.

The service MAY enforce application-level access control on searches and updates, subject to the monitoring requirements of the selected deployment mode.

## 6. Tree-head verification

Every accepted verification cycle **MUST** cryptographically verify the current tree head under the key and configuration associated with the selected deployment mode.

The tree head **MUST** be rejected when:

- its signature is invalid;
- its timestamp exceeds the configured `max_ahead_ms`;
- its timestamp is older than the configured `max_behind_ms`;
- its tree size is smaller than the retained prior tree size;
- the same tree size is presented with a different root; or
- the client detects an otherwise inconsistent fork or rollback.

## 7. Search proof

A successful lookup **MUST** verify:

- all required VRF proofs;
- the value commitment opening;
- the search or greatest-version proof;
- the combined inclusion/consistency proof required by the pinned protocol;
- the claimed greatest version of the label; and
- the mapping between the authenticated value and the expected PR #11 subject digest.

A client **MUST NOT** accept a service-provided key merely because the service returns a syntactically valid directory response.

## 8. Persistent checkpoints

Except where explicitly relaxed by the Third-Party Management profile, clients **MUST** retain enough authenticated state to detect rollback or fork behavior across verification cycles.

The E2EESA reference checkpoint contains:

- log identifier;
- tree size;
- tree root;
- tree timestamp;
- PR #11 subject digest; and
- greatest observed label version.

For a non-first observation, the client **MUST** prove consistency from the retained prior checkpoint before accepting the new state.

If a non-first observation lacks the checkpoint required by the selected profile, the client **MUST NOT** silently treat it as a first observation.

## 9. Owner monitoring

A label owner **MUST** monitor its own label according to the pinned protocol so that unauthorized new versions, removal/obscuring of prior versions, or incorrect update sequencing can be detected.

Applications SHOULD perform owner monitoring automatically in the background whenever durable client operation makes this practical.

Failure to complete required owner monitoring **MUST** prevent a conformance result from being represented as current.

## 10. Profile A — Contact Monitoring

Profile reference: `kt-contact-monitoring@0.1.0`

This profile uses the IETF Contact Monitoring deployment mode without an independent third party.

It requires:

- durable client checkpoint persistence;
- regular owner monitoring;
- contact monitoring when a recent lookup creates a monitoring obligation;
- fork detection through an anonymous route to the transparency service, peer-to-peer gossip, or both; and
- retention of monitoring state until the relevant label-version pair is sufficiently anchored by the protocol's distinguished-log mechanism.

A required contact-monitor operation **MUST** be completed before the lookup can be treated as fully monitored.

Because no independent third party exists, the deployment's anti-fork security depends materially on state continuity and out-of-band/partition-resistant fork detection.

## 11. Profile B — Third-Party Auditing

Profile reference: `kt-third-party-auditing@0.1.0`

This is a recommended profile for stateful native clients.

The service operator runs the transparency log and one or more independent auditors attest to the correctness of authenticated tree state.

The policy **MUST** specify:

- number of independent third parties;
- signature threshold;
- maximum acceptable auditor lag; and
- durable client checkpoint persistence.

When multiple auditors are combined under one threshold key or equivalent verification policy, the valid threshold **MUST** be at least a strict majority of configured independent auditors.

A client **MUST** reject an auditor-backed result when:

- fewer than the required threshold of auditor attestations verify;
- auditor lag exceeds policy;
- the auditor started too late to secure the state relied upon by the client; or
- the auditor-backed tree state conflicts with retained client state.

The auditor's role does not eliminate owner monitoring.

## 12. Profile C — Third-Party Management

Profile reference: `kt-third-party-management@0.1.0`

This is a recommended profile where client state may be ephemeral or adversarially lost.

An independent third-party manager operates the transparency log, while the service operator authenticates creation of new label versions.

The client **MUST** verify the manager-authenticated tree state.

The service operator's authorization signature on label updates **MUST** be verified where required by the pinned protocol.

The service operator **MUST** also operate a mechanism for detecting forks presented by the manager.

When multiple independent managers are combined into a threshold system, the valid threshold **MUST** be at least a strict majority.

This profile MAY operate without requiring every client to persist a prior checkpoint, but clients that do retain state SHOULD still verify continuity against it.

## 13. Threshold third parties

For the two third-party deployment profiles, E2EESA allows one or more independent third parties.

When `third_party_count > 1`, `third_party_threshold` **MUST** be at least `floor(third_party_count / 2) + 1`.

The threshold **MUST NOT** exceed the configured third-party count.

A deployment **SHOULD** choose third parties with independent administrative, hosting, network, and organizational failure domains where practical.

## 14. Gossip and split-view detection

Contact Monitoring **MUST** use a partition-resistant path for fork detection, such as:

- anonymous access to the transparency log;
- peer-to-peer gossip of authenticated tree state; or
- both.

Third-party profiles use their independent third party as the primary anti-partition mechanism, but MAY additionally use peer gossip or anonymous comparison.

Peer gossip is only a complete anti-partition mechanism when users are reasonably expected to form a connected gossip graph. Products **MUST NOT** claim global consistency merely because occasional peers exchange checkpoints.

## 15. State loss

State loss weakens rollback and split-view detection in Contact Monitoring and Third-Party Auditing deployments.

Products selecting those profiles **MUST** store checkpoints in durable application state and SHOULD protect them from rollback with the strongest available local secure-storage mechanism.

When state loss is detected, the product **MUST** treat security assurance as degraded until the selected protocol's recovery conditions have been satisfied.

Third-Party Management is the preferred E2EESA profile when durable client state cannot reasonably be assumed.

## 16. Clock and freshness

The tree-head timestamp **MUST** be compared to the client's observation time.

A tree head that is too far in the future or too far in the past under the configured `max_ahead_ms` and `max_behind_ms` values **MUST** be rejected.

The Reasonable Monitoring Window and, where applicable, auditor maximum lag **MUST** be materially shorter than the expected interval between client state-loss events.

## 17. Update authorization

KT does not replace the PR #8 identity/device authorization model.

A new directory value **MUST** reflect identity state that is already valid under the selected identity architecture.

A successful transparency inclusion proof for an unauthorized key **MUST NOT** convert that key into an authorized E2EE identity.

Transparency detects directory inconsistency; identity authorization determines whether a key should exist.

## 18. Failure behavior

If a client detects any of the following, it **MUST NOT** report automatic key verification as successful:

- invalid tree-head signature;
- invalid search, inclusion, consistency, VRF, or commitment proof;
- PR #11 subject-digest mismatch;
- tree-size or label-version rollback;
- same-size/different-root fork;
- explicit fork detection;
- required monitoring failure;
- insufficient third-party threshold;
- unacceptable auditor lag; or
- manager/service update-authentication failure.

Products SHOULD make these failures distinguishable from ordinary network unavailability.

## 19. Conformance evidence

A conforming verification cycle **MUST** preserve enough evidence to determine:

1. exact E2EESA KT profile;
2. exact pinned IETF protocol and cipher suite;
3. PR #11 subject digest;
4. label version;
5. tree size, root, and timestamp;
6. tree-head signature result;
7. VRF, commitment, search, greatest-version, and consistency results;
8. prior checkpoint used, when applicable;
9. owner/contact monitoring state;
10. fork-check channel and result;
11. third-party threshold result, when applicable;
12. auditor lag, when applicable;
13. service update-signature and manager-fork-detection result, when applicable; and
14. whether a new checkpoint was persisted.

The reference semantic validator consumes these already-verified results. Cryptographic proof verification itself **MUST** be implemented by a conformant implementation of the pinned KT protocol.

## 20. Security-claim boundaries

A successful KT profile can support `SP-KEY-CONSISTENCY` and `SP-ROLLBACK-RESISTANCE` within the assumptions of the selected deployment.

It does not by itself establish:

- real-world identity;
- endpoint integrity;
- message confidentiality;
- manual safety-number verification;
- post-quantum authentication; or
- global anti-partition security when the selected deployment's gossip/third-party assumptions are not met.
