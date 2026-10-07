# ADR 0008: Key Transparency deployment profiles

**Status:** Accepted for pre-1.0 development

## Context

E2EE key directories remain vulnerable when a malicious or compromised service can selectively substitute public keys for chosen users. Manual safety-number verification helps only for relationships that users explicitly compare and does not provide global directory consistency. A transparency system therefore needs authenticated history, lookup proofs, rollback/fork detection, and a deployment model describing who prevents or detects split views.

The IETF Key Transparency working group now has an active architecture draft and standards-track protocol draft covering these requirements and three serious deployment modes.

## Serious alternatives considered

1. **Invent an E2EESA-specific transparency tree.** Rejected because the IETF Key Transparency protocol already addresses authenticated search, consistency, commitments, VRF label privacy, monitoring, and third-party deployment modes.
2. **Contact Monitoring.** No independent third party, but stronger dependence on durable client state, monitoring, and partition-resistant anonymous/peer communication.
3. **Third-Party Auditing.** Service operates the log while independent auditors attest to authenticated log state. Good fit for durable native clients.
4. **Third-Party Management.** Independent manager operates the log while the service authenticates updates and detects manager forks. Better fit for ephemeral/state-loss-prone clients.
5. **Certificate-Transparency-style append-only log only.** Rejected as incomplete for privacy-sensitive key directories because KT also requires efficient private-label lookup and monitoring semantics.
6. **Manual verification only.** Rejected as a complete directory-consistency solution because it does not protect relationships that users never manually compare.

## Decision

E2EESA defines three selectable KT profiles:

- `kt-contact-monitoring@0.1.0`;
- `kt-third-party-auditing@0.1.0`; and
- `kt-third-party-management@0.1.0`.

The exact protocol is pinned as `KEYTRANS-IETF-05`, corresponding to `draft-ietf-keytrans-protocol-05` and `draft-ietf-keytrans-architecture-09`.

The draft's `0x0002 KT_128_SHA256_Ed25519` suite is the E2EESA 0.1 recommended cipher suite; `0x0001 KT_128_SHA256_P256` is allowed.

KT values bind directly to PR #11's canonical `subject_digest_hex`.

## Security consequences

Contact Monitoring avoids third-party trust but depends more heavily on retained client state and a partition-resistant gossip/anonymous channel.

Third-Party Auditing introduces independent auditors and bounded lag, reducing reliance on peer gossip while retaining client checkpoint continuity.

Third-Party Management is more tolerant of ephemeral clients but introduces a manager/service non-collusion assumption and requires service authentication of updates plus fork detection.

Multiple third parties may be combined only with a threshold of at least a strict majority.

## Compatibility constraints

The IETF protocol remains an Internet-Draft, so E2EESA treats it as provisional and version-pins exact revisions.

Identity authorization remains defined by PR #8. Manual verification remains defined by PR #11. KT may attach consistency evidence to the same subject digest but cannot redefine either mechanism.

## Evidence and references

- IETF `draft-ietf-keytrans-architecture-09`.
- IETF `draft-ietf-keytrans-protocol-05`.
- RFC 9381, Verifiable Random Functions.
- Signal Automatic Key Verification deployment, including independent auditors and privacy-preserving label/value handling.
- E2EESA PR #8 Identity and Device Architecture.
- E2EESA PR #11 Key Verification.

## Reconsideration triggers

Revisit when the IETF drafts advance to a materially different revision or RFC, when standardized post-quantum KT cipher suites emerge, when independent review identifies unsafe state-loss assumptions, or when deployed privacy requirements require a different label/value access-control model.
