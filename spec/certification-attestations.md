# Signed Certification Attestations

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 30.

A certification attestation is the portable, signed statement corresponding to a current PR 29 certified lifecycle state and an exact PR 28 evidence bundle.

The canonical payload is independent of signature-envelope format. E2EESA supports multiple serious envelope ecosystems and signing policies rather than requiring one serialization for every verifier.

## 1. Canonical certification payload

The certification payload binds:

- attestation ID;
- certification case ID;
- product ID, version and platform;
- assurance profile;
- exact assurance-plan digest;
- exact configuration digest;
- exact effective profile set;
- exact evidence-bundle digest;
- exact source and artifact digests;
- lifecycle event-log digest;
- latest lifecycle event ID;
- issuer ID;
- signing-policy ID;
- issuance, not-before and expiration times;
- surveillance due time;
- public status-reference URI; and
- the supported/conditional security-property claims published by the certificate.

The payload MUST be serialized as the E2EESA canonical JSON subset before signing.

All object member names in the certification payload are fixed ASCII schema keys. Strings MUST be valid Unicode scalar sequences. No floating-point values are permitted. Object keys are serialized in lexical order with UTF-8 JSON, no insignificant whitespace and no ASCII-only escaping requirement. Arrays whose schema semantics are sets MUST be lexically sorted before serialization.

This constrained representation is intentionally compatible with JSON canonicalization requirements without making certificate semantics depend on platform-specific pretty-printing.

## 2. Signature envelope options

E2EESA 0.1 supports three serious envelope formats:

### JWS compact

- RFC 7515 compact serialization;
- canonical certification payload embedded as the JWS payload;
- protected `alg`, `kid`, and `typ`;
- `typ` = `e2eesa-cert+jws`;
- `alg=none` is prohibited;
- unprotected substitution of algorithm or key identity is prohibited;
- `b64=false` / detached-payload variants are not used by this profile.

### COSE_Sign1

- RFC 9052/9053 COSE_Sign1;
- canonical certification payload is the payload bstr;
- `alg`, `kid`, and content type are protected;
- external AAD is the UTF-8 string `E2EESA-CERT-0.1`;
- content type = `application/vnd.e2eesa.certification+json`.

### DSSE

- DSSE JSON envelope;
- payload type = `application/vnd.e2eesa.certification+json`;
- payload bytes are the canonical certification payload;
- DSSE PAE is used exactly as specified;
- key trust and algorithm authorization come from the E2EESA signing policy, not from DSSE `keyid` alone.

DSSE permits multiple signatures in one envelope. JWS compact and COSE_Sign1 may be published as multiple envelopes over identical payload bytes when a threshold policy requires multiple signatures.

## 3. Signature algorithms

Every signing algorithm MUST be a `signature` algorithm in the E2EESA cryptographic registry and MUST NOT have a prohibited/deprecated lifecycle status for new issuance.

The initial certification mappings are:

- `ALG-ED25519`;
- `ALG-ECDSA-P256-SHA256`;
- `ALG-ECDSA-P384-SHA384`;
- `ALG-ML-DSA-44`;
- `ALG-ML-DSA-65`; and
- `ALG-ML-DSA-87`.

RFC 9964 supplies standardized JOSE and COSE ML-DSA algorithm identifiers. E2EESA MUST NOT invent private JOSE/COSE algorithm identifiers for these algorithms.

## 4. Signing policy options

Two initial policies are supported.

### Classical threshold

At least one authorized classical signature is required.

This is the interoperability baseline.

### Dual classical + post-quantum

At least two distinct authorized keys are required:

- at least one classical signature; and
- at least one post-quantum ML-DSA signature.

Every counted signature MUST cover exactly the same canonical payload bytes.

The dual policy is intended where long-lived verification or post-quantum signature resilience justifies the additional verifier and key-management requirements.

Neither policy changes the underlying E2EE architecture.

## 5. Key authorization

A signing policy lists trusted certification keys.

Each key binds:

- key ID;
- E2EESA algorithm ID;
- immutable public-key digest;
- public-key retrieval/reference locator;
- validity start/end;
- key status; and
- signer role.

A signature counts only when:

- its key is present and active in policy;
- the algorithm matches that key;
- the key is valid at attestation issuance time;
- the algorithm remains permitted by E2EESA policy;
- the external cryptographic verifier verifies the envelope over the exact canonical payload; and
- the key has not been revoked for the relevant signing time under the applicable revocation policy.

A key identifier alone is never a trust decision.

## 6. Cryptographic verification interface

The reference semantic engine does not implement Ed25519, ECDSA, ML-DSA, JOSE, COSE or DSSE cryptography itself.

Instead, verification is fail-closed and requires a cryptographic verifier callback/backend.

That backend MUST:

1. parse the declared envelope format;
2. verify its protected algorithm and key identity semantics;
3. recover/confirm the signed payload bytes;
4. require those bytes to equal the expected canonical payload exactly;
5. perform the algorithm-specific signature verification under the policy-authorized public key; and
6. return only successfully verified key/algorithm pairs.

If no cryptographic verifier is available, the attestation does not validate.

This separation avoids creating a second home-grown cryptographic implementation inside the standard repository.

## 7. Lifecycle binding

An attestation may be issued only when PR 29 lifecycle replay is valid and derives `certified`.

The attestation:

- MUST identify the latest lifecycle event;
- MUST bind the complete lifecycle event-log digest;
- MUST bind the exact current evidence bundle;
- MUST NOT expire after the lifecycle certificate expiry;
- MUST NOT claim a surveillance due date different from the lifecycle state; and
- MUST NOT be issued before the lifecycle's certification decision.

A suspended, revoked, expired, denied or overdue certification cannot produce a valid new attestation.

## 8. Evidence binding

The PR 28 certification evidence bundle MUST validate before issuance.

The payload's:

- assurance profile;
- assurance-plan digest;
- configuration digest;
- effective profiles;
- source digest;
- artifact digest; and
- published property claims

MUST agree with the validated evidence bundle and assurance plan.

The signed attestation therefore cannot silently widen the scope of the reviewed evidence.

## 9. Claim publication

Only PR 28 claim-evidence records with status `supported` or `conditional` may be published as positive certification claims.

Each published claim includes:

- property ID;
- status;
- threat IDs; and
- limitations.

`conditional` claims MUST retain their limitations.

A `not-supported` claim MUST NOT be rendered as certified.

## 10. Public status reference

Every attestation contains an HTTPS status-reference URI.

The status service publishes signed status statements for the attestation/case.

Consumers checking current certification status MUST verify a current signed status statement when:

- local policy requires online status;
- the attestation's surveillance due time has passed;
- a newer status sequence is known; or
- revocation/suspension information is otherwise indicated.

## 11. Signed status statements

A status statement binds:

- status statement ID;
- attestation ID;
- certification case ID;
- monotonically increasing sequence;
- lifecycle state;
- effective time;
- prior status-statement digest, when sequence > 0;
- evidence-bundle digest;
- certificate expiry;
- surveillance due time;
- issuer ID; and
- signing-policy ID.

Status statements use the same canonical serialization, envelope options and signing policy machinery as certification attestations, with payload type `application/vnd.e2eesa.certification-status+json`.

A status state of `suspended`, `revoked` or `expired` MUST cause current-certification verification to fail.

## 12. Replay and rollback defense

A verifier maintaining state MUST reject a status sequence lower than the highest verified sequence for that certification case.

For sequence > 0, the `previous_status_digest` MUST bind the prior accepted status payload when the verifier possesses it.

A newer valid adverse status MUST NOT be overridden by replaying an older `certified` statement.

## 13. Payload and envelope separation

Envelope metadata MUST NOT silently change payload semantics.

Algorithm negotiation is not performed from untrusted envelope input. The signing policy determines which algorithms and keys are acceptable.

Multiple envelope formats may publish the same attestation. Their canonical payload digest MUST be identical.

## 14. Fail-closed behavior

Attestation validation fails on:

- non-current PR 29 lifecycle state;
- invalid PR 28 evidence bundle;
- payload/evidence/lifecycle scope mismatch;
- malformed or noncanonical payload data;
- unknown envelope format;
- unknown or unauthorized key;
- unregistered or non-signature algorithm;
- expired/not-yet-valid key;
- signing threshold failure;
- missing required post-quantum signature under dual policy;
- missing cryptographic verifier;
- cryptographic verification failure;
- attestation validity outside lifecycle validity;
- surveillance due mismatch;
- unsupported property publication;
- stale/adverse signed status; or
- status sequence rollback.

## 15. References

- RFC 7515 — JSON Web Signature (JWS).
- RFC 9052 / RFC 9053 — COSE structures and algorithms.
- RFC 9964 — ML-DSA for JOSE and COSE.
- DSSE protocol — pre-authentication encoding and multi-signature envelope.
- E2EESA PR 6 cryptographic registry, PR 28 evidence model and PR 29 lifecycle.
