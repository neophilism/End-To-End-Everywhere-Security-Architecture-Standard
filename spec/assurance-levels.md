# E2EESA Assurance Levels

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 27.

Assurance levels describe the depth of evidence supporting a security claim. They do not change the cryptographic architecture and they do not, by themselves, issue an Open E2EE Verified certificate.

Levels are monotonic: a higher level includes the required evidence depth of lower levels plus additional requirements.

## 1. Levels

| Exact profile | Name | Minimum verification depth |
| --- | --- | --- |
| `assurance-a1-observed@0.1.0` | A1 Observed | Independent black-box/property/fuzz/adversarial assessment |
| `assurance-a2-reviewed@0.1.0` | A2 Reviewed | Combined black-box + white-box assessment, secure-development baseline, reproducible/attested supply chain |
| `assurance-a3-protocol-formal@0.1.0` | A3 Protocol Formal | A2 + symbolic protocol proof for applicable protocol-level claims |
| `assurance-a4-implementation-formal@0.1.0` | A4 Implementation Formal | A3 + machine-checked code/refinement proof for applicable security-critical implementation claims |
| `assurance-a5-comprehensive-formal@0.1.0` | A5 Comprehensive Formal | A4 + computational/game-based proof for applicable cryptographic construction/composition claims and two independent assessors |

These are evidence levels, not declarations that every product must attain A5.

## 2. Monotonicity

Each assurance profile MUST resolve all exact profile dependencies listed by its registry entry and profile catalog entry.

A higher-level profile MUST NOT remove a requirement present at a lower level unless a later E2EESA version explicitly supersedes that requirement with an equal-or-stronger mechanism.

## 3. A1 Observed

A1 requires `verification-blackbox@0.1.0`.

A1 can establish externally observable behavior within the limits of PR 25. It MUST NOT be used to imply source-level key lifecycle, software-integrity, forward-secrecy state-erasure, build provenance or formal protocol assurance that cannot be established from external behavior alone.

A1 is useful for interoperability, external attack-surface and behavior assessment. It is not the default target for high-assurance E2EE certification.

## 4. A2 Reviewed

A2 requires:

- `verification-combined@0.1.0`;
- `development-ssdf-baseline@0.1.0`; and
- `supply-chain-attested-reproducible@0.1.0`.

A2 is the first level that combines independent external behavior testing, internal/source assessment, secure-development evidence and reproducible/attested release evidence.

A2 is the E2EESA 0.1 recommended general-purpose assurance baseline. This recommendation does not pre-judge the future Open E2EE Verified badge threshold.

## 5. A3 Protocol Formal

A3 includes all A2 requirements and requires `formal-symbolic-protocol@0.1.0`.

When the product claims a protocol-level property covered by the A3 formal-property set, the assurance plan MUST derive a matching symbolic formal obligation.

The A3 formal-property set initially includes:

- `SP-CONFIDENTIALITY`;
- `SP-MESSAGE-AUTHENTICITY`;
- `SP-PEER-AUTHENTICATION`;
- `SP-AUTHORIZATION-INTEGRITY`;
- `SP-FORWARD-SECRECY`;
- `SP-POST-COMPROMISE-SECURITY`;
- `SP-KEY-CONSISTENCY`;
- `SP-DOWNGRADE-RESISTANCE`;
- `SP-REPLAY-RESISTANCE`;
- `SP-ROLLBACK-RESISTANCE`;
- `SP-PQ-CONFIDENTIALITY`; and
- `SP-PQ-AUTHENTICATION`.

The derived obligation applies only to properties the product actually claims.

## 6. A4 Implementation Formal

A4 includes all A3 requirements and requires `formal-code-refinement@0.1.0`.

For claimed properties in the A4 implementation-property set, the assurance plan MUST derive code/refinement obligations for the security-critical implementation boundary that realizes the claim.

The A4 set initially includes:

- `SP-CONFIDENTIALITY`;
- `SP-INTEGRITY`;
- `SP-AUTHORIZATION-INTEGRITY`;
- `SP-ROLLBACK-RESISTANCE`;
- `SP-RECOVERY-CONFIDENTIALITY`;
- `SP-BACKUP-CONFIDENTIALITY`; and
- `SP-SOFTWARE-INTEGRITY`.

A4 does not imply that the entire application, operating system, compiler or hardware stack is formally verified. The verified boundary and trusted computing base MUST remain explicit.

## 7. A5 Comprehensive Formal

A5 includes all A4 requirements and requires `formal-computational-proof@0.1.0`.

For claimed properties in the A5 computational-property set, the assurance plan MUST derive computational proof obligations when the E2EESA policy treats the product-specific cryptographic construction or composition as requiring such evidence.

The initial A5 set includes:

- `SP-CONFIDENTIALITY`;
- `SP-MESSAGE-AUTHENTICITY`;
- `SP-FORWARD-SECRECY`;
- `SP-POST-COMPROMISE-SECURITY`;
- `SP-PQ-CONFIDENTIALITY`; and
- `SP-PQ-AUTHENTICATION`.

A5 also requires at least two independent assessor identities at the assurance-plan level.

The existence of standardized primitives does not remove the need to prove implementation/refinement correspondence for claims that depend on production code. Conversely, E2EESA MUST NOT demand a new cryptographic proof merely because a product uses a standardized, already analyzed primitive exactly as specified; the computational obligation applies to the product-specific construction/composition scope declared by the policy.

## 8. Assurance plans

An assurance plan binds:

- exact assurance profile;
- exact E2EESA configuration;
- exact product/version/platform;
- claimed security properties;
- independent assessor identities; and
- any product-specific computational-proof scopes required at A5.

The assurance resolver MUST:

1. resolve the exact E2EESA configuration;
2. ensure the selected assurance profile is in the effective profile set;
3. ensure all level dependencies are present through deterministic profile resolution;
4. reject claimed property IDs not provided by the effective architecture;
5. enforce minimum independent assessor count; and
6. derive formal obligations for applicable claimed properties.

## 9. Property provenance

Assurance machinery does not create security properties.

The claimed-property set MUST be a subset of properties provided by non-assurance architecture profiles in the effective configuration.

Verification, formal-verification and assurance profiles MUST NOT be used as the sole reason a product claims confidentiality, forward secrecy, post-compromise security or another architecture property.

## 10. Independent assessors

Assessor IDs MUST be unique.

A1–A4 require at least one independent assessor at this stage. A5 requires at least two.

PR 28 and later certification evidence rules define assessor qualification, organizational independence, authentication and conflict-of-interest evidence.

## 11. Multiple configurations

A separate assurance plan is required for each materially different exact configuration, product version and platform whose security claims differ.

Evidence for one mutually exclusive architecture option MUST NOT be used to satisfy a different option merely because both are permitted by E2EESA.

## 12. Fail-closed semantics

An assurance plan fails if:

- its assurance profile is unknown or not selected;
- profile dependencies do not resolve;
- the exact configuration is invalid;
- a claimed property is unknown;
- a claimed property is not provided by the effective architecture;
- independent assessor count is below the level floor; or
- required formal obligations cannot be derived because their formal profile is missing.

## 13. Certification boundary

Assurance level is one input to certification, not certification itself.

PRs 28–30 define evidence bundles, certification lifecycle and signed certification attestations. Those PRs may establish badge-specific minimum assurance levels without changing the meaning of A1–A5.
