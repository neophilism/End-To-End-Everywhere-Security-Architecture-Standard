# Cryptographic Registry and Lifecycle

**Status:** Normative

This document defines how E2EESA registers cryptographic building blocks and how lifecycle status constrains their use.

## 1. Closed-world rule

A conformant E2EESA profile MUST reference cryptographic algorithms and named suites by exact registry identifier. An implementation MUST NOT treat an unregistered primitive, informal alias, or implementation-specific algorithm name as E2EESA-approved.

Registration is necessary but not sufficient for use. A primitive is usable only when its lifecycle status and the consuming profile both permit that use.

## 2. No new cryptographic primitives

E2EESA does not invent cryptographic primitives. New registry entries SHOULD refer to publicly specified, externally reviewed standards or mature specifications. Experimental research mechanisms MUST be explicitly marked experimental and MUST NOT be represented as production-recommended.

## 3. Lifecycle status

Registry entries use the same lifecycle vocabulary as profiles:

- **recommended** — preferred default for new E2EESA profiles when the primitive fits the use case;
- **allowed** — acceptable when selected by a profile for interoperability, performance, security-margin, or deployment reasons;
- **provisional** — requires explicit opt-in while a dependency, standard, or analysis remains unsettled;
- **experimental** — research only unless a later profile explicitly permits experimental use;
- **legacy** — retained only for migration or constrained compatibility;
- **deprecated** — new use SHOULD NOT occur and migration is expected;
- **prohibited** — MUST NOT provide a cryptographic security property in a conformant configuration.

A consuming profile MUST NOT assign a stronger lifecycle posture to a suite than the weakest lifecycle status of its component algorithms.

## 4. Algorithm categories

The registry currently recognizes:

- key agreement;
- KEMs;
- signatures;
- cryptographic hashes;
- KDFs; and
- AEAD algorithms.

Registration does not imply that an algorithm is valid in every category, protocol, key role, message format, or threat model.

## 5. Multiple serious options

Where multiple standardized constructions are defensible, E2EESA keeps them as explicit alternatives rather than collapsing them into one hidden default.

The registry therefore includes multiple classical key-agreement, signature, hash, KDF, and AEAD choices, along with standardized post-quantum KEM and signature choices.

A later profile MAY narrow these choices for a specific product class or interoperability target.

## 6. Post-quantum scope

ML-KEM and ML-DSA are registered as post-quantum primitives. Their presence in the registry does not by itself create a post-quantum product claim.

A conformant post-quantum claim MUST still satisfy the Security Properties Model and the applicable profile requirements.

Classical/post-quantum hybrid composition is intentionally not defined here. Hybrid key establishment and authentication require explicit protocol binding, downgrade resistance, transcript binding, failure semantics, and key-combination rules. Those rules belong to dedicated later profiles.

## 7. Named suites

A named suite is a registry object that references exact algorithm identifiers and a protocol specification.

Suites MUST NOT contain prohibited algorithms. Suite status MUST NOT be stronger than the weakest status of any component.

The initial named suites are standardized RFC 9180 HPKE combinations. This registry does not redefine HPKE mode semantics.

## 8. Context and domain separation

Registry approval never removes the obligation to define:

- domain separation;
- transcript construction;
- associated data;
- nonce generation and uniqueness;
- key separation;
- public-key validation;
- signature context;
- serialization;
- failure handling; and
- algorithm negotiation.

Those details belong to the consuming protocol or profile.

## 9. Prohibited historical algorithms

MD5 and SHA-1 are retained in the registry only so a validator can deterministically identify and reject their attempted use for E2EESA cryptographic security properties.

Their registration MUST NOT be interpreted as approval.

## 10. Fail-closed interpretation

A validator MUST reject:

- unknown algorithm or suite identifiers;
- malformed identifiers;
- duplicate identifiers;
- unknown registry fields;
- suites containing unknown or prohibited algorithms;
- a suite whose lifecycle status is stronger than a component status; and
- deprecated or prohibited entries lacking a recorded status reason.

The registry MUST remain machine-readable and versioned so conformance artifacts can record the exact algorithm universe against which they were evaluated.
