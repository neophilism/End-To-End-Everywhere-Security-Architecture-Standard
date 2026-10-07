# Profiles

Profiles represent named, versioned implementation choices that satisfy E2EESA security invariants.

A profile is not an arbitrary bag of switches. A profile:

- has a stable identifier and exact version;
- belongs to exactly one profile family;
- declares its lifecycle status;
- declares the registered security properties it participates in providing;
- declares exact-version dependencies and incompatibilities; and
- may be selected only when the complete resolved configuration is valid.

Profile references use the form `profile-id@major.minor.patch`.

## Families

A family defines the cardinality of an architectural decision domain:

- `exactly-one`
- `at-most-one`
- `one-or-more`
- `many`

This is the mechanism used later to represent multiple serious solutions to disputed architecture questions.

## Lifecycle statuses

- `recommended` — allowed by default for new configurations
- `allowed` — allowed by default
- `provisional` — explicit opt-in required
- `experimental` — explicit opt-in required and not production-recommended
- `legacy` — explicit opt-in required for compatibility/migration
- `deprecated` — explicit opt-in required and migration warning expected
- `prohibited` — never selectable by a conformant configuration

## Resolution

The profile engine expands exact dependencies, reports auto-added profiles, rejects unknown references, checks incompatible pairs, prevents multiple versions of the same profile, enforces family cardinality, and rejects lifecycle states that are not permitted by the configuration.

See `spec/profile-configuration.md` for normative rules.
\n## Identity architecture profiles\n\nPR 8 introduces the `identity-architecture` family with account-root, existing-device cross-signing, and threshold-quorum alternatives. The family is `at-most-one` during pre-1.0 foundation development so earlier resolver fixtures remain valid; product conformance requires one when identity/device management is in scope.\n\n## Pairwise E2EE profiles\n\nPR 9 introduces the `pairwise-e2ee` family with four complete asynchronous secure-messaging alternatives: X3DH + Double Ratchet, PQXDH + Double Ratchet, PQXDH + SPQR/ML-KEM Braid, and the recommended PQXDH + Triple Ratchet hybrid. The family remains `at-most-one` during pre-1.0 foundation development; a product implementing pairwise E2EE must select one applicable profile for conformance.\n\n## Group E2EE profiles\n\nPR 10 introduces the `group-e2ee` family with three complete alternatives: MLS 1.0 (recommended), Sender-Keys-style AEAD, and pairwise ciphertext fanout. The family remains `at-most-one` during pre-1.0 foundation development; products implementing group E2EE must select one profile when group messaging is in scope.\n\n## Key verification profiles\n\nPR 11 introduces the `key-verification` family with two manual verification subjects: `verify-account-root@0.1.0` for stable account-root verification and `verify-device-set@0.1.0` for direct verification of the complete active device-key set. Both render the same canonical subject through a 60-digit safety number and versioned QR payload, and both require explicit out-of-band confirmation.\n
## Key transparency profiles

PR 12 introduces the `key-transparency` family with Contact Monitoring, Third-Party Auditing, and Third-Party Management alternatives. The exact IETF protocol and architecture drafts are version-pinned, and every accepted transparency value binds to the PR #11 canonical verification subject digest.

## Backup and recovery profiles

PR 13 introduces the `backup-recovery` family with three mutually exclusive architectures: no recoverable backup, user-secret recovery, and hardware/HSM-assisted recovery. Recoverable profiles use fresh per-generation backup data keys and never allow the storage service or hardware recovery layer to hold plaintext or an unwrapped backup data key.

## Metadata privacy profiles

PR 14 introduces the `metadata-privacy` family with three complete choices: minimized service metadata, sender-hidden delivery, and relay-partitioned sender-hidden delivery. The strongest profile combines sender-hidden envelopes with RFC 9458 Oblivious HTTP, authenticated non-personalized gateway configuration, no identifying relay headers, independent relay/gateway operation, request padding, replay protection, and zero durable source-IP retention after request completion.

## Contact discovery profiles

PR 15 introduces the `contact-discovery` family with exact-handle/invite discovery, recommended RFC 9497 VOPRF private-membership discovery, and attested confidential-compute private-set discovery. All profiles prohibit raw address-book and ordinary identifier-hash upload, enforce target discoverability policy, and return only requested matches. PR 14 metadata-privacy transport can be composed when source-network metadata must also be hidden.
