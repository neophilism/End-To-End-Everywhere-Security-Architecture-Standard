# Authenticated backup generation and recovery-credential rotation (AUD-12)

**Status:** Normative lifecycle boundary; reference checks are not proof of ciphertext confidentiality.

## Required authenticated transition

Credential rotation for an E2EESA server-hosted recoverable backup **MUST** be a client-authorized, versioned transition between the exact previous and new manifest identities, including an independently trusted old generation checkpoint. The authorization transcript MUST bind the original identity, backup, recovery profile, content algorithm, prior-generation digest and successor-generation digest. A service-side counter increment, password field update, or changed salt is not sufficient.

Every new backup generation **MUST** generate a fresh uniformly random BDEK with at least 256 bits of entropy using the endpoint's approved cryptographic provider. The BDEK MUST NOT be reused, derived solely from the old BDEK, or supplied to a storage service unwrapped. The endpoint MUST create a newly authenticated recovery wrap for the fresh BDEK under newly derived recovery credential material, and re-encrypt the new generation's backup content with a registered AEAD and safe nonce strategy. Source/binary-reviewed tests and independent cryptographic verification are required to prove actual fresh bytes and ciphertext authentication. Two different key identifiers, commitments, ciphertext digests or salt values alone do **not** prove that the underlying cryptographic keys differ.

An old recovery credential **MUST NOT** decrypt the *new* generation's content or unwrap its fresh BDEK; this MUST be established by an actual negative decrypt test against a real implementation. The new credential MUST successfully authenticate and decrypt the same new generation under correct authorization. Any hardware-assisted recovery path MUST additionally satisfy AUD-11 hardware release identity, attempt-budget and shared-counter requirements.

## Retained copies and scope

Changing credentials **MUST NOT** be represented as revoking already retained historical ciphertext, historical recovery wraps, third-party snapshots, previous software-vault exports or compromised user secrets. A former credential may still decrypt a lawfully or maliciously retained old generation. Products MUST disclose this limit and separately offer optional authenticated re-encryption/deletion policies without pretending that untrusted copies can be erased.

Local-only software-vault password changes and server-hosted recoverable backup-credential rotations have different adversary and authority assumptions and MUST be evaluated separately. A backup-credential transition MUST NOT silently enroll or authorize new cryptographic identities or devices.

## Reference/evidence contract

\`scripts/backup_generation_rotation.py\` pins manifest and transition digests under explicit versioned domain separators, rejects stale independent checkpoints and salt-only/key-ID-only transitions, and requires source-addressable cryptographic test evidence. It intentionally returns \`release_ready=false\` because a reference tool cannot establish that attestation references are authentic or decrypt tests actually ran. Implementations MUST verify signatures/proofs, true random key generation, new AEAD authentication and old-credential rejection with real key material in an appropriately isolated test environment; NEVER publish raw recovery secrets or BDEKs in CI or assurance records.

\`tests/test_backup_generation_rotation.py\` exercises rollback, same-key commitment, missing wraps, stale authorization, inadequate entropy, retained-old-copy disclosure, and hardware/profile separation.
