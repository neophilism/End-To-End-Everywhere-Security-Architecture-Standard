# AUD-12 implementation status

AUD-12.1 introduces a reference generation-transition checker and normative lifecycle contract. It binds identity, profile, algorithm, generation, credential epoch, distinct new key/ciphertext/wrap digests and explicit authorizer context to an independently trusted previous-generation checkpoint. It rejects salt-only rotation and demands negative decrypt-test evidence references.

**Still pending:** Actual external cryptographic signature verification, secure generation of fresh 256-bit BDEKs by real clients, re-encryption with a registered AEAD, old-credential negative decryption integration tests, hardware-release tests, retained-copy disclosure in deployed clients and cross-platform adoption. A structurally complete evidence record is not proof these tests occurred. The parent audit package and 1.0 security assurance remain pending.
