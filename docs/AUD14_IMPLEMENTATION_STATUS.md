# AUD-14 implementation status

AUD-14.1 adds an exact-profile, exact-PQXDH-revision and exact-ML-KEM-Braid-revision reference check for PQXDH-based sessions. The accompanying tests cover key/ciphertext substitution under independently trusted digests, association-data byte mismatch, wrong protocol revision, mismatched KEM, downgrade, malformed inputs and accidental alteration of the published PQXDH R3 associated-data convention.

The supported convention is `pqxdh-r3-published-ad@0.1.0`. Existing production profile semantics are **not** changed by silently appending optional KEM public-key information: any extra mandatory associated-data convention requires a newly reviewed and versioned profile. The selected ML-KEM parameter sets already incorporate their public key in secret derivation, so the original PQXDH associated-data construction is retained.

**Remaining AUD-14 work:** independently acquire and pin an immutable full ML-KEM Braid and protocol-source byte snapshot; independently test complete PQXDH and Braid implementations against external vectors (both roles, tampered signatures/prekeys/ciphertexts and every supported KEM variant); authenticate source and trust inputs and prove real endpoint interoperability. This reference model does not implement a KEM, signature verification, AEAD authentication, full transcript crypto, source-content archive, or certification.
