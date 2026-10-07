# ADR 0012: Attachment and file encryption

**Status:** Accepted for pre-1.0 development

## Context

Large attachments need resumable upload/download and bounded-memory processing without trusting object storage for plaintext or integrity.

A single whole-file AEAD operation is simple but blocks safe random access and resumable streaming. Ad hoc chunk encryption can introduce nonce reuse, chunk substitution, truncation, key leakage, and misleading deletion semantics.

## Serious alternatives considered

1. One AEAD operation over the entire file. Rejected as the universal format because authenticated random access and resumable transfer are poor.
2. Independent authenticated chunks under one fresh file key. Selected. It supports streaming, bounded memory, resume, and range retrieval.
3. One fresh key per chunk. Rejected as unnecessary key-management complexity.
4. Random nonce per chunk. Viable, but a per-file random prefix plus deterministic chunk counter makes uniqueness and auditing straightforward.
5. Deterministic/convergent encryption for deduplication. Rejected because it reveals file equality and can expose guessable content.
6. Share URLs carrying the attachment key. Rejected as the normative mechanism because copied URLs and client/browser telemetry create avoidable leakage.
7. Merkle tree over chunks. Not required in 0.1 because the authenticated manifest commits context/count, every chunk authenticates its position and length, and the private manifest carries a final whole-file hash.
8. AES-GCM-SIV only. Not required. It is allowed as a misuse-resistant option, but fresh-key and unique-nonce requirements remain mandatory.

## Decision

E2EESA defines one recommended profile: attachment-chunked-aead@0.1.0.

Every attachment gets a fresh 256-bit key and random four-byte nonce prefix.

Chunk nonce = nonce_prefix || uint64_be(chunk_index).

AES-256-GCM and ChaCha20-Poly1305 are recommended. AES-256-GCM-SIV is allowed.

The private manifest is delivered inside the parent pairwise/group E2EE message. Its canonical context digest is included in every chunk's authenticated associated data with attachment id, chunk index/count, and plaintext chunk length.

## Security consequences

The storage provider cannot decrypt content or modify/reorder/truncate chunks without detection.

Range requests and resumed transfer do not require unauthenticated plaintext release.

Filename, media type, exact plaintext size, and plaintext hash remain private inside the E2EE manifest, although ciphertext size and access timing remain observable.

Deletion can remove server-held ciphertext and sender-local keys but cannot revoke a key already delivered to a recipient.

## Standards basis

- NIST SP 800-38D for AES-GCM and unique-IV requirements.
- RFC 8439 for ChaCha20-Poly1305 with a 256-bit key and unique 96-bit nonce.
- RFC 8452 for AES-GCM-SIV.
- E2EESA pairwise/group E2EE, identity/device, metadata-privacy, and backup/recovery profiles.

## Reconsideration triggers

Revisit if a broadly adopted streaming-AEAD file standard emerges that meets E2EESA range/replay/deletion requirements, if AEAD guidance changes, if sparse very-large objects require Merkle proofs, or if safe deduplication can be provided without unacceptable equality leakage.
