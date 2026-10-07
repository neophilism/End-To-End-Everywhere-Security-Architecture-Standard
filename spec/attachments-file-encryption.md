# Attachments and File Encryption

**Status:** Normative

Profile reference: attachment-chunked-aead@0.1.0

## 1. Core invariant

The attachment storage service MUST NOT receive attachment plaintext or the attachment decryption key. The attachment key and private manifest MUST be delivered only inside an authenticated E2EE parent message to devices authorized under the applicable identity/device state.

## 2. Fresh per-attachment key

Every attachment MUST use a fresh randomly generated 256-bit attachment key. The key MUST NOT be reused for another attachment, transformed derivative, or re-share context. Deterministic or convergent file encryption is outside this profile.

## 3. Private manifest

The private manifest is carried inside the authenticated E2EE parent message. It binds the format/profile version, attachment and parent-message identifiers, key identifier and key, AEAD/hash choices, nonce prefix, chunk size/count, exact plaintext size, filename, media type, whole-file plaintext hash, storage object identifier, and manifest-context digest.

The storage service MUST NOT require private-manifest fields such as filename, media type, plaintext hash, or attachment key in storage metadata.

## 4. Manifest context digest

The manifest-context digest uses canonical UTF-8 JSON with sorted keys and no insignificant whitespace.

Its input contains domain string E2EESA-ATTACHMENT-MANIFEST-v1 and the complete manifest except the attachment key value and the manifest-context digest itself.

Changing any bound manifest field MUST change the digest.

## 5. Chunking

Configured chunk size MUST be between 64 KiB and 8 MiB. All chunks except the final chunk contain exactly the configured chunk size. The final chunk contains the remaining bytes.

An empty file is exactly one zero-length plaintext chunk and still produces an authenticated AEAD tag.

chunk_count MUST equal ceil(plaintext_size_bytes / chunk_size_bytes), except zero-length files use one chunk.

## 6. AEAD and nonce construction

E2EESA 0.1 permits:

- ALG-AES-256-GCM — recommended;
- ALG-CHACHA20-POLY1305 — recommended; and
- ALG-AES-256-GCM-SIV — allowed.

Every chunk uses the same fresh per-attachment key and a distinct 96-bit nonce:

4-byte nonce_prefix || uint64_be(chunk_index)

Chunk indices are zero-based. The nonce prefix is randomly generated per attachment and stored in the private manifest.

Nonce uniqueness remains mandatory with AES-256-GCM-SIV.

## 7. Chunk associated data

Every chunk AEAD operation MUST authenticate at least:

- attachment_id;
- manifest_context_digest_hex;
- chunk_index;
- chunk_count; and
- plaintext_length_bytes.

Cross-attachment substitution, chunk reordering, wrong-position substitution, and false-length claims MUST fail authentication or semantic validation.

## 8. Streaming and range retrieval

Clients MAY upload/download chunks independently and MAY resume or seek directly to a chunk once they possess the authenticated manifest.

A client MUST authenticate a chunk before releasing that chunk's plaintext to a parser, renderer, filesystem consumer, preview generator, or application layer.

The completed file MUST also be checked against the whole-file plaintext hash from the private manifest.

## 9. Key distribution

The attachment key and manifest MUST be delivered inside an E2EESA pairwise or group E2EE message.

The key MUST NOT appear in an HTTP URL, query parameter, storage/CDN metadata, logs, analytics events, or unencrypted push payloads.

A URL fragment is intentionally not the normative key-distribution mechanism because copied URLs and client/browser telemetry create avoidable leakage paths.

## 10. Recipient authorization and group changes

The sender MUST use current authorized recipient-device state before distributing the attachment key.

Removed group members MUST NOT receive keys for attachments sent after removal.

New group members MUST NOT automatically receive historical attachment keys merely because they joined.

A recipient that already received a key or plaintext cannot later be forced to forget it.

## 11. Replay, substitution, reordering, and truncation

Protection comes from the fresh key, random attachment identifier, authenticated E2EE manifest, manifest digest, chunk position/count/length in AAD, and final whole-file hash.

A storage service that reorders, substitutes, or truncates chunks MUST cause validation failure.

## 12. Storage trust boundary

The storage service may hold ciphertext and serve byte ranges, but it is not trusted for plaintext confidentiality, integrity, key secrecy, private file metadata, recipient authorization, or proof that deletion reached every replica.

## 13. Deletion, expiry, and recall semantics

User-visible deletion MUST request removal from primary storage and known replicas/caches according to documented retention rules.

Orphaned uploads MUST be eligible for bounded cleanup.

Deleting the sender's local key can provide sender-local cryptographic erasure when no local copies remain.

After a recipient has received a key or plaintext, remote key revocation, expiry, and storage deletion cannot guarantee recipient recall. Products MUST NOT claim global cryptographic recall.

## 14. Thumbnails, previews, and derivatives

A thumbnail, waveform, transcoded copy, OCR result, extracted text, or other derivative MUST remain local to an authorized endpoint or be protected as a distinct E2EESA attachment with a fresh key and manifest.

## 15. Metadata boundary

Filename, media type, exact plaintext size, and plaintext hash remain inside the private E2EE manifest. The storage provider can still infer approximate ciphertext size and may observe timing, object count, and access frequency.

This profile does not itself claim complete metadata confidentiality.

## 16. Availability

Attachment confidentiality/integrity do not imply availability. Storage or network adversaries can withhold/delete ciphertext. Resumable transfer reduces retransmission cost but does not create an availability guarantee.

## 17. Security claim boundaries

A conforming attachment can support SP-CONFIDENTIALITY, SP-INTEGRITY, and SP-REPLAY-RESISTANCE for the attachment format.

It does not itself establish recipient identity, complete metadata confidentiality, secure deletion of recipient-held copies, global recall, or availability.

## 18. Conformance evidence

Conformance MUST demonstrate fresh 256-bit keying, exact manifest digest, correct chunk count/final length, exact 96-bit prefix-counter nonce construction, chunk AAD binding, AEAD verification before plaintext release, E2EE-only key distribution to authorized devices, no key leakage to URLs/storage metadata, no service plaintext/key access, final file-hash verification, no automatic historical key delivery to new group members, and accurate deletion/recall semantics.
