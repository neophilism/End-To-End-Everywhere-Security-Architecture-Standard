# ADR 0011: Contact discovery profiles

**Status:** Accepted for pre-1.0 development

## Context

Address-book discovery is useful but creates a severe privacy risk if clients upload raw contacts or easily invertible hashes. Low-entropy identifiers such as phone numbers can be enumerated. Serious architectures therefore either avoid address-book discovery, use a cryptographic private-membership protocol, or place the matching computation inside a remotely attested confidential-compute boundary.

## Serious alternatives considered

1. **Exact handle/invite only.** No address-book upload and minimal architecture, but no automatic "which of my contacts are here?" experience.
2. **Ordinary hashed identifiers.** Rejected. The practical identifier domain is small enough for the service to reverse or precompute hashes.
3. **RFC 9497 VOPRF private membership.** Recommended. Blinded evaluations protect query inputs from the evaluator while a pseudorandom directory representation enables local membership checking.
4. **Generic PSI construction.** Not frozen in E2EESA 0.1 because no single deployed/standardized PSI wire protocol is mature enough here to justify inventing a bespoke profile when VOPRF membership covers the required discovery function.
5. **Attested confidential compute.** Allowed. It provides scalable private-set intersection with straightforward semantics but adds hardware, attestation, implementation, and side-channel trust.
6. **Return server-generated contact suggestions.** Rejected as a privacy-preserving discovery substitute because it can expose or infer a social graph unrelated to the client's explicit query set.

## Decision

E2EESA defines:

- `contact-exact-handle@0.1.0`;
- `contact-voprf-directory@0.1.0` — recommended; and
- `contact-attested-private-set@0.1.0`.

The VOPRF profile pins RFC 9497 VOPRF mode with `ristretto255-SHA512`.

All profiles require explicit target discoverability policy and prohibit raw address-book and ordinary identifier-hash upload.

## Security consequences

Exact-handle mode minimizes collection but exposes the explicit lookup to the service.

VOPRF discovery cryptographically hides identifier inputs/outputs from the VOPRF evaluator, but authorized clients can still enumerate identifiers subject to online query budgets.

Confidential-compute discovery hides query plaintext from the host/service but depends on remote attestation, trusted code, and the declared TEE side-channel model.

None of the profiles automatically hides IP address, timing, batch size, or request frequency.

## Evidence and references

- RFC 9497, Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups.
- Signal private contact discovery design and its explanation of why truncated hashes of phone numbers are reversible.
- Signal current private-contact-discovery user documentation.
- E2EESA PR #8 Identity and Device Architecture.
- E2EESA PR #12 Key Transparency.
- E2EESA PR #14 Metadata Privacy.

## Reconsideration triggers

Revisit if a broadly standardized PSI protocol becomes an Internet Standard with a deployment model better suited to contact discovery, if post-quantum VOPRF/PSI mechanisms mature, or if confidential-compute assurance/attestation standards materially improve.
