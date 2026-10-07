# Contact Discovery Profiles

**Status:** Normative

This document defines E2EESA contact-discovery architectures for learning whether known identifiers correspond to discoverable users without turning a client's address book into service-visible metadata.

## 1. Core invariant

A contact-discovery mechanism **MUST NOT** require uploading the client's raw address book to the messaging service.

A mechanism **MUST NOT** substitute raw or ordinary unhashed/truncated-hash identifier uploads for private discovery. Phone numbers, email addresses, and similar identifiers generally occupy enumerable spaces; ordinary hashing does not provide meaningful secrecy against a service that can enumerate the input domain.

Only users whose discoverability policy permits the queried discovery mode **MUST** appear as positive results.

## 2. Identifier normalization

Every deployment **MUST** define a versioned identifier-normalization profile.

Clients and directory construction **MUST** use the identical normalization profile for a given directory epoch.

E2EESA does not prescribe universal email-address case folding, international-number parsing, Unicode mapping, or username canonicalization because those rules are application and identifier-type dependent.

A normalization change that alters discovery keys **MUST** create a new normalization-profile version and, where applicable, a new directory epoch.

## 3. Result minimization

Discovery responses **MUST** return only whether queried identifiers correspond to discoverable entries and the minimum bootstrap information needed to initiate the E2EE identity-resolution flow.

Discovery **MUST NOT** return unrelated users, enumerable profile data, address-book similarity scores, social-graph suggestions, or hidden matches that the querying client did not request.

Any key or identity state returned after discovery remains subject to PR #8 identity authorization and PR #12 Key Transparency where applicable.

## 4. Profile A — exact handle / invite discovery

Profile reference: `contact-exact-handle@0.1.0`

This profile performs no address-book matching.

The user explicitly supplies exactly one handle, QR code, invite URI, or equivalent discovery token at a time.

The service MAY learn the exact queried handle. This profile therefore claims address-book minimization, not query secrecy.

The profile **MUST** enforce `max_batch_size = 1`.

Applications SHOULD prefer sufficiently high-entropy or collision-resistant shareable handles where feasible. If a handle is intentionally human memorable, the product **MUST NOT** imply that guessing or enumeration is cryptographically prevented.

## 5. Profile B — RFC 9497 VOPRF directory discovery

Profile reference: `contact-voprf-directory@0.1.0`

This is the recommended cryptographic contact-discovery profile.

The client normalizes each local identifier, blinds it, and submits the blinded elements to a server implementing RFC 9497 **VOPRF mode**.

E2EESA 0.1 pins:

- mode: VOPRF (`0x01`);
- ciphersuite: `ristretto255-SHA512`; and
- mechanism identifier: `VOPRF-RISTRETTO255-SHA512`.

The client **MUST** verify the VOPRF proof against the expected public key for the selected directory epoch before using any finalized output.

The VOPRF execution provides input privacy against the evaluator: the server learns neither the client's private identifier inputs nor finalized VOPRF outputs from the protocol execution.

## 6. VOPRF directory membership structure

The service MAY publish or deliver an authenticated membership structure containing pseudorandom directory tags derived from finalized VOPRF outputs for discoverable registered identifiers.

The structure MAY be a sorted authenticated set, filter, Merkleized structure, or another deterministic membership representation.

It **MUST** bind:

- normalization-profile version;
- VOPRF public-key identifier;
- directory epoch;
- directory snapshot version; and
- digest/authentication data sufficient to detect substitution or rollback under the application's directory policy.

The client **MUST NOT** treat an unauthenticated directory snapshot as authoritative.

## 7. Enumeration resistance

VOPRF input privacy does not prevent an authorized client from deliberately querying many guessed identifiers.

The service **MUST** therefore apply an explicit online evaluation budget or equivalent abuse-control mechanism.

The policy **MUST** define:

- maximum batch size; and
- maximum VOPRF evaluations/queries per account per day or equivalent rate-control window.

These limits are enumeration controls, not proof that enumeration is impossible.

Products **MUST NOT** claim resistance to a malicious client that legitimately possesses enough query budget to test the target identifier space.

## 8. VOPRF epoch rotation

VOPRF server keys **MUST** have explicit identifiers and epochs.

Key rotation **MUST** cause directory membership tags to be regenerated for the new epoch.

Clients **MUST NOT** combine a proof from one VOPRF public key with a directory snapshot constructed under another key.

Old directory snapshots SHOULD expire according to a documented policy, and rollback to an obsolete epoch **MUST** be detectable where the product claims rollback resistance.

## 9. Profile C — attested confidential-compute private set

Profile reference: `contact-attested-private-set@0.1.0`

This profile sends the normalized query set through an encrypted channel that terminates inside an attested confidential-compute boundary.

Before submitting contact identifiers, the client **MUST**:

1. verify the hardware/platform attestation chain;
2. verify that the measured code/configuration is on an authorized allowlist;
3. bind the encrypted session to the attested instance; and
4. refuse plaintext fallback outside the trusted boundary.

Only code inside the measured trusted boundary may process plaintext contact identifiers.

The host operating system, hypervisor, orchestration layer, and surrounding service **MUST NOT** receive plaintext identifiers.

## 10. Confidential-compute result handling

The trusted code **MUST** return only the intersection or minimum discovery results permitted by Section 3.

Plaintext query identifiers **MUST NOT** be durably persisted by the host or trusted workload.

The implementation **MUST** erase query plaintext and transient matching state from reusable trusted memory as soon as practical after completion.

The attested workload SHOULD be reproducibly buildable or otherwise independently auditable.

## 11. Confidential-compute security boundary

Remote attestation does not make a TEE infallible.

The profile's assurance depends on:

- the selected confidential-compute technology;
- attestation root/key security;
- correctness of measured code;
- microcode/firmware state;
- side-channel mitigations;
- rollback protection for trusted workload state; and
- the declared physical and privileged-host adversary model.

A product **MUST NOT** generalize an attestation success into a claim that all hardware side channels are solved.

## 12. Discoverability consent

Every profile **MUST** enforce the target user's discoverability setting.

A user who disables discovery by an identifier **MUST NOT** appear as a positive match for that identifier, even when the querying party already knows it.

Discoverability may differ by identifier type or discovery channel.

Changing discoverability SHOULD take effect in the next directory snapshot/epoch or confidential-compute dataset update within a documented maximum delay.

## 13. Network metadata

Private contact discovery does not automatically hide the querying client's IP address, timing, query batch size, or request frequency.

Products that need source-network-address confidentiality SHOULD combine contact discovery with an appropriate PR #14 metadata-privacy transport.

A VOPRF evaluation may hide the queried identifiers while the service still knows which account or IP issued a batch of a particular size.

The confidential-compute host likewise may observe encrypted request size/timing even when it cannot see identifiers.

## 14. Authentication and bootstrap boundary

A positive contact-discovery result only establishes that a queried identifier maps to a discoverable service entry according to the selected profile.

It does not independently prove the real-world identity of that entry.

The client **MUST** continue through the normal E2EESA identity/device, key-verification, and key-transparency flow before representing the peer as cryptographically verified.

## 15. Conformance evidence

A conforming discovery event **MUST** preserve enough evidence to determine:

1. exact contact-discovery profile;
2. normalization-profile version;
3. query/batch size;
4. discoverability-policy enforcement;
5. absence of raw address-book upload;
6. absence of raw/unkeyed identifier-hash upload;
7. result minimization;
8. for VOPRF: blinded-input handling, verified proof, exact public-key id, directory epoch, authenticated snapshot, snapshot version, and enumeration budget;
9. for confidential compute: attestation, measurement authorization, trusted-boundary channel termination, host plaintext exclusion, non-persistence, and memory zeroization; and
10. whether the service observed explicit query identifiers.

The semantic validator checks these declared/verified facts. It does not implement VOPRF, directory authentication, remote attestation, confidential computing, rate limiting, or secure memory erasure.
