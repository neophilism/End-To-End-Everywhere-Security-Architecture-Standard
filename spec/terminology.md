# Terminology

**Status:** Normative

This document defines core terms used throughout E2EESA. Later profiles MAY add domain-specific terminology, but MUST NOT silently redefine terms in this document.

## 1. Actors and system boundaries

### User

A natural person or organizational principal that uses an E2EE-capable product or service.

### Account

A logical service identity used to associate a user with one or more devices, credentials, settings, or service-side records.

An account is not necessarily a cryptographic identity.

### Device

A physical or virtual computing environment controlled by or acting for a user and capable of hosting one or more endpoints.

A single device MAY host multiple endpoints.

### Endpoint

The trusted software-and-key boundary at which protected content is encrypted before leaving the sender side and decrypted after reaching an intended recipient side.

An endpoint is defined by its cryptographic function, not merely by physical hardware.

Software outside the endpoint trust boundary MUST NOT be assumed to have access to plaintext or endpoint-held secret key material.

### Client

Software acting on behalf of a user. A client MAY contain an endpoint, but the terms are not synonymous.

### Service

One or more network-accessible systems that provide delivery, storage, discovery, synchronization, coordination, identity, or other application functions.

### Service provider

The entity that operates or controls a service.

### Intermediary

Any system that processes, stores, routes, indexes, relays, or otherwise handles protected communications between endpoints without being an intended content recipient.

### Intended recipient

A user, account, device, endpoint, or authorized group member that the sender intentionally authorizes to obtain protected plaintext.

## 2. Data and cryptographic material

### Plaintext

Protected content in a form available to an authorized application or user before encryption or after successful decryption.

### Ciphertext

The output of an encryption operation intended to conceal plaintext from parties lacking the required decryption capability.

### Protected content

Application content whose confidentiality or integrity is within the scope of an E2EESA security claim.

### Metadata

Information about communication, storage, identity, devices, relationships, timing, size, routing, group membership, access patterns, or other context that is not itself the protected content payload.

Whether a particular field is treated as protected content or metadata MUST be explicit in the applicable profile.

### Secret key material

Any cryptographic secret whose disclosure could enable decryption, impersonation, unauthorized signing, unauthorized key derivation, or another security failure within the applicable threat model.

### Long-term key

A secret or public key intended to persist across multiple sessions, epochs, or protocol runs.

### Ephemeral key

A key generated for limited-duration use and intended to be discarded according to the applicable protocol.

### Session

A bounded cryptographic context in which participants derive or use key material for protected communication.

### Epoch

A protocol-defined generation of group or session state during which a defined set of cryptographic state is current.

## 3. End-to-end encryption

### End-to-end encryption (E2EE)

A communication or storage architecture in which protected content is encrypted at an authorized endpoint and can be decrypted only by intended recipient endpoints, subject to explicitly defined recovery or export capabilities.

An intermediary or service provider that is not an intended recipient MUST NOT possess routine technical capability to obtain protected plaintext from information available to that intermediary or provider alone.

Transport encryption between an endpoint and a service is not, by itself, E2EE.

### E2EE boundary

The set of components, code, key stores, and execution environments that are trusted to access protected plaintext or secret key material for a particular E2EE operation.

### Server-side encryption

Encryption in which a service or service-controlled component retains routine capability to decrypt protected data.

Server-side encryption MAY provide valuable security but MUST NOT be described as E2EE unless the service is itself an intended endpoint under the explicitly claimed security model.

### Client-side encryption

Encryption performed by client software before data is sent to a remote service.

Client-side encryption is not automatically E2EE. It is E2EE only when the complete architecture satisfies the definition of E2EE and the claimed recipient/trust model.

## 4. Identity, authentication, and verification

### Cryptographic identity

A cryptographically represented identity or identity root used to authenticate a user, account, device, or endpoint.

### Device identity

A cryptographic identity associated with a specific device or endpoint.

### Authentication

The property or process by which a participant gains assurance about the identity or authorization of another participant or message origin.

### Authorization

A decision that a principal is permitted to perform an action, access content, join a group, add a device, recover an account, or exercise another protected capability.

Authentication and authorization are distinct.

### Key verification

A process by which a user or system gains assurance that a cryptographic key is correctly associated with the intended identity.

### Key transparency

A mechanism that makes identity-to-key bindings auditable so that inconsistent, substituted, or selectively presented bindings can be detected according to the mechanism's security model.

### Key substitution attack

An attack in which an adversary causes a participant to accept an adversary-controlled or unintended key as belonging to another identity.

## 5. Security properties

### Confidentiality

The property that protected content is not disclosed to an unauthorized party.

### Integrity

The property that unauthorized modification of protected data is detected.

### Message authenticity

The property that a recipient can establish that a protected message was generated by an authorized sender or sender endpoint according to the applicable protocol.

### Forward secrecy

The property that compromise of designated current or long-term secret key material does not compromise designated past protected content beyond the exposure allowed by the applicable profile.

A profile claiming forward secrecy MUST identify which key compromises and which past communications are covered.

### Post-compromise security (PCS)

The property that, after specified secret state is compromised, subsequent protocol evolution can restore protection for later communications once the adversary no longer controls the required endpoint or state, according to the applicable threat model.

PCS MUST NOT be interpreted as protection while an adversary retains continuous control of an endpoint capable of observing plaintext or fresh secret state.

### Key consistency

The property that honest participants can detect or prevent materially inconsistent views of identity-key or group-state information when the applicable protocol claims such consistency.

### Downgrade resistance

The property that an adversary cannot cause participants to use a weaker protocol, version, algorithm, profile, or capability than their applicable policies permit without detection or failure.

### Replay resistance

The property that unauthorized replay of previously valid protocol data is rejected or rendered harmless according to the applicable protocol.

### Deniability

A property whereby protocol evidence is intentionally insufficient, under a defined model, to provide transferable cryptographic proof to an uninvolved third party that a particular participant authored a particular communication.

### Non-repudiation

A property intended to provide durable evidence attributable to a principal such that authorship or approval can be demonstrated to a third party under the applicable model.

Deniability and non-repudiation represent different security goals; neither is universally preferable.

## 6. Compromise and recovery

### Compromise

A condition in which an adversary obtains unauthorized access to data, secret state, execution capability, credentials, or control relevant to a claimed security property.

### Endpoint compromise

Compromise that permits an adversary to inspect or manipulate an endpoint, its plaintext, or its secret state within the applicable threat model.

### Key compromise

Unauthorized acquisition or use of secret key material.

### Account compromise

Unauthorized control of account-level authentication or authorization capability.

Account compromise does not necessarily imply compromise of existing E2EE message keys, and endpoint compromise does not necessarily imply account compromise. Profiles MUST state the consequences they assume.

### Recovery

A process by which a user regains access to an account, cryptographic identity, encrypted backup, protected content, or cryptographic capability after loss of ordinary credentials, keys, or devices.

### Recovery secret

A user-held or otherwise protected secret specifically used to authorize or derive recovery capability.

### Backup

A retained copy of protected content, state, keys, or derived recovery material intended to permit restoration after loss or replacement.

A backup's security properties MUST be evaluated independently of the live communication channel.

## 7. Groups and membership

### Group

A cryptographic communication context authorizing more than one recipient participant or endpoint.

### Membership

The protocol state that determines which principals or endpoints are authorized participants in a group at a given epoch.

### Member removal

A membership transition intended to prevent a removed member from decrypting protected content created after the removal takes effect, subject to the applicable protocol and compromise model.

### Rekey

The derivation, distribution, or establishment of fresh cryptographic key material replacing or advancing previously current key material.

## 8. Assurance and lifecycle

### Conformance

Satisfaction of all applicable normative requirements for a declared E2EESA version, profiles, capabilities, and assurance scope.

### Assurance

The justified level of confidence that a system satisfies specified security requirements based on evidence such as design review, source review, testing, formal analysis, provenance, audit, or operational monitoring.

### Security profile

A named and versioned set of requirements and architectural choices that satisfies E2EESA invariants for a defined use case or security model.

### Capability

An optional functional area that applies only to products that provide that feature, such as backup, contact discovery, or real-time media.

### Security invariant

A security requirement that every conformant configuration within its scope MUST satisfy and that a profile is not permitted to disable.

### Provisional

A lifecycle state for a mechanism or profile that is usable only under explicitly stated constraints because a dependency, external standard, or evidence base is not yet sufficiently stable for final status.

### Experimental

A lifecycle state for research or candidate mechanisms that MUST NOT be treated as production-recommended merely because they are represented by E2EESA.

### Deprecated

A lifecycle state indicating that new deployments SHOULD NOT select the mechanism and migration away from existing use is expected.

### Prohibited

A lifecycle state indicating that the mechanism MUST NOT be selected by a conformant configuration within the prohibition's scope.

## 9. Threat-model terms

### Adversary

A party or process attempting to violate one or more claimed security properties.

### Honest participant

A participant that follows the applicable protocol and is not compromised for the purpose of the analyzed threat.

### Malicious service provider

A service provider assumed, for a particular threat model, to deviate arbitrarily from the prescribed server behavior in an attempt to violate security properties.

### Insider

A person or process with legitimate privileged access that abuses that access or whose privileged credentials are compromised.

### Supply-chain compromise

Unauthorized modification or substitution of source code, dependencies, build systems, artifacts, signing infrastructure, distribution mechanisms, or updates in a manner relevant to security.

### Quantum adversary

An adversary assumed to possess cryptographically relevant quantum-computing capability sufficient to attack algorithms whose security depends on problems vulnerable to such computation.

## 10. Interpretive rule

When a term in this document is used in another E2EESA document, this definition controls unless that document explicitly introduces a more specific term for a narrower scope.

A profile MUST NOT use ordinary-language ambiguity to reduce the security meaning of an E2EESA-defined term.
