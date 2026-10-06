# Unified Threat Model

**Status:** Normative

This document defines the baseline adversary model and threat-declaration rules used by E2EESA. It does not require every product to withstand every threat. It requires every security claim to state which threats are in scope, which are out of scope, and what properties remain protected under each relevant compromise condition.

## 1. Principles

### 1.1 Capability-based modeling

Threats MUST be described in terms of adversary capabilities, trust-boundary violations, and compromise conditions.

Labels such as "nation-state", "criminal", "insider", "advanced attacker", or "honest-but-curious" MUST NOT substitute for a capability description.

### 1.2 Claims are conditional

A security claim MUST identify the threat conditions under which it is intended to hold.

A profile MUST NOT imply that confidentiality survives an endpoint compromise that gives an adversary contemporaneous access to plaintext unless the profile defines a narrower protected asset or execution boundary that remains uncompromised.

### 1.3 Distinct compromises remain distinct

Network compromise, service compromise, account compromise, endpoint compromise, key compromise, recovery compromise, hardware compromise, and supply-chain compromise MUST be modeled separately unless a profile explicitly defines a composition rule between them.

### 1.4 Composition matters

A profile MUST evaluate credible combinations of threats when the combination materially changes the security outcome.

The fact that a system tolerates threat A and threat B independently MUST NOT be treated as proof that it tolerates A and B simultaneously.

## 2. Protected assets

Threat analysis MUST identify relevant protected assets. E2EESA recognizes at least:

- protected content plaintext;
- content-encryption keys and derived secret state;
- long-term identity keys;
- device identity keys;
- recovery secrets and recovery authorization material;
- group membership state;
- key-transparency state and audit evidence;
- authentication credentials;
- software signing keys;
- build and release provenance;
- configuration and policy state;
- metadata;
- backups;
- audit and certification evidence.

Profiles MAY define additional protected assets.

## 3. Adversary capability classes

### TM-NET-PASSIVE: Passive network observation

The adversary can observe network traffic available on one or more network paths, including addresses, timing, sizes, ordering, and unprotected protocol fields, but cannot modify traffic on those paths.

Profiles claiming content confidentiality against this threat MUST protect protected content independently of transport-path secrecy.

### TM-NET-ACTIVE: Active network control

The adversary can observe, delay, drop, replay, reorder, inject, redirect, or modify network traffic on controlled paths.

Applicable profiles MUST state how authentication, integrity, replay resistance, and downgrade resistance behave under this threat.

### TM-SERVICE-READ: Service data access

The adversary can read data available to service infrastructure, including stored ciphertext, queues, databases, logs, caches, routing state, and service-visible metadata.

A genuine E2EE content-confidentiality claim MUST survive this threat for protected content unless the service is explicitly an intended recipient.

### TM-SERVICE-ACTIVE: Malicious service provider or compromised service control plane

The adversary can cause service infrastructure to deviate arbitrarily from prescribed server behavior, including returning false directory data, withholding or reordering messages, presenting inconsistent state, attempting key substitution, manipulating membership state, or targeting users selectively.

Profiles MUST identify which properties are expected to survive and which require transparency, user verification, external auditing, or another consistency mechanism.

### TM-ACCOUNT: Account-control compromise

The adversary obtains account-level authentication or authorization capability sufficient to exercise actions normally available to the account.

Profiles MUST state whether account compromise permits device enrollment, key replacement, recovery, history restoration, group changes, or other cryptographically significant actions.

Account compromise MUST NOT automatically be equated with disclosure of existing E2EE message keys.

### TM-CREDENTIAL: Credential theft

The adversary obtains one or more authentication credentials, session tokens, recovery codes, passwords, or equivalent authorization artifacts without necessarily controlling an endpoint.

The consequences MUST be determined by the capability actually granted by the stolen credential.

### TM-ENDPOINT-STATE: Endpoint secret-state compromise

The adversary obtains a snapshot of cryptographic secret state from an endpoint without necessarily retaining continuing control of the endpoint.

Profiles claiming forward secrecy or post-compromise security MUST state the exposure window and recovery behavior for this threat.

### TM-ENDPOINT-LIVE: Live endpoint compromise

The adversary gains contemporaneous execution or observation capability within the endpoint trust boundary sufficient to read plaintext, fresh secrets, or protocol state while control persists.

E2EESA does not require a messaging protocol to conceal plaintext from an adversary that presently controls an endpoint authorized to access that plaintext.

Profiles MUST distinguish protection after compromise ends from protection during continuing compromise.

### TM-DEVICE-PHYSICAL: Physical device possession

The adversary obtains physical possession of a device and may attempt offline extraction, boot manipulation, debugging, storage inspection, or attacks against local authentication and protected storage.

Profiles MUST state assumptions about device lock state, secure hardware, local authentication, key erasure, and offline attack resistance where relevant.

### TM-INSIDER: Privileged insider abuse

The adversary possesses legitimate privileged access to one or more service, build, support, certification, recovery, or administrative systems and abuses that access.

Profiles MUST model insider capabilities according to actual privileges rather than assuming that organizational policy prevents misuse.

### TM-UPDATE: Malicious software update

The adversary can cause a target to receive software or configuration signed, distributed, or otherwise accepted as an authorized update.

A profile claiming resistance to this threat MUST identify the independent mechanism that prevents or detects malicious authorized updates, such as threshold authorization, reproducible-build verification, code transparency, independent review, or another explicitly defined control.

Ordinary application-layer E2EE alone does not defend an endpoint after trusted update infrastructure has installed malicious endpoint code.

### TM-SUPPLY-CHAIN: Build or dependency compromise

The adversary can modify source dependencies, build inputs, build infrastructure, generated artifacts, package repositories, CI/CD systems, or provenance records.

Profiles MUST state what supply-chain controls are required to detect, prevent, or constrain such compromise.

### TM-SIGNING-KEY: Release-signing compromise

The adversary obtains or can misuse a software, firmware, configuration, or artifact signing capability.

Profiles MUST state rotation, revocation, threshold, transparency, or recovery controls where signing compromise is in scope.

### TM-RECOVERY: Recovery-system compromise

The adversary gains unauthorized capability over a recovery mechanism, including recovery secrets, recovery authorization, recovery services, recovery trustees, or recovery hardware.

Profiles that provide recovery MUST state whether this threat can expose historical content, permit identity takeover, add a device, or merely restore specific protected assets.

### TM-BACKUP: Backup compromise

The adversary obtains stored backup material and any service-side information associated with it.

Backup confidentiality MUST be assessed separately from live-channel confidentiality.

### TM-HARDWARE: Secure-hardware compromise

The adversary violates assumptions of a TEE, HSM, secure enclave, TPM, hardware token, or similar protected execution or key-storage mechanism used by the selected profile.

Profiles relying on secure hardware MUST explicitly identify which security claims depend on the hardware assumption and how failure is contained, detected, or recovered.

### TM-DIRECTORY: Identity or key-directory equivocation

The adversary causes different honest users to receive inconsistent identity-to-key, device-list, membership, or directory views.

Profiles claiming resistance MUST define how equivocation is prevented or detected.

### TM-METADATA: Metadata observation or inference

The adversary obtains service-visible or network-visible metadata and may correlate timing, size, routing, identity, social-graph, device, or access-pattern information.

Content E2EE MUST NOT be represented as metadata confidentiality.

Any metadata-protection claim MUST identify the metadata fields and observer capabilities covered.

### TM-DOS: Availability attack

The adversary can delay, drop, suppress, flood, exhaust, or selectively deny service.

Confidentiality and authenticity claims MUST NOT be conflated with availability.

Profiles that claim availability properties MUST define them separately.

### TM-ROLLBACK: State rollback or replay

The adversary can restore, replay, fork, or present stale cryptographic, membership, recovery, transparency, or configuration state.

Profiles with state-continuity requirements MUST state how rollback is prevented or detected.

### TM-RNG: Randomness failure

The adversary causes, predicts, biases, or learns random values used by a cryptographic operation.

Profiles MUST state which randomness assumptions are required. Implementations MUST use approved cryptographic random-number generation appropriate to the selected cryptographic profile.

### TM-CLOCK: Time-source manipulation

The adversary can manipulate wall-clock or time-synchronization inputs used for expiry, certificate validation, transparency freshness, revocation, or policy decisions.

Profiles relying on time MUST state tolerances and failure behavior.

### TM-QUANTUM-HARVEST: Store-now-decrypt-later adversary

The adversary records ciphertext and associated protocol data now and is assumed to gain cryptographically relevant quantum capability later.

Profiles claiming post-quantum confidentiality MUST identify which historical data remains protected under this model.

### TM-QUANTUM-ACTIVE: Cryptographically relevant active quantum adversary

The adversary possesses quantum capability sufficient to attack cryptographic algorithms whose security depends on quantum-vulnerable assumptions while participating actively in protocol execution.

Profiles claiming protection under this threat MUST use an applicable post-quantum or hybrid profile and MUST state any remaining classical assumptions.

## 4. Composite scenarios

At minimum, later profiles MUST consider whether the following combinations materially alter their security claims:

1. malicious service plus active network control;
2. account compromise plus attempted device enrollment;
3. endpoint-state compromise followed by loss of adversary access;
4. live endpoint compromise plus later recovery of endpoint control;
5. backup compromise plus credential theft;
6. recovery-system compromise plus account compromise;
7. malicious update plus service targeting;
8. supply-chain compromise plus signing-key compromise;
9. directory equivocation plus selective service behavior;
10. physical device possession plus offline credential guessing;
11. quantum harvest today plus future quantum capability.

A profile MAY declare a composite scenario out of scope, but MUST do so explicitly where users could reasonably infer otherwise from the profile's claims.

## 5. Threat declarations by profiles

Every production profile MUST declare:

- protected assets;
- applicable threat IDs;
- security properties expected to survive each applicable threat;
- security properties explicitly not claimed under each applicable threat;
- trust assumptions;
- recovery conditions, when a property can recover after compromise;
- relevant composite scenarios; and
- any threats expressly out of scope.

A profile MUST NOT use an undefined phrase such as "secure against sophisticated attackers" in place of this declaration.

## 6. Temporal compromise model

Where compromise may be temporary, the analysis SHOULD distinguish:

- **before compromise**;
- **during compromise**;
- **after compromise ends but before protocol healing**; and
- **after protocol healing**.

Claims of post-compromise security MUST define the event that constitutes healing and the conditions required for it.

## 7. Server and provider assumptions

A profile MUST state whether its service is modeled as:

- honest;
- honest but able to read all service-visible state;
- compromised;
- malicious and actively deviating; or
- malicious and selectively presenting different views to different users.

A genuine E2EE content-confidentiality profile MUST NOT require an honest service provider to keep protected content confidential from the provider itself.

## 8. Endpoint assumptions

Profiles MUST state which endpoint components are trusted and which privileged components are outside the endpoint boundary.

A profile MUST NOT claim protection from malicious code executing inside the same trusted endpoint boundary with unrestricted access to plaintext unless an additional isolation boundary is explicitly defined and evaluated.

## 9. Recovery, backup, and hardware assumptions

Recovery, backup, and hardware-assisted security are independent attack surfaces.

A profile that uses any of them MUST model their compromise consequences explicitly and MUST NOT inherit the security claims of the live communication protocol without analysis.

## 10. Quantum scope

"Post-quantum" MUST be treated as a property of a specified mechanism and threat model, not a blanket label for the entire product.

A profile that uses both classical and post-quantum components MUST identify:

- which claimed properties rely on each component;
- whether confidentiality fails only if both components fail or if either component fails;
- whether authentication remains classically dependent; and
- the harvest-now/decrypt-later consequences.

## 11. Non-goals of the baseline threat model

This baseline does not claim that cryptography can prevent:

- an authorized recipient from deliberately disclosing received plaintext;
- a live compromised endpoint from exposing plaintext it is authorized to process;
- coercion of a user outside the technical system;
- correctness of information supplied by an authorized participant;
- availability in the face of an adversary able to prevent all communication; or
- security properties that a selected profile explicitly declares out of scope.

Later profiles MAY introduce controls addressing narrower forms of these risks, but MUST state the additional assumptions involved.

## 12. Fail-closed interpretation

If a conformance claim omits a threat necessary to interpret a claimed security property, the claim MUST NOT be interpreted as silently covering that threat.

Ambiguity about whether a high-impact compromise is covered MUST resolve toward the narrower claim until the profile or evidence explicitly establishes broader coverage.
