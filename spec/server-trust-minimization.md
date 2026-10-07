# Server Trust Minimization

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 21.

`server-ciphertext-only@0.1.0` defines a common service invariant rather than a
new cipher or messaging protocol. It applies to infrastructure outside the
authorized endpoint boundary, including relays, queues, CDNs, object stores,
backup stores, push services, diagnostics, search services and their subprocessors.

## 1. Protected-content boundary

Services MUST receive, route and store only application ciphertext for E2EE
content. They MUST NOT possess message/file/media keys, device authorization
roots, unwrapped backup data keys, recovery secrets, or a credential that enables
their recovery. A service-side KMS may protect service credentials and metadata,
but MUST NOT unwrap the application's E2EE layer. Service keys MUST be independent
from application keys and limited to the explicitly assessed purposes:
TLS/service authentication, metadata-at-rest encryption or abuse controls.

Encrypting server disks with a server-held key does not satisfy E2EE. Application
ciphertext MUST remain encrypted across TLS terminators and service-side
storage-encryption boundaries. Compromise of service credentials alone MUST NOT
provide plaintext access. This requirement does not assert that a service cannot
delay, drop, replay or misroute ciphertext.

## 2. Exhaustive inventory and authority

The assessment MUST inventory every discovered service component, subprocessor,
privileged key/capability and processing path. The discovered component set MUST
equal the assessed set; duplicate or missing identities fail validation. Reports
MUST include privileged/operator-access paths, restores, logs, replicas and
background processing, not just nominal application permissions.

Account login, routing directory access and storage credentials MUST NOT
unilaterally add an authorized E2EE device. Clients MUST verify recipient
authorization under PR 8 and verify authenticated envelopes before accepting
content. The actual device recipient set MUST exactly equal the authorized set
for the object and sending event. A service cannot resolve a delivery failure by
adding its own key. PR 7 negotiation and PRs 11–12 key verification/transparency
remain independently applicable.

## 3. Queues, attachments and derived content

Queue/object records MUST bind an opaque locator, creation/expiry times, assessed
component and client-authorized device recipients. Locators MUST NOT contain
cryptographic keys or recovery material. Private filenames/manifests remain
endpoint-encrypted under PR 16. Thumbnails, previews, OCR, transcodes and search
indexes MUST remain encrypted or be generated only at authorized endpoints.
Server-side plaintext indexes or preview generation fail this profile.

The policy MUST specify a bounded ciphertext retention interval, no greater than
30 days in this version. Evidence MUST show valid creation/expiry times within
that bound, purge at or before expiry, and no invented future deletion. Storage
replicas, failed-delivery queues and backups MUST follow the same declared
retention semantics. Long-term endpoint-controlled archives belong to the PR 13
backup profile and require a separately assessed retention policy/profile version.

Deleting ciphertext from infrastructure is not recipient recall. Clients may
already hold plaintext or keys; no server profile can guarantee their deletion.

## 4. Metadata, operations and deliberate endpoint services

Server metadata MUST be limited to the explicit allowlist of recipient routing,
ciphertext size, expiry and delivery state. Metadata at rest MUST be encrypted;
logs MUST exclude content and E2EE secrets. PR 14 defines stronger sender/network
privacy where selected. This profile alone does not hide recipient routing,
traffic volume, timing, size, account access or availability behavior.

Transcription, recording, moderation or search bots that receive plaintext are
authorized endpoints and MUST be visible and separately authorized as such.
They MUST NOT be described as ciphertext-only infrastructure. Voluntary abuse
reports likewise require an explicit disclosure scope and separately assessed
endpoint/export path; they are not an implicit server decryption entitlement.

## 5. Evidence and adversarial validation

Evidence MUST bind the exact policy and product/version/platform, identify an
assessor and reference content-addressed architecture/access-test reports. Reports
MUST demonstrate a service-compromise exercise covering storage/admin credential
access, KMS boundaries, queue/object dumps, backups, logging, derived-content
paths and attempts to enroll an attacker device. Missing coverage requires
remediation, not a blanket confidentiality claim.

The semantic engine validates evidence structure, key separation, recipient
completeness and retention relationships. It does not decrypt sampled records,
inspect a live deployment or authenticate assessor reports. Its fixture records
are synthetic examples. Actual deployment assurance depends on authenticated
reports and independent examination in the later verification/certification
layers. A malicious authorized endpoint, compromised client or colluding
authorized recipients remain outside the infrastructure confidentiality claim.

## 6. Existing normative dependencies

This profile composes with [identity/device authorization](identity-device-architecture.md),
[backup/recovery](backup-recovery.md), [metadata privacy](metadata-privacy.md),
[attachments](attachments-file-encryption.md), [media](real-time-media.md),
[secret storage](secret-storage-hardware-protection.md),
[transport](transport-security.md) and [client security](native-web-client-security.md).
No new cryptographic primitive or wire format is introduced.
