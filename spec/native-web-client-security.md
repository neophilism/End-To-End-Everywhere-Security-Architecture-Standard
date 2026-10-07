# Native and Web Client Security

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 20.

This layer governs the executable code that handles endpoint plaintext and
cryptographic secrets. It composes with PR 18 secret storage and PR 19 transport;
neither TLS nor non-exportable keys makes malicious endpoint code trustworthy.

## 1. Supported execution profiles

| Exact profile | Execution trust | Status |
| --- | --- | --- |
| `client-native-signed@0.1.0` | Independently installed release-signing trust root and platform execution enforcement | Recommended |
| `client-web-hardened@0.1.0` | Origin delivers executable code; independent transparency detects inconsistent releases | Allowed |
| `client-web-verified-bootstrap@0.1.0` | Independently installed bootstrap verifies executable closure before execution | Recommended |

A product MUST select one applicable `client-security` profile for each assessed
platform. Profiles for different platforms are assessed separately. A PWA or
service worker downloaded from the same origin does not, by itself, establish
independent bootstrap trust. Ordinary web clients MUST disclose origin code
delivery trust and MUST NOT claim prevention of malicious-origin code execution.

## 2. Release identity and update trust

Every release MUST have a complete manifest of executable artifacts, including
workers, WASM, plugins, preload code and dynamically imported modules. Each entry
MUST bind a relative path, byte length and SHA-256 content digest. The release
identity is `sha256:` plus the digest of the repository's deterministic JSON
encoding: ASCII JSON, sorted keys, no whitespace, escaped non-ASCII characters,
no NaN/Infinity. This is a local evidence encoding, not an RFC 8785 claim.

The client MUST authenticate release/update metadata against independently
provisioned trust roots. The signing identity MUST match the policy's pinned
signers. Product, version, platform, policy digest and complete executable closure
MUST be bound to the release assessment. Unknown or unverified executable content
MUST fail closed before it handles E2EE material.

Update systems MUST protect against rollback, freeze, mix-and-match and partial
installation attacks. They MUST persist accepted release sequences, reject a
sequence below the pinned minimum or prior accepted value, enforce metadata
expiration against a trustworthy time source, atomically install verified
artifacts, and maintain a safe failure state. Trust-root rotation MUST be
authenticated under the previous and replacement authorization policy. The TUF
1.0.36 reference defines a supported metadata architecture; this evidence layer
does not implement a TUF client or permit its security checks to be omitted.

## 3. Code transparency

Release manifests MUST be included in an append-only code log. Inclusion and
consistency proofs, checkpoint persistence and equivocation monitoring MUST be
verified. At least one independently operated witness MUST be available, with
the policy permitted to require more. The log operator and witnesses MUST be
independent from the delivery operator and from one another under the deployment
threat model. Witness identifiers alone do not prove independent ownership.

Accepted log entries MUST bind the exact release digest; checkpoints MUST NOT
roll back. A split view, unverified entry, unsupported release or required witness
failure MUST prevent a new release from being accepted. Availability behavior
for an already verified cached release MUST be documented; using cached verified
code MUST NOT silently accept an expired update or a different release.

For the ordinary web profile, transparency remains a monitoring/evidence
mechanism: malicious origin code can bypass an origin-delivered verifier. Only an
independently trusted execution gate can claim rejection before execution.

## 4. Native controls

Native clients MUST verify platform signing or an equivalent authenticated
package/installer signature, run with least privilege and platform-appropriate
sandbox isolation, disable production debug interfaces, authenticate updates,
and isolate untrusted messages, attachments and renderers from secret handling.
Desktop platforms without built-in package signing MUST implement an explicitly
assessed authenticated installer and update chain rather than claim a nonexistent
OS guarantee. Native manifests and signing assessments are platform scoped.

## 5. Browser controls

Browser clients MUST pin an HTTPS origin, require a secure context and HSTS,
exclude mixed content, and enforce CSP through an HTTP response header. This
version deliberately supports a restrictive hash-authorized CSP subset:

- `default-src`, `object-src`, `base-uri`, `frame-ancestors` are `'none'`;
- `script-src` contains explicit SHA-256 hashes only; overriding
  `script-src-elem` MUST carry the identical list;
- `script-src-attr` is `'none'`, workers are restricted to `'self'`, and
  `connect-src` contains explicit HTTPS origins.

All executable subresources and service-worker updates MUST bind to the release
manifest. SRI checks MUST be applied where the browser supports them; additional
loader verification MUST cover executable types without SRI enforcement. CSP
hashes and SRI metadata MUST be derived from the assessed artifact bytes. Safe DOM
construction and injection defenses MUST be verified; Trusted Types MAY supply
an additional supported-browser control, with an assessed fallback.

Cross-origin messaging MUST check both origin and source, protect state changes
against CSRF, isolate untrusted frames/content, prohibit third-party scripts in
the secret-handling context and avoid plaintext secrets in local/session storage.
Persistent secrets MUST use authenticated encryption with an explicit unlock and
key-storage policy. A non-extractable WebCrypto key alone does not prevent
same-origin malicious JavaScript from invoking it. Extension/browser compromise
risks MUST be disclosed rather than treated as defeated by CSP or SRI.

The verified-bootstrap profile MUST install its verifier through an independent
authenticated channel. The verifier MUST cover top-level HTML/bootstrap code,
all descendants and service-worker updates before execution, persist release and
log continuity, and reject manifest mismatches. A same-origin HTML page pinning
its own JavaScript is insufficient.

## 6. Evidence and limitations

Policies and evidence MUST use the closed schemas in this PR. Assessment records
MUST reference content-addressed reports and identify the assessor, exact policy,
product version and platform. Synthetic fixtures are examples, not signed
reports, verified binaries or certificates.

`client_security_engine.py` validates record shape, binding and security
semantics. It does not fetch artifacts, validate signatures/proofs, or inspect a
running browser. External assessors MUST perform and authenticate those checks;
boolean evidence fields are declared results, never proof of their truth.
Protection from a compromised OS/browser, malicious authorized release signer or
hostile authorized endpoint is outside all three profiles. The supply-chain and
verification milestones add deeper build and testing evidence.

## 7. Version-pinned references

- [TUF specification v1.0.36](https://github.com/theupdateframework/specification/releases/tag/v1.0.36)
- [CSP Level 3, 16 September 2026 Working Draft](https://www.w3.org/TR/2026/WD-CSP3-20260916/) — work in progress; the supported subset above is fixed by this E2EESA version.
- [SRI Recommendation, 23 June 2016](https://www.w3.org/TR/2016/REC-SRI-20160623/)
