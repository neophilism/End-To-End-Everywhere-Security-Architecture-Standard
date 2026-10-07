# Software Supply Chain

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 24.

`supply-chain-attested-reproducible@0.1.0` binds distributed release bytes to
their source, inputs, builder, signing policy and independent reproduction.
It references the approved [SLSA 1.2 specification](https://slsa.dev/spec/v1.2/).
SLSA specification version 1.2 and its build-provenance predicate version 1 are
distinct identifiers and MUST NOT be conflated.

## 1. Immutable inventory and SBOMs

Every assessed release MUST include a complete inventory of source, runtime,
build and CI inputs, including transitives. Component identities MUST be unique,
dependency edges MUST resolve inside the inventory, and every input MUST bind an
exact version, source URI and SHA-256 artifact digest. Floating versions/tags,
unrecorded downloads, implicit package-registry resolution and undocumented
build inputs fail this profile. Pinning only direct dependencies is insufficient.

A standards-valid SPDX 2.3 or CycloneDX 1.6 SBOM MUST bind the exact release
subject. The selected format, underlying document digest, validation report and
normalized inventory projection MUST be recorded. The normalized projection in
`supply-chain-evidence` is an assessment contract, not an SPDX/CycloneDX document.
Actual SBOM validity/completeness MUST be checked by an appropriate format parser
and by comparison with build/distribution contents. Dependencies outside a
declared distribution scope still need separately scoped runtime/build evidence.

## 2. Artifact signing and provenance verification

Distributed bytes MUST have their digest recomputed and authenticated under the
policy's independent release-signing trust roots. Signing credentials MUST be
isolated from untrusted pull requests and ordinary build steps. Rotation,
revocation, rollback/freeze and transparency continue to follow PR 20.

Build provenance MUST use an in-toto Statement v1, the exact predicate type
`https://slsa.dev/provenance/v1`, and an authenticated DSSE envelope with payload
type `application/vnd.in-toto+json`. Signature verification MUST include the DSSE
pre-authentication encoding, algorithm/key authorization and trust-root policy;
base64 parsing or a signature-shaped string is not verification.

This version supports a closed SLSA statement subset. It MUST bind one exact
artifact subject, the policy-authorized builder and build type, canonical source
repository and exact commit, expected external parameters, all resolved inventory
materials and valid build timing. Unknown external parameters, unofficial source
forks, wrong artifacts or builder mismatch fail closed. The supported build type
`https://endtoendeverywhere.org/e2eesa/build-types/source-archive/0.1.0` describes
deterministic source-archive construction with `source_repository` and
`source_commit` as its only external parameters; it is a versioned local contract.

Verified signing identities MUST meet the policy threshold and belong to its
trusted set. Duplicate signatures from one identity do not meet multiple seats.
Assessor reports MUST authenticate the verification outcome and provenance's
origin; declarations from the artifact publisher alone are insufficient.

## 3. Builder assurance and reproducibility

Builds MUST be ephemeral and hermetic with pinned toolchain/configuration/inputs
and isolated signing. A separate builder/operator MUST reproduce byte-identical
artifacts from the assessed inputs and source. Differences MUST be investigated
and fixed; the evidence cannot redefine success as merely similar functionality.
Matching bytes do not establish that the source is safe or nonmalicious.

The minimum SLSA Build track is L2: hosted building and authenticated
platform-generated provenance require an independent builder assessment. An L3
claim additionally requires isolated builds and provenance that ordinary build
users cannot forge. These records do not perform the entire SLSA assessment or
certify a builder. Source-track levels are separate and MUST NOT be inferred from
a Build-level claim. Reproducibility is an additional E2EESA requirement, not an
automatic consequence of any SLSA level.

## 4. Reference source-release builder

`scripts/build_reference_release.py --output /absolute/path/outside/checkout`
builds the tracked, clean source tree into:

- `e2eesa-source.tar.gz`, with sorted paths, normalized owners/modes, fixed zero
  tar/gzip timestamps and no environment-dependent gzip filename;
- `release-manifest.json`, with source commit, file inventory and actual archive
  SHA-256 digest;
- `sbom.spdx.json`, an SPDX 2.3 source-distribution document bound to that archive.

The builder rejects dirty checkouts, escaping/duplicate paths, symlink files and
output inside the source tree. Reproductions MUST use compatible pinned
Python/zlib/tar implementations; compressed output is not claimed stable across
arbitrary toolchain changes. The SBOM uses a fixed reproducibility epoch, not an
asserted assessment date, and explicitly scopes itself to the source distribution.
CI/runtime components require separate inventories. It neither signs releases
nor uploads credentials, provenance or packages.

The reference validation workflow also pins remote actions by full immutable
commit SHA. This improves the repository's test pipeline; it does not by itself
make that pipeline a certified hermetic release builder.

## 5. Validation and limits

The semantic engine checks closed schemas, artifact/policy/source/material
binding, signature threshold identities, SBOM projection completeness, timing,
builder-level evidence and independent reproduction relationships. It does not
verify cryptographic signatures, query live builders or parse a full SBOM format.
Those operations require the external report digests and authenticated assessor
evidence. The source-release builder separately computes actual file/archive
digests and produces reproducible bytes; synthetic protocol fixtures do not
represent real signed attestations or a release certification.

## 6. References

- [SLSA 1.2 build requirements](https://slsa.dev/spec/v1.2/build-requirements)
- [SLSA 1.2 artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [SPDX 2.3 specification](https://spdx.github.io/spdx-spec/v2.3/)
- [CycloneDX 1.6 JSON reference](https://cyclonedx.org/docs/1.6/json/)
- [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
