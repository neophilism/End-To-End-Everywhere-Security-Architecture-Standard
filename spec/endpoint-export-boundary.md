# Endpoint export boundary (AUD-10)

**Status:** Normative reference rule; not a product assessment or hardware enforcement claim.

## Covered flows

An E2EESA protected-content boundary **MUST** treat export of plaintext, classifiers, embeddings, previews, content-derived hashes, search indexes, diagnostics, telemetry, provider API inputs and similar derived artifacts as content disclosure, even when the artifact omits the original plaintext. A service or provider does not become an authorized recipient merely because a developer relabels its processing role.

Policies **MUST** bind claims to specific source/build components, protected data flows, the exact intended endpoint identities and key fingerprints, transport recipients, and authorized exposure of metadata. Implementation evidence must inspect export/egress on normal, failure, retry, crash, analytics, and background paths, not only the happy path. An exhaustive policy JSON alone does not establish complete runtime coverage.

## Legitimate encrypted transport

Endpoint-only ciphertext **MAY** traverse an explicitly declared relay or intended endpoint where the actual encryption construction, recipient key binding, and intended recipient have been independently established by the application. Encryption to a provider-controlled key **MUST NOT** be treated as end-to-end recipient ciphertext. The exposed ciphertext length, timing, routing and other protocol metadata **MUST** remain separately declared and must not be inferred secret from content encryption.

## Intentional disclosure

Content-derived export to a non-recipient **MUST** be rejected absent an explicit, authenticated, user-initiated disclosure selecting a finite set of exact content IDs, exact destinations, export types and purpose, with a bounded expiry. A general terms-of-service setting, automated policy trigger, or broad future-content authorization **MUST NOT** substitute for this selection. The host **MUST** durably record used authorization IDs and prevent reuse across restarts and devices; the reference batch evaluator only enforces within the observed batch or supplied independently trusted spent-ID set.

Public-data services and authorized business processing **MUST** be classified accurately, without pretending that public facts are private E2EE content. Public outputs still require a declared destination.

## Assessment limits

The reference evaluator at \`scripts/endpoint_egress_engine.py\` validates structured *observations*, not raw memory, network packets, embeddings, filesystem exports, provider account controls, or actual ciphertext. Actual host instrumentation **MUST** prove each observation has the declared destination, real key recipient and data origin; implementation must commit checks at the final egress boundary. A malicious caller can forge labels, timestamps, authorization references, or reported destinations. No conformance should be claimed based solely on the reference evaluator. Negative cases at \`tests/test_endpoint_egress_engine.py\` demonstrate the policy boundaries, including provider-key encryption, undeclared metadata, recipient relabeling, unsafe background export, and unauthorized content selection.
