# Push-provider and response-correlation privacy (AUD-17)

**Status:** Normative policy contract, not production endpoint qualification.

## Explicit push transport modes

Push providers are observers and non-recipient infrastructure, not trusted plaintext recipients. E2EESA defines two distinct modes:

- **Wake-only**: an application sends an empty payload, with explicitly declared minimal routing and wake fields only. It **MUST NOT** include message bodies, previews, content-derived hashes, conversation IDs, relationship IDs, or plaintext sender/recipient information. Token and timing metadata nevertheless remain visible to the push provider.
- **Opaque-encrypted-payload**: an application MAY include endpoint ciphertext only when bound to the exact selected cryptographic profile and already authorized endpoint key. The push provider **MUST NOT** possess the decryption key or receive a decryptable key copy. This mode must disclose outer payload length and other routing/timing metadata; it **MUST NOT** claim provider anonymity simply because ciphertext is opaque.

Applications **MUST** reject mode confusion and silent fallback to payloads decryptable using provider-controlled keys. Provider-owned transport encryption does not substitute for endpoint E2EE. The allowed outer fields **MUST** be explicitly inventoried for each provider and application scope; arbitrary payload extensions or unrecognized fields fail closed.

## Token scope, automatic responses, and observer model

Routing tokens SHOULD be scoped to a single application/service/provider role and **MUST NOT** be reused across unrelated services where such reuse creates an avoidable direct linkage. Observation and disclosure reports MUST cover push delivery timestamps, token reuse, size, routing identifiers, automatic responses, and failure/retry paths. Products MUST NOT assert that nondeterministic jitter or provider confidentiality provides unlinkability against a global passive observer.

Automatic receipt behavior MAY follow one of three explicit policies: no automatic receipt, bounded delay, or minimum batch. The selected policy MUST constrain actual response dispatch at the source/build runtime egress boundary. A delay or batch does not establish an anonymity set without independently measured and threat-modelled results. Any response-correlation digest is traceability evidence only, not a privacy verdict.

## Actual security evidence

Reference evaluator \`scripts/push_metadata_engine.py\` and negative fixtures \`tests/test_push_metadata_engine.py\` validate declared observation fields, exact provider/recipient/key bindings, two distinct payload modes, token cross-service reuse and response timing labels. They cannot determine actual provider decryptability, private key isolation, packet contents or global timing correlation. Source-bound endpoint instrumentation and real provider captures, including crash/retry and notification service extensions, MUST supply such evidence before passing applicable product conformance. Neither provider confidentiality nor relationship anonymity is granted by this reference evaluator.
