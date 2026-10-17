# AUD-17 implementation status

AUD-17.1 introduces a strict push observation reference policy with separate wake-only and endpoint-only ciphertext modes. It rejects provider-decryptable payload declarations, undeclared relationship identifiers, mixed-profile or wrong-recipient messages, cross-service token reuse, and automatic response violations. It never declares relationship anonymity or actually verified provider confidentiality.

**Remaining:** source/build-bound provider packet captures and decryptability audits; token-scoping implementation and cross-device behavior; timing-correlation measurements against stated observers; actual response dispatch integration; notification service extensions; failure/crash/retry instrumentation; reliable source-bound conformance. The parent AUD-17 remains pending.
