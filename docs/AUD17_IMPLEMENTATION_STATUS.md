# AUD-17 observer and response-correlation implementation slice

Reference-only validator for push wake-only and encrypted-payload options. It denies undeclared visible outer fields, plaintext relationship identifiers, cross-service token reuse, and provider-decryptable ciphertext under a confidentiality representation. Mode-specific response policies require explicit evidence flags; neither delay, batching nor jitter proves anonymity. Even a passing reference record retains timing and routing observability and never claims deployed provider confidentiality.

Pending full unit acceptance: actual push provider field capture, signed endpoint recipient/key verification, authenticated consent and recipient state, measured traffic timing correlation, real background response flows, browser/native integration, provider-specific expiry, and privacy-preserving conformance reporting. This reference does not establish complete protection or independent certification.
