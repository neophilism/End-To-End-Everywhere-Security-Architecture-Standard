# AUD-23.1 — Independent Python/Node group update digest agreement

This slice exercises the existing Python canonical serializer and a separate JavaScript canonical implementation on exact AUD-15 group member commitments and applied-transition receipts. Tests cover stable set sorting, receipt changes, domain separation and invalid membership objects. Both implementations independently compute the SHA-256 over the same versioned domain and canonical bytes.

These are **cross-language digest fixtures**. They do not implement or independently validate MLS, a KEM, signatures, external partner systems or actual interoperable group messaging. AUD-23's full adversarial composition and two-independent-cryptographic-implementation requirements remain pending.
