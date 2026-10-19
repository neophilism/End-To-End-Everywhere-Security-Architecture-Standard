# AUD-23 cross-language canonical byte verification slice

This test invokes the existing independent ECMAScript canonical implementation and compares exact byte output with the Python implementation on Unicode order, nested structures, ordered arrays, and the safe-integer boundary. It requires Node.js in the test runtime; missing Node skips with an explicit unverified signal rather than claiming agreement.

This is only a narrow canonicalization contract, not two independently deployed cryptographic endpoints or complete PQXDH/MLS interoperability. Remaining unit acceptance includes signed/digest domain-separated contract bytes, cross-profile composed adversarial flows, historical version artifacts, malformed-schema property testing, provider-backed integration, and independent implementation evidence.
