# AUD-20.1 — TLS identity, public CT and ECH boundary

A TLS certificate path, RFC 9525 service reference identity, and platform public-Web PKI Certificate Transparency enforcement are separately required where applicable. A private PKI does not inherit unrelated public CT mandates. Common Name fallback cannot establish RFC 9525 service identity.

ECH under RFC 9849 has distinct offered, accepted, rejected, authenticated disable and authenticated retry states. Strict ECH-required mode rejects plaintext fallback. Optional fallback after authenticated outer/public-name rejection must not be represented as ECH-protected. ECH does not eliminate IP/DNS/timing observers or provide global anonymity.

The reference code checks declared results and independently supplied digests only. It does not run real TLS, verify certificates or SCTs, implement ECH cryptographic acceptance or certify product security. Full AUD-20 runtime and platform interoperability remain pending.
