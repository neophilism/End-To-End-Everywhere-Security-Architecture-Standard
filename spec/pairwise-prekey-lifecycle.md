# Pairwise prekey publication, expiry, and private-key retention (AUD-13)

**Status:** Normative policy bound to the exact pairwise profile; reference checks are not cryptographic verification.

## Prekey age and offline behavior

E2EESA's versioned recommended policy selects a seven-day **recommended** signed prekey publication lifetime and a thirty-day **maximum**. These are E2EESA release-policy values, **not** universal promises made by the Signal specifications. Applications MAY select stricter, separately versioned policies, documenting availability tradeoffs. The private-key deletion grace for delayed initial messages MUST be separately bounded, with E2EESA reference policy limiting it to seven days.

An endpoint **MUST** verify signed-prekey signatures against the authorized recipient identity and reject missing, future, expired, overlong and substituted bundles. The endpoint **MUST NOT** use inaccurate server time alone to weaken expiry; uncertain time near the boundary must result in conservative rejection or separately authenticated time. Long-offline clients MUST refresh stale bundles rather than silently downgrade to an unexpired but weaker profile. This may prevent delivery until a recipient replenishes keys, an availability cost the product MUST disclose.

A consumed one-time prekey **MUST** be marked consumed and its private key destroyed according to the selected published protocol. An available one-time prekey MUST NOT be silently skipped. Depleted one-time stock SHOULD trigger replenishment and risk/availability reporting; appropriate protocol-defined last-resort prekeys MAY be used only under the exact selected initialization protocol and without overstating replay resistance.

## Precise classical versus post-quantum roles

The exact \`pairwise-x3dh-double-ratchet@0.1.0\` profile has **no PQ KEM role**. A classical-only profile MUST NOT be rejected for lacking a PQ KEM, nor represented as post-quantum confidential. PQXDH-based profiles MUST bind the exact selected ML-KEM parameter set and ensure applicable PQ prekey material is present; a stripped PQ prekey MUST NOT silently trigger a classical fallback.

The recommended reference choice is \`ALG-ML-KEM-768\`. \`ALG-ML-KEM-1024\` is a supported stronger parameter set; \`ALG-ML-KEM-512\` requires an explicit constrained interoperability exception with versioned scope and rationale. An allowed parameter set is not inherently defective: the security claim must precisely describe the chosen strength and assumptions. No current PQXDH-based option here claims post-quantum authentication.

## Retention and lifetime limits

Publishing a fresh signed prekey does not prove that the previous private key was deleted. Products MUST document and test the deletion-grace window and old-key copy/backup handling. A stale private key retained beyond its stated grace invalidates the bounded-exposure claim. Copies retained by an attacker cannot be retroactively erased; an observed deletion timestamp and signed fixture are not proof of complete erasure.

## Evidence limits

\`scripts/pairwise_prekey_lifecycle.py\` checks policy-consistent recorded times, lifetimes, strength pins, one-time stock/consumption, and retirement grace. This reference evaluator **does not** validate cryptographic prekey signatures, actual KEM encapsulation, secure deletion, a trusted clock or full offline delivery. Those require independently verified endpoint/provider integration evidence. Tests at \`tests/test_pairwise_prekey_lifecycle.py\` exercise expired bundles, clock uncertainty, missing PQ material, classical X3DH independence, exhausted one-time stock and late private-key deletion. The accepted operational reference profile must be versioned before production adoption; this standard development tree remains non-certifying.
