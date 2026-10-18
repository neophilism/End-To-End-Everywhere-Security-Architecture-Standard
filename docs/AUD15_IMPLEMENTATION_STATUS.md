# AUD-15 applied group update verification (reference)

AUD-15.1 adds a versioned applied-transition receipt validator for all three registered group architectures. It binds the old independently accepted group state/epoch, exact operation type, new membership commitment, changed state digest, authorization/proof references and authenticated commitment digest. Stale, queued, proposal-only or mismatched transitions cannot count as applied. Existing group message/member evidence is revalidated.

A PQXDH-enabled pairwise fanout component does not, by itself, qualify a full group post-quantum confidentiality claim. No current MLS/sender-key group profile establishes that claim. Its release requires a new exact group-level design and assurance scope.

**Still pending:** independent cryptographic verification of applied MLS Commit/UpdatePath and confirmation, actual sender-key rotation/redistribution, authentic epoch heads and crash/race rollback, cross-endpoint tests, and rigorous post-quantum group-property analysis. The reference evaluator's `consistent=true` is not deployed evidence or certification. AUD-15 remains pending.
