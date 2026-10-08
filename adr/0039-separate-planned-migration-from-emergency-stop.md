# ADR-0039: Separate planned migration from emergency stop

- **Status:** Accepted
- **Date:** 2026-10-08
- **Decision class:** ⚖️ Multi-option
- **Affected components:** cryptographic algorithms, named suites, production profiles, migration tooling
- **Security properties affected:** downgrade resistance, confidentiality, integrity, authenticity, availability

## Context

Cryptographic/protocol retirement occurs for different reasons.

A normal standards transition can benefit from overlap, adoption measurement and compatibility handling.

A confirmed security break may require immediate cessation of new use.

Historical ciphertext/signatures may still need to be read, verified or migrated after new security use is prohibited.

Treating all of these as one `deprecated` flag loses necessary safety semantics.

## Decision

E2EESA retains the existing lifecycle statuses and adds explicit migration plans.

Cutover strategies:

- overlap-prefer-new;
- scheduled-cutover;
- emergency-stop.

Legacy-processing policies:

- hard-cutoff;
- historical-read-verify-only;
- migration-only.

Fallback policies:

- disabled;
- bounded-until-new-use-stop.

Emergency stop always disables fallback and prohibits the affected asset for new security use.

Historical processing is a separately bounded archival/migration exception and does not restore production approval.

## Security consequences

A registry rollback or compatibility fallback cannot silently reactivate a retired asset.

Broken algorithms can be prohibited immediately while still permitting narrowly scoped recovery of historical data where necessary.

The tradeoff is more explicit migration state and evidence.

## Standards grounding

NIST transition guidance emphasizes planning for stronger algorithms and keys.

IETF BCP 201 emphasizes algorithm agility so protocols can migrate without redesign and recommends measuring deployment shift.

## Reconsideration triggers

Re-open if a later widely adopted cryptographic transition standard defines stronger portable lifecycle/migration semantics that supersede this model.
