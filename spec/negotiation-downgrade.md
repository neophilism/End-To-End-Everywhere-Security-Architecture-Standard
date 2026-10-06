# Negotiation and Downgrade Defense

**Status:** Normative

This document defines E2EESA invariants for negotiating protocol versions and cryptographic suites without allowing a network attacker, service intermediary, stale configuration, or automatic compatibility fallback to silently reduce security.

## 1. Core invariant

Negotiation MUST be fail closed.

An endpoint MUST NOT accept a protocol version, cryptographic suite, profile set, or registry version that is weaker than or different from the exact locally pinned policy merely to make a connection succeed.

## 2. Explicit version ordering

A negotiation policy MUST define an explicit ordered list of protocol versions from oldest to newest and an explicit minimum permitted version.

Implementations MUST NOT infer security ordering from lexical or numeric comparison of arbitrary version strings.

If multiple protocol versions are mutually supported, the highest mutually supported version in the policy order MUST be selected.

If no mutually supported version exists at or above the minimum, negotiation MUST fail.

## 3. Exact suite pinning

A negotiation policy MUST pin the exact cryptographic registry version and an explicit set of permitted named suite identifiers.

Endpoints MUST NOT advertise, select, or accept a suite outside that pinned set.

Aliases, free-form algorithm names, implicit provider defaults, and floating suite references MUST NOT satisfy suite pinning.

A selected suite MUST be present in both parties' authenticated advertised capability sets.

## 4. Transcript binding

Before protected application traffic is accepted, the authenticated negotiation transcript MUST bind at least:

- negotiation policy identifier;
- protocol identifier;
- cryptographic registry version;
- the initiator's complete offered protocol-version set;
- the responder's complete supported protocol-version set;
- the initiator's complete offered suite set;
- the responder's complete supported suite set;
- selected protocol version;
- selected suite identifier;
- exact effective profile references;
- initiator freshness nonce or protocol-equivalent freshness value; and
- responder freshness nonce or protocol-equivalent freshness value.

A protocol MAY bind additional fields. A policy MUST NOT remove any baseline field above.

If the authenticated transcript does not cover a downgrade-sensitive field, negotiation MUST fail.

## 5. Profile and configuration binding

Negotiation MUST bind the exact effective E2EESA profile set evaluated for the connection.

A peer or intermediary MUST NOT be able to make a connection succeed under a different profile set without creating a distinct, authenticated negotiation result.

This prevents a deployment from advertising one architecture while actually negotiating another.

## 6. No automatic weaker fallback

After a failed negotiation, an implementation MUST NOT automatically retry by:

- lowering its minimum protocol version;
- deleting stronger protocol versions from its offer;
- adding an unpinned or weaker suite;
- changing the effective profile set;
- changing the cryptographic registry version; or
- disabling a required transcript-binding field.

A user or administrator MAY deliberately change policy. Such a change is a new configuration decision and MUST NOT be represented as automatic negotiation fallback.

## 7. Freshness and replay

A negotiation MUST be bound to protocol-level freshness.

The reference evidence model uses independent initiator and responder nonces. A concrete protocol MAY use a different replay-resistant freshness mechanism, but it MUST provide equivalent session uniqueness and authenticated binding.

A repeated negotiation context MUST NOT be accepted as a fresh negotiation when replay would affect authorization, key establishment, version selection, or suite selection.

## 8. Selection failure

No-overlap is a normal failure state.

If the parties have no mutually permitted protocol version or no mutually permitted suite, the implementation MUST fail closed and surface an incompatibility condition. It MUST NOT manufacture compatibility by weakening policy.

## 9. Relationship to cryptographic agility

Algorithm agility is permitted only inside the bounds of the pinned registry and policy.

Agility MUST NOT become a path for downgrade.

This document intentionally does not rank permitted suites by cryptographic strength. Different registered suites can be defensible for different deployments. A later protocol profile MAY define deterministic suite preference rules, but all such choices remain subject to the transcript-binding and pinning invariants in this document.

## 10. Evidence model

The reference negotiation evidence object records both advertised capability sets, the selected result, policy/profile pins, transcript-binding coverage, freshness values, and whether fallback retry occurred.

The reference validator MUST reject evidence when:

- the selected version is not the highest mutually supported version;
- the selected version is below the policy floor;
- any advertised or selected suite is outside the pinned set;
- the selected suite is not mutually supported;
- registry or profile pins differ from policy;
- required transcript fields are not authenticated;
- the transcript is not authenticated;
- automatic fallback was attempted;
- freshness values are malformed or identical; or
- a caller-supplied replay cache reports the same nonce pair as already used.

## 11. External precedent

These invariants are implementation-neutral, but they follow established secure-protocol practice: modern TLS guidance requires preference for newer supported protocol versions and forbids automatic fallback to deprecated earlier versions. TLS 1.3 also binds negotiation into its authenticated handshake design.

E2EESA applies the same fail-closed principle to its own protocol, profile, registry, and suite negotiation rather than copying TLS wire formats.

## 12. Conformance

A product that supports negotiation MUST demonstrate:

- minimum-version enforcement;
- highest-mutual-version selection;
- exact suite pinning;
- authenticated transcript coverage;
- exact registry/profile binding;
- no automatic weaker fallback;
- negative tests for downgrade attempts; and
- replay/freshness testing appropriate to its protocol.

A product MUST NOT claim SP-DOWNGRADE-RESISTANCE merely because it supports modern algorithms. The negotiation behavior itself must satisfy this document and the Security Properties Model.
