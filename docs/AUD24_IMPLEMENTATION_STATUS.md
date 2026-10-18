# AUD-24.1 — Explicit SDK migration and historical identity boundary

This reference contract preserves original signed source bytes and exact legacy serialization version, allows explicit verification-only preservation or a distinct *new* development-derived record, and independently binds the historical verifier report to the original artifact digest. It rejects implicit reinterpretation of old signatures under active canonical bytes, rewriting historical attestations, or promoting a historical artifact into new production certification.

A changed identity root is a replacement with explicit authorization and a new peer comparison, **not** continuation of verified peer trust. The record cannot enroll devices, change local secrets, or prove that authority was actually authenticated; implementers MUST check real credential signatures and store trusted migration evidence before using it.

Remaining AUD-24 work includes integration-envelope version negotiation across the six downstream systems, schema conversions for all applicable scopes, actual SDK language bindings, preserved historical fixtures, mixed-version transport tests, and source-bound deployment migration evidence. This slice does not complete AUD-24 or certify any product.
