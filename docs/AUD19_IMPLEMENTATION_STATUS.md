# AUD-19.1 — Group input parser crash containment

This slice prevents Python unhashable JSON structures (nested dictionaries, arrays, or null values) from crashing E2EESA's group policy/evidence reference validator. Malformed profile, protocol, cipher suite and membership authorization fields now return deterministic validation errors instead of triggering unhandled set/dict-key operations. Semantic validation still rejects malformed member identifiers; the engine must not silently drop them as an accepted membership.

**Reference scope only.** This addresses one narrow input boundary in the standard's group reference code. It does **not** establish deployed parser isolation, memory/time/CPU bounds, safe native codecs, network ingress hardening, fuzzing of all schemas, or real-client conformance. AUD-19 remains pending until those additional requirements are measured.
