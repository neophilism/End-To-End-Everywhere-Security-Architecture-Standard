# Canonical serialization

The active `e2eesa-jcs-integer-v1` scheme restricts RFC 8785 to null, booleans, Unicode scalar strings, arrays, string-keyed objects, and integers from -9007199254740991 through 9007199254740991. Parsers MUST reject duplicate keys, lone surrogates, nonfinite numbers, floating-point literals, and unsafe integers before hashing. Unicode normalization is not performed. Object keys use UTF-16 code-unit order; output is UTF-8 with JSON escapes only where required.

Arrays MUST preserve order. Only paths explicitly declared as sets by the owning schema may be preprocessed; duplicate set elements are rejected. Event timelines and identity history are ordered arrays.

Exact imported scores and probabilities SHOULD be retained as decimal strings with their source precision. The legacy external-score adapter uses tagged exact binary64 decimal strings, without rounding, and cannot recover precision lost before import. It is a separately declared input model, not a floating-point exception to canonical serialization.

Historical ASCII-escaped and UTF-8 Python encodings remain available only by explicit scheme identity. A verifier MUST NOT reinterpret historical signed bytes as active bytes or regenerate a historical attestation. The rc.1 archive contains its original implementations and fixtures. Development fixtures may be rebound to the active scheme.

`registry/canonical-serialization.json` inventories active digest owners. Release archive verification intentionally retains its historical byte contract. Domain-separated constructions and their exact field sets are defined by the digest contracts.
