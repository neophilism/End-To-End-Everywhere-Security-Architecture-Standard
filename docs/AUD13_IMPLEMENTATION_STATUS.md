# AUD-13 implementation status

AUD-13.1 adds a reference evaluator for published pairwise prekey lifetime, clock-uncertainty bounds, one-time stock/consumption, PQXDH-vs-classical exact KEM selection, last-resort exhaustion and retired private-key deletion grace. Negative tests cover expiry, delayed/future bundles, missing PQ material, wrong KEM strength, absent signatures and retention violations.

**Not complete:** Real cryptographic prekey authenticity checks and external interoperability, trusted clocks, long-offline recovery studies, measured prekey-stock replenishment under load, actual key deletion evidence, client deployment and supported strength-profile release. The reference evaluator cannot prove these and must not be used as a certification assertion.
