# AUD-11 implementation status

AUD-11.1 adds a reference hardware recovery attempt budget with explicit measured hardware/policy identity, authenticated attempt-initiation preconditions, monotonic reservation, independently anchored state digest, one-device/shared-replica modes, exhausted-budget denial, and separately authorized reset transitions. Negative tests cover rollback, unauthorized use, rogue replicas, swapped measurement, and missing evidence.

**Remains pending:** actual HSM and attestation chain verification; hardware-enforced atomic pre-guess reservations; verifiable shared monotonic counters across replicas; signed authenticated counters; crash/race/partition/recovery hardware testing; availability and low-entropy calibration evidence. This reference must not be marked as full AUD-11 implementation, nor as independently reviewed recovery security.
