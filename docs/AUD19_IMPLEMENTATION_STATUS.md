# AUD-19 parser boundary reference gate

This first reference slice describes the minimum platform-specific evidence for parser process isolation, enforced OS sandbox, denied network and key access, validated IPC, resource bounds and crash containment. A separate worker name or memory-safe wrapper does not establish isolation. A browser worker is specifically not accepted as proof of OS-level process isolation.

Actual native and web runtime enforcement, sandbox profiles, adversarial malicious media fuzzing, exploit attempts against key access and egress, platform release identities and independently verified test captures are outstanding. This reference returns boundary_supported=false even for structurally complete evidence until full runtime verification. Do not claim client or E2EESA certification based on this structural model.
