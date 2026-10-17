# AUD-10.2: source-bound egress assurance gate

The active scoped assessment evaluator now refuses to give a complete protected-content implementation claim when a separately trusted, source/build-bound egress assurance record is absent, stale, mock, incomplete, or unrelated to the assessed data flow.

The reviewer adapter MUST independently collect and authenticate actual egress captures and completeness evidence for **success, failure, crash, retry, analytics, background and user-action** paths. It MUST verify protected-content derivatives, declared recipient keys, metadata and explicit disclosure consent. This record is **not** a user-applicant request field; injecting one in a submission fails request validation. Missing or stale evidence produces an **indeterminate** protected-content claim, not a false pass.

The adapter MUST bind its results to the exact source and binary artifact digests of the component inventory, exact flow ID and current time window. Its provenance and packet-capture references MUST point to real, inspectable evidence; the reference evaluator cannot establish that these references are authentic. A synthetic test record marked \`real-provider\` does not thereby become a valid production assessor.

This is an implementation advance toward AUD-10, but cannot certify an application until a trustworthy assessor adapter implements the actual observation, trusted provenance, anti-tampering and coverage checks. The original reference egress policy and endpoint runtime integration still require work; AUD-10 remains pending.
