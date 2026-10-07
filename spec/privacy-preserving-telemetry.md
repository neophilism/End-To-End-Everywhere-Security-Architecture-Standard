# Privacy-Preserving Telemetry

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 22.

## 1. Explicit architecture choice

| Exact profile | Exported data | Trust boundary |
| --- | --- | --- |
| `telemetry-none@0.1.0` | None | No diagnostic collector or durable telemetry |
| `telemetry-minimized-diagnostics@0.1.0` | Closed coarse diagnostic events | Collector sees opted-in events without personal identifiers |
| `telemetry-dp-aggregate@0.1.0` | Pure-DP aggregate counts only | Central collector sees bounded inputs; publications receive DP protection |

The no-export profile is recommended. Both export profiles MUST be disabled by
default and require explicit revocable consent. No core messaging function may
depend on consent. Withdrawal MUST stop future collection and purge retained raw
inputs; an already published aggregate cannot be recalled. An independently
requested user support export is a separate disclosed action, not a bypass that
enables background telemetry.

## 2. Common prohibitions and retention

All profiles MUST exclude plaintext content, keys, recovery material, account or
device identifiers, contacts, conversation/group IDs, URLs, file paths, full
timestamps, IP addresses at the collector, raw crash dumps and free-form error
text. Stable pseudonyms, unsalted identifier hashes and cross-product joining
are prohibited. An opaque identifier can still be linkable; renaming it does not
remove the prohibition. Operational source-IP stripping MUST occur before the
diagnostic collection boundary. This does not promise network anonymity from an
ingress relay, carrier or global observer.

Diagnostic storage MUST have an explicit retention bound of at most seven days.
Transport and access to diagnostic exports MUST be authenticated and encrypted.
Sensitive error details MUST be converted locally to registered diagnostic codes.
Logs, exception handlers, analytics SDKs and report transports MUST be covered by
the leakage assessment; sanitization after secret data was logged is insufficient.

## 3. Minimized diagnostics

This version admits only `startup-failure`, `delivery-latency` and `protocol-error`
codes, a coarse platform class, release major version and four fixed count/value
buckets. Policies MUST explicitly permit each exported code. Unknown fields or
free-form values fail closed. Adding a metric requires a reviewed schema/profile
revision, a collection-purpose justification and a privacy analysis.

Minimization reduces exposure but does not mathematically establish differential
privacy or unlinkability. Coarse diagnostics MUST NOT be marketed as anonymous
merely because explicit names were removed.

## 4. Differential privacy aggregate profile

The supported construction is a central Laplace count mechanism evaluated under
[NIST SP 800-226, March 2025 final](https://csrc.nist.gov/pubs/sp/800/226/final).
This is a fixed evidence profile, not a new protocol or an implementation of the
random sampler. Distributed/local DP architectures may be added as separately
reviewed profiles rather than silently replacing this collector trust boundary.

The privacy unit MUST be a user's lifetime contributions in the declared
accounting domain, with add/remove-user adjacency. Each query's user contribution
MUST be clipped to [0,1], giving count sensitivity 1. Each release MUST use fresh,
independently assessed Laplace noise at scale `1 / epsilon`. Schema parameters
represent epsilon in millionths and the scale as the rational number
`1,000,000 / epsilon_micros`, avoiding floating-point budget comparison errors.
Delta MUST be zero. Finite-precision noise generation MUST use an assessed
implementation; a naive floating-point sampler is not accepted solely because
the nominal scale formula is correct.

All releases, including repeated queries, MUST enter the authenticated ledger.
Basic sequential composition sums their epsilon values; lifetime total epsilon
MUST NOT exceed the explicit policy budget, at most 1 in this profile version.
Budgets MUST NOT reset on upgrade, reinstall, account/session rotation, metric
rename, platform change or product split within the accounting domain. Release
IDs MUST be unique. Ledger continuity, prior-release completeness and contribution
bound enforcement MUST be independently assessed. A ledger hash alone does not
prove its completeness or authenticity.

The policy MUST require at least 20 distinct contributing users per release.
This cohort rule is an additional minimization condition, not the source of the
DP guarantee. Counts may be rounded/clamped through deterministic post-processing;
fresh releases or retries that reveal new noise MUST spend privacy budget again.
Raw inputs MUST have access controls and be purged under the declared retention
policy. DP exports MUST NOT include individual diagnostic events alongside the
aggregate. The central collector MUST disclose that it can observe raw inputs;
DP for published output does not protect against a malicious central collector.

## 5. Evidence, testing and claim limits

Evidence MUST bind the policy, product/version/platform, assessor and report
digests. Reports MUST test secret/identifier leakage, consent and withdrawal,
retention, transport, small-cohort suppression and, where applicable, adjacency,
contribution clipping, randomness, accountant continuity and cumulative spending.

The validator checks closed schemas, policy binding, retention and pure-DP
parameter/accounting relationships. It does not generate noise, authenticate
reports or prove a deployment satisfies DP. A `noise_mechanism_verified` result
requires an external mathematical/implementation assessment. Synthetic fixtures
and successful record validation do not establish certification or user anonymity.

The broader privacy analysis follows
[RFC 6973](https://www.rfc-editor.org/rfc/rfc6973.html), including correlation and
secondary use. PR 14 metadata protection, PR 20 client integrity and PR 21 service
trust boundaries remain separately applicable.
