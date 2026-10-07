# Secure Development Standard

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 23.

`development-ssdf-baseline@0.1.0` establishes a common development/process
baseline. It references [NIST SP 800-218, SSDF 1.1, 2022 final](https://csrc.nist.gov/pubs/sp/800/218/final).
The 1.2 revision draft is not silently treated as final. This is an E2EESA
practice-level alignment, not a claim of NIST certification or a complete
task-level crosswalk; PR 46 supplies the broader external standards crosswalk.

## 1. Practice coverage and accountable evidence

The registry maps the following local controls to all 19 SSDF practice areas.
Each control MUST have an accountable owner and content-addressed evidence:

| Local control | SSDF practice | E2EESA evidence obligation |
| --- | --- | --- |
| SD-REQUIREMENTS | PO.1 | Maintained security requirements and product threat assumptions |
| SD-OWNERS | PO.2 | Trained accountable maintainers, reviewers and release owners |
| SD-TOOLS | PO.3 | Approved toolchain, automation and protected configuration |
| SD-RELEASE-GATES | PO.4 | Measurable release checks that fail closed |
| SD-ENVIRONMENT | PO.5 | Isolated development/build environments and access controls |
| SD-SOURCE-ACCESS | PS.1 | Protected source history and authorization records |
| SD-RELEASE-AUTH | PS.2 | Authenticated product releases and distribution metadata |
| SD-ARCHIVE | PS.3 | Retained release inputs, artifacts and assessment records |
| SD-DESIGN | PW.1 | Reviewed architecture and threat-informed design |
| SD-DESIGN-REVIEW | PW.2 | Qualified independent security design review |
| SD-DEPENDENCIES | PW.4 | Inventory, pinning, screening and update ownership |
| SD-SECURE-CODE | PW.5 | Language-specific secure implementation rules |
| SD-BUILD-CONFIG | PW.6 | Hardened compilation/build configuration |
| SD-CODE-REVIEW | PW.7 | Independent approval of exact release source |
| SD-TESTING | PW.8 | Relevant positive, adversarial and fuzz coverage |
| SD-DEFAULTS | PW.9 | Secure configuration and no silent downgrade defaults |
| SD-INTAKE | RV.1 | Vulnerability intake and ongoing discovery |
| SD-REMEDIATION | RV.2 | Triage, fixes and affected-version tracking |
| SD-ROOT-CAUSE | RV.3 | Root-cause analysis and regression prevention |

Every baseline control MUST be satisfied. A team with no third-party application
package still assesses its runtime/build dependencies and records that scope;
it MUST NOT omit the dependency control. Organizational size does not remove
independent review, source protection or release evidence requirements.

## 2. Change control and independent review

Every release assessment MUST bind product/version/platform, exact policy and a
SHA-256 source inventory digest. Approvals, gate results and remediation tests
MUST cover that same source. Changing code after approval invalidates the prior
approval and affected checks.

At least one independent reviewer MUST approve each change. No author may count
as their own reviewer. Two distinct release authorizers, including an independent
reviewer, MUST authorize release. Identity/authorization of reviewers and
authorizers MUST be authenticated outside these evidence records. Security
classification MUST be reviewed; cryptographic/protocol changes additionally
require qualified cryptographic review rather than only ordinary code review.

Requirements, threat models, test plans, language rules and secure defaults MUST
be updated as needed. Changes to invariants, crypto algorithms, trust boundaries
or profile lifecycle MUST include rationale, compatibility impact and an ADR.
Emergency changes MUST retain security review and tests; deployment urgency does
not authorize weaker E2EE invariants or undocumented recipient trust.

## 3. Executable release gates

The release MUST have passing unit, adversarial, fuzz, secret-scan,
dependency-scan and static-analysis checks. Each result MUST identify an immutable
tool/configuration and report, exact source and completion time. Skipped,
cancelled, failed, stale or future-dated checks fail this profile. The policy
sets freshness, no more than seven days; this is not a substitute for rerunning
checks after source changes.

Fuzz campaigns MUST cover applicable parsers/state transitions with meaningful
time/corpus bounds and preserve minimized failures. Static/dependency scans MUST
use maintained rules/data and include transitive/build/runtime dependencies.
Secret detection MUST cover release inputs and logs. Test success alone does not
prove cryptographic security or establish an absence of unknown vulnerabilities.

Build environments MUST isolate untrusted pull requests from signing/release
secrets. Protected branches and review records, least-privilege automation,
dependency update ownership, toolchain integrity and archived release inputs
MUST be assessed. PR 24 provides the deeper supply-chain evidence model; PR 25
provides verification profile coverage.

## 4. Findings and remediation

Open security findings block release until fixed or explicitly resolved through
the permitted noncritical risk process. A fixed finding MUST carry a retest report
and remediation source digest matching the release source. High and critical
findings MUST be fixed; this baseline prohibits release waivers for them.

Medium/low residual risks MAY be accepted only by an independent reviewer, with
a concrete rationale, affected scope, compensating controls documented in the
report, owner and a future expiration. Expired/missing acceptance fails validation.
Risk acceptance MUST NOT waive an E2EESA invariant. Deduplication MUST preserve
source evidence and affected-version history. Root-cause work MUST produce
appropriate regression coverage and feed future requirements/training.

## 5. Limits of the validator

The engine verifies practice coverage, source/policy binding, review separation,
gate status/freshness and finding-state rules. It does not inspect the real review
quality, scan execution, training, branch protection or signed authorization.
These declared results require authenticated assessor reports and independent
assessment. Fixtures are synthetic; this repository is not declaring that every
future product or the pre-1.0 reference tooling is already certified.
