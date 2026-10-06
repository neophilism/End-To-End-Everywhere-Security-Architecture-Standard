# Normative Language

**Status:** Normative

This document defines how requirements are expressed throughout E2EESA.

## 1. Requirement keywords

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described by RFC 2119 as clarified by RFC 8174 when, and only when, they appear in all capitals.

Lowercase uses of words such as "must", "should", or "may" are ordinary prose and are not normative keywords.

## 2. Meaning of requirement strength

### MUST / MUST NOT

A `MUST` requirement is an unconditional requirement for conformance within its stated scope.

A `MUST NOT` requirement is an unconditional prohibition for conformance within its stated scope.

An implementation that violates an applicable `MUST` or `MUST NOT` requirement is non-conformant with the profile, capability, or standard version that contains the requirement.

### SHOULD / SHOULD NOT

A `SHOULD` requirement describes a strong recommendation for which valid reasons to deviate may exist.

A conformant implementation that deviates from an applicable `SHOULD` or `SHOULD NOT` requirement:

1. MUST document the deviation;
2. MUST document the reason for the deviation;
3. MUST document the security consequences introduced by the deviation; and
4. MUST NOT claim a security property that the deviation invalidates.

A profile MAY strengthen a `SHOULD` requirement to `MUST`.

### MAY

A `MAY` requirement describes a genuinely optional behavior.

Optional behavior MUST NOT silently weaken an invariant or a security property claimed by the selected profile.

## 3. Scope

Every normative requirement MUST have an identifiable scope.

The scope may be:

- the E2EESA standard as a whole;
- a product class;
- a security profile;
- a capability;
- a protocol or algorithm lifecycle state;
- an assurance level; or
- a specifically identified subsystem.

A requirement MUST NOT be interpreted outside its stated scope merely because the same terminology is used elsewhere.

## 4. Security invariants and profile choices

A **security invariant** is a normative requirement that no conformant profile is permitted to disable.

A **profile choice** is a named, versioned architecture choice that is permitted only when all applicable invariants remain satisfied.

A profile MUST NOT redefine an invariant into an optional behavior.

Where multiple serious architectures are supported, each MUST be represented explicitly rather than hidden behind undocumented implementation defaults.

## 5. Configuration and negotiation

Configurable behavior MUST be validated before it is treated as conformant.

A system MUST NOT claim conformance merely because every individual selected option is independently listed as permitted. The complete selected configuration MUST satisfy all compatibility, dependency, and prohibition rules.

Where peers negotiate a profile, protocol version, cipher suite, or capability:

- the negotiation MUST be integrity-protected within the applicable protocol;
- the selected result MUST satisfy each peer's minimum accepted security policy; and
- an attacker MUST NOT be able to force a weaker permitted option without detection.

## 6. Claims

A conformance claim MUST identify, at minimum:

- the E2EESA version;
- each applicable profile and profile version;
- applicable capabilities;
- applicable assurance level, when assurance levels are defined; and
- any documented deviations permitted by `SHOULD` or `SHOULD NOT` requirements.

A claim such as "E2EESA compliant" without sufficient scope to determine what was actually evaluated MUST NOT be used once multiple production profiles exist.

## 7. Conflicts

If two applicable normative requirements conflict, the implementation MUST NOT silently choose one.

The conflict MUST be resolved by one of:

1. an explicit precedence rule in the standard;
2. a more specific profile requirement whose precedence is expressly stated;
3. a later standard version that resolves the conflict; or
4. an erratum or normative clarification.

Until resolved, the conflicting configuration MUST be treated as non-conformant.

## 8. External specifications

When E2EESA incorporates or depends on an external specification, the E2EESA requirement MUST identify the applicable version or version policy.

A moving external specification MUST NOT silently change the meaning of an already published E2EESA version.

Draft external specifications MUST be identified as provisional unless E2EESA explicitly freezes and audits a particular draft revision for a defined profile.

## 9. Experimental material

Experimental material MUST NOT be represented as production-recommended solely because it exists in this repository.

An experimental profile MUST be explicitly labeled `experimental`.

Promotion out of experimental status requires the process defined by the research-to-production promotion rules once those rules are adopted.
