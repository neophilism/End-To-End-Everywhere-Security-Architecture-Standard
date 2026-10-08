# Deprecation and Emergency Migration

**Status:** Normative. **Version:** 0.1.0. **Milestone:** PR 39. **Decision class:** ⚖️ multi-option.

PR 39 defines lifecycle retirement and migration for E2EESA algorithms, suites and production profiles.

It uses the existing lifecycle vocabulary:

- `recommended`;
- `allowed`;
- `provisional`;
- `experimental`;
- `legacy`;
- `deprecated`; and
- `prohibited`.

PR 39 does not invent a parallel status system.

## 1. Planned and emergency retirement are different

A planned transition may provide overlap time so implementations can deploy a replacement and measure adoption.

An emergency transition responds to a credible or confirmed security failure and prioritizes stopping unsafe new use.

The same migration plan format supports both, but emergency plans have stricter timing and fallback rules.

## 2. Asset kinds

A migration plan targets exactly one:

- registered cryptographic algorithm;
- registered named cryptographic suite; or
- exact production profile reference.

The plan records the asset's current registry status and the intended terminal status.

A migration does not silently rename an asset or mutate its identity.

## 3. Cutover strategies

E2EESA implements three serious strategies.

### Overlap, prefer new

`overlap-prefer-new`

Used for ordinary planned transitions.

A safe replacement is deployed before the old asset stops new use.

During a bounded overlap:

- the replacement is preferred;
- old/new negotiation is downgrade-bound;
- fallback may occur only if the plan explicitly chooses bounded fallback;
- fallback use is observable; and
- a fixed new-use stop time exists.

### Scheduled cutover

`scheduled-cutover`

Used when a coordinated environment can switch at a defined cutover.

A safe replacement is required.

Old use may continue under the plan until the cutover, after which new use/fallback is denied.

### Emergency stop

`emergency-stop`

Used for security emergencies.

New security use of the affected asset stops at the emergency cutoff.

A replacement SHOULD be identified when one is safely available, but emergency stop is allowed without a replacement when continuing use is worse than temporary loss of capability.

Emergency migration MUST NOT silently fall back to the affected asset.

## 4. Legacy-processing policies

Retirement of new security use is distinct from handling historical data.

E2EESA supports:

### Hard cutoff

`hard-cutoff`

No use after the cutoff, including historical processing.

### Historical read/verify only

`historical-read-verify-only`

The retired asset may be used only to decrypt or verify immutable historical material created before the recorded historical cutoff.

This permission:

- does not make the algorithm/profile conformant for new security use;
- must not negotiate the asset with a peer;
- must not create new keys, ciphertext, signatures, sessions or protected objects;
- must be isolated from ordinary protocol negotiation; and
- must retain an audit record.

### Migration only

`migration-only`

The retired asset may be used only inside an auditable conversion/re-encryption/re-signing/re-wrapping workflow that produces a replacement-format artifact.

The old asset may not provide an ongoing security claim after migration.

## 5. Fallback options

There is legitimate deployment disagreement over compatibility fallback during planned overlap.

E2EESA supports:

- `disabled`; and
- `bounded-until-new-use-stop`.

Bounded fallback is permitted only before `new_use_stop_at`.

It requires:

- cryptographically bound algorithm/profile negotiation where negotiation exists;
- downgrade detection/rejection;
- a reason code for each fallback;
- telemetry/accounting of fallback use; and
- no fallback after the stop time.

Emergency-stop plans always use `disabled`.

## 6. Migration timeline

Every plan records:

- announced/effective time;
- replacement-available time when applicable;
- new-use stop time;
- legacy-processing stop time when applicable; and
- prohibition time.

Times are monotonic.

For overlap transitions:

`effective ≤ replacement_available ≤ new_use_stop ≤ legacy_processing_stop ≤ prohibit`

For scheduled cutover:

`effective ≤ replacement_available ≤ new_use_stop = prohibit`

unless a bounded historical/migration-only window is explicitly retained.

For emergency stop:

- `new_use_stop_at` must not be after the emergency decision effective time;
- fallback is disabled;
- target terminal status is `prohibited`.

Historical processing, if allowed, is governed independently by its bounded stop time.

## 7. Status projection

### Planned overlap

At plan effective time, the asset becomes `deprecated`.

After new use stops, the asset is `legacy` when a historical/migration window remains.

At prohibition time, the asset becomes `prohibited`.

### Scheduled cutover

At plan effective time, the asset becomes `deprecated`.

At cutover/prohibition time, the asset becomes `prohibited`, unless a bounded legacy-processing window requires an intermediate `legacy` state.

### Emergency stop

At emergency effective time, the asset becomes `prohibited` for new cryptographic security use.

Historical read/verify or migration-only handling is an exception defined by the migration plan; it does not weaken the registry's `prohibited` meaning.

## 8. Replacement requirements

A planned migration requires a replacement.

The replacement:

- must exist in the corresponding registry/catalog;
- must not be the same asset;
- must not be `legacy`, `deprecated`, or `prohibited`;
- must not depend on the retiring profile through a required-profile edge; and
- must have verification/interoperability evidence appropriate to the migration.

An emergency plan may have no replacement.

## 9. Dependency impact

The migration engine computes dependencies visible in the canonical registries.

For an algorithm:

- every named suite containing the algorithm is a known dependent.

For a profile:

- every profile with a direct `requires_profile_refs` dependency is a known dependent.

Every known dependent must appear in the migration plan with an action:

- `replace`;
- `deprecate`;
- `legacy`;
- `retire`; or
- `update-requirement`.

A plan may list additional deployment-specific dependents.

When an algorithm becomes prohibited, a named suite that still contains it cannot remain in the live cryptographic registry because the existing registry validator forbids suites containing prohibited algorithms.

PR 39 therefore removes such retired suites from the live suite list and preserves their retirement identity/evidence in the migration record.

## 10. Evidence

Every plan binds immutable evidence for:

- retirement trigger/reason;
- replacement verification when replacement exists;
- migration/interoperability testing for planned transitions;
- dependent-impact analysis; and
- approval.

Adoption/fallback telemetry is required when bounded fallback is enabled.

Emergency plans record the incident/advisory/vulnerability evidence that caused the emergency.

## 11. Reason classes

Reason classes are:

- `cryptanalytic-break`;
- `active-exploitation`;
- `standard-withdrawal`;
- `security-margin`;
- `interoperability-retirement`;
- `implementation-risk`;
- `ecosystem-migration`; and
- `other`.

`cryptanalytic-break` and `active-exploitation` require emergency mode unless an explicit security review establishes that the affected usage is not exploitable in the E2EESA scope.

## 12. Migration execution events

A migration case is append-only and records events such as:

- `activate-plan`;
- `replacement-available`;
- `prefer-replacement`;
- `stop-new-use`;
- `enter-legacy-processing`;
- `prohibit`;
- `dependent-migrated`;
- `complete`; and
- `emergency-stop`.

Events cannot move backward to a stronger/less-restricted lifecycle state.

Observed completion evidence is separate from planned dates.

## 13. Overdue checks

At an as-of time, validation reports overdue obligations when:

- replacement availability was due but not observed;
- new use should have stopped but no stop/emergency event exists;
- a dependent migration deadline passed;
- legacy processing should have stopped;
- prohibition should have occurred; or
- a plan should be complete but known dependents remain unresolved.

## 14. Downgrade resistance

A migration MUST NOT create a downgrade channel.

After `new_use_stop_at`:

- the retired asset is not advertised;
- the retired asset is not accepted as ordinary fallback;
- a peer offering only the retired asset causes failure or an explicitly non-secure compatibility path outside E2EESA conformance;
- automatic fallback to plaintext is prohibited; and
- configuration rollback cannot silently reactivate the retired asset.

Bounded fallback before the stop time must be observable.

## 15. Registry projection

PR 39 can project lifecycle changes into:

- `registry/cryptographic-algorithms.json`; and
- `profiles/catalog.json`.

Algorithm projection preserves required `status_reason` fields.

Suite projection never leaves a suite stronger than a component.

Profile projection uses the existing profile lifecycle status.

All projected registries/catalogs must pass their pre-existing validators.

## 16. Emergency historical-data exception

A prohibited cryptographic primitive may be invoked for historical-read/verify-only or migration-only handling only when:

- the plan explicitly selects that policy;
- the operation is scoped to material created before the historical cutoff;
- no new cryptographic security claim is made using the prohibited primitive;
- ordinary negotiation cannot invoke it;
- access is audited; and
- the legacy-processing deadline has not passed.

This is an archival/migration exception, not production approval.

## 17. Fail-closed behavior

Validation fails on:

- unknown asset/replacement;
- current-status mismatch;
- unsafe replacement lifecycle;
- non-monotonic timeline;
- emergency fallback;
- emergency plan with non-prohibited terminal status;
- bounded fallback without downgrade protection/telemetry;
- historical processing without cutoff/audit/isolation controls;
- unknown or uncovered registry dependents;
- plan/event digest tampering;
- backward lifecycle event;
- late event chronology;
- unresolved overdue obligations; or
- projected registry/catalog failing existing validators.

## 18. References

- NIST SP 800-131A Rev. 2 and subsequent transition work.
- RFC 7696 / BCP 201 algorithm-agility guidance.
- RFC 6916 / BCP 182 migration-process example.
- Existing E2EESA cryptographic registry lifecycle.
- Existing E2EESA profile lifecycle.
