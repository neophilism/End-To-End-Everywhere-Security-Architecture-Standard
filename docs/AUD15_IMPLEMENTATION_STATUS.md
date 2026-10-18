# AUD-15: group update cadence and flow-specific claims

This first reference slice rejects unsatisfied update, freshness, stale-member and sender-distribution conditions, and prevents a direct-message post-quantum result being inherited by group, media, attachment or backup flows. A scheduled timer, uncommitted MLS proposal, or an update without fresh honest secret material does not establish post-compromise healing. Even structurally consistent records return healed=false until endpoint cryptographic verification.

Selected production thresholds, offline grace, safe sender-key renewal, actual trusted commit verification, endpoint measurements and deployment evidence remain unresolved. This is a non-certifying reference policy, not a new protocol, key schedule, or implementation of MLS. Independently verified source vectors and threat-model evidence are needed before any standards conformance or quantum-security claim.
