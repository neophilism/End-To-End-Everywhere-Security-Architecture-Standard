"""AUD-19 parser sandbox evidence gate, not a sandbox implementation."""
from __future__ import annotations

def validate_parser_boundary(record):
    def deny(reason):
        return {"boundary_supported": False, "reason": reason, "real_isolation_verified": False}
    required = {"platform", "parser_process_separate", "os_sandbox_enforced",
                "no_key_material_access", "network_egress_denied",
                "ipc_schema_validated", "input_size_limited", "resource_budget_enforced",
                "crash_contained", "host_boundary_test_ref", "fuzz_evidence_ref",
                "source_build_digest", "runtime_observation_verified"}
    if not isinstance(record, dict) or set(record) != required:
        return deny("missing-boundary-evidence")
    if record["platform"] not in ("native-linux", "native-macos", "native-windows", "web-worker"):
        return deny("unsupported-platform")
    for field in required - {"platform", "host_boundary_test_ref",
                             "fuzz_evidence_ref", "source_build_digest"}:
        if type(record[field]) is not bool:
            return deny("invalid-control-flag")
    for field in ("host_boundary_test_ref", "fuzz_evidence_ref", "source_build_digest"):
        if not isinstance(record[field], str) or len(record[field]) < 8:
            return deny("missing-artifact-bound-evidence")
    if record["platform"] == "web-worker":
        return deny("web-worker-alone-is-not-process-isolation-proof")
    for field in ("parser_process_separate", "os_sandbox_enforced",
                  "no_key_material_access", "network_egress_denied",
                  "ipc_schema_validated", "input_size_limited",
                  "resource_budget_enforced", "crash_contained",
                  "runtime_observation_verified"):
        if not record[field]:
            return deny("boundary-control-unverified:" + field)
    return {"boundary_supported": False, "reason": "structural-evidence-needs-independent-runtime-verification",
            "structural_conditions_satisfied": True, "real_isolation_verified": False}
