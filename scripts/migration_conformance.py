#!/usr/bin/env python3
"""AUD-24: versioned legacy migration boundaries with preserved signed evidence.

This is an evidence contract, not a cryptographic verifier or automated converter.
An external host must verify historical bytes under their original registered
scheme and authenticate current identity/device authority before committing.
"""
from __future__ import annotations
import re
from typing import Any

DIGEST=re.compile(r"^sha256:[0-9a-f]{64}$")
MODES={"verify-historical-only","derive-new-record-preserve-history"}
SOURCE_SCHEMES={"legacy-python-ascii-v0","legacy-python-utf8-v0"}
ACTIVE="e2eesa-jcs-integer-v1"
REQUIRED={
    "schema_version","source_standard_basis","target_standard_basis",
    "source_serialization_scheme","target_serialization_scheme",
    "source_artifact_digest","new_artifact_digest",
    "migration_mode","source_signed_bytes_preserved",
    "historical_signature_verified_on_original_bytes",
    "source_identity_root","target_identity_root",
    "identity_authority_transition","fresh_peer_comparison_required",
    "reenrollment_explicitly_authorized","source_evidence_class",
    "target_evidence_class","migration_test_report_digest",
}
TRUSTED={"source_standard_basis","source_artifact_digest",
         "historical_verifier_report_digest","approved_authority_transition_digest"}


def assess(record: dict[str,Any], trusted: dict[str,Any]) -> dict[str,Any]:
    def result(ok:bool,why:str)->dict[str,Any]:
        return {"consistent":ok,"reason":why,"cryptographically_verified":False,
                "legacy_signed_bytes_rewritten":False}
    if not isinstance(record,dict) or set(record)!=REQUIRED:
        return result(False,"invalid-migration-record-shape")
    if not isinstance(trusted,dict) or set(trusted)!=TRUSTED:
        return result(False,"missing-independent-source-verifier")
    if record["schema_version"]!="0.1":
        return result(False,"unsupported-migration-schema")
    if (record["source_standard_basis"]!="0.9.0-rc.1" or
        record["target_standard_basis"]!="0.9.0-rc.2-dev" or
        (not isinstance(record["source_serialization_scheme"],str) or record["source_serialization_scheme"] not in SOURCE_SCHEMES) or
        record["target_serialization_scheme"]!=ACTIVE):
        return result(False,"unsupported-legacy-or-new-basis")
    if not isinstance(record["migration_mode"],str) or record["migration_mode"] not in MODES:
        return result(False,"unsafe-migration-mode")
    if (record["source_signed_bytes_preserved"] is not True or
        record["historical_signature_verified_on_original_bytes"] is not True):
        return result(False,"historical-signed-bytes-or-original-scheme-invalid")
    for name in ("source_artifact_digest","migration_test_report_digest"):
        value=record[name]
        if not isinstance(value,str) or not DIGEST.fullmatch(value):
            return result(False,"invalid-source-or-test-digest")
    new=record["new_artifact_digest"]
    if record["migration_mode"]=="verify-historical-only":
        if new is not None or record["target_evidence_class"]!="historical-verification-only":
            return result(False,"verify-only-cannot-create-new-attestation")
    elif not isinstance(new,str) or not DIGEST.fullmatch(new) or new==record["source_artifact_digest"]:
        return result(False,"derived-record-must-be-distinct")
    if record["source_evidence_class"] not in ("historical-signed-artifact","historical-unsigned-artifact"):
        return result(False,"invalid-source-evidence-class")
    if not isinstance(record["source_identity_root"],str) or not record["source_identity_root"]:
        return result(False,"missing-source-authority")
    if not isinstance(record["target_identity_root"],str) or not record["target_identity_root"]:
        return result(False,"missing-target-authority")
    if record["identity_authority_transition"] not in ("retained-root","replacement-identity"):
        return result(False,"unsupported-identity-authority-transition")
    changed=record["source_identity_root"]!=record["target_identity_root"]
    if changed:
        if (record["identity_authority_transition"]!="replacement-identity" or
            record["fresh_peer_comparison_required"] is not True or
            record["reenrollment_explicitly_authorized"] is not True):
            return result(False,"replacement-must-not-inherit-verified-trust")
        approval=trusted["approved_authority_transition_digest"]
        if not isinstance(approval,str) or not DIGEST.fullmatch(approval):
            return result(False,"independent-replacement-authority-evidence-missing")
    elif (record["identity_authority_transition"]!="retained-root" or
          record["reenrollment_explicitly_authorized"] is True):
        return result(False,"unchanged-identity-cannot-claim-replacement")
    if (trusted["source_standard_basis"]!=record["source_standard_basis"] or
        trusted["source_artifact_digest"]!=record["source_artifact_digest"] or
        trusted["historical_verifier_report_digest"]!=record["migration_test_report_digest"]):
        return result(False,"source-or-historical-verifier-binding-mismatch")
    if record["migration_mode"]=="derive-new-record-preserve-history" and record["target_evidence_class"]!="unassessed-development-derived":
        return result(False,"cannot-promote-historical-artifact-to-production-conformance")
    return result(True,"development-migration-contract-consistent")
