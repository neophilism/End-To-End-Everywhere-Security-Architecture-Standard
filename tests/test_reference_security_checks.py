from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import run_reference_security_checks as checks


class ReferenceSecurityChecksTests(unittest.TestCase):
    def test_seeded_malformed_and_semantic_cases_execute(self):
        report=checks.run_campaign(20261007,60)
        self.assertTrue(report["passed"],report["failures"])
        self.assertEqual(report["malformed_input_cases"],60)
        self.assertEqual(report["semantic_property_cases"],180)
        self.assertFalse(report["independent_assessment"])

    def test_regressed_recipient_authorization_is_detected(self):
        with patch.object(checks.server_trust_engine,"validate_deployment",return_value=[]):
            report=checks.run_campaign(42,3)
        self.assertFalse(report["passed"])
        self.assertTrue(any(f["check"]=="recipient-authorization" for f in report["failures"]))

    def test_privacy_accountant_regression_is_detected(self):
        with patch.object(checks.telemetry_engine,"validate_telemetry",return_value=[]):
            report=checks.run_campaign(42,20)
        self.assertFalse(report["passed"])
        self.assertTrue(any(f["check"]=="dp-composition" for f in report["failures"]))

    def test_nonce_collision_is_detected(self):
        with patch.object(checks.attachment_encryption_engine,"expected_nonce_hex",return_value="0"*24):
            report=checks.run_campaign(42,3)
        self.assertFalse(report["passed"])
        self.assertTrue(any(f["check"]=="attachment-nonce" for f in report["failures"]))

    def test_campaign_bounds_are_enforced(self):
        for iterations in (0,-1,100001,True):
            with self.assertRaises(ValueError):checks.run_campaign(42,iterations)


if __name__=="__main__":unittest.main()
