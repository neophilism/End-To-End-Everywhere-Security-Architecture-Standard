import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from parser_boundary_reference import validate_parser_boundary

class ParserBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.good = {"platform": "native-linux", "parser_process_separate": True,
                     "os_sandbox_enforced": True, "no_key_material_access": True,
                     "network_egress_denied": True, "ipc_schema_validated": True,
                     "input_size_limited": True, "resource_budget_enforced": True,
                     "crash_contained": True, "runtime_observation_verified": True,
                     "host_boundary_test_ref": "runtime-test-one",
                     "fuzz_evidence_ref": "fuzz-corpus-one",
                     "source_build_digest": "sha256:abcdefghijklmnopqrstuvwxyz0123456789"}

    def test_reference_cannot_certify_actual_sandbox(self):
        decision = validate_parser_boundary(self.good)
        self.assertTrue(decision["structural_conditions_satisfied"])
        self.assertFalse(decision["boundary_supported"])

    def test_network_keys_process_and_ipc_are_required(self):
        for field in ("parser_process_separate","os_sandbox_enforced",
                      "no_key_material_access", "network_egress_denied",
                      "ipc_schema_validated", "crash_contained"):
            with self.subTest(field=field):
                self.assertFalse(validate_parser_boundary({**self.good,field:False})["boundary_supported"])
                self.assertIn("unverified",validate_parser_boundary({**self.good,field:False})["reason"])

    def test_worker_name_is_not_isolation(self):
        x={**self.good,"platform":"web-worker"}
        self.assertEqual(validate_parser_boundary(x)["reason"],
                         "web-worker-alone-is-not-process-isolation-proof")

if __name__=="__main__":
    unittest.main()
