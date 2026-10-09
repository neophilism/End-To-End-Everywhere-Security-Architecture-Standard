from __future__ import annotations

import copy
from io import StringIO
import json
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import conformance_engine  # noqa: E402
import e2eesa_conformance  # noqa: E402
import formal_verification  # noqa: E402


class ConformanceCliTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def plan(self) -> dict:
        return self.load("fixtures/conformance/valid/production-assurance-plan.json")

    def bundle(self) -> dict:
        return self.load("fixtures/conformance/valid/production-certification-bundle.json")

    def request_template(self) -> dict:
        return self.load("fixtures/conformance/valid/production-request.json")

    def cli_registry(self) -> dict:
        return self.load("registry/conformance-cli.json")

    def prepare_objects(self):
        plan = self.plan()
        bundle = self.bundle()
        bundle["assurance_plan_digest"] = formal_verification.canonical_digest(plan)
        bundle["configuration_digest"] = formal_verification.canonical_digest(
            plan["configuration"]
        )
        inputs = e2eesa_conformance.load_standard_inputs(ROOT)
        request = e2eesa_conformance.bind_request(
            self.request_template(), plan, bundle, inputs
        )
        return request, plan, bundle, inputs

    def write_json(self, directory: Path, name: str, value: dict) -> Path:
        path = directory / name
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def invoke(self, argv: list[str]):
        stdout = StringIO()
        stderr = StringIO()
        code = e2eesa_conformance.main(
            ["--root", str(ROOT), *argv],
            stdout=stdout,
            stderr=stderr,
        )
        return code, stdout.getvalue(), stderr.getvalue()

    def temp_inputs(self, directory: Path, *, mutate_bundle=None, mutate_request=None):
        request, plan, bundle, inputs = self.prepare_objects()
        if mutate_bundle is not None:
            mutate_bundle(bundle)
            request = e2eesa_conformance.bind_request(
                self.request_template(), plan, bundle, inputs
            )
        if mutate_request is not None:
            mutate_request(request)
        return (
            self.write_json(directory, "request.json", request),
            self.write_json(directory, "plan.json", plan),
            self.write_json(directory, "bundle.json", bundle),
            request,
            plan,
            bundle,
        )

    def test_cli_registry_contract_is_valid(self) -> None:
        self.assertEqual(
            e2eesa_conformance.validate_cli_registry(self.cli_registry()), []
        )

    def test_basis_outputs_exact_pr40_input_digests(self) -> None:
        code, stdout, stderr = self.invoke(["basis"])
        self.assertEqual(code, e2eesa_conformance.EXIT_PASS, stderr)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        inputs = e2eesa_conformance.load_standard_inputs(ROOT)
        self.assertEqual(
            payload["input_digests"],
            conformance_engine.evaluation_input_digests(**inputs),
        )
        self.assertEqual(
            payload["standard_version"], inputs["catalog"]["standard_version"]
        )

    def test_bind_request_fills_only_mechanical_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            template = self.request_template()
            plan = self.plan()
            bundle = self.bundle()
            bundle["assurance_plan_digest"] = formal_verification.canonical_digest(plan)
            bundle["configuration_digest"] = formal_verification.canonical_digest(
                plan["configuration"]
            )
            request_path = self.write_json(directory, "template.json", template)
            plan_path = self.write_json(directory, "plan.json", plan)
            bundle_path = self.write_json(directory, "bundle.json", bundle)

            code, stdout, stderr = self.invoke([
                "bind-request",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_PASS, stderr)
            bound = json.loads(stdout)
            self.assertEqual(bound["assessment_id"], template["assessment_id"])
            self.assertEqual(
                bound["conformance_policy_ref"],
                template["conformance_policy_ref"],
            )
            self.assertEqual(bound["evaluated_at"], template["evaluated_at"])
            self.assertEqual(bound["family_scope"], template["family_scope"])
            self.assertEqual(bound["migration_context"], template["migration_context"])
            self.assertEqual(
                bound["assurance_plan_digest"],
                formal_verification.canonical_digest(plan),
            )
            self.assertEqual(
                bound["certification_bundle_digest"],
                conformance_engine.canonical_digest(bundle),
            )
            self.assertEqual(
                bound["request_digest"],
                conformance_engine.compute_request_digest(bound),
            )

    def test_bind_request_refuses_identity_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            template = self.request_template()
            template["product_id"] = "different-product"
            plan = self.plan()
            bundle = self.bundle()
            request_path = self.write_json(directory, "template.json", template)
            plan_path = self.write_json(directory, "plan.json", plan)
            bundle_path = self.write_json(directory, "bundle.json", bundle)
            code, _stdout, stderr = self.invoke([
                "bind-request",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_INVALID_INPUT)
            self.assertIn("does not match plan/bundle", stderr)

    def test_evaluate_pass_returns_zero_and_pr40_result(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            request_path, plan_path, bundle_path, *_ = self.temp_inputs(directory)
            code, stdout, stderr = self.invoke([
                "evaluate",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_PASS, stderr)
            result = json.loads(stdout)
            self.assertEqual(result["verdict"], "pass", result["reasons"])
            self.assertFalse(result["production_certification_eligible"])

    def test_evaluate_fail_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)

            def mutate_request(request: dict) -> None:
                request["input_digests"]["profile_catalog"] = "sha256:" + "9" * 64
                request["request_digest"] = conformance_engine.compute_request_digest(
                    request
                )

            request_path, plan_path, bundle_path, *_ = self.temp_inputs(
                directory, mutate_request=mutate_request
            )
            code, stdout, _stderr = self.invoke([
                "evaluate",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_FAIL)
            self.assertEqual(json.loads(stdout)["verdict"], "fail")

    def test_evaluate_indeterminate_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)

            def conditional(bundle: dict) -> None:
                bundle["claim_evidence"][0]["status"] = "conditional"

            request_path, plan_path, bundle_path, *_ = self.temp_inputs(
                directory, mutate_bundle=conditional
            )
            code, stdout, _stderr = self.invoke([
                "evaluate",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_INDETERMINATE)
            self.assertEqual(json.loads(stdout)["verdict"], "indeterminate")

    def test_invalid_invocation_uses_normative_exit_code_three(self) -> None:
        code, _stdout, stderr = self.invoke(["evaluate"])
        self.assertEqual(code, e2eesa_conformance.EXIT_INVALID_INPUT)
        self.assertIn("required", stderr)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "duplicate.json"
            path.write_text(
                '{"schema_version":"0.1","schema_version":"0.1"}',
                encoding="utf-8",
            )
            code, _stdout, stderr = self.invoke([
                "bind-request",
                "--request", str(path),
                "--assurance-plan", str(path),
                "--certification-bundle", str(path),
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_INVALID_INPUT)
            self.assertIn("duplicate JSON object key", stderr)

    def test_top_level_non_object_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "array.json"
            path.write_text("[]", encoding="utf-8")
            code, _stdout, stderr = self.invoke([
                "bind-request",
                "--request", str(path),
                "--assurance-plan", str(path),
                "--certification-bundle", str(path),
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_INVALID_INPUT)
            self.assertIn("top-level JSON value must be an object", stderr)

    def test_verify_result_reproduces_saved_result(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            request_path, plan_path, bundle_path, *_ = self.temp_inputs(directory)
            eval_code, stdout, stderr = self.invoke([
                "evaluate",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
            ])
            self.assertEqual(eval_code, 0, stderr)
            result = json.loads(stdout)
            result_path = self.write_json(directory, "result.json", result)

            code, stdout, stderr = self.invoke([
                "verify-result",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
                "--result", str(result_path),
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_PASS, stderr)
            payload = json.loads(stdout)
            self.assertTrue(payload["verified"])
            self.assertEqual(payload["result_digest"], result["result_digest"])

    def test_verify_result_tamper_returns_dedicated_mismatch_exit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            request_path, plan_path, bundle_path, *_ = self.temp_inputs(directory)
            result = e2eesa_conformance.evaluate_files(
                request_path=str(request_path),
                assurance_plan_path=str(plan_path),
                certification_bundle_path=str(bundle_path),
                root=ROOT,
            )
            result["verdict"] = "fail"
            result_path = self.write_json(directory, "tampered-result.json", result)
            code, stdout, _stderr = self.invoke([
                "verify-result",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
                "--result", str(result_path),
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_RESULT_MISMATCH)
            payload = json.loads(stdout)
            self.assertFalse(payload["verified"])

    def test_explain_checks_self_digest_but_does_not_reevaluate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            request_path, plan_path, bundle_path, *_ = self.temp_inputs(directory)
            result = e2eesa_conformance.evaluate_files(
                request_path=str(request_path),
                assurance_plan_path=str(plan_path),
                certification_bundle_path=str(bundle_path),
                root=ROOT,
            )
            result_path = self.write_json(directory, "result.json", result)
            code, stdout, stderr = self.invoke([
                "explain", "--result", str(result_path), "--format", "text"
            ])
            self.assertEqual(code, 0, stderr)
            self.assertIn("verdict: PASS", stdout)
            self.assertIn("claim_scope: production-conformance", stdout)

            result["result_digest"] = "sha256:" + "9" * 64
            self.write_json(directory, "bad-result.json", result)
            code, stdout, _stderr = self.invoke([
                "explain", "--result", str(directory / "bad-result.json")
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_RESULT_MISMATCH)
            self.assertFalse(json.loads(stdout)["verified"])

    def test_migration_artifacts_must_be_supplied_as_pair(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            request_path, plan_path, bundle_path, *_ = self.temp_inputs(directory)
            migration_plan = ROOT / "fixtures/deprecation-migration/valid/planned-plan.json"
            code, _stdout, stderr = self.invoke([
                "evaluate",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
                "--migration-plan", str(migration_plan),
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_INVALID_INPUT)
            self.assertIn("must be supplied together", stderr)

    def test_nonmigration_policy_with_paired_migration_artifacts_reaches_pr40(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            request_path, plan_path, bundle_path, *_ = self.temp_inputs(directory)
            migration_plan = ROOT / "fixtures/deprecation-migration/valid/planned-plan.json"
            migration_case = ROOT / "fixtures/deprecation-migration/valid/planned-case.json"
            code, stdout, _stderr = self.invoke([
                "evaluate",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
                "--migration-plan", str(migration_plan),
                "--migration-case", str(migration_case),
            ])
            self.assertEqual(code, e2eesa_conformance.EXIT_FAIL)
            result = json.loads(stdout)
            self.assertTrue(any(
                item["code"] == "migration-artifacts-not-permitted"
                for item in result["reasons"]
            ))

    def test_output_file_is_written_and_stdout_stays_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            request_path, plan_path, bundle_path, *_ = self.temp_inputs(directory)
            output = directory / "result.json"
            code, stdout, stderr = self.invoke([
                "evaluate",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
                "--output", str(output),
            ])
            self.assertEqual(code, 0, stderr)
            self.assertEqual(stdout, "")
            self.assertTrue(output.is_file())
            self.assertEqual(json.loads(output.read_text())["verdict"], "pass")

    def test_text_output_is_presentation_of_same_result(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            request_path, plan_path, bundle_path, *_ = self.temp_inputs(directory)
            code, stdout, stderr = self.invoke([
                "evaluate",
                "--request", str(request_path),
                "--assurance-plan", str(plan_path),
                "--certification-bundle", str(bundle_path),
                "--format", "text",
            ])
            self.assertEqual(code, 0, stderr)
            self.assertIn("verdict: PASS", stdout)
            self.assertIn("production_certification_eligible: false", stdout)

    def test_missing_basis_root_is_invalid_input(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        with tempfile.TemporaryDirectory() as td:
            code = e2eesa_conformance.main(
                ["--root", td, "basis"],
                stdout=stdout,
                stderr=stderr,
            )
        self.assertEqual(code, e2eesa_conformance.EXIT_INVALID_INPUT)
        self.assertIn("cannot read", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
