#!/usr/bin/env python3
"""Reference CLI for the E2EESA PR 40 conformance engine."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, TextIO

import canonical_serialization
import conformance_engine
import formal_verification

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INDETERMINATE = 2
EXIT_INVALID_INPUT = 3
EXIT_RESULT_MISMATCH = 4

DEFAULT_ROOT = Path(__file__).resolve().parents[1]

STANDARD_FILES = {
    "conformance_registry": "registry/conformance.json",
    "catalog": "profiles/catalog.json",
    "crypto": "registry/cryptographic-algorithms.json",
    "property_registry": "registry/security-properties.json",
    "threat_registry": "registry/threat-model.json",
    "assurance_registry": "registry/assurance-levels.json",
    "certification_registry": "registry/certification-evidence.json",
    "promotion_registry": "registry/research-promotion.json",
    "migration_registry": "registry/deprecation-migration.json",
}


class InputError(ValueError):
    """Command-level input error."""


class CliArgumentParser(argparse.ArgumentParser):
    """argparse adapter that preserves the normative PR 41 exit-code contract."""

    def error(self, message: str) -> None:
        raise InputError(message)


class ConformanceArgumentParser(argparse.ArgumentParser):
    """Argument parser whose syntax errors follow the normative CLI exit contract."""

    def error(self, message: str) -> None:
        raise InputError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_json(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot read {file_path}: {exc}") from exc
    try:
        value = canonical_serialization.parse_json(text)
    except InputError:
        raise
    except json.JSONDecodeError as exc:
        raise InputError(
            f"invalid JSON in {file_path}: line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc
    except ValueError as exc:
        raise InputError(str(exc)) from exc
    if not isinstance(value, dict):
        raise InputError(f"{file_path}: top-level JSON value must be an object")
    return value


def load_standard_inputs(root: str | Path) -> dict[str, dict[str, Any]]:
    root_path = Path(root)
    values: dict[str, dict[str, Any]] = {}
    for name, relative in STANDARD_FILES.items():
        values[name] = load_json(root_path / relative)
    return values


def _json_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_name = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        temp_name = None
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def write_output(
    value: object,
    *,
    output_format: str,
    output: str | None,
    stdout: TextIO,
) -> None:
    if output_format == "json":
        text = _json_text(value)
    else:
        if isinstance(value, dict) and "verdict" in value:
            text = render_result_text(value)
        elif isinstance(value, dict):
            lines = [
                f"{key}: {json.dumps(item, ensure_ascii=False, sort_keys=True)}"
                for key, item in sorted(value.items())
            ]
            text = "\n".join(lines) + "\n"
        else:
            text = str(value) + "\n"

    if output in (None, "-"):
        stdout.write(text)
        stdout.flush()
        return
    _write_atomic(Path(output), text)


def render_result_text(result: dict[str, Any]) -> str:
    lines = [
        f"verdict: {str(result.get('verdict', 'unknown')).upper()}",
        f"claim_scope: {result.get('claim_scope')}",
        (
            "product: "
            f"{result.get('product_id')} {result.get('product_version')} "
            f"({result.get('platform')})"
        ),
        (
            "production_certification_eligible: "
            f"{str(bool(result.get('production_certification_eligible'))).lower()}"
        ),
        f"effective_profiles: {len(result.get('effective_profile_refs', []))}",
        f"in_scope_families: {len(result.get('in_scope_family_ids', []))}",
        f"required_properties: {len(result.get('required_property_ids', []))}",
    ]
    reasons = result.get("reasons")
    if isinstance(reasons, list) and reasons:
        lines.append("reasons:")
        for item in reasons:
            if isinstance(item, dict):
                lines.append(
                    f"  [{item.get('severity')}] {item.get('code')}: "
                    f"{item.get('message')}"
                )
    else:
        lines.append("reasons: none")
    return "\n".join(lines) + "\n"


def verdict_exit_code(verdict: object) -> int:
    if verdict == "pass":
        return EXIT_PASS
    if verdict == "fail":
        return EXIT_FAIL
    if verdict == "indeterminate":
        return EXIT_INDETERMINATE
    raise InputError(f"unknown conformance verdict: {verdict}")


def basis_document(inputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "standard_version": inputs["catalog"].get("standard_version"),
        "input_digests": conformance_engine.evaluation_input_digests(**inputs),
    }


def bind_request(
    request: dict[str, Any],
    assurance_plan: dict[str, Any],
    certification_bundle: dict[str, Any],
    inputs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    result = json.loads(json.dumps(request))

    identity_fields = ("product_id", "product_version", "platform")
    for field in identity_fields:
        plan_value = assurance_plan.get(field)
        bundle_value = certification_bundle.get(field)
        request_value = request.get(field)
        if plan_value != bundle_value:
            raise InputError(
                f"plan/bundle {field} mismatch: {plan_value!r} != {bundle_value!r}"
            )
        if request_value != plan_value:
            raise InputError(
                f"request {field} does not match plan/bundle: "
                f"{request_value!r} != {plan_value!r}"
            )

    configuration = assurance_plan.get("configuration")
    if not isinstance(configuration, dict):
        raise InputError("assurance plan configuration must be an object")

    result["standard_version"] = inputs["catalog"].get("standard_version")
    result["assurance_plan_digest"] = formal_verification.canonical_digest(
        assurance_plan
    )
    result["certification_bundle_digest"] = conformance_engine.canonical_digest(
        certification_bundle
    )
    result["configuration_digest"] = formal_verification.canonical_digest(
        configuration
    )
    result["source_digest"] = certification_bundle.get("source_digest")
    result["artifact_digest"] = certification_bundle.get("artifact_digest")
    result["input_digests"] = conformance_engine.evaluation_input_digests(**inputs)
    result["request_digest"] = conformance_engine.compute_request_digest(result)
    return result


def _migration_pair(
    migration_plan_path: str | None,
    migration_case_path: str | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if bool(migration_plan_path) != bool(migration_case_path):
        raise InputError(
            "--migration-plan and --migration-case must be supplied together"
        )
    if migration_plan_path is None:
        return None, None
    return load_json(migration_plan_path), load_json(migration_case_path)


def evaluate_files(
    *,
    request_path: str,
    assurance_plan_path: str,
    certification_bundle_path: str,
    root: str | Path,
    migration_plan_path: str | None = None,
    migration_case_path: str | None = None,
) -> dict[str, Any]:
    inputs = load_standard_inputs(root)
    request = load_json(request_path)
    plan = load_json(assurance_plan_path)
    bundle = load_json(certification_bundle_path)
    migration_plan, migration_case = _migration_pair(
        migration_plan_path, migration_case_path
    )
    return conformance_engine.evaluate_conformance(
        request,
        plan,
        bundle,
        **inputs,
        migration_plan=migration_plan,
        migration_case=migration_case,
    )


def verify_result_files(
    *,
    request_path: str,
    assurance_plan_path: str,
    certification_bundle_path: str,
    result_path: str,
    root: str | Path,
    migration_plan_path: str | None = None,
    migration_case_path: str | None = None,
) -> tuple[dict[str, Any], list[str]]:
    saved = load_json(result_path)
    expected = evaluate_files(
        request_path=request_path,
        assurance_plan_path=assurance_plan_path,
        certification_bundle_path=certification_bundle_path,
        root=root,
        migration_plan_path=migration_plan_path,
        migration_case_path=migration_case_path,
    )
    return expected, conformance_engine.validate_result(saved, expected)


def validate_cli_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("conformance CLI registry schema_version must be 0.1")
    if set(registry.get("commands", [])) != {
        "basis","bind-request","evaluate","verify-result","explain"
    }:
        errors.append("conformance CLI registry command set mismatch")
    if set(registry.get("formats", [])) != {"json","text"}:
        errors.append("conformance CLI registry format set mismatch")
    expected_codes = {
        0:"PASS", 1:"FAIL", 2:"INDETERMINATE",
        3:"INVALID_INPUT", 4:"RESULT_MISMATCH",
    }
    items = registry.get("exit_codes")
    if not isinstance(items, list):
        return errors + ["conformance CLI exit_codes must be an array"]
    actual: dict[int, str] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"conformance CLI exit_codes[{index}] must be an object")
            continue
        code = item.get("code")
        name = item.get("name")
        if not isinstance(code, int) or isinstance(code, bool):
            errors.append(f"conformance CLI exit_codes[{index}] code must be integer")
            continue
        if code in actual:
            errors.append(f"conformance CLI duplicate exit code {code}")
        actual[code] = name
        if not isinstance(item.get("meaning"), str) or not item["meaning"].strip():
            errors.append(f"conformance CLI exit code {code} meaning must be non-empty")
    if actual != expected_codes:
        errors.append("conformance CLI exit code contract mismatch")
    return sorted(set(errors))


def build_parser() -> argparse.ArgumentParser:
    parser = ConformanceArgumentParser(
        prog="e2eesa-conformance",
        description="Evaluate and verify E2EESA conformance using the PR 40 engine.",
    )
    parser.add_argument(
        "--root",
        default=str(DEFAULT_ROOT),
        help="E2EESA repository root containing profiles/ and registry/.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def output_args(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--format",
            choices=("json","text"),
            default="json",
            dest="output_format",
        )
        command.add_argument(
            "--output",
            default="-",
            help="Output path, or - for stdout (default).",
        )

    basis = subparsers.add_parser(
        "basis", help="Print the current standard version and input digests."
    )
    output_args(basis)

    bind = subparsers.add_parser(
        "bind-request", help="Fill mechanically derived request binding fields."
    )
    bind.add_argument("--request", required=True)
    bind.add_argument("--assurance-plan", required=True)
    bind.add_argument("--certification-bundle", required=True)
    output_args(bind)

    evaluate = subparsers.add_parser(
        "evaluate", help="Evaluate a bound conformance request."
    )
    evaluate.add_argument("--request", required=True)
    evaluate.add_argument("--assurance-plan", required=True)
    evaluate.add_argument("--certification-bundle", required=True)
    evaluate.add_argument("--migration-plan")
    evaluate.add_argument("--migration-case")
    output_args(evaluate)

    verify = subparsers.add_parser(
        "verify-result", help="Reevaluate and verify a saved conformance result."
    )
    verify.add_argument("--request", required=True)
    verify.add_argument("--assurance-plan", required=True)
    verify.add_argument("--certification-bundle", required=True)
    verify.add_argument("--result", required=True)
    verify.add_argument("--migration-plan")
    verify.add_argument("--migration-case")
    output_args(verify)

    explain = subparsers.add_parser(
        "explain", help="Validate self-digest and explain a saved result."
    )
    explain.add_argument("--result", required=True)
    output_args(explain)

    return parser


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        root = Path(args.root)

        if args.command == "basis":
            inputs = load_standard_inputs(root)
            write_output(
                basis_document(inputs),
                output_format=args.output_format,
                output=args.output,
                stdout=stdout,
            )
            return EXIT_PASS

        if args.command == "bind-request":
            inputs = load_standard_inputs(root)
            request = load_json(args.request)
            plan = load_json(args.assurance_plan)
            bundle = load_json(args.certification_bundle)
            bound = bind_request(request, plan, bundle, inputs)
            write_output(
                bound,
                output_format=args.output_format,
                output=args.output,
                stdout=stdout,
            )
            return EXIT_PASS

        if args.command == "evaluate":
            result = evaluate_files(
                request_path=args.request,
                assurance_plan_path=args.assurance_plan,
                certification_bundle_path=args.certification_bundle,
                root=root,
                migration_plan_path=args.migration_plan,
                migration_case_path=args.migration_case,
            )
            write_output(
                result,
                output_format=args.output_format,
                output=args.output,
                stdout=stdout,
            )
            return verdict_exit_code(result.get("verdict"))

        if args.command == "verify-result":
            expected, errors = verify_result_files(
                request_path=args.request,
                assurance_plan_path=args.assurance_plan,
                certification_bundle_path=args.certification_bundle,
                result_path=args.result,
                root=root,
                migration_plan_path=args.migration_plan,
                migration_case_path=args.migration_case,
            )
            if errors:
                payload = {
                    "verified":False,
                    "errors":errors,
                }
                write_output(
                    payload,
                    output_format=args.output_format,
                    output=args.output,
                    stdout=stdout,
                )
                return EXIT_RESULT_MISMATCH
            payload = {
                "verified":True,
                "verdict":expected["verdict"],
                "result_digest":expected["result_digest"],
            }
            write_output(
                payload,
                output_format=args.output_format,
                output=args.output,
                stdout=stdout,
            )
            return verdict_exit_code(expected.get("verdict"))

        if args.command == "explain":
            result = load_json(args.result)
            if result.get("result_digest") != conformance_engine.compute_result_digest(result):
                write_output(
                    {
                        "verified":False,
                        "errors":["conformance result_digest does not match canonical result"],
                    },
                    output_format=args.output_format,
                    output=args.output,
                    stdout=stdout,
                )
                return EXIT_RESULT_MISMATCH
            write_output(
                result,
                output_format=args.output_format,
                output=args.output,
                stdout=stdout,
            )
            return EXIT_PASS

        raise InputError(f"unsupported command: {args.command}")

    except InputError as exc:
        stderr.write(f"error: {exc}\n")
        stderr.flush()
        return EXIT_INVALID_INPUT
    except (KeyError, TypeError, ValueError) as exc:
        stderr.write(f"error: {exc}\n")
        stderr.flush()
        return EXIT_INVALID_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
