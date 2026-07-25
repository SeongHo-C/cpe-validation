"""Unit tests for digest-pinned Syft CycloneDX SBOM generation."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.generate_sbom import (
    EXPECTED_SYFT_VERSION,
    CycloneDxValidationError,
    InputValidationError,
    OutputExistsError,
    RepositoryNotFoundError,
    RunSummary,
    SyftCommandError,
    SyftNotFoundError,
    SyftVersionError,
    build_parser,
    build_syft_command,
    build_syft_environment,
    check_syft_version,
    exit_code_for_summary,
    generate_single_sbom,
    load_digest_input,
    main,
    process_images,
    repository_name,
    sbom_output_filename,
    select_repository,
    validate_cyclonedx_output,
    validate_digest,
    validate_image_entry,
)


DIGEST = "sha256:" + ("a" * 64)
SECOND_DIGEST = "sha256:" + ("b" * 64)


def image_fixture(
    repository: str = "memcached",
    tag: str = "1.6.45",
    digest: str = DIGEST,
) -> dict[str, object]:
    normalized_repository = f"docker.io/library/{repository}"
    return {
        "status": "success",
        "input_reference": f"{normalized_repository}:{tag}",
        "normalized_repository": normalized_repository,
        "input_tag": tag,
        "target_os": "linux",
        "target_architecture": "amd64",
        "platform_manifest_digest": digest,
        "pinned_reference": f"{normalized_repository}@{digest}",
        "error": None,
    }


def input_fixture(
    images: list[object] | None = None,
    schema_version: object = 1,
    platform_os: str = "linux",
    platform_architecture: str = "amd64",
) -> dict[str, object]:
    if images is None:
        images = [
            image_fixture(),
            image_fixture("nginx", "1.30.4", SECOND_DIGEST),
        ]
    return {
        "schema_version": schema_version,
        "selection_date": "2026-07-24",
        "platform": {
            "os": platform_os,
            "architecture": platform_architecture,
        },
        "total_images": len(images),
        "success_count": len(images),
        "failure_count": 0,
        "images": images,
    }


def cyclone_dx_fixture(
    components: list[object] | None = None,
) -> dict[str, object]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [] if components is None else components,
    }


def write_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def completed_process(
    command: list[str],
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=command,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def version_runner(version: str) -> mock.Mock:
    runner = mock.Mock()
    runner.return_value = completed_process(
        ["syft", "version", "-o", "json"],
        stdout=json.dumps(
            {"application": "syft", "version": version}
        ),
    )
    return runner


def successful_scan_runner(
    document: object | None = None,
) -> mock.Mock:
    output_document = (
        cyclone_dx_fixture() if document is None else document
    )
    runner = mock.Mock()

    def run(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        output_argument = command[command.index("--output") + 1]
        temporary_path = Path(output_argument.split("=", 1)[1])
        write_json(temporary_path, output_document)
        return completed_process(command)

    runner.side_effect = run
    return runner


class SyftVersionTests(unittest.TestCase):
    def test_accepts_exact_version(self) -> None:
        runner = version_runner("1.49.0")

        self.assertEqual(
            check_syft_version(runner),
            EXPECTED_SYFT_VERSION,
        )
        self.assertEqual(
            runner.call_args.args[0],
            ["syft", "version", "-o", "json"],
        )
        self.assertFalse(runner.call_args.kwargs["shell"])

    def test_accepts_v_prefixed_version(self) -> None:
        self.assertEqual(
            check_syft_version(version_runner("v1.49.0")),
            EXPECTED_SYFT_VERSION,
        )

    def test_rejects_different_version(self) -> None:
        with self.assertRaises(SyftVersionError):
            check_syft_version(version_runner("1.48.0"))

    def test_handles_missing_executable(self) -> None:
        runner = mock.Mock(side_effect=FileNotFoundError("syft"))

        with self.assertRaises(SyftNotFoundError):
            check_syft_version(runner)

    def test_rejects_failed_version_command(self) -> None:
        runner = mock.Mock(
            return_value=completed_process(
                ["syft", "version", "-o", "json"],
                returncode=2,
                stderr="version failed",
            )
        )

        with self.assertRaisesRegex(
            SyftVersionError,
            "version failed",
        ):
            check_syft_version(runner)

    def test_rejects_non_json_version_output(self) -> None:
        runner = mock.Mock(
            return_value=completed_process(
                ["syft", "version", "-o", "json"],
                stdout="not json",
            )
        )

        with self.assertRaises(SyftVersionError):
            check_syft_version(runner)


class InputValidationTests(unittest.TestCase):
    def test_loads_normal_input_and_preserves_image_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_path = Path(temporary_directory) / "image-digests.json"
            write_json(input_path, input_fixture())

            document = load_digest_input(input_path)

        self.assertEqual(
            [
                image["normalized_repository"]
                for image in document["images"]
            ],
            [
                "docker.io/library/memcached",
                "docker.io/library/nginx",
            ],
        )

    def test_rejects_wrong_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_path = Path(temporary_directory) / "image-digests.json"
            write_json(
                input_path,
                input_fixture(schema_version=2),
            )

            with self.assertRaises(InputValidationError):
                load_digest_input(input_path)

    def test_rejects_non_linux_amd64_platform(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_path = Path(temporary_directory) / "image-digests.json"
            write_json(
                input_path,
                input_fixture(platform_architecture="arm64"),
            )

            with self.assertRaises(InputValidationError):
                load_digest_input(input_path)

    def test_rejects_non_array_images(self) -> None:
        document = input_fixture()
        document["images"] = {}
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_path = Path(temporary_directory) / "image-digests.json"
            write_json(input_path, document)

            with self.assertRaises(InputValidationError):
                load_digest_input(input_path)

    def test_accepts_valid_digest(self) -> None:
        self.assertEqual(validate_digest(DIGEST), DIGEST)

    def test_rejects_invalid_digest(self) -> None:
        for invalid_digest in (
            "sha256:1234",
            "sha256:" + ("G" * 64),
            "sha512:" + ("a" * 64),
        ):
            with self.subTest(digest=invalid_digest):
                with self.assertRaises(InputValidationError):
                    validate_digest(invalid_digest)

    def test_rejects_pinned_digest_mismatch(self) -> None:
        image = image_fixture()
        image["pinned_reference"] = (
            "docker.io/library/memcached@" + SECOND_DIGEST
        )

        with self.assertRaises(InputValidationError):
            validate_image_entry(image)

    def test_rejects_failed_image_before_syft(self) -> None:
        image = image_fixture()
        image["status"] = "failed"

        with self.assertRaises(InputValidationError):
            validate_image_entry(image)

    def test_extracts_repository_name(self) -> None:
        self.assertEqual(
            repository_name("docker.io/library/memcached"),
            "memcached",
        )

    def test_builds_sbom_filename(self) -> None:
        self.assertEqual(
            sbom_output_filename(
                "docker.io/library/memcached",
                "1.6.45",
            ),
            "memcached-1.6.45.cdx.json",
        )


class CommandAndEnvironmentTests(unittest.TestCase):
    def test_builds_exact_fixed_syft_command(self) -> None:
        temporary_path = Path("/tmp/memcached.cdx.json.tmp")

        command = build_syft_command(
            f"docker.io/library/memcached@{DIGEST}",
            temporary_path,
        )

        self.assertEqual(
            command,
            [
                "syft",
                "scan",
                f"docker.io/library/memcached@{DIGEST}",
                "--from",
                "registry",
                "--platform",
                "linux/amd64",
                "--scope",
                "squashed",
                "--output",
                f"cyclonedx-json={temporary_path}",
            ],
        )
        self.assertNotIn("--enrich", command)
        self.assertNotIn("all-layers", command)

    def test_builds_required_environment_and_preserves_existing(self) -> None:
        environment = build_syft_environment(
            {
                "PATH": "/example/bin",
                "SYFT_CHECK_FOR_APP_UPDATE": "old",
            }
        )

        self.assertEqual(environment["PATH"], "/example/bin")
        self.assertEqual(
            environment["SYFT_FORMAT_CYCLONEDX_JSON_PRETTY"],
            "true",
        )
        self.assertEqual(
            environment["SYFT_CHECK_FOR_APP_UPDATE"],
            "false",
        )


class CycloneDxValidationTests(unittest.TestCase):
    def test_accepts_valid_cyclonedx_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "sbom.json"
            write_json(output_path, cyclone_dx_fixture())

            document = validate_cyclonedx_output(output_path)

        self.assertEqual(document["bomFormat"], "CycloneDX")

    def test_rejects_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "sbom.json"
            output_path.write_text("{invalid", encoding="utf-8")

            with self.assertRaises(CycloneDxValidationError):
                validate_cyclonedx_output(output_path)

    def test_rejects_wrong_bom_format(self) -> None:
        document = cyclone_dx_fixture()
        document["bomFormat"] = "SPDX"
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "sbom.json"
            write_json(output_path, document)

            with self.assertRaises(CycloneDxValidationError):
                validate_cyclonedx_output(output_path)

    def test_rejects_empty_spec_version(self) -> None:
        document = cyclone_dx_fixture()
        document["specVersion"] = ""
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "sbom.json"
            write_json(output_path, document)

            with self.assertRaises(CycloneDxValidationError):
                validate_cyclonedx_output(output_path)

    def test_rejects_non_array_components(self) -> None:
        document = cyclone_dx_fixture()
        document["components"] = {}
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "sbom.json"
            write_json(output_path, document)

            with self.assertRaises(CycloneDxValidationError):
                validate_cyclonedx_output(output_path)

    def test_accepts_empty_components_and_no_cpe(self) -> None:
        document = cyclone_dx_fixture(components=[])
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "sbom.json"
            write_json(output_path, document)

            validated = validate_cyclonedx_output(output_path)

        self.assertEqual(validated["components"], [])


class SingleImageGenerationTests(unittest.TestCase):
    def test_existing_output_is_rejected_without_running_syft(self) -> None:
        runner = successful_scan_runner()
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            final_path = (
                output_directory / "memcached-1.6.45.cdx.json"
            )
            final_path.write_text("existing", encoding="utf-8")

            with self.assertRaises(OutputExistsError):
                generate_single_sbom(
                    image_fixture(),
                    output_directory,
                    runner=runner,
                )

            self.assertEqual(
                final_path.read_text(encoding="utf-8"),
                "existing",
            )
            runner.assert_not_called()

    def test_overwrite_replaces_only_after_successful_validation(
        self,
    ) -> None:
        runner = successful_scan_runner()
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            final_path = (
                output_directory / "memcached-1.6.45.cdx.json"
            )
            final_path.write_text("existing", encoding="utf-8")

            returned_path = generate_single_sbom(
                image_fixture(),
                output_directory,
                overwrite=True,
                runner=runner,
            )

            self.assertEqual(returned_path, final_path)
            self.assertEqual(
                json.loads(final_path.read_text(encoding="utf-8")),
                cyclone_dx_fixture(),
            )

    def test_failed_overwrite_preserves_existing_output(self) -> None:
        runner = mock.Mock(
            return_value=completed_process(
                ["syft", "scan"],
                returncode=1,
                stderr="registry unavailable",
            )
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            final_path = (
                output_directory / "memcached-1.6.45.cdx.json"
            )
            final_path.write_text("existing", encoding="utf-8")

            with self.assertRaises(SyftCommandError):
                generate_single_sbom(
                    image_fixture(),
                    output_directory,
                    overwrite=True,
                    runner=runner,
                )

            self.assertEqual(
                final_path.read_text(encoding="utf-8"),
                "existing",
            )

    def test_syft_failure_removes_temporary_file(self) -> None:
        captured_path: list[Path] = []

        def fail(
            command: list[str],
            **_: object,
        ) -> subprocess.CompletedProcess[str]:
            output_argument = command[command.index("--output") + 1]
            captured_path.append(
                Path(output_argument.split("=", 1)[1])
            )
            return completed_process(
                command,
                returncode=3,
                stderr="authentication failed",
            )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            with self.assertRaisesRegex(
                SyftCommandError,
                "authentication failed",
            ):
                generate_single_sbom(
                    image_fixture(),
                    output_directory,
                    runner=fail,
                )

            self.assertEqual(len(captured_path), 1)
            self.assertFalse(captured_path[0].exists())
            self.assertEqual(list(output_directory.iterdir()), [])

    def test_invalid_generated_json_removes_temporary_file(self) -> None:
        captured_path: list[Path] = []

        def write_invalid(
            command: list[str],
            **_: object,
        ) -> subprocess.CompletedProcess[str]:
            output_argument = command[command.index("--output") + 1]
            temporary_path = Path(output_argument.split("=", 1)[1])
            captured_path.append(temporary_path)
            temporary_path.write_text("{invalid", encoding="utf-8")
            return completed_process(command)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            with self.assertRaises(CycloneDxValidationError):
                generate_single_sbom(
                    image_fixture(),
                    output_directory,
                    runner=write_invalid,
                )

            self.assertFalse(captured_path[0].exists())
            self.assertEqual(list(output_directory.iterdir()), [])

    def test_scan_uses_list_arguments_and_required_environment(
        self,
    ) -> None:
        runner = successful_scan_runner()
        with tempfile.TemporaryDirectory() as temporary_directory:
            generate_single_sbom(
                image_fixture(),
                Path(temporary_directory),
                runner=runner,
            )

        command = runner.call_args.args[0]
        keyword_arguments = runner.call_args.kwargs
        self.assertIsInstance(command, list)
        self.assertEqual(command[0:2], ["syft", "scan"])
        self.assertIn(
            f"docker.io/library/memcached@{DIGEST}",
            command,
        )
        self.assertFalse(keyword_arguments["shell"])
        self.assertEqual(
            keyword_arguments["env"][
                "SYFT_FORMAT_CYCLONEDX_JSON_PRETTY"
            ],
            "true",
        )
        self.assertEqual(
            keyword_arguments["env"]["SYFT_CHECK_FOR_APP_UPDATE"],
            "false",
        )


class OrderedProcessingTests(unittest.TestCase):
    def test_continues_after_invalid_image_and_counts_results(self) -> None:
        invalid_image = image_fixture()
        invalid_image["status"] = "failed"
        runner = successful_scan_runner()
        standard_output = io.StringIO()
        standard_error = io.StringIO()

        with tempfile.TemporaryDirectory() as temporary_directory:
            with (
                contextlib.redirect_stdout(standard_output),
                contextlib.redirect_stderr(standard_error),
            ):
                summary = process_images(
                    [
                        invalid_image,
                        image_fixture(
                            "nginx",
                            "1.30.4",
                            SECOND_DIGEST,
                        ),
                    ],
                    Path(temporary_directory),
                    runner=runner,
                )

        self.assertEqual(
            summary,
            RunSummary(total=2, success=1, failed=1),
        )
        self.assertEqual(runner.call_count, 1)
        self.assertIn("[failed] memcached:1.6.45", standard_error.getvalue())
        self.assertIn("[success] nginx:1.30.4", standard_output.getvalue())

    def test_all_success_returns_zero_exit_code(self) -> None:
        runner = successful_scan_runner()
        with tempfile.TemporaryDirectory() as temporary_directory:
            with contextlib.redirect_stdout(io.StringIO()):
                summary = process_images(
                    [image_fixture()],
                    Path(temporary_directory),
                    runner=runner,
                )

        self.assertEqual(exit_code_for_summary(summary), 0)

    def test_any_failure_returns_nonzero_exit_code(self) -> None:
        summary = RunSummary(total=2, success=1, failed=1)

        self.assertNotEqual(exit_code_for_summary(summary), 0)

    def test_selects_one_repository(self) -> None:
        images = input_fixture()["images"]

        selected = select_repository(images, "nginx")

        self.assertEqual(len(selected), 1)
        self.assertEqual(
            selected[0]["normalized_repository"],
            "docker.io/library/nginx",
        )

    def test_rejects_missing_repository_without_syft(self) -> None:
        images = input_fixture()["images"]
        runner = mock.Mock()

        with self.assertRaises(RepositoryNotFoundError):
            select_repository(images, "missing")

        runner.assert_not_called()

    @mock.patch("scripts.generate_sbom.check_syft_version")
    def test_missing_repository_main_skips_syft_version(
        self,
        version_mock: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            input_path = temporary_path / "image-digests.json"
            write_json(input_path, input_fixture())
            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = main(
                    [
                        "--input",
                        str(input_path),
                        "--repository",
                        "missing",
                        "--output-dir",
                        str(temporary_path / "sboms"),
                    ]
                )

        self.assertNotEqual(exit_code, 0)
        version_mock.assert_not_called()

    def test_cli_defaults_do_not_create_real_results(self) -> None:
        pilot_directory = Path(__file__).resolve().parents[1]
        real_output_directory = pilot_directory / "results/sboms"
        existed_before = real_output_directory.exists()

        arguments = build_parser().parse_args([])

        self.assertEqual(
            arguments.input,
            Path("results/image-digests.json"),
        )
        self.assertEqual(arguments.output_dir, Path("results/sboms"))
        self.assertEqual(
            real_output_directory.exists(),
            existed_before,
        )


if __name__ == "__main__":
    unittest.main()
