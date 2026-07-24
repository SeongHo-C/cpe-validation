"""Unit tests for ordered platform-specific digest collection."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.resolve_image_digest import (
    DockerCommandError,
    InvalidDigestError,
    InvalidInputError,
    MultipleMatchingManifestsError,
    NoMatchingManifestError,
    OutputExistsError,
    build_image_reference,
    extract_manifest_metadata,
    load_input_configuration,
    raw_output_filename,
    resolve_image_digest,
    resolve_images_from_file,
    run_docker_command,
)


TOP_LEVEL_DIGEST = "sha256:" + ("a" * 64)
SECOND_TOP_LEVEL_DIGEST = "sha256:" + ("f" * 64)
AMD64_DIGEST = "sha256:" + ("b" * 64)
SECOND_AMD64_DIGEST = "sha256:" + ("e" * 64)
ARM64_DIGEST = "sha256:" + ("c" * 64)
ATTESTATION_DIGEST = "sha256:" + ("d" * 64)


def descriptor(
    digest: str,
    os_name: str,
    architecture: str,
) -> dict[str, object]:
    return {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": digest,
        "size": 1024,
        "platform": {
            "os": os_name,
            "architecture": architecture,
        },
    }


def index_fixture(
    top_level_digest: str = TOP_LEVEL_DIGEST,
    amd64_digest: str = AMD64_DIGEST,
) -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "digest": top_level_digest,
        "size": 4096,
        "manifests": [
            descriptor(amd64_digest, "linux", "amd64"),
            descriptor(ARM64_DIGEST, "linux", "arm64"),
        ],
    }


def manifest_bytes(
    top_level_digest: str = TOP_LEVEL_DIGEST,
    amd64_digest: str = AMD64_DIGEST,
) -> bytes:
    return json.dumps(
        index_fixture(top_level_digest, amd64_digest),
        separators=(",", ":"),
    ).encode("utf-8")


def write_input_file(
    path: Path,
    image_lines: str = """
  - repository: memcached
    tag: "1.6.45"
  - repository: nginx
    tag: "1.30.4"
""",
    platform_os: str = "linux",
    platform_architecture: str = "amd64",
) -> None:
    path.write_text(
        f"""selection_date: "2026-07-24"
registry: docker.io
namespace: library
platform:
  os: {platform_os}
  architecture: {platform_architecture}
images:
{image_lines}
""",
        encoding="utf-8",
    )


class ExtractManifestMetadataTests(unittest.TestCase):
    def test_selects_exactly_one_linux_amd64_manifest(self) -> None:
        metadata = extract_manifest_metadata(
            index_fixture(),
            "linux",
            "amd64",
        )

        self.assertEqual(
            metadata["top_level_digest"],
            TOP_LEVEL_DIGEST,
        )
        self.assertEqual(
            metadata["platform_manifest_digest"],
            AMD64_DIGEST,
        )
        self.assertEqual(
            metadata["platform_manifest_media_type"],
            "application/vnd.oci.image.manifest.v1+json",
        )

    def test_fails_when_no_manifest_matches(self) -> None:
        fixture = index_fixture()
        fixture["manifests"] = [
            descriptor(ARM64_DIGEST, "linux", "arm64"),
        ]

        with self.assertRaises(NoMatchingManifestError):
            extract_manifest_metadata(fixture, "linux", "amd64")

    def test_fails_when_multiple_manifests_match(self) -> None:
        fixture = index_fixture()
        fixture["manifests"] = [
            descriptor(AMD64_DIGEST, "linux", "amd64"),
            descriptor(SECOND_AMD64_DIGEST, "linux", "amd64"),
        ]

        with self.assertRaises(MultipleMatchingManifestsError):
            extract_manifest_metadata(fixture, "linux", "amd64")

    def test_ignores_unknown_unknown_attestation_manifest(self) -> None:
        fixture = index_fixture()
        attestation = descriptor(
            ATTESTATION_DIGEST,
            "unknown",
            "unknown",
        )
        attestation["annotations"] = {
            "vnd.docker.reference.type": "attestation-manifest",
            "vnd.docker.reference.digest": AMD64_DIGEST,
        }
        fixture["manifests"] = [
            descriptor(AMD64_DIGEST, "linux", "amd64"),
            attestation,
        ]

        metadata = extract_manifest_metadata(
            fixture,
            "linux",
            "amd64",
        )

        self.assertEqual(
            metadata["platform_manifest_digest"],
            AMD64_DIGEST,
        )

    def test_rejects_invalid_platform_digest_format(self) -> None:
        fixture = index_fixture()
        fixture["manifests"][0]["digest"] = "sha256:1234"  # type: ignore[index]

        with self.assertRaises(InvalidDigestError):
            extract_manifest_metadata(fixture, "linux", "amd64")

    def test_rejects_invalid_top_level_digest_format(self) -> None:
        fixture = index_fixture()
        fixture["digest"] = "sha256:" + ("g" * 64)

        with self.assertRaises(InvalidDigestError):
            extract_manifest_metadata(fixture, "linux", "amd64")


class DockerCommandTests(unittest.TestCase):
    @mock.patch("scripts.resolve_image_digest.subprocess.run")
    def test_nonzero_stdout_and_stderr_are_reported(
        self,
        run_mock: mock.Mock,
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=["docker", "buildx", "version"],
            returncode=1,
            stdout=b"shim failure\n",
            stderr=b"plugin failure\n",
        )
        standard_error = io.StringIO()

        with contextlib.redirect_stderr(standard_error):
            with self.assertRaises(DockerCommandError) as context:
                run_docker_command(
                    ["docker", "buildx", "version"]
                )

        reported = standard_error.getvalue()
        self.assertIn(
            'docker_stderr="plugin failure\\n"',
            reported,
        )
        self.assertIn(
            'docker_stdout_on_error="shim failure\\n"',
            reported,
        )
        self.assertIn("shim failure", str(context.exception))
        self.assertIn("plugin failure", str(context.exception))


class InputConfigurationTests(unittest.TestCase):
    def test_builds_image_reference(self) -> None:
        self.assertEqual(
            build_image_reference(
                "docker.io",
                "library",
                "memcached",
                "1.6.45",
            ),
            "docker.io/library/memcached:1.6.45",
        )

    def test_yaml_input_order_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_path = Path(temporary_directory) / "images.yaml"
            write_input_file(input_path)

            configuration = load_input_configuration(input_path)

        self.assertEqual(
            [
                image["repository"]
                for image in configuration["images"]
            ],
            ["memcached", "nginx"],
        )

    def test_unquoted_yaml_tag_remains_a_string(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_path = Path(temporary_directory) / "images.yaml"
            write_input_file(
                input_path,
                image_lines="""
  - repository: python
    tag: 3.10
""",
            )

            configuration = load_input_configuration(input_path)

        self.assertEqual(
            configuration["images"][0]["tag"],
            "3.10",
        )

    def test_rejects_non_pilot_platform(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_path = Path(temporary_directory) / "images.yaml"
            write_input_file(
                input_path,
                platform_architecture="arm64",
            )

            with self.assertRaises(InvalidInputError):
                load_input_configuration(input_path)

    def test_builds_single_raw_output_filename(self) -> None:
        self.assertEqual(
            raw_output_filename("memcached", "1.6.45"),
            "memcached-1.6.45.json",
        )


class SingleImageResolutionTests(unittest.TestCase):
    @mock.patch("scripts.resolve_image_digest.run_docker_command")
    def test_success_preserves_one_raw_file_and_pinned_reference(
        self,
        run_mock: mock.Mock,
    ) -> None:
        original_bytes = manifest_bytes()
        run_mock.return_value = original_bytes

        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            with contextlib.redirect_stderr(io.StringIO()):
                result, exit_code = resolve_image_digest(
                    "docker.io/library/memcached:1.6.45",
                    "linux",
                    "amd64",
                    project_root,
                )

            raw_path = (
                project_root
                / "results/raw/memcached-1.6.45.json"
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(result["status"], "success")
            self.assertEqual(
                result["platform_manifest_digest"],
                AMD64_DIGEST,
            )
            self.assertEqual(
                result["pinned_reference"],
                f"docker.io/library/memcached@{AMD64_DIGEST}",
            )
            self.assertEqual(
                result["raw_output"],
                "results/raw/memcached-1.6.45.json",
            )
            self.assertEqual(raw_path.read_bytes(), original_bytes)
            self.assertEqual(run_mock.call_count, 1)
            self.assertEqual(
                run_mock.call_args.args[0],
                [
                    "docker",
                    "buildx",
                    "imagetools",
                    "inspect",
                    "docker.io/library/memcached:1.6.45",
                    "--format",
                    "{{json .Manifest}}",
                ],
            )

    @mock.patch("scripts.resolve_image_digest.run_docker_command")
    def test_failure_has_error_and_no_raw_output(
        self,
        run_mock: mock.Mock,
    ) -> None:
        run_mock.side_effect = DockerCommandError(
            "registry unavailable"
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            with contextlib.redirect_stderr(io.StringIO()):
                result, exit_code = resolve_image_digest(
                    "docker.io/library/memcached:1.6.45",
                    "linux",
                    "amd64",
                    project_root,
                )

        self.assertEqual(exit_code, 1)
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["raw_output"])
        self.assertEqual(
            result["error"],
            {
                "type": "docker_command_failed",
                "message": "registry unavailable",
            },
        )


class BatchResolutionTests(unittest.TestCase):
    @mock.patch("scripts.resolve_image_digest.run_docker_command")
    def test_continues_after_failure_and_counts_results(
        self,
        run_mock: mock.Mock,
    ) -> None:
        run_mock.side_effect = [
            DockerCommandError("first image failed"),
            manifest_bytes(
                SECOND_TOP_LEVEL_DIGEST,
                SECOND_AMD64_DIGEST,
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            input_path = project_root / "images.yaml"
            write_input_file(input_path)
            with contextlib.redirect_stderr(io.StringIO()):
                result, exit_code = resolve_images_from_file(
                    input_path,
                    project_root,
                )

            saved_result = json.loads(
                (
                    project_root / "results/image-digests.json"
                ).read_text(encoding="utf-8")
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(result["total_images"], 2)
        self.assertEqual(result["success_count"], 1)
        self.assertEqual(result["failure_count"], 1)
        self.assertEqual(len(result["images"]), 2)
        self.assertEqual(
            result["images"][0]["error"],
            {
                "type": "docker_command_failed",
                "message": "first image failed",
            },
        )
        self.assertEqual(
            result["images"][1]["status"],
            "success",
        )
        self.assertEqual(saved_result, result)
        self.assertEqual(run_mock.call_count, 2)

    @mock.patch("scripts.resolve_image_digest.run_docker_command")
    def test_integrated_result_preserves_order_and_structure(
        self,
        run_mock: mock.Mock,
    ) -> None:
        run_mock.side_effect = [
            manifest_bytes(),
            manifest_bytes(
                SECOND_TOP_LEVEL_DIGEST,
                SECOND_AMD64_DIGEST,
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            input_path = project_root / "images.yaml"
            write_input_file(input_path)
            with contextlib.redirect_stderr(io.StringIO()):
                result, exit_code = resolve_images_from_file(
                    input_path,
                    project_root,
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["selection_date"], "2026-07-24")
        self.assertEqual(
            result["platform"],
            {"os": "linux", "architecture": "amd64"},
        )
        self.assertEqual(result["total_images"], 2)
        self.assertEqual(result["success_count"], 2)
        self.assertEqual(result["failure_count"], 0)
        self.assertEqual(
            [
                image["input_reference"]
                for image in result["images"]
            ],
            [
                "docker.io/library/memcached:1.6.45",
                "docker.io/library/nginx:1.30.4",
            ],
        )

    @mock.patch("scripts.resolve_image_digest.run_docker_command")
    def test_existing_integrated_result_is_not_overwritten(
        self,
        run_mock: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            input_path = project_root / "images.yaml"
            write_input_file(input_path)
            result_path = (
                project_root / "results/image-digests.json"
            )
            result_path.parent.mkdir(parents=True)
            sentinel = '{"status":"existing"}\n'
            result_path.write_text(sentinel, encoding="utf-8")

            with self.assertRaises(OutputExistsError):
                resolve_images_from_file(
                    input_path,
                    project_root,
                )

            self.assertEqual(
                result_path.read_text(encoding="utf-8"),
                sentinel,
            )
            run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
