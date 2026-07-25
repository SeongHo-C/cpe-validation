from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.test import TestCase

from sboms.importers import ImporterError, import_sboms
from sboms.models import Component, DockerImage, SBOMDocument


class SbomImporterTests(TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.repository_root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def build_document(
        self,
        index: int,
        *,
        tools_as_list: bool = False,
    ) -> dict[str, object]:
        tools: object = [
            {
                "name": "syft",
                "version": "1.49.0",
            }
        ]
        if not tools_as_list:
            tools = {"components": tools}
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": f"urn:uuid:fixture-{index}",
            "version": 1,
            "metadata": {
                "timestamp": "2026-07-25T12:00:00+00:00",
                "tools": tools,
            },
            "components": [
                {
                    "bom-ref": f"primary-{index}",
                    "type": "library",
                    "group": "example.group",
                    "name": f"package-{index}",
                    "version": "1.0",
                    "publisher": "Example Publisher",
                    "purl": f"pkg:generic/package-{index}@1.0",
                    "cpe": (
                        "cpe:2.3:a:example:package:"
                        "1.0:*:*:*:*:*:*:*"
                    ),
                    "properties": [
                        {
                            "name": "fixture:source",
                            "value": "unit-test",
                        }
                    ],
                },
                {
                    "bom-ref": f"candidate-{index}",
                    "type": "library",
                    "name": f"candidate-{index}",
                    "properties": [
                        {
                            "name": "syft:cpe23",
                            "value": (
                                "cpe:2.3:a:example:package:"
                                "*:*:*:*:*:*:*:*"
                            ),
                        }
                    ],
                },
            ],
        }

    def write_fixture(
        self,
        documents: list[dict[str, object]],
        *,
        repository_root: Path | None = None,
        omitted_files: set[int] | None = None,
    ) -> tuple[Path, Path]:
        root = repository_root or self.repository_root
        sbom_directory = root / "pilot/results/sboms"
        sbom_directory.mkdir(parents=True, exist_ok=True)
        omitted = omitted_files or set()
        images = []
        for index, document in enumerate(documents):
            repository = f"docker.io/library/example{index}"
            tag = f"1.{index}"
            manifest_digest = f"sha256:{index + 1:064x}"
            filename = f"example{index}-{tag}.cdx.json"
            images.append(
                {
                    "status": "success",
                    "normalized_repository": repository,
                    "input_tag": tag,
                    "platform_manifest_digest": manifest_digest,
                    "pinned_reference": (
                        f"{repository}@{manifest_digest}"
                    ),
                }
            )
            if index not in omitted:
                (sbom_directory / filename).write_text(
                    json.dumps(document),
                    encoding="utf-8",
                )

        digest_file = root / "pilot/results/image-digests.json"
        digest_file.parent.mkdir(parents=True, exist_ok=True)
        digest_file.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "platform": {
                        "os": "linux",
                        "architecture": "amd64",
                    },
                    "total_images": len(images),
                    "success_count": len(images),
                    "failure_count": 0,
                    "images": images,
                }
            ),
            encoding="utf-8",
        )
        return sbom_directory, digest_file

    def run_import(
        self,
        documents: list[dict[str, object]],
        *,
        dry_run: bool = False,
        omitted_files: set[int] | None = None,
    ):
        sbom_directory, digest_file = self.write_fixture(
            documents,
            omitted_files=omitted_files,
        )
        return import_sboms(
            sbom_directory=sbom_directory,
            digest_file=digest_file,
            repository_root=self.repository_root,
            dry_run=dry_run,
            expected_image_count=len(documents),
        )

    def test_first_import_creates_image_document_and_components(
        self,
    ) -> None:
        result = self.run_import([self.build_document(0)])

        self.assertEqual(DockerImage.objects.count(), 1)
        self.assertEqual(SBOMDocument.objects.count(), 1)
        self.assertEqual(Component.objects.count(), 2)
        self.assertEqual(result.images_created, 1)
        self.assertEqual(result.sboms_created, 1)
        self.assertEqual(result.components_created, 2)

    def test_reimport_is_idempotent(self) -> None:
        documents = [self.build_document(0)]
        self.run_import(documents)
        counts_before = (
            DockerImage.objects.count(),
            SBOMDocument.objects.count(),
            Component.objects.count(),
        )

        second = self.run_import(documents)

        self.assertEqual(
            (
                DockerImage.objects.count(),
                SBOMDocument.objects.count(),
                Component.objects.count(),
            ),
            counts_before,
        )
        self.assertEqual(second.images_existing, 1)
        self.assertEqual(second.sboms_created, 0)
        self.assertEqual(second.sboms_skipped, 1)
        self.assertEqual(second.components_created, 0)

    def test_component_fields_are_mapped_without_normalization(
        self,
    ) -> None:
        self.run_import([self.build_document(0)])

        component = Component.objects.get(bom_ref="primary-0")
        self.assertEqual(component.component_type, "library")
        self.assertEqual(component.group, "example.group")
        self.assertEqual(component.name, "package-0")
        self.assertEqual(component.version, "1.0")
        self.assertEqual(component.publisher, "Example Publisher")
        self.assertEqual(component.purl, "pkg:generic/package-0@1.0")
        self.assertEqual(
            component.cpe,
            "cpe:2.3:a:example:package:1.0:*:*:*:*:*:*:*",
        )
        self.assertEqual(
            component.properties,
            [{"name": "fixture:source", "value": "unit-test"}],
        )

    def test_syft_cpe23_property_is_preserved_but_not_promoted(
        self,
    ) -> None:
        self.run_import([self.build_document(0)])

        component = Component.objects.get(bom_ref="candidate-0")
        self.assertEqual(component.cpe, "")
        self.assertEqual(
            component.properties,
            [
                {
                    "name": "syft:cpe23",
                    "value": (
                        "cpe:2.3:a:example:package:"
                        "*:*:*:*:*:*:*:*"
                    ),
                }
            ],
        )

    def test_duplicate_bom_ref_rolls_back_everything(self) -> None:
        document = self.build_document(0)
        document["components"][1]["bom-ref"] = "primary-0"  # type: ignore[index]

        with self.assertRaisesRegex(
            ImporterError,
            r"example0-1\.0\.cdx\.json: duplicate bom-ref: primary-0",
        ):
            self.run_import([document])

        self.assertEqual(DockerImage.objects.count(), 0)
        self.assertEqual(SBOMDocument.objects.count(), 0)
        self.assertEqual(Component.objects.count(), 0)

    def test_wrong_cyclonedx_format_is_rejected(self) -> None:
        document = self.build_document(0)
        document["bomFormat"] = "SPDX"

        with self.assertRaisesRegex(
            ImporterError,
            "bomFormat must be 'CycloneDX'",
        ):
            self.run_import([document])

    def test_missing_expected_sbom_file_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            ImporterError,
            r"missing expected SBOM files: example0-1\.0\.cdx\.json",
        ):
            self.run_import(
                [self.build_document(0)],
                omitted_files={0},
            )

    def test_failure_in_second_file_rolls_back_first_file(self) -> None:
        first_document = self.build_document(0)
        second_document = self.build_document(1)
        second_document["bomFormat"] = "SPDX"

        with self.assertRaises(ImporterError):
            self.run_import([first_document, second_document])

        self.assertEqual(DockerImage.objects.count(), 0)
        self.assertEqual(SBOMDocument.objects.count(), 0)
        self.assertEqual(Component.objects.count(), 0)

    def test_dry_run_parses_but_rolls_back(self) -> None:
        result = self.run_import(
            [self.build_document(0)],
            dry_run=True,
        )

        self.assertEqual(result.files_processed, 1)
        self.assertEqual(result.components_created, 2)
        self.assertEqual(DockerImage.objects.count(), 0)
        self.assertEqual(SBOMDocument.objects.count(), 0)
        self.assertEqual(Component.objects.count(), 0)

    def test_existing_docker_image_mismatch_is_not_overwritten(
        self,
    ) -> None:
        manifest_digest = f"sha256:{1:064x}"
        existing = DockerImage.objects.create(
            repository="docker.io/library/different",
            tag="9.9",
            manifest_digest=manifest_digest,
            pinned_reference=(
                f"docker.io/library/different@{manifest_digest}"
            ),
        )

        with self.assertRaisesRegex(
            ImporterError,
            "existing DockerImage metadata mismatch",
        ):
            self.run_import([self.build_document(0)])

        existing.refresh_from_db()
        self.assertEqual(
            existing.repository,
            "docker.io/library/different",
        )
        self.assertEqual(SBOMDocument.objects.count(), 0)
        self.assertEqual(Component.objects.count(), 0)

    def test_tools_list_layout_is_supported(self) -> None:
        document = self.build_document(0, tools_as_list=True)
        document["metadata"]["tools"][0]["name"] = "SyFt"  # type: ignore[index]

        self.run_import([document])

        sbom_document = SBOMDocument.objects.get()
        self.assertEqual(sbom_document.generator_name, "SyFt")
        self.assertEqual(sbom_document.generator_version, "1.49.0")

    def test_nested_components_are_imported_once(self) -> None:
        document = self.build_document(0)
        components = document["components"]
        nested = components.pop()  # type: ignore[union-attr]
        components[0]["components"] = [nested]  # type: ignore[index]

        result = self.run_import([document])

        self.assertEqual(result.components_created, 2)
        self.assertEqual(Component.objects.count(), 2)

    def test_management_command_dry_run_uses_ten_file_fixture(
        self,
    ) -> None:
        actual_repository_root = Path(settings.BASE_DIR).parent
        with tempfile.TemporaryDirectory(
            dir=actual_repository_root
        ) as temporary_directory:
            command_root = Path(temporary_directory)
            documents = [
                self.build_document(index) for index in range(10)
            ]
            sbom_directory, digest_file = self.write_fixture(
                documents,
                repository_root=command_root,
            )
            standard_output = io.StringIO()

            call_command(
                "import_sboms",
                "--sbom-dir",
                str(sbom_directory),
                "--digest-file",
                str(digest_file),
                "--dry-run",
                stdout=standard_output,
            )

        output = standard_output.getvalue()
        self.assertIn("Files processed: 10", output)
        self.assertIn("Dry run completed", output)
        self.assertIn("No database changes were committed", output)
        self.assertEqual(DockerImage.objects.count(), 0)
        self.assertEqual(SBOMDocument.objects.count(), 0)
        self.assertEqual(Component.objects.count(), 0)


if __name__ == "__main__":
    unittest.main()
