from __future__ import annotations

import csv
import hashlib
import io
import json
import tempfile
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.test import TestCase

from cpe.cpe23 import CPE23StructuralStatus
from sboms.cpe_profiling import (
    COMPONENT_CPES_FILENAME,
    OUTPUT_FILENAMES,
    SUMMARY_FILENAME,
    build_cpe_profile,
    write_cpe_profile,
)
from sboms.models import Component, DockerImage, SBOMDocument


class CPEProfilingTests(TestCase):
    explicit_cpe = (
        r"cpe:2.3:a:Example:Product\:Server:1.0:*:-:*:*:*:*:*"
    )
    wildcard_cpe = (
        "cpe:2.3:o:example:system:*:*:*:*:*:*:*:*"
    )
    na_cpe = "cpe:2.3:h:example:device:-:*:*:*:*:*:*:*"

    @classmethod
    def setUpTestData(cls) -> None:
        first_image = DockerImage.objects.create(
            repository="docker.io/library/first",
            tag="1.0",
            manifest_digest="sha256:" + ("1" * 64),
            pinned_reference=(
                "docker.io/library/first@sha256:" + ("1" * 64)
            ),
        )
        second_image = DockerImage.objects.create(
            repository="docker.io/library/second",
            tag="2.0",
            manifest_digest="sha256:" + ("2" * 64),
            pinned_reference=(
                "docker.io/library/second@sha256:" + ("2" * 64)
            ),
        )
        first_sbom = SBOMDocument.objects.create(
            docker_image=first_image,
            source_path="pilot/results/sboms/first-1.0.cdx.json",
            file_sha256="3" * 64,
            spec_version="1.7",
            generator_name="syft",
            generator_version="1.49.0",
        )
        second_sbom = SBOMDocument.objects.create(
            docker_image=second_image,
            source_path="pilot/results/sboms/second-2.0.cdx.json",
            file_sha256="4" * 64,
            spec_version="1.7",
            generator_name="syft",
            generator_version="1.49.0",
        )

        fixtures = (
            (
                first_sbom,
                "primary-one",
                "Primary One",
                cls.explicit_cpe,
            ),
            (first_sbom, "without-cpe", "Without CPE", ""),
            (
                first_sbom,
                "invalid-prefix",
                "Invalid Prefix",
                "cpe:2.2:a:example:product:1.0:*:*:*:*:*:*:*",
            ),
            (
                first_sbom,
                "invalid-count",
                "Invalid Count",
                "cpe:2.3:a:example:product:1.0:*",
            ),
            (
                first_sbom,
                "invalid-part",
                "Invalid Part",
                "cpe:2.3:x:example:product:1.0:*:*:*:*:*:*:*",
            ),
            (
                first_sbom,
                "invalid-escape",
                "Invalid Escape",
                "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*\\",
            ),
            (
                second_sbom,
                "primary-two",
                "Primary Two",
                cls.explicit_cpe,
            ),
            (
                second_sbom,
                "wildcard",
                "Wildcard",
                cls.wildcard_cpe,
            ),
            (second_sbom, "na", "NA Version", cls.na_cpe),
        )
        for sbom, bom_ref, name, cpe in fixtures:
            Component.objects.create(
                sbom_document=sbom,
                bom_ref=bom_ref,
                component_type="library",
                name=name,
                version="1.0",
                cpe=cpe,
            )

    def test_only_primary_cpes_are_in_detailed_output(self) -> None:
        profile = build_cpe_profile()

        self.assertEqual(profile.summary["total_components"], 9)
        self.assertEqual(
            profile.summary["components_with_primary_cpe"],
            8,
        )
        self.assertEqual(
            profile.summary["components_without_primary_cpe"],
            1,
        )
        self.assertEqual(len(profile.component_cpes), 8)
        self.assertTrue(
            all(row["raw_cpe"] for row in profile.component_cpes)
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            write_cpe_profile(profile, output_directory)
            with (
                output_directory / COMPONENT_CPES_FILENAME
            ).open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 8)

    def test_image_summary_counts(self) -> None:
        profile = build_cpe_profile()
        rows = {
            row["repository"]: row for row in profile.image_summary
        }

        self.assertEqual(
            rows["docker.io/library/first"]["total_components"],
            6,
        )
        self.assertEqual(
            rows["docker.io/library/first"][
                "components_with_primary_cpe"
            ],
            5,
        )
        self.assertEqual(
            rows["docker.io/library/first"][
                "components_without_primary_cpe"
            ],
            1,
        )
        self.assertEqual(
            rows["docker.io/library/second"]["total_components"],
            3,
        )
        self.assertEqual(
            rows["docker.io/library/second"][
                "components_with_primary_cpe"
            ],
            3,
        )

    def test_structural_status_part_and_version_counts(self) -> None:
        summary = build_cpe_profile().summary
        status_counts = summary["status_counts"]

        self.assertEqual(
            status_counts["STRUCTURALLY_VALID"]["component_count"],
            4,
        )
        for status in (
            CPE23StructuralStatus.INVALID_PREFIX,
            CPE23StructuralStatus.INVALID_FIELD_COUNT,
            CPE23StructuralStatus.INVALID_ESCAPE,
            CPE23StructuralStatus.INVALID_PART,
        ):
            self.assertEqual(
                status_counts[status.value]["component_count"],
                1,
            )
        self.assertEqual(
            summary["part_counts"]["a"]["component_count"],
            2,
        )
        self.assertEqual(
            summary["part_counts"]["o"]["component_count"],
            1,
        )
        self.assertEqual(
            summary["part_counts"]["h"]["component_count"],
            1,
        )
        self.assertEqual(
            summary["version_category_counts"]["wildcard"][
                "component_count"
            ],
            1,
        )
        self.assertEqual(
            summary["version_category_counts"]["NA"][
                "component_count"
            ],
            1,
        )
        self.assertEqual(
            summary["version_category_counts"]["explicit"][
                "component_count"
            ],
            2,
        )

    def test_reused_cpe_counts_distinct_relationships(self) -> None:
        profile = build_cpe_profile()
        row = next(
            row
            for row in profile.cpe_usage
            if row["raw_cpe"] == self.explicit_cpe
        )

        self.assertEqual(row["component_count"], 2)
        self.assertEqual(row["image_count"], 2)
        self.assertEqual(row["sbom_count"], 2)
        self.assertEqual(row["component_name_count"], 2)
        self.assertEqual(profile.summary["reused_primary_cpes"], 1)

    def test_raw_cpe_and_escaped_fields_are_preserved(self) -> None:
        profile = build_cpe_profile()
        row = next(
            row
            for row in profile.component_cpes
            if row["component_name"] == "Primary One"
        )

        self.assertEqual(row["raw_cpe"], self.explicit_cpe)
        self.assertEqual(row["vendor_raw"], "Example")
        self.assertEqual(
            row["product_raw"],
            r"Product\:Server",
        )

    def test_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first_directory = root / "first"
            second_directory = root / "second"
            write_cpe_profile(
                build_cpe_profile(),
                first_directory,
            )
            write_cpe_profile(
                build_cpe_profile(),
                second_directory,
            )

            for filename in OUTPUT_FILENAMES:
                with self.subTest(filename=filename):
                    first_hash = hashlib.sha256(
                        (first_directory / filename).read_bytes()
                    ).hexdigest()
                    second_hash = hashlib.sha256(
                        (second_directory / filename).read_bytes()
                    ).hexdigest()
                    self.assertEqual(first_hash, second_hash)

    def test_stdout_only_creates_no_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "profile"
            standard_output = io.StringIO()

            call_command(
                "profile_cpes",
                "--stdout-only",
                "--output-dir",
                str(output_directory),
                stdout=standard_output,
            )

            self.assertFalse(output_directory.exists())
            summary = json.loads(standard_output.getvalue())
            self.assertEqual(summary["schema_version"], 1)

    def test_relative_output_path_uses_repository_root(self) -> None:
        repository_root = Path(settings.BASE_DIR).parent
        with tempfile.TemporaryDirectory(
            dir=repository_root
        ) as temporary_directory:
            output_directory = Path(temporary_directory) / "profile"
            relative_output = output_directory.relative_to(
                repository_root
            )

            call_command(
                "profile_cpes",
                "--output-dir",
                str(relative_output),
                stdout=io.StringIO(),
            )

            self.assertTrue(
                (output_directory / SUMMARY_FILENAME).is_file()
            )

    def test_profile_build_is_database_read_only(self) -> None:
        counts_before = (
            DockerImage.objects.count(),
            SBOMDocument.objects.count(),
            Component.objects.count(),
        )

        build_cpe_profile()

        counts_after = (
            DockerImage.objects.count(),
            SBOMDocument.objects.count(),
            Component.objects.count(),
        )
        self.assertEqual(counts_after, counts_before)
