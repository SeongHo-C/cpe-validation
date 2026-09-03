from __future__ import annotations

import csv
import io
import json
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from cpe_dictionary.models import (
    CpeDictionarySnapshot,
    CpeName,
)
from sboms.cpe_exact_match_analysis import (
    COMPONENT_MATCHES_FILENAME,
    OUTPUT_FILENAMES,
    SUMMARY_FILENAME,
    UNIQUE_CPE_MATCHES_FILENAME,
    CPEExactMatchAnalysis,
    CPEExactMatchAnalysisError,
    build_cpe_exact_match_analysis,
    validate_cpe_exact_match_analysis,
    write_cpe_exact_match_analysis,
)
from sboms.models import Component, DockerImage, SBOMDocument


ACTIVE_CPE = "cpe:2.3:a:example:active:1.0:*:*:*:*:*:*:*"
DEPRECATED_CPE = (
    "cpe:2.3:a:example:deprecated:1.0:*:*:*:*:*:*:*"
)
MISSING_CPE = (
    "cpe:2.3:a:example:missing:1.0:*:*:*:*:*:*:*"
)


class CPEExactMatchAnalysisTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.snapshot = CpeDictionarySnapshot.objects.create(
            snapshot_id="20260725T035002Z",
            status=CpeDictionarySnapshot.Status.COMPLETE,
            feed_last_modified=datetime(
                2026,
                7,
                25,
                3,
                50,
                2,
                tzinfo=timezone.utc,
            ),
            manifest_sha256="a" * 64,
            archive_sha256="b" * 64,
            content_sha256="c" * 64,
            member_count=1,
            expected_record_count=2,
            record_count=2,
            active_count=1,
            deprecated_count=1,
            completed_at=datetime(
                2026,
                7,
                27,
                tzinfo=timezone.utc,
            ),
        )
        for number, raw_cpe, deprecated in (
            (1, ACTIVE_CPE, False),
            (2, DEPRECATED_CPE, True),
        ):
            CpeName.objects.create(
                snapshot=cls.snapshot,
                cpe_name_id=UUID(int=number),
                cpe_name=raw_cpe,
                deprecated=deprecated,
                created_at_nvd=datetime(
                    2020,
                    1,
                    1,
                    tzinfo=timezone.utc,
                ),
                last_modified_at_nvd=datetime(
                    2026,
                    1,
                    1,
                    tzinfo=timezone.utc,
                ),
                part="a",
                vendor="example",
                product="product",
                version="1.0",
                update="*",
                edition="*",
                language="*",
                sw_edition="*",
                target_sw="*",
                target_hw="*",
                other="*",
            )

        image = DockerImage.objects.create(
            repository="docker.io/library/example",
            tag="1.0",
            manifest_digest="sha256:" + ("1" * 64),
            pinned_reference=(
                "docker.io/library/example@sha256:" + ("1" * 64)
            ),
        )
        sbom = SBOMDocument.objects.create(
            docker_image=image,
            source_path="fixtures/sboms/example-1.0.cdx.json",
            file_sha256="2" * 64,
            spec_version="1.7",
            generator_name="syft",
            generator_version="1.49.0",
        )
        for index, (name, raw_cpe) in enumerate(
            (
                ("Active One", ACTIVE_CPE),
                ("Active Two", ACTIVE_CPE),
                ("Deprecated", DEPRECATED_CPE),
                ("Missing", MISSING_CPE),
                ("No CPE", ""),
            ),
            start=1,
        ):
            Component.objects.create(
                sbom_document=sbom,
                bom_ref=f"component-{index}",
                component_type="library",
                name=name,
                version="1.0",
                cpe=raw_cpe,
            )

    @staticmethod
    def model_counts() -> tuple[int, ...]:
        return (
            DockerImage.objects.count(),
            SBOMDocument.objects.count(),
            Component.objects.count(),
            CpeDictionarySnapshot.objects.count(),
            CpeName.objects.count(),
        )

    def test_builds_unique_and_component_results(self) -> None:
        analysis = build_cpe_exact_match_analysis(self.snapshot)
        summary = analysis.summary

        self.assertEqual(summary["schema_version"], 1)
        self.assertEqual(
            summary["snapshot_id"],
            self.snapshot.snapshot_id,
        )
        self.assertEqual(
            summary["snapshot_manifest_sha256"],
            "a" * 64,
        )
        self.assertEqual(summary["total_components"], 5)
        self.assertEqual(summary["components_with_primary_cpe"], 4)
        self.assertEqual(
            summary["components_without_primary_cpe"],
            1,
        )
        self.assertEqual(summary["unique_primary_cpes"], 3)
        self.assertEqual(
            summary["unique_status_counts"],
            {
                "OFFICIAL_ACTIVE": 1,
                "OFFICIAL_DEPRECATED": 1,
                "NOT_IN_DICTIONARY": 1,
                "NOT_PRESENT": 0,
            },
        )
        self.assertEqual(
            summary["component_status_counts"],
            {
                "OFFICIAL_ACTIVE": 2,
                "OFFICIAL_DEPRECATED": 1,
                "NOT_IN_DICTIONARY": 1,
                "NOT_PRESENT": 1,
            },
        )
        self.assertEqual(len(analysis.unique_cpe_matches), 3)
        self.assertEqual(len(analysis.component_matches), 5)

    def test_build_uses_fixed_query_count(self) -> None:
        with self.assertNumQueries(2):
            build_cpe_exact_match_analysis(self.snapshot)

    def test_generated_csvs_include_provenance(self) -> None:
        analysis = build_cpe_exact_match_analysis(self.snapshot)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            paths = write_cpe_exact_match_analysis(
                analysis,
                output_directory,
            )
            self.assertEqual(len(paths), 3)
            with (
                output_directory / UNIQUE_CPE_MATCHES_FILENAME
            ).open(encoding="utf-8", newline="") as stream:
                unique_rows = list(csv.DictReader(stream))
            with (
                output_directory / COMPONENT_MATCHES_FILENAME
            ).open(encoding="utf-8", newline="") as stream:
                component_rows = list(csv.DictReader(stream))

        self.assertEqual(len(unique_rows), 3)
        self.assertEqual(len(component_rows), 5)
        self.assertTrue(
            all(
                row["snapshot_id"] == self.snapshot.snapshot_id
                for row in unique_rows + component_rows
            )
        )
        self.assertTrue(
            all(row["image_reference"] for row in component_rows)
        )

    def test_refuses_overwrite_unless_requested(self) -> None:
        analysis = build_cpe_exact_match_analysis(self.snapshot)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            write_cpe_exact_match_analysis(
                analysis,
                output_directory,
            )
            with self.assertRaisesRegex(
                CPEExactMatchAnalysisError,
                "Refusing to overwrite",
            ):
                write_cpe_exact_match_analysis(
                    analysis,
                    output_directory,
                )
            write_cpe_exact_match_analysis(
                analysis,
                output_directory,
                overwrite=True,
            )

    def test_invariant_mismatch_fails(self) -> None:
        analysis = build_cpe_exact_match_analysis(self.snapshot)
        invalid_summary = deepcopy(analysis.summary)
        invalid_summary["total_components"] += 1
        invalid_analysis = CPEExactMatchAnalysis(
            summary=invalid_summary,
            unique_cpe_matches=analysis.unique_cpe_matches,
            component_matches=analysis.component_matches,
        )

        with self.assertRaises(CPEExactMatchAnalysisError):
            validate_cpe_exact_match_analysis(invalid_analysis)

    def test_build_is_database_read_only(self) -> None:
        counts_before = self.model_counts()

        build_cpe_exact_match_analysis(self.snapshot)

        self.assertEqual(self.model_counts(), counts_before)

    def test_management_command_outputs_results_and_is_read_only(
        self,
    ) -> None:
        counts_before = self.model_counts()
        stdout = io.StringIO()

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "results"
            call_command(
                "evaluate_cpe_exact_matches",
                "--snapshot-id",
                self.snapshot.snapshot_id,
                "--output-dir",
                str(output_directory),
                stdout=stdout,
            )
            for filename in OUTPUT_FILENAMES:
                self.assertTrue(
                    (output_directory / filename).is_file()
                )
            summary = json.loads(
                (
                    output_directory / SUMMARY_FILENAME
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(summary["total_components"], 5)
            with self.assertRaises(CommandError):
                call_command(
                    "evaluate_cpe_exact_matches",
                    "--snapshot-id",
                    self.snapshot.snapshot_id,
                    "--output-dir",
                    str(output_directory),
                    stdout=io.StringIO(),
                )
            call_command(
                "evaluate_cpe_exact_matches",
                "--snapshot-id",
                self.snapshot.snapshot_id,
                "--output-dir",
                str(output_directory),
                "--overwrite",
                stdout=io.StringIO(),
            )

        self.assertEqual(self.model_counts(), counts_before)

    def test_management_command_rejects_invariant_mismatch(
        self,
    ) -> None:
        analysis = build_cpe_exact_match_analysis(self.snapshot)
        invalid_summary = deepcopy(analysis.summary)
        invalid_summary["unique_primary_cpes"] += 1
        invalid_analysis = CPEExactMatchAnalysis(
            summary=invalid_summary,
            unique_cpe_matches=analysis.unique_cpe_matches,
            component_matches=analysis.component_matches,
        )

        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch(
                "sboms.management.commands."
                "evaluate_cpe_exact_matches."
                "build_cpe_exact_match_analysis",
                return_value=invalid_analysis,
            ),
            self.assertRaises(CommandError),
        ):
            call_command(
                "evaluate_cpe_exact_matches",
                "--snapshot-id",
                self.snapshot.snapshot_id,
                "--output-dir",
                temporary_directory,
                stdout=io.StringIO(),
            )
