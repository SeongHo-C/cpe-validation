from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from cpe.cpe23 import parse_cpe23_formatted_string
from cpe_dictionary.models import (
    CpeDictionarySnapshot,
    CpeName,
)
from sboms.cpe_mismatch_profiling import (
    FIELD_VALUE_COUNTS_FILENAME,
    OUTPUT_FILENAMES,
    SUMMARY_FILENAME,
    UNIQUE_CPE_MISMATCH_PROFILES_FILENAME,
    CPEMismatchProfileAnalysis,
    CPEMismatchProfileStatus,
    CPEMismatchProfilingError,
    build_cpe_mismatch_profile_analysis,
    validate_cpe_mismatch_profile_analysis,
    write_cpe_mismatch_profile_analysis,
)
from sboms.exact_matching import (
    CPEExactMatchResult,
    CPEExactMatchStatus,
)
from sboms.models import Component, DockerImage, SBOMDocument


def make_cpe(
    *,
    part: str = "a",
    vendor: str = "vendor",
    product: str = "product",
    version: str = "1.0",
    update: str = "*",
) -> str:
    return (
        f"cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:"
        "*:*:*:*:*:*"
    )


class CPEMismatchProfilingTests(TestCase):
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
            expected_record_count=0,
            record_count=0,
            active_count=0,
            deprecated_count=0,
            completed_at=datetime(
                2026,
                7,
                27,
                tzinfo=timezone.utc,
            ),
        )
        cls.image = DockerImage.objects.create(
            repository="docker.io/library/example",
            tag="1.0",
            manifest_digest="sha256:" + ("1" * 64),
            pinned_reference=(
                "docker.io/library/example@sha256:" + ("1" * 64)
            ),
        )
        cls.sbom = SBOMDocument.objects.create(
            docker_image=cls.image,
            source_path="pilot/results/sboms/example-1.0.cdx.json",
            file_sha256="2" * 64,
            spec_version="1.7",
            generator_name="syft",
            generator_version="1.49.0",
        )

    def create_dictionary_record(
        self,
        raw_cpe: str,
        *,
        deprecated: bool = False,
        deprecated_by: list[str] | None = None,
    ) -> CpeName:
        parse_result = parse_cpe23_formatted_string(raw_cpe)
        self.assertTrue(parse_result.is_structurally_valid)
        return CpeName.objects.create(
            snapshot=self.snapshot,
            cpe_name_id=uuid4(),
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
            deprecated_by=deprecated_by or [],
            **parse_result.fields,
        )

    def create_component(
        self,
        raw_cpe: str,
        *,
        name: str | None = None,
        bom_ref: str | None = None,
    ) -> Component:
        identifier = Component.objects.count() + 1
        return Component.objects.create(
            sbom_document=self.sbom,
            bom_ref=bom_ref or f"component-{identifier}",
            component_type="library",
            name=name or f"Component {identifier}",
            version="1.0",
            cpe=raw_cpe,
        )

    @staticmethod
    def rows_by_cpe(
        analysis: CPEMismatchProfileAnalysis,
    ) -> dict[str, dict]:
        return {
            row["primary_cpe"]: row
            for row in analysis.unique_cpe_mismatch_profiles
        }

    @staticmethod
    def model_counts() -> tuple[int, ...]:
        return (
            DockerImage.objects.count(),
            SBOMDocument.objects.count(),
            Component.objects.count(),
            CpeDictionarySnapshot.objects.count(),
            CpeName.objects.count(),
        )

    def test_selects_only_unique_raw_mismatches(self) -> None:
        active = make_cpe(product="active")
        deprecated = make_cpe(product="deprecated")
        mismatch = make_cpe(product="missing")
        self.create_dictionary_record(active)
        self.create_dictionary_record(
            deprecated,
            deprecated=True,
        )
        self.create_component(active)
        self.create_component(deprecated)
        self.create_component(mismatch)
        self.create_component(mismatch)
        self.create_component("")

        analysis = build_cpe_mismatch_profile_analysis(
            self.snapshot
        )

        self.assertEqual(
            analysis.summary["unique_official_active"],
            1,
        )
        self.assertEqual(
            analysis.summary["unique_official_deprecated"],
            1,
        )
        self.assertEqual(
            analysis.summary["unique_not_in_dictionary"],
            1,
        )
        self.assertEqual(
            analysis.summary[
                "component_weighted_not_in_dictionary"
            ],
            2,
        )
        self.assertEqual(
            len(analysis.unique_cpe_mismatch_profiles),
            1,
        )
        self.assertEqual(
            analysis.unique_cpe_mismatch_profiles[0][
                "component_count"
            ],
            2,
        )
        self.assertEqual(analysis.summary["total_components"], 5)
        self.assertEqual(
            analysis.summary["components_with_primary_cpe"],
            4,
        )

    def test_classifies_all_profiles_with_exclusive_priority(
        self,
    ) -> None:
        four_input = make_cpe(
            product="four",
            update="input",
        )
        self.create_dictionary_record(
            make_cpe(product="four", update="active")
        )
        self.create_dictionary_record(
            make_cpe(product="four", update="deprecated"),
            deprecated=True,
            deprecated_by=["replacement"],
        )

        three_input = make_cpe(
            product="three",
            version="9.0",
        )
        self.create_dictionary_record(
            make_cpe(product="three", version="1.0")
        )
        self.create_dictionary_record(
            make_cpe(product="three", version="2.0"),
            deprecated=True,
        )

        two_input = make_cpe(
            vendor="syft",
            product="two",
        )
        self.create_dictionary_record(
            make_cpe(vendor="official", product="two")
        )
        none_input = make_cpe(product="none")
        unparsable_input = "not-a-cpe"
        for raw_cpe in (
            four_input,
            three_input,
            two_input,
            none_input,
            unparsable_input,
        ):
            self.create_component(raw_cpe)

        analysis = build_cpe_mismatch_profile_analysis(
            self.snapshot
        )
        rows = self.rows_by_cpe(analysis)

        self.assertEqual(
            rows[four_input]["profile_status"],
            "SAME_PART_VENDOR_PRODUCT_VERSION",
        )
        self.assertEqual(
            rows[four_input][
                "same_part_vendor_product_version_count"
            ],
            2,
        )
        self.assertEqual(
            rows[four_input][
                "same_part_vendor_product_version_active_count"
            ],
            1,
        )
        self.assertEqual(
            rows[four_input][
                "same_part_vendor_product_version_deprecated_count"
            ],
            1,
        )
        self.assertEqual(
            rows[three_input]["profile_status"],
            "SAME_PART_VENDOR_PRODUCT",
        )
        self.assertEqual(
            rows[three_input][
                "same_part_vendor_product_version_count"
            ],
            0,
        )
        self.assertEqual(
            rows[three_input]["same_part_vendor_product_count"],
            2,
        )
        self.assertEqual(
            rows[two_input]["profile_status"],
            "SAME_PART_PRODUCT",
        )
        self.assertEqual(
            rows[none_input]["profile_status"],
            "NO_STRUCTURED_MATCH",
        )
        self.assertEqual(
            rows[unparsable_input]["profile_status"],
            "UNPARSABLE",
        )
        self.assertNotEqual(
            rows[unparsable_input]["structural_error_message"],
            "",
        )
        self.assertEqual(
            sum(analysis.summary["profile_status_counts"].values()),
            5,
        )

    def test_structured_comparison_is_exact_and_not_normalized(
        self,
    ) -> None:
        scenarios = {
            make_cpe(
                vendor="Vendor",
                product="case-product",
            ): "SAME_PART_PRODUCT",
            make_cpe(
                vendor=" vendor",
                product="space-product",
            ): "SAME_PART_PRODUCT",
            make_cpe(
                vendor="red_hat",
                product="alias-product",
            ): "SAME_PART_PRODUCT",
            make_cpe(
                product="product_alias",
            ): "NO_STRUCTURED_MATCH",
            make_cpe(
                product="version-product",
                version="1.0-r1",
            ): "SAME_PART_VENDOR_PRODUCT",
            make_cpe(
                part="o",
                product="part-product",
            ): "NO_STRUCTURED_MATCH",
        }
        self.create_dictionary_record(
            make_cpe(vendor="vendor", product="case-product")
        )
        self.create_dictionary_record(
            make_cpe(vendor="vendor", product="space-product")
        )
        self.create_dictionary_record(
            make_cpe(vendor="redhat", product="alias-product")
        )
        self.create_dictionary_record(make_cpe(product="product"))
        self.create_dictionary_record(
            make_cpe(product="version-product", version="1.0")
        )
        self.create_dictionary_record(
            make_cpe(part="a", product="part-product")
        )
        for raw_cpe in scenarios:
            self.create_component(raw_cpe)

        rows = self.rows_by_cpe(
            build_cpe_mismatch_profile_analysis(self.snapshot)
        )

        for raw_cpe, expected_status in scenarios.items():
            with self.subTest(raw_cpe=raw_cpe):
                self.assertEqual(
                    rows[raw_cpe]["profile_status"],
                    expected_status,
                )

    def test_raw_exact_match_inside_profile_population_fails(
        self,
    ) -> None:
        raw_cpe = make_cpe(product="inconsistent")
        self.create_dictionary_record(raw_cpe)
        self.create_component(raw_cpe)
        inconsistent_result = CPEExactMatchResult(
            status=CPEExactMatchStatus.NOT_IN_DICTIONARY,
            input_cpe=raw_cpe,
            snapshot_id=self.snapshot.snapshot_id,
            matched_cpe_name_id=None,
            matched_cpe_name=None,
            deprecated=None,
        )

        with (
            patch(
                "sboms.cpe_mismatch_profiling.match_cpes",
                return_value={raw_cpe: inconsistent_result},
            ),
            self.assertRaisesRegex(
                CPEMismatchProfilingError,
                "raw exact match",
            ),
        ):
            build_cpe_mismatch_profile_analysis(self.snapshot)

    def test_reuses_structured_keys_and_has_fixed_query_count(
        self,
    ) -> None:
        components = []
        for index in range(1001):
            components.append(
                Component(
                    sbom_document=self.sbom,
                    bom_ref=f"bulk-{index}",
                    component_type="library",
                    name=f"Bulk {index}",
                    version="1.0",
                    cpe=make_cpe(product=f"bulk-{index}"),
                )
            )
        Component.objects.bulk_create(components)

        with CaptureQueriesContext(connection) as captured:
            analysis = build_cpe_mismatch_profile_analysis(
                self.snapshot
            )

        self.assertEqual(len(captured), 4)
        self.assertEqual(
            analysis.summary["dictionary_query_count"],
            2,
        )
        self.assertEqual(
            analysis.summary[
                "unique_part_vendor_product_version_keys"
            ],
            1001,
        )
        dictionary_queries = [
            query["sql"]
            for query in captured.captured_queries
            if "cpe_dictionary_cpename" in query["sql"]
        ]
        self.assertEqual(len(dictionary_queries), 2)
        for sql in dictionary_queries:
            self.assertNotIn('"titles"', sql)
            self.assertNotIn('"references"', sql)

    def test_multiple_cpes_with_one_key_share_one_aggregation(
        self,
    ) -> None:
        first = make_cpe(product="shared", update="one")
        second = make_cpe(product="shared", update="two")
        self.create_component(first)
        self.create_component(second)

        analysis = build_cpe_mismatch_profile_analysis(
            self.snapshot
        )

        self.assertEqual(
            analysis.summary[
                "unique_part_vendor_product_version_keys"
            ],
            1,
        )
        self.assertEqual(
            analysis.summary["unique_part_vendor_product_keys"],
            1,
        )
        self.assertEqual(
            analysis.summary["unique_part_product_keys"],
            1,
        )
        self.assertEqual(
            analysis.summary["dictionary_query_count"],
            2,
        )

    def test_field_value_counts_include_unique_and_weighted_counts(
        self,
    ) -> None:
        first = make_cpe(vendor="one", product="shared")
        second = make_cpe(vendor="two", product="shared")
        self.create_component(first)
        self.create_component(first)
        self.create_component(second)
        self.create_component("invalid")

        analysis = build_cpe_mismatch_profile_analysis(
            self.snapshot
        )
        counts = analysis.field_value_counts

        self.assertEqual(
            counts["unique_cpe_counts"]["product"]["shared"],
            2,
        )
        self.assertEqual(
            counts["component_weighted_counts"]["product"][
                "shared"
            ],
            3,
        )
        self.assertEqual(
            counts["profile_status_by_part"][
                "<unparsable>"
            ]["UNPARSABLE"],
            1,
        )
        self.assertFalse(counts["field_value_counts_truncated"])

    def test_outputs_are_deterministic_and_atomically_replaced(
        self,
    ) -> None:
        high_usage = make_cpe(product="zeta")
        low_usage = make_cpe(product="alpha")
        self.create_component(high_usage)
        self.create_component(high_usage)
        self.create_component(low_usage)
        analysis = build_cpe_mismatch_profile_analysis(
            self.snapshot
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            with patch(
                "sboms.cpe_mismatch_profiling.os.replace",
                wraps=os.replace,
            ) as atomic_replace:
                paths = write_cpe_mismatch_profile_analysis(
                    analysis,
                    output_directory,
                )
            self.assertEqual(atomic_replace.call_count, 3)
            self.assertEqual(
                tuple(path.name for path in paths),
                OUTPUT_FILENAMES,
            )
            summary = json.loads(
                (output_directory / SUMMARY_FILENAME).read_text(
                    encoding="utf-8"
                )
            )
            field_counts = json.loads(
                (
                    output_directory / FIELD_VALUE_COUNTS_FILENAME
                ).read_text(encoding="utf-8")
            )
            with (
                output_directory
                / UNIQUE_CPE_MISMATCH_PROFILES_FILENAME
            ).open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))

        self.assertEqual(summary["profiled_unique_cpes"], 2)
        self.assertIn("not candidate ranking", summary["analysis_scope"])
        self.assertEqual(
            field_counts["snapshot_id"],
            self.snapshot.snapshot_id,
        )
        self.assertEqual(
            field_counts["analysis_scope"],
            summary["analysis_scope"],
        )
        self.assertEqual(
            [row["primary_cpe"] for row in rows],
            [high_usage, low_usage],
        )
        self.assertTrue(
            all(
                row["snapshot_id"] == self.snapshot.snapshot_id
                for row in rows
            )
        )

    def test_refuses_overwrite_unless_requested(self) -> None:
        self.create_component(make_cpe(product="missing"))
        analysis = build_cpe_mismatch_profile_analysis(
            self.snapshot
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            write_cpe_mismatch_profile_analysis(
                analysis,
                output_directory,
            )
            with self.assertRaisesRegex(
                CPEMismatchProfilingError,
                "Refusing to overwrite",
            ):
                write_cpe_mismatch_profile_analysis(
                    analysis,
                    output_directory,
                )
            write_cpe_mismatch_profile_analysis(
                analysis,
                output_directory,
                overwrite=True,
            )

    def test_atomic_write_failure_is_reported_and_cleans_temps(
        self,
    ) -> None:
        self.create_component(make_cpe(product="missing"))
        analysis = build_cpe_mismatch_profile_analysis(
            self.snapshot
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            with (
                patch(
                    "sboms.cpe_mismatch_profiling.os.replace",
                    side_effect=OSError("rename failed"),
                ),
                self.assertRaisesRegex(OSError, "rename failed"),
            ):
                write_cpe_mismatch_profile_analysis(
                    analysis,
                    output_directory,
                )
            self.assertEqual(list(output_directory.iterdir()), [])

    def test_invariant_violations_fail(self) -> None:
        self.create_component(make_cpe(product="missing"))
        analysis = build_cpe_mismatch_profile_analysis(
            self.snapshot
        )
        invalid_summary = deepcopy(analysis.summary)
        invalid_summary["unique_not_in_dictionary"] += 1
        invalid_analysis = CPEMismatchProfileAnalysis(
            summary=invalid_summary,
            unique_cpe_mismatch_profiles=(
                analysis.unique_cpe_mismatch_profiles
            ),
            field_value_counts=analysis.field_value_counts,
        )

        with self.assertRaises(CPEMismatchProfilingError):
            validate_cpe_mismatch_profile_analysis(
                invalid_analysis
            )

        invalid_rows = [
            dict(row)
            for row in analysis.unique_cpe_mismatch_profiles
        ]
        invalid_rows[0][
            "same_part_vendor_product_version_count"
        ] = 1
        invalid_hierarchy = CPEMismatchProfileAnalysis(
            summary=analysis.summary,
            unique_cpe_mismatch_profiles=tuple(invalid_rows),
            field_value_counts=analysis.field_value_counts,
        )
        with self.assertRaisesRegex(
            CPEMismatchProfilingError,
            "hierarchy",
        ):
            validate_cpe_mismatch_profile_analysis(
                invalid_hierarchy
            )

    def test_management_command_is_read_only_and_preserves_exact_outputs(
        self,
    ) -> None:
        self.create_component(make_cpe(product="missing"))
        counts_before = self.model_counts()
        stdout = io.StringIO()

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output_directory = root / "mismatch"
            exact_output = root / "cpe-exact-match" / "summary.json"
            exact_output.parent.mkdir()
            exact_output.write_text(
                "existing exact-match result\n",
                encoding="utf-8",
            )
            call_command(
                "profile_cpe_dictionary_mismatches",
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
            self.assertEqual(
                exact_output.read_text(encoding="utf-8"),
                "existing exact-match result\n",
            )
            with self.assertRaises(CommandError):
                call_command(
                    "profile_cpe_dictionary_mismatches",
                    "--snapshot-id",
                    self.snapshot.snapshot_id,
                    "--output-dir",
                    str(output_directory),
                    stdout=io.StringIO(),
                )
            call_command(
                "profile_cpe_dictionary_mismatches",
                "--snapshot-id",
                self.snapshot.snapshot_id,
                "--output-dir",
                str(output_directory),
                "--overwrite",
                stdout=io.StringIO(),
            )

        self.assertEqual(self.model_counts(), counts_before)

    def test_command_rejects_invariant_failure(self) -> None:
        empty_analysis = CPEMismatchProfileAnalysis(
            summary={
                "unique_official_active": 0,
                "unique_official_deprecated": 0,
                "unique_not_in_dictionary": 1,
                "unique_primary_cpes": 0,
                "profile_status_counts": {
                    status.value: 0
                    for status in CPEMismatchProfileStatus
                },
                "component_weighted_profile_status_counts": {
                    status.value: 0
                    for status in CPEMismatchProfileStatus
                },
                "component_weighted_not_in_dictionary": 0,
                "profiled_unique_cpes": 0,
                "components_with_primary_cpe": 0,
                "components_without_primary_cpe": 0,
                "total_components": 0,
                "snapshot_id": self.snapshot.snapshot_id,
            },
            unique_cpe_mismatch_profiles=(),
            field_value_counts={
                "snapshot_id": self.snapshot.snapshot_id,
            },
        )

        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch(
                "sboms.management.commands."
                "profile_cpe_dictionary_mismatches."
                "build_cpe_mismatch_profile_analysis",
                return_value=empty_analysis,
            ),
            self.assertRaises(CommandError),
        ):
            call_command(
                "profile_cpe_dictionary_mismatches",
                "--snapshot-id",
                self.snapshot.snapshot_id,
                "--output-dir",
                temporary_directory,
                stdout=io.StringIO(),
            )
