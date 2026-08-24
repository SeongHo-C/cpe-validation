import csv
from collections import Counter

from django.conf import settings
from django.test import SimpleTestCase

from sboms.unitronics_ground_truth_full_dry_run import (
    _load_runtime_evidence,
    _parse_cpe22_family,
    classify_runtime_rows,
)


class UnitronicsFullDryRunRuntimeTests(SimpleTestCase):
    @staticmethod
    def _rows(relative_path: str) -> list[dict[str, str]]:
        path = settings.REPOSITORY_ROOT / relative_path
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    def test_conservative_runtime_partition_is_reproducible(self) -> None:
        components = self._rows(
            "analysis/results/unitronics-ground-truth-preanalysis/"
            "61602e128acb__52.07.13.7/components.csv"
        )
        packages = self._rows(
            "analysis/results/unitronics-source-package-analysis/"
            "61602e128acb__52.07.13.7/packages.csv"
        )
        runtime = self._rows(
            "analysis/results/unitronics-product-runtime-rulebook/"
            "61602e128acb__52.07.13.7/representative_cases.csv"
        )
        versions = self._rows(
            "analysis/results/unitronics-version-normalization-rulebook/"
            "61602e128acb__52.07.13.7/representative_cases.csv"
        )

        evidence = _load_runtime_evidence(runtime, versions)
        rows = classify_runtime_rows(
            components,
            {row["component_id"]: row for row in packages},
            evidence,
        )

        self.assertEqual(len(rows), 582)
        self.assertEqual(
            Counter(row["runtime_status"] for row in rows),
            Counter(
                {
                    "PRODUCT_RUNTIME": 14,
                    "NON_PRODUCT_RUNTIME": 176,
                    "REVIEW_REQUIRED": 392,
                }
            ),
        )
        fixed_positive_ids = {
            component_id
            for component_id, item in evidence.items()
            if item["status"] == "PRODUCT_RUNTIME"
        }
        actual_positive_ids = {
            row["component_id"]
            for row in rows
            if row["runtime_status"] == "PRODUCT_RUNTIME"
        }
        self.assertEqual(actual_positive_ids, fixed_positive_ids)

    def test_cpe22_control_id_comparison_extracts_only_family(self) -> None:
        self.assertEqual(
            _parse_cpe22_family("cpe:/a:haxx:libcurl"),
            ("a", "haxx", "libcurl"),
        )
        self.assertIsNone(_parse_cpe22_family("not-a-cpe"))
