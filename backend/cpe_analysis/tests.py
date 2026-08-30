from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from rest_framework import status


class CpeAnalysisSummaryAPITests(SimpleTestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.repository_root = Path(self.temporary_directory.name)
        self.manifest_path = (
            self.repository_root
            / "data/cpe_candidate_universe/manifest.json"
        )
        self.manifest_path.parent.mkdir(parents=True)
        self.settings_override = override_settings(
            REPOSITORY_ROOT=self.repository_root
        )
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)

    @property
    def url(self) -> str:
        return reverse("cpe_analysis_api:summary")

    def write_manifest(self, data: object) -> None:
        self.manifest_path.write_text(
            json.dumps(data),
            encoding="utf-8",
        )

    def test_returns_manifest_summary_without_database_access(self) -> None:
        self.write_manifest(
            {
                "positive_gt_components_at_validation": 158,
                "searchable_candidate_families": 181_484,
                "ignored_field": "not exposed",
            }
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json(),
            {
                "positive_gt_components_at_validation": 158,
                "searchable_candidate_families": 181_484,
            },
        )

    def test_missing_manifest_returns_service_unavailable(self) -> None:
        response = self.client.get(self.url)

        self.assertEqual(
            response.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            response.json(),
            {
                "code": "cpe_analysis_manifest_unavailable",
                "detail": "CPE analysis metadata is unavailable.",
            },
        )

    def test_malformed_or_invalid_manifest_returns_service_unavailable(
        self,
    ) -> None:
        cases = (
            "{not-json",
            json.dumps([]),
            json.dumps(
                {
                    "positive_gt_components_at_validation": 158,
                    "searchable_candidate_families": "181484",
                }
            ),
        )
        for raw_manifest in cases:
            with self.subTest(raw_manifest=raw_manifest):
                self.manifest_path.write_text(
                    raw_manifest,
                    encoding="utf-8",
                )
                response = self.client.get(self.url)
                self.assertEqual(
                    response.status_code,
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                )

    def test_endpoint_is_read_only(self) -> None:
        self.write_manifest(
            {
                "positive_gt_components_at_validation": 158,
                "searchable_candidate_families": 181_484,
            }
        )

        response = self.client.post(self.url, data={})

        self.assertEqual(
            response.status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
