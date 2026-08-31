from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from cpe_analysis.models import (
    CPEAnalysisRun,
    CPEAnalysisRunStatus,
)
from cpe_analysis.views import CPE_ANALYSIS_ALGORITHM_IDS


class CpeAnalysisSummaryAPITests(TestCase):
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

    def create_run(
        self,
        *,
        algorithm_id: str = "length_normalized_levenshtein",
        status_value: str = CPEAnalysisRunStatus.COMPLETED,
        top1_accuracy: float | None = 0.4,
        completed_at=None,
    ) -> CPEAnalysisRun:
        is_completed = status_value == CPEAnalysisRunStatus.COMPLETED
        return CPEAnalysisRun.objects.create(
            algorithm_id=algorithm_id,
            status=status_value,
            parameters={},
            query_count=158,
            candidate_family_count=181_484,
            top1_accuracy=top1_accuracy if is_completed else None,
            recall_at_5=0.7848101265822784 if is_completed else None,
            recall_at_10=0.8037974683544303 if is_completed else None,
            mrr=0.5565417164607827 if is_completed else None,
            unique_correct_count=63 if is_completed else None,
            ambiguous_count=55 if is_completed else None,
            not_top_group_count=40 if is_completed else None,
            completed_at=completed_at if is_completed else None,
        )

    def valid_manifest(self) -> dict[str, int]:
        return {
            "positive_gt_components_at_validation": 158,
            "searchable_candidate_families": 181_484,
        }

    @staticmethod
    def algorithm_by_id(
        body: dict[str, object],
        algorithm_id: str,
    ) -> dict[str, object]:
        algorithms = body["algorithms"]
        assert isinstance(algorithms, list)
        return next(
            algorithm
            for algorithm in algorithms
            if algorithm["algorithm_id"] == algorithm_id
        )

    def test_returns_manifest_summary_with_no_run_states(self) -> None:
        self.write_manifest(
            {
                **self.valid_manifest(),
                "ignored_field": "not exposed",
            }
        )

        with self.assertNumQueries(1):
            response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        body = response.json()
        self.assertEqual(body["positive_gt_components_at_validation"], 158)
        self.assertEqual(body["searchable_candidate_families"], 181_484)
        self.assertEqual(body["method_count"], 6)
        self.assertEqual(body["completed_method_count"], 0)
        self.assertEqual(
            [algorithm["algorithm_id"] for algorithm in body["algorithms"]],
            list(CPE_ANALYSIS_ALGORITHM_IDS),
        )
        self.assertTrue(
            all(
                algorithm["status"] == "NOT_RUN"
                and algorithm["metrics"] is None
                for algorithm in body["algorithms"]
            )
        )

    def test_returns_completed_run_metrics_and_scope(self) -> None:
        self.write_manifest(self.valid_manifest())
        self.create_run(
            top1_accuracy=0.3987341772151899,
            completed_at=timezone.now(),
        )

        with self.assertNumQueries(1):
            response = self.client.get(self.url)

        body = response.json()
        levenshtein = self.algorithm_by_id(
            body,
            "length_normalized_levenshtein",
        )
        self.assertEqual(body["completed_method_count"], 1)
        self.assertEqual(levenshtein["status"], "COMPLETED")
        self.assertEqual(
            levenshtein["query_count"],
            body["positive_gt_components_at_validation"],
        )
        self.assertEqual(
            levenshtein["candidate_family_count"],
            body["searchable_candidate_families"],
        )
        self.assertEqual(
            levenshtein["metrics"],
            {
                "top1_accuracy": 0.3987341772151899,
                "recall_at_5": 0.7848101265822784,
                "recall_at_10": 0.8037974683544303,
                "mrr": 0.5565417164607827,
            },
        )

    def test_latest_completed_run_is_selected(self) -> None:
        self.write_manifest(self.valid_manifest())
        now = timezone.now()
        self.create_run(
            top1_accuracy=0.3,
            completed_at=now - timedelta(hours=2),
        )
        latest = self.create_run(
            top1_accuracy=0.4,
            completed_at=now - timedelta(hours=1),
        )

        response = self.client.get(self.url)

        levenshtein = self.algorithm_by_id(
            response.json(),
            "length_normalized_levenshtein",
        )
        self.assertEqual(levenshtein["metrics"]["top1_accuracy"], 0.4)
        self.assertEqual(latest.status, CPEAnalysisRunStatus.COMPLETED)

    def test_running_run_does_not_hide_prior_completed_run(self) -> None:
        self.write_manifest(self.valid_manifest())
        completed = self.create_run(
            top1_accuracy=0.35,
            completed_at=timezone.now() - timedelta(hours=1),
        )
        self.create_run(status_value=CPEAnalysisRunStatus.RUNNING)

        response = self.client.get(self.url)

        levenshtein = self.algorithm_by_id(
            response.json(),
            "length_normalized_levenshtein",
        )
        self.assertEqual(levenshtein["status"], "COMPLETED")
        self.assertEqual(
            levenshtein["metrics"]["top1_accuracy"],
            completed.top1_accuracy,
        )

    def test_incomplete_runs_only_are_reported_as_not_run(self) -> None:
        self.write_manifest(self.valid_manifest())
        self.create_run(status_value=CPEAnalysisRunStatus.RUNNING)
        self.create_run(status_value=CPEAnalysisRunStatus.FAILED)

        response = self.client.get(self.url)

        body = response.json()
        levenshtein = self.algorithm_by_id(
            body,
            "length_normalized_levenshtein",
        )
        self.assertEqual(body["completed_method_count"], 0)
        self.assertEqual(levenshtein["status"], "NOT_RUN")
        self.assertIsNone(levenshtein["metrics"])

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
        self.write_manifest(self.valid_manifest())

        response = self.client.post(self.url, data={})

        self.assertEqual(
            response.status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
