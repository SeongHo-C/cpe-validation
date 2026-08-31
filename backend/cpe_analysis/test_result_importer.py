from __future__ import annotations

import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import TestCase

from cpe_analysis.models import (
    CPEAnalysisQueryResult,
    CPEAnalysisRun,
)
from cpe_analysis.result_importer import (
    BenchmarkArtifactValidationError,
    ExistingAnalysisRunError,
    ExpectedBenchmarkIdentity,
    calculate_database_metrics,
    import_benchmark_results,
)
from sboms.models import Component, SBOMDocument


class BenchmarkResultImporterTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.sbom_document = SBOMDocument.objects.create(
            manufacturer="Example Vendor",
            product_name="Example Firmware",
            product_version="1.0",
            source_path="test/importer-example.cdx.json",
            file_sha256="f" * 64,
            spec_version="1.6",
            generator_name="test",
            generator_version="1.0",
        )
        cls.components = tuple(
            Component.objects.create(
                sbom_document=cls.sbom_document,
                bom_ref=f"component-{index}",
                component_type="library",
                name=f"Component {index}",
                version="1.0",
            )
            for index in range(1, 4)
        )

    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.artifact_directory = Path(self.temporary_directory.name)
        component_ids = [component.pk for component in self.components]
        self.rows = [
            self.row(
                component_id=component_ids[0],
                target_score=0.0,
                better_count=0,
                tie_size=1,
                outcome="UNIQUE_CORRECT",
            ),
            self.row(
                component_id=component_ids[1],
                target_score=0.2,
                better_count=0,
                tie_size=3,
                outcome="CORRECT_BUT_AMBIGUOUS",
            ),
            self.row(
                component_id=component_ids[2],
                target_score=0.4,
                better_count=1,
                tie_size=1,
                outcome="NOT_TOP_GROUP",
            ),
        ]
        self.expected_identity = ExpectedBenchmarkIdentity(
            algorithm_id="test_algorithm",
            query_count=3,
            candidate_family_count=10,
            top1_count=1,
            recall_at_5_count=3,
            recall_at_10_count=3,
            mrr=(1 + (1 / 3) + (1 / 2)) / 3,
            unique_correct_count=1,
            ambiguous_count=1,
            not_top_group_count=1,
        )
        self.write_artifacts()

    @staticmethod
    def row(
        *,
        component_id: int,
        target_score: float,
        better_count: int,
        tie_size: int,
        outcome: str,
    ) -> dict[str, object]:
        best_rank = better_count + 1
        worst_rank = better_count + tie_size
        return {
            "component_id": component_id,
            "algorithm_id": "test_algorithm",
            "target_score": target_score,
            "better_count": better_count,
            "tie_size": tie_size,
            "best_rank": best_rank,
            "worst_rank": worst_rank,
            "outcome": outcome,
            "top_group_hit": best_rank == 1,
            "top1_success": worst_rank == 1,
            "recall_at_5_success": worst_rank <= 5,
            "recall_at_10_success": worst_rank <= 10,
            "reciprocal_rank": 1 / worst_rank,
        }

    def write_artifacts(
        self,
        *,
        rows: list[dict[str, object]] | None = None,
        aggregate_updates: dict[str, object] | None = None,
    ) -> None:
        rows = rows if rows is not None else self.rows
        with (
            self.artifact_directory / "per_query_results.csv"
        ).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=tuple(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

        top1_count = sum(int(row["worst_rank"]) == 1 for row in rows)
        recall_at_5_count = sum(
            int(row["worst_rank"]) <= 5 for row in rows
        )
        recall_at_10_count = sum(
            int(row["worst_rank"]) <= 10 for row in rows
        )
        mrr = sum(1 / int(row["worst_rank"]) for row in rows) / len(
            rows
        )
        outcomes = {
            outcome: sum(row["outcome"] == outcome for row in rows)
            for outcome in (
                "UNIQUE_CORRECT",
                "CORRECT_BUT_AMBIGUOUS",
                "NOT_TOP_GROUP",
            )
        }
        aggregate = {
            "algorithm_id": "test_algorithm",
            "candidate_family_count": 10,
            "correct_but_ambiguous_count": outcomes[
                "CORRECT_BUT_AMBIGUOUS"
            ],
            "mrr": mrr,
            "not_top_group_count": outcomes["NOT_TOP_GROUP"],
            "query_count": len(rows),
            "recall_at_10": recall_at_10_count / len(rows),
            "recall_at_10_success_count": recall_at_10_count,
            "recall_at_5": recall_at_5_count / len(rows),
            "recall_at_5_success_count": recall_at_5_count,
            "top1_accuracy": top1_count / len(rows),
            "top1_success_count": top1_count,
            "top_group_hit_count": sum(
                int(row["best_rank"]) == 1 for row in rows
            ),
            "unique_correct_count": outcomes["UNIQUE_CORRECT"],
        }
        aggregate.update(aggregate_updates or {})
        input_manifest = {
            "algorithm": {"algorithm_id": "test_algorithm"},
            "candidate_family_count": 10,
            "query_count": len(rows),
            "version_used": False,
        }
        summary = {
            "algorithm_id": "test_algorithm",
            "aggregate_metrics": aggregate,
            "dataset": {
                "candidate_families": 10,
                "queries": len(rows),
            },
        }
        for filename, value in (
            ("aggregate_metrics.json", aggregate),
            ("input_manifest.json", input_manifest),
            ("summary.json", summary),
        ):
            (self.artifact_directory / filename).write_text(
                json.dumps(value),
                encoding="utf-8",
            )

    def import_results(self, *, dry_run: bool = False):
        return import_benchmark_results(
            self.artifact_directory,
            expected_identity=self.expected_identity,
            dry_run=dry_run,
        )

    def test_successful_import_creates_one_run_and_all_results(self) -> None:
        result = self.import_results()

        self.assertFalse(result.dry_run)
        self.assertEqual(result.inserted_query_results, 3)
        self.assertEqual(CPEAnalysisRun.objects.count(), 1)
        self.assertEqual(CPEAnalysisQueryResult.objects.count(), 3)
        run = CPEAnalysisRun.objects.get()
        self.assertEqual(run.parameters, {})
        self.assertEqual(run.query_results.count(), 3)

    def test_database_rank_recalculation_matches_run_aggregate(self) -> None:
        result = self.import_results()
        run = CPEAnalysisRun.objects.get(pk=result.run_id)
        metrics = calculate_database_metrics(run)

        self.assertEqual(metrics, result.metrics)
        self.assertAlmostEqual(run.top1_accuracy, metrics.top1_accuracy)
        self.assertAlmostEqual(run.recall_at_5, metrics.recall_at_5)
        self.assertAlmostEqual(run.recall_at_10, metrics.recall_at_10)
        self.assertAlmostEqual(run.mrr, metrics.mrr)
        self.assertEqual(metrics.top_group_hit_count, 2)

    def test_dry_run_validates_without_inserting_rows(self) -> None:
        result = self.import_results(dry_run=True)

        self.assertTrue(result.dry_run)
        self.assertEqual(result.component_coverage, 3)
        self.assertEqual(result.inserted_query_results, 0)
        self.assertEqual(CPEAnalysisRun.objects.count(), 0)
        self.assertEqual(CPEAnalysisQueryResult.objects.count(), 0)

    def test_duplicate_component_artifact_is_rejected(self) -> None:
        duplicate_rows = [dict(row) for row in self.rows]
        duplicate_rows[2]["component_id"] = duplicate_rows[0][
            "component_id"
        ]
        self.write_artifacts(rows=duplicate_rows)

        with self.assertRaises(BenchmarkArtifactValidationError):
            self.import_results()
        self.assertEqual(CPEAnalysisRun.objects.count(), 0)
        self.assertEqual(CPEAnalysisQueryResult.objects.count(), 0)

    def test_duplicate_import_does_not_create_another_run(self) -> None:
        self.import_results()

        with self.assertRaises(ExistingAnalysisRunError):
            self.import_results()
        self.assertEqual(CPEAnalysisRun.objects.count(), 1)
        self.assertEqual(CPEAnalysisQueryResult.objects.count(), 3)

    def test_invalid_rank_artifact_leaves_no_partial_rows(self) -> None:
        invalid_rows = [dict(row) for row in self.rows]
        invalid_rows[2]["best_rank"] = 3
        self.write_artifacts(rows=invalid_rows)

        with self.assertRaises(BenchmarkArtifactValidationError):
            self.import_results()
        self.assertEqual(CPEAnalysisRun.objects.count(), 0)
        self.assertEqual(CPEAnalysisQueryResult.objects.count(), 0)

    def test_missing_component_leaves_no_partial_rows(self) -> None:
        invalid_rows = [dict(row) for row in self.rows]
        invalid_rows[2]["component_id"] = 999_999
        self.write_artifacts(rows=invalid_rows)

        with self.assertRaises(BenchmarkArtifactValidationError):
            self.import_results()
        self.assertEqual(CPEAnalysisRun.objects.count(), 0)
        self.assertEqual(CPEAnalysisQueryResult.objects.count(), 0)

    def test_aggregate_mismatch_leaves_no_partial_rows(self) -> None:
        self.write_artifacts(aggregate_updates={"top1_success_count": 2})

        with self.assertRaises(BenchmarkArtifactValidationError):
            self.import_results()
        self.assertEqual(CPEAnalysisRun.objects.count(), 0)
        self.assertEqual(CPEAnalysisQueryResult.objects.count(), 0)
