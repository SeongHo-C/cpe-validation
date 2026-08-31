from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from cpe_analysis.models import (
    CPEAnalysisOutcome,
    CPEAnalysisQueryResult,
    CPEAnalysisRun,
    CPEAnalysisRunStatus,
)
from sboms.models import Component, SBOMDocument


class CPEAnalysisModelTests(TestCase):
    def setUp(self) -> None:
        self.sbom_document = SBOMDocument.objects.create(
            manufacturer="Example Vendor",
            product_name="Example Firmware",
            product_version="1.0",
            source_path="test/example.cdx.json",
            file_sha256="a" * 64,
            spec_version="1.6",
            generator_name="test",
            generator_version="1.0",
        )
        self.component = self.create_component("component-1")

    def create_component(self, bom_ref: str) -> Component:
        return Component.objects.create(
            sbom_document=self.sbom_document,
            bom_ref=bom_ref,
            component_type="library",
            name=bom_ref,
            version="1.0",
        )

    def create_run(
        self,
        *,
        status: str = CPEAnalysisRunStatus.COMPLETED,
    ) -> CPEAnalysisRun:
        completed = status == CPEAnalysisRunStatus.COMPLETED
        return CPEAnalysisRun.objects.create(
            algorithm_id="length_normalized_levenshtein",
            status=status,
            parameters={},
            query_count=158,
            candidate_family_count=181_484,
            top1_accuracy=0.3987341772151899 if completed else None,
            recall_at_5=0.7848101265822784 if completed else None,
            recall_at_10=0.8037974683544303 if completed else None,
            mrr=0.5565417164607827 if completed else None,
            unique_correct_count=63 if completed else None,
            ambiguous_count=55 if completed else None,
            not_top_group_count=40 if completed else None,
            completed_at=timezone.now() if completed else None,
        )

    def query_result(
        self,
        *,
        run: CPEAnalysisRun,
        component: Component | None = None,
        best_rank: int = 1,
        worst_rank: int = 1,
        tie_size: int = 1,
        outcome: str = CPEAnalysisOutcome.UNIQUE_CORRECT,
    ) -> CPEAnalysisQueryResult:
        return CPEAnalysisQueryResult(
            run=run,
            component=component or self.component,
            target_score=0.0,
            better_count=best_rank - 1,
            tie_size=tie_size,
            best_rank=best_rank,
            worst_rank=worst_rank,
            outcome=outcome,
        )

    def test_completed_run_can_be_created(self) -> None:
        run = self.create_run()

        self.assertEqual(run.status, CPEAnalysisRunStatus.COMPLETED)
        self.assertEqual(run.unique_correct_count, 63)
        self.assertIsNotNone(run.completed_at)

    def test_running_run_allows_null_metrics(self) -> None:
        run = self.create_run(status=CPEAnalysisRunStatus.RUNNING)

        self.assertIsNone(run.top1_accuracy)
        self.assertIsNone(run.recall_at_5)
        self.assertIsNone(run.recall_at_10)
        self.assertIsNone(run.mrr)
        self.assertIsNone(run.unique_correct_count)
        self.assertIsNone(run.ambiguous_count)
        self.assertIsNone(run.not_top_group_count)
        self.assertIsNone(run.completed_at)

    def test_multiple_runs_for_the_same_algorithm_are_allowed(self) -> None:
        first = self.create_run()
        second = self.create_run()

        self.assertNotEqual(first.pk, second.pk)
        self.assertEqual(first.algorithm_id, second.algorithm_id)

    def test_not_run_is_not_a_persisted_status(self) -> None:
        self.assertNotIn("NOT_RUN", CPEAnalysisRunStatus.values)

    def test_parameters_must_be_a_json_object(self) -> None:
        run = self.create_run()
        run.parameters = ["not", "an", "object"]

        with self.assertRaises(ValidationError):
            run.full_clean()

    def test_query_result_relates_run_and_component(self) -> None:
        run = self.create_run()
        result = self.query_result(run=run)
        result.full_clean()
        result.save()

        self.assertEqual(list(run.query_results.all()), [result])
        self.assertEqual(
            list(self.component.cpe_analysis_results.all()),
            [result],
        )

    def test_run_component_pair_is_unique(self) -> None:
        run = self.create_run()
        self.query_result(run=run).save()

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                self.query_result(run=run).save()

    def test_three_valid_outcome_semantics(self) -> None:
        run = self.create_run()
        cases = (
            (CPEAnalysisOutcome.UNIQUE_CORRECT, 1, 1, 1),
            (CPEAnalysisOutcome.CORRECT_BUT_AMBIGUOUS, 1, 3, 3),
            (CPEAnalysisOutcome.NOT_TOP_GROUP, 2, 4, 3),
        )
        for index, (outcome, best_rank, worst_rank, tie_size) in enumerate(
            cases,
            start=2,
        ):
            with self.subTest(outcome=outcome):
                result = self.query_result(
                    run=run,
                    component=self.create_component(f"component-{index}"),
                    best_rank=best_rank,
                    worst_rank=worst_rank,
                    tie_size=tie_size,
                    outcome=outcome,
                )
                result.full_clean()
                result.save()

    def test_invalid_outcome_semantics_are_rejected(self) -> None:
        run = self.create_run()
        cases = (
            (CPEAnalysisOutcome.UNIQUE_CORRECT, 1, 2),
            (CPEAnalysisOutcome.CORRECT_BUT_AMBIGUOUS, 1, 1),
            (CPEAnalysisOutcome.NOT_TOP_GROUP, 1, 2),
        )
        for outcome, best_rank, worst_rank in cases:
            with self.subTest(outcome=outcome):
                result = self.query_result(
                    run=run,
                    best_rank=best_rank,
                    worst_rank=worst_rank,
                    tie_size=worst_rank - best_rank + 1,
                    outcome=outcome,
                )
                with self.assertRaises(ValidationError):
                    result.full_clean()

    def test_rank_order_and_positive_constraints_are_validated(self) -> None:
        run = self.create_run()
        invalid_rank_order = self.query_result(
            run=run,
            best_rank=2,
            worst_rank=1,
            outcome=CPEAnalysisOutcome.NOT_TOP_GROUP,
        )
        zero_values = self.query_result(
            run=run,
            best_rank=0,
            worst_rank=0,
            tie_size=0,
        )

        with self.assertRaises(ValidationError):
            invalid_rank_order.full_clean()
        with self.assertRaises(ValidationError):
            zero_values.full_clean()

    def test_derived_rank_metrics_are_not_database_fields(self) -> None:
        run = self.create_run()
        result = self.query_result(
            run=run,
            best_rank=1,
            worst_rank=5,
            tie_size=5,
            outcome=CPEAnalysisOutcome.CORRECT_BUT_AMBIGUOUS,
        )
        field_names = {
            field.name for field in CPEAnalysisQueryResult._meta.fields
        }

        self.assertTrue(result.top_group_hit)
        self.assertFalse(result.top1_success)
        self.assertTrue(result.recall_at_5_success)
        self.assertTrue(result.recall_at_10_success)
        self.assertEqual(result.reciprocal_rank, 0.2)
        self.assertTrue(
            {
                "top_group_hit",
                "top1_success",
                "recall_at_5_success",
                "recall_at_10_success",
                "reciprocal_rank",
            }.isdisjoint(field_names)
        )

    def test_models_contain_only_the_minimal_fields(self) -> None:
        run_fields = {field.name for field in CPEAnalysisRun._meta.fields}
        result_fields = {
            field.name for field in CPEAnalysisQueryResult._meta.fields
        }

        self.assertEqual(
            run_fields,
            {
                "id",
                "algorithm_id",
                "status",
                "parameters",
                "query_count",
                "candidate_family_count",
                "top1_accuracy",
                "recall_at_5",
                "recall_at_10",
                "mrr",
                "unique_correct_count",
                "ambiguous_count",
                "not_top_group_count",
                "created_at",
                "completed_at",
            },
        )
        self.assertEqual(
            result_fields,
            {
                "id",
                "run",
                "component",
                "target_score",
                "better_count",
                "tie_size",
                "best_rank",
                "worst_rank",
                "outcome",
            },
        )
